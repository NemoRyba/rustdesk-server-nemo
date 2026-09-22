use crate::common::*;
use hbb_common::nemo_device_auth_payload;
use crate::peer::*;
use hbb_common::{
    allow_err, bail,
    bytes::{Bytes, BytesMut},
    bytes_codec::BytesCodec,
    config,
    futures::future::join_all,
    futures_util::{
        sink::SinkExt,
        stream::{SplitSink, StreamExt},
    },
    log,
    protobuf::{Message as _, MessageField},
    rendezvous_proto::{
        register_pk_response::Result::{TOO_FREQUENT, UUID_MISMATCH},
        *,
    },
    tcp::{listen_any, Encrypt, FramedStream},
    timeout,
    tokio::{
        self,
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::{mpsc, Mutex},
        time::{interval, Duration},
    },
    tokio_util::codec::Framed,
    try_into_v4,
    udp::FramedSocket,
    AddrMangle, ResultType,
};
use ipnetwork::Ipv4Network;
use sodiumoxide::crypto::{box_, sign};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
    sync::Arc,
    time::Instant,
};

#[derive(Clone, Debug)]
enum Data {
    Msg(Box<RendezvousMessage>, SocketAddr),
    RelayServers0(String),
    RelayServers(RelayServers),
}

// Upstream bug port (91fb928, rustdesk-server #676): i64 not i32 — `as_millis() as i32`
// wraps negative after ~24.9 days offline and falsely reports a peer online (relaying to
// its stale addr). Widened here and at the two elapsed casts below.
const REG_TIMEOUT: i64 = 30_000;
type TcpStreamSink = SplitSink<Framed<TcpStream, BytesCodec>, Bytes>;
type WsSink = SplitSink<tokio_tungstenite::WebSocketStream<TcpStream>, tungstenite::Message>;
enum Sink {
    // C (--key-exchange): the cipher rides WITH the sink. A punch/relay sink is
    // MOVED into `tcp_punch` and drained later from another task, so a
    // per-connection local would not survive; `Encrypt` also carries monotonic
    // send/recv counters (tcp.rs), so it must never be cloned or reset once the
    // connection is secured. `None` = this connection is plaintext, i.e. today.
    TcpStream(TcpStreamSink, Option<Encrypt>),
    Ws(WsSink),
}
type Sender = mpsc::UnboundedSender<Data>;
type Receiver = mpsc::UnboundedReceiver<Data>;
static ROTATION_RELAY_SERVER: AtomicUsize = AtomicUsize::new(0);
type RelayServers = Vec<String>;
const CHECK_RELAY_TIMEOUT: u64 = 3_000;
static ALWAYS_USE_RELAY: AtomicBool = AtomicBool::new(false);
// TBFDesk: whether plaintext UDP registration is still accepted.
//
// The KeyExchange protects the TCP rendezvous channel only -- UDP has no handshake, so
// a client registering over UDP is in the clear no matter what --key-exchange says.
// Closing this is therefore the LAST step of the rollout, not the first: refuse UDP
// before the fleet is on disable-udp=Y and those clients simply cannot register.
static UDP_REGISTRATION: AtomicBool = AtomicBool::new(true);

// C (--key-exchange): server half of the rendezvous handshake the client already
// speaks (client common.rs::secure_tcp_impl). Process-global like
// ALWAYS_USE_RELAY above, resolved once in `start` before anything listens.
static KEY_EXCHANGE_MODE: AtomicU8 = AtomicU8::new(KeyExchangeMode::Off as u8);
// The client answers our offer immediately, so a peer that says nothing is a peer
// that does not speak this handshake; do not hold the task for the full read window.
const KEY_EXCHANGE_TIMEOUT: u64 = 3_000;

/// C: how this server treats the rendezvous key exchange. `Require` is the default
/// (main.rs). `Off` sends nothing at all -- and because the handshake block in
/// `handle_listener_inner` is also where the device-key proof is read, `Off` leaves
/// Layer 1 unenforced on this transport, not just unencrypted. Debugging only.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum KeyExchangeMode {
    Off = 0,
    /// Offer the handshake; a client that does not complete it stays plaintext.
    Offer = 1,
    /// Offer the handshake and close the connection when it does not complete.
    Require = 2,
}

impl KeyExchangeMode {
    fn parse(v: &str) -> ResultType<Self> {
        match v.trim().to_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "offer" => Ok(Self::Offer),
            "require" => Ok(Self::Require),
            // An EMPTY value is the same silent downgrade as a typo, and it is the one
            // an operator hits by accident: `--key-exchange ""`, an unset ${VAR} in a
            // systemd ExecStart, or a blank entry in .env / --config all arrive here as
            // "". get_arg_or applies the compiled-in `require` only when the flag is
            // ABSENT, so "" always means someone passed the flag and meant something.
            "" => bail!(
                "--key-exchange was given an empty value, expected off|offer|require \
                 (omit the flag for the default, require)"
            ),
            // A typo must not silently downgrade a security flag to off; an
            // operator only ever sees this by having set the flag explicitly.
            other => bail!(
                "Invalid --key-exchange={}, expected off|offer|require",
                other
            ),
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Offer => "offer",
            Self::Require => "require",
        }
    }
}

#[inline]
fn key_exchange_mode() -> KeyExchangeMode {
    match KEY_EXCHANGE_MODE.load(Ordering::SeqCst) {
        x if x == KeyExchangeMode::Offer as u8 => KeyExchangeMode::Offer,
        x if x == KeyExchangeMode::Require as u8 => KeyExchangeMode::Require,
        _ => KeyExchangeMode::Off,
    }
}

// Store punch hole requests
use once_cell::sync::Lazy;
use tokio::sync::Mutex as TokioMutex; // differentiate if needed
#[derive(Clone)]
struct PunchReqEntry { tm: Instant, from_ip: String, to_ip: String, to_id: String }
static PUNCH_REQS: Lazy<TokioMutex<Vec<PunchReqEntry>>> = Lazy::new(|| TokioMutex::new(Vec::new()));
const PUNCH_REQ_DEDUPE_SEC: u64 = 60;

#[derive(Clone)]
struct Inner {
    serial: i32,
    version: String,
    software_url: String,
    mask: Option<Ipv4Network>,
    local_ip: String,
    sk: Option<sign::SecretKey>,
}

/// H43: a live rendezvous connection we can push INTO, keyed by peer id. hbbs used
/// to reach a peer only over UDP (`Data::Msg`), so a peer that registered over TCP or
/// WS showed up online but could never RECEIVE a punch or relay request -- it could
/// call out, and nothing could call it. The connection task owns its sink; this is the
/// handle other tasks use to hand it a message to write.
type PeerPush = tokio::sync::mpsc::UnboundedSender<RendezvousMessage>;

#[derive(Clone)]
pub struct RendezvousServer {
    tcp_punch: Arc<Mutex<HashMap<SocketAddr, Sink>>>,
    /// Peers whose rendezvous connection is TCP/WS rather than UDP. Entries are
    /// replaced on reconnect and swept when their receiver is gone, so a task that
    /// exits never has to remove its own -- which would otherwise race a reconnect
    /// that had already replaced it.
    tcp_peers: Arc<Mutex<HashMap<String, PeerPush>>>,
    pm: PeerMap,
    tx: Sender,
    relay_servers: Arc<RelayServers>,
    relay_servers0: Arc<RelayServers>,
    rendezvous_servers: Arc<Vec<String>>,
    inner: Arc<Inner>,
}

enum LoopFailure {
    UdpSocket,
    Listener3,
    Listener2,
    Listener,
}

/// An un-upgraded client hitting `--udp-registration=N` has NO fallback: start_udp never
/// bails on silence, it just retries forever. With only a debug log on the server, such a
/// machine goes silently dark and nothing on either end says why. So warn -- but throttle
/// it, because that client retries every few seconds and would otherwise flood the log.
fn warn_udp_refused_throttled(kind: &str, addr: SocketAddr) {
    use std::sync::Mutex;
    static LAST: Lazy<Mutex<Option<Instant>>> = Lazy::new(|| Mutex::new(None));
    let mut last = LAST.lock().unwrap();
    let due = last.map(|t| t.elapsed().as_secs() >= 60).unwrap_or(true);
    if due {
        *last = Some(Instant::now());
        log::warn!(
            "Refusing plaintext UDP {} from {} (udp-registration=N). That client is NOT \
             online and has no fallback -- it needs disable-udp=Y. Further refusals are \
             logged at most once a minute.",
            kind,
            addr
        );
    } else {
        log::debug!("Refusing plaintext UDP {} from {}", kind, addr);
    }
}

/// H5: a rendezvous connection whose peer proved, with a pinned device key, that it is a
/// provisioned fleet member. `peer_id` is the id the proof is bound to, so the
/// registration that follows can be held to it.
#[derive(Clone, Debug)]
pub(crate) struct AuthedDevice {
    pub device_pub_b64: String,
    pub peer_id: String,
}

impl RendezvousServer {
    #[tokio::main(flavor = "multi_thread")]
    pub async fn start(
        port: i32,
        serial: i32,
        key: &str,
        rmem: usize,
        key_exchange: &str,
    ) -> ResultType<()> {
        let (key, sk) = Self::get_server_sk(key);
        #[cfg(feature = "nemo-management-api")]
        let nemo_server_secret_key = sk.clone();
        // C (--key-exchange): resolve the mode before anything listens, and log it
        // like ALWAYS_USE_RELAY below so the effective mode is readable straight out
        // of the boot log. The offer is signed with the server key, so without one
        // no client can verify it.
        let mut key_exchange = KeyExchangeMode::parse(key_exchange)?;
        if key_exchange != KeyExchangeMode::Off && sk.is_none() {
            if key_exchange == KeyExchangeMode::Require {
                // require-with-no-key refuses every TCP accept, i.e. a total outage.
                // Fail at boot rather than after the fleet has reconnected.
                bail!("--key-exchange=require needs a server signing key: pass -k <private key> or put id_ed25519 next to hbbs");
            }
            // Degrade loudly: a silent offer no client can verify shows up on the
            // client only as the 18s READ_TIMEOUT of secure_tcp, with no server hint.
            log::warn!(
                "--key-exchange={} has no server signing key to sign the offer with (pass -k <private key> or put id_ed25519 next to hbbs); degrading to off",
                key_exchange.as_str()
            );
            key_exchange = KeyExchangeMode::Off;
        }
        KEY_EXCHANGE_MODE.store(key_exchange as u8, Ordering::SeqCst);
        log::info!("key-exchange={}", key_exchange.as_str());
        // `off` skips the whole handshake block in handle_listener_inner -- which is also
        // where the NemoClientAuth arm and the require-device-key refusal live -- so it
        // does not merely drop encryption, it drops Layer 1 on this transport while the
        // stored require_device_key still reads `true` in the config and the admin API.
        // Warn like udp-registration=Y below: the plaintext path must be impossible to
        // miss. This also covers the degrade-to-off path above.
        if key_exchange == KeyExchangeMode::Off {
            log::warn!(
                "key-exchange=off: the rendezvous TCP channel is PLAINTEXT and carries no \
                 device-key proof, so require-device-key is NOT enforced on it -- anything \
                 that connects may register, punch and relay unauthenticated. TBFDesk \
                 clients refuse an unsecured rendezvous, so this also takes the fleet \
                 offline. Debugging only; the default is require."
            );
        }
        let udp_registration = get_arg_or("udp-registration", "N".to_owned())
            .to_uppercase()
            .starts_with('Y');
        UDP_REGISTRATION.store(udp_registration, Ordering::SeqCst);
        log::info!("udp-registration={}", if udp_registration { "Y" } else { "N" });
        // Make the remaining plaintext path impossible to miss. --key-exchange only
        // covers TCP; as long as UDP registration is accepted, a client that has not
        // been switched to disable-udp=Y is still registering in the clear.
        if udp_registration {
            // Inverted: N is the default now, so it is switching it back ON that deserves
            // the warning.
            log::warn!(
                "udp-registration=Y: plaintext UDP registration is ACCEPTED. UDP has no \
                 key exchange and no device-key proof, so any client registering that way \
                 does so in the clear and unauthenticated -- it bypasses both \
                 --key-exchange and require-device-key. Only use this to recover a fleet \
                 that cannot yet reach the TCP channel."
            );
        }
        if !udp_registration {
            log::info!(
                "udp-registration=N (default): plaintext UDP registration is refused, so \
                 every client->server message is encrypted. Clients need disable-udp=Y, \
                 which is now their default too, and are reachable in both directions -- \
                 hbbs pushes punch and relay requests over the peer's own rendezvous \
                 connection. NOTE this does not disable UDP hole punching, which is a \
                 separate client switch (enable-udp-punch)."
            );
        }
        let nat_port = port - 1;
        let ws_port = port + 2;
        let pm = PeerMap::new().await?;
        log::info!("serial={}", serial);
        let rendezvous_servers = get_servers(&get_arg("rendezvous-servers"), "rendezvous-servers");
        log::info!("Listening on tcp/udp :{}", port);
        log::info!("Listening on tcp :{}, extra port for NAT test", nat_port);
        log::info!("Listening on websocket :{}", ws_port);
        let mut socket = create_udp_listener(port, rmem).await?;
        let (tx, mut rx) = mpsc::unbounded_channel::<Data>();
        let software_url = get_arg("software-url");
        let version = hbb_common::get_version_from_url(&software_url);
        if !version.is_empty() {
            log::info!("software_url: {}, version: {}", software_url, version);
        }
        let mask = get_arg("mask").parse().ok();
        let local_ip = if mask.is_none() {
            "".to_owned()
        } else {
            get_arg_or(
                "local-ip",
                local_ip_address::local_ip()
                    .map(|x| x.to_string())
                    .unwrap_or_default(),
            )
        };
        let mut rs = Self {
            tcp_punch: Arc::new(Mutex::new(HashMap::new())),
            tcp_peers: Arc::new(Mutex::new(HashMap::new())),
            pm,
            tx: tx.clone(),
            relay_servers: Default::default(),
            relay_servers0: Default::default(),
            rendezvous_servers: Arc::new(rendezvous_servers),
            inner: Arc::new(Inner {
                serial,
                version,
                software_url,
                sk,
                mask,
                local_ip,
            }),
        };
        log::info!("mask: {:?}", rs.inner.mask);
        log::info!("local-ip: {:?}", rs.inner.local_ip);
        std::env::set_var("PORT_FOR_API", port.to_string());
        rs.parse_relay_servers(&get_arg("relay-servers"));
        #[cfg(feature = "nemo-management-api")]
        {
            crate::nemo_management::init_from_args();
            crate::nemo_management::spawn_hbbs_api(
                rs.pm.clone(),
                key.clone(),
                nemo_server_secret_key,
            )
            .await?;
        }
        let mut listener = create_tcp_listener(port).await?;
        let mut listener2 = create_tcp_listener(nat_port).await?;
        let mut listener3 = create_tcp_listener(ws_port).await?;
        let test_addr = std::env::var("TEST_HBBS").unwrap_or_default();
        if std::env::var("ALWAYS_USE_RELAY")
            .unwrap_or_default()
            .to_uppercase()
            == "Y"
        {
            ALWAYS_USE_RELAY.store(true, Ordering::SeqCst);
        }
        log::info!(
            "ALWAYS_USE_RELAY={}",
            if ALWAYS_USE_RELAY.load(Ordering::SeqCst) {
                "Y"
            } else {
                "N"
            }
        );
        // test_hbbs sends itself a UDP RegisterPeer and exit(1)s if it goes unanswered.
        // With udp-registration=N that arm refuses by design, so the self-test can only
        // ever time out -- it would take the server down about 26 seconds after every
        // boot, having already served clients happily over TCP in the meantime.
        //
        // Its stated purpose ("temp solution to solve udp socket failure") is moot when
        // no peer registers over UDP, so skip it rather than carve out a loopback
        // exemption that would reintroduce a plaintext path just to satisfy a probe.
        if !udp_registration && test_addr.to_lowercase() != "no" {
            log::info!(
                "Skipping the UDP self-test: udp-registration=N means the arm it probes \
                 refuses by design, so the probe could only ever time out."
            );
        }
        if udp_registration && test_addr.to_lowercase() != "no" {
            let test_addr = if test_addr.is_empty() {
                listener.local_addr()?
            } else {
                test_addr.parse()?
            };
            tokio::spawn(async move {
                if let Err(err) = test_hbbs(test_addr).await {
                    if test_addr.is_ipv6() && test_addr.ip().is_unspecified() {
                        let mut test_addr = test_addr;
                        test_addr.set_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                        if let Err(err) = test_hbbs(test_addr).await {
                            log::error!("Failed to run hbbs test with {test_addr}: {err}");
                            std::process::exit(1);
                        }
                    } else {
                        log::error!("Failed to run hbbs test with {test_addr}: {err}");
                        std::process::exit(1);
                    }
                }
            });
        };
        let main_task = async move {
            loop {
                log::info!("Start");
                match rs
                    .io_loop(
                        &mut rx,
                        &mut listener,
                        &mut listener2,
                        &mut listener3,
                        &mut socket,
                        &key,
                    )
                    .await
                {
                    LoopFailure::UdpSocket => {
                        drop(socket);
                        socket = create_udp_listener(port, rmem).await?;
                    }
                    LoopFailure::Listener => {
                        drop(listener);
                        listener = create_tcp_listener(port).await?;
                    }
                    LoopFailure::Listener2 => {
                        drop(listener2);
                        listener2 = create_tcp_listener(nat_port).await?;
                    }
                    LoopFailure::Listener3 => {
                        drop(listener3);
                        listener3 = create_tcp_listener(ws_port).await?;
                    }
                }
            }
        };
        let listen_signal = listen_signal();
        tokio::select!(
            res = main_task => res,
            res = listen_signal => res,
        )
    }

    async fn io_loop(
        &mut self,
        rx: &mut Receiver,
        listener: &mut TcpListener,
        listener2: &mut TcpListener,
        listener3: &mut TcpListener,
        socket: &mut FramedSocket,
        key: &str,
    ) -> LoopFailure {
        let mut timer_check_relay = interval(Duration::from_millis(CHECK_RELAY_TIMEOUT));
        loop {
            tokio::select! {
                _ = timer_check_relay.tick() => {
                    if self.relay_servers0.len() > 1 {
                        let rs = self.relay_servers0.clone();
                        let tx = self.tx.clone();
                        tokio::spawn(async move {
                            check_relay_servers(rs, tx).await;
                        });
                    }
                }
                Some(data) = rx.recv() => {
                    match data {
                        Data::Msg(msg, addr) => { allow_err!(socket.send(msg.as_ref(), addr).await); }
                        Data::RelayServers0(rs) => { self.parse_relay_servers(&rs); }
                        Data::RelayServers(rs) => { self.relay_servers = Arc::new(rs); }
                    }
                }
                res = socket.next() => {
                    match res {
                        Some(Ok((bytes, addr))) => {
                            if let Err(err) = self.handle_udp(&bytes, addr.into(), socket, key).await {
                                log::error!("udp failure: {}", err);
                                return LoopFailure::UdpSocket;
                            }
                        }
                        Some(Err(err)) => {
                            log::error!("udp failure: {}", err);
                            return LoopFailure::UdpSocket;
                        }
                        None => {
                            // unreachable!() ?
                        }
                    }
                }
                res = listener2.accept() => {
                    match res {
                        Ok((stream, addr))  => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener2(stream, addr).await;
                        }
                        Err(err) => {
                           log::error!("listener2.accept failed: {}", err);
                           return LoopFailure::Listener2;
                        }
                    }
                }
                res = listener3.accept() => {
                    match res {
                        Ok((stream, addr))  => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener(stream, addr, key, true).await;
                        }
                        Err(err) => {
                           log::error!("listener3.accept failed: {}", err);
                           return LoopFailure::Listener3;
                        }
                    }
                }
                res = listener.accept() => {
                    match res {
                        Ok((stream, addr)) => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener(stream, addr, key, false).await;
                        }
                       Err(err) => {
                           log::error!("listener.accept failed: {}", err);
                           return LoopFailure::Listener;
                       }
                    }
                }
            }
        }
    }

    #[inline]
    async fn handle_udp(
        &mut self,
        bytes: &BytesMut,
        addr: SocketAddr,
        socket: &mut FramedSocket,
        // Unused since the UDP punch/hole/local-addr handlers were disabled (upstream
        // 80d3a50/109d9a2, reflection/amplification); kept in the signature for symmetry
        // with handle_listener and in case a future UDP arm needs it.
        _key: &str,
    ) -> ResultType<()> {
        if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(bytes) {
            match msg_in.union {
                Some(rendezvous_message::Union::RegisterPeer(rp)) => {
                    if !UDP_REGISTRATION.load(Ordering::SeqCst) {
                        warn_udp_refused_throttled("RegisterPeer", addr);
                        return Ok(());
                    }
                    // B registered
                    if !rp.id.is_empty() {
                        #[cfg(feature = "nemo-management-api")]
                        {
                            crate::nemo_management::record_peer_seen(&rp.id, addr).await;
                            if crate::nemo_management::is_peer_blocked(&self.pm, &rp.id).await {
                                crate::nemo_management::record_policy_rejection(
                                    &rp.id,
                                    addr,
                                    "peer is blocked",
                                )
                                .await;
                                return Ok(());
                            }
                        }
                        log::trace!("New peer registered: {:?} {:?}", &rp.id, &addr);
                        self.update_addr(rp.id, addr, socket).await?;
                        if self.inner.serial > rp.serial {
                            let mut msg_out = RendezvousMessage::new();
                            msg_out.set_configure_update(ConfigUpdate {
                                serial: self.inner.serial,
                                rendezvous_servers: (*self.rendezvous_servers).clone(),
                                ..Default::default()
                            });
                            socket.send(&msg_out, addr).await?;
                        }
                    }
                }
                Some(rendezvous_message::Union::RegisterPk(rk)) => {
                    if !UDP_REGISTRATION.load(Ordering::SeqCst) {
                        warn_udp_refused_throttled("RegisterPk", addr);
                        return Ok(());
                    }
                    if let Some(res) = self.register_pk_core(rk, addr).await {
                        return send_rk_res(socket, addr, res).await;
                    }
                    return Ok(());
                }
                Some(rendezvous_message::Union::PunchHoleRequest(_ph)) => {
                    // Upstream security port (80d3a50, rustdesk-server #670): UDP
                    // PunchHoleRequest is intentionally unsupported to avoid UDP
                    // reflection/amplification (a spoofed-source packet made hbbs emit a
                    // response to a victim). Supported clients punch over the TCP
                    // rendezvous, where `handle_tcp_punch_hole_request` ->
                    // `handle_punch_hole_request` runs the Nemo policy/recording hooks --
                    // and where the device-key proof exists to bind the controller to
                    // its id (H44), which is exactly what a UDP datagram cannot carry.
                }
                Some(rendezvous_message::Union::PunchHoleSent(_phs)) => {
                    // Upstream security port (109d9a2): UDP PunchHoleSent intentionally
                    // unsupported to avoid UDP reflection/amplification.
                }
                Some(rendezvous_message::Union::LocalAddr(_la)) => {
                    // Upstream security port (109d9a2): UDP LocalAddr intentionally
                    // unsupported to avoid UDP reflection/amplification.
                }
                Some(rendezvous_message::Union::ConfigureUpdate(mut cu)) => {
                    if try_into_v4(addr).ip().is_loopback() && cu.serial > self.inner.serial {
                        let mut inner: Inner = (*self.inner).clone();
                        inner.serial = cu.serial;
                        self.inner = Arc::new(inner);
                        self.rendezvous_servers = Arc::new(
                            cu.rendezvous_servers
                                .drain(..)
                                .filter(|x| {
                                    !x.is_empty()
                                        && test_if_valid_server(x, "rendezvous-server").is_ok()
                                })
                                .collect(),
                        );
                        log::info!(
                            "configure updated: serial={} rendezvous-servers={:?}",
                            self.inner.serial,
                            self.rendezvous_servers
                        );
                    }
                }
                Some(rendezvous_message::Union::SoftwareUpdate(su)) => {
                    if !self.inner.version.is_empty() && su.url != self.inner.version {
                        let mut msg_out = RendezvousMessage::new();
                        msg_out.set_software_update(SoftwareUpdate {
                            url: self.inner.software_url.clone(),
                            ..Default::default()
                        });
                        socket.send(&msg_out, addr).await?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    #[inline]
    async fn handle_tcp(
        &mut self,
        bytes: &[u8],
        sink: &mut Option<Sink>,
        addr: SocketAddr,
        key: &str,
        ws: bool,
        // H43: the handle for pushing INTO this connection. Registered against the
        // peer id when it registers, so hbbs can later reach a TCP/WS-only peer.
        push_tx: &PeerPush,
        // H5: who this connection proved to be with its device key, if anyone. The
        // handshake cannot know which id the client will register as, so the binding is
        // enforced here, where that id finally appears.
        authed: Option<&AuthedDevice>,
    ) -> bool {
        if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(bytes) {
            match msg_in.union {
                Some(rendezvous_message::Union::PunchHoleRequest(ph)) => {
                    // there maybe several attempt, so sink can be none
                    if let Some(sink) = sink.take() {
                        self.tcp_punch.lock().await.insert(try_into_v4(addr), sink);
                    }
                    allow_err!(self
                        .handle_tcp_punch_hole_request(addr, ph, key, ws, authed)
                        .await);
                    return true;
                }
                Some(rendezvous_message::Union::RequestRelay(mut rf)) => {
                    // there maybe several attempt, so sink can be none
                    if let Some(sink) = sink.take() {
                        self.tcp_punch.lock().await.insert(try_into_v4(addr), sink);
                    }
                    #[cfg(feature = "nemo-management-api")]
                    let nemo_id = rf.id.clone();
                    #[cfg(feature = "nemo-management-api")]
                    if !nemo_id.is_empty()
                        && !crate::nemo_management::is_peer_allowed(&self.pm, &nemo_id).await
                    {
                        crate::nemo_management::record_policy_rejection(
                            &nemo_id,
                            addr,
                            "relay target is not allowed by TBF policy",
                        )
                        .await;
                        let mut rr = RelayResponse {
                            refuse_reason: "relay target is not allowed by TBF policy".to_owned(),
                            ..Default::default()
                        };
                        rr.set_id(nemo_id);
                        let mut msg_out = RendezvousMessage::new();
                        msg_out.set_relay_response(rr);
                        allow_err!(self.send_to_tcp_sync(msg_out, addr).await);
                        return true;
                    }
                    #[cfg(feature = "nemo-management-api")]
                    if let Some((controller_id, reason)) = crate::nemo_management::controller_policy_rejection_from_field(
                        &self.pm,
                        &rf.licence_key,
                        &nemo_id,
                        // H44: the identity the gates key off now comes from the device
                        // key this connection PROVED, not from the unsigned marker the
                        // client wrote into licence_key. A marker naming anyone else is
                        // refused, and no marker at all no longer means "no gates".
                        authed.map(|who| who.peer_id.as_str()),
                    )
                    .await
                    {
                        crate::nemo_management::record_policy_rejection(
                            &controller_id,
                            addr,
                            &reason,
                        )
                        .await;
                        let mut rr = RelayResponse {
                            refuse_reason: reason,
                            ..Default::default()
                        };
                        rr.set_id(nemo_id);
                        let mut msg_out = RendezvousMessage::new();
                        msg_out.set_relay_response(rr);
                        allow_err!(self.send_to_tcp_sync(msg_out, addr).await);
                        return true;
                    }
                    // H9/H32: the per-user ACL + require-login gate, which until now
                    // ran ONLY on the punch path. A registered but logged-out client
                    // that asked for a relay instead of punching reached its target
                    // while require_login was on. The controller's identity rides in
                    // licence_key here, not version -- same marker, different field.
                    #[cfg(feature = "nemo-management-api")]
                    if let Some((controller_id, reason)) =
                        crate::nemo_management::nemo_user_rejection_from_field(
                            &rf.licence_key,
                            &nemo_id,
                            // TASK #19: the token in the marker is bound to the device
                            // key this connection proved at the handshake.
                            authed.map(|who| who.device_pub_b64.as_str()),
                        )
                    {
                        crate::nemo_management::record_policy_rejection(
                            &controller_id,
                            addr,
                            &reason,
                        )
                        .await;
                        let mut rr = RelayResponse {
                            refuse_reason: reason,
                            ..Default::default()
                        };
                        rr.set_id(nemo_id);
                        let mut msg_out = RendezvousMessage::new();
                        msg_out.set_relay_response(rr);
                        allow_err!(self.send_to_tcp_sync(msg_out, addr).await);
                        return true;
                    }
                    #[cfg(feature = "nemo-management-api")]
                    let mut nemo_forwarded = false;
                    if let Some(peer) = self.pm.get_in_memory(&rf.id).await {
                        let mut msg_out = RendezvousMessage::new();
                        // Same per-connection permissions on the relay path. The
                        // controller's identity rides in licence_key here, not version.
                        #[cfg(feature = "nemo-management-api")]
                        {
                            rf.control_permissions =
                                crate::nemo_management::control_permissions_for(&rf.licence_key)
                                    .into();
                        }
                        rf.socket_addr = AddrMangle::encode(addr).into();
                        let target_id = rf.id.clone();
                        msg_out.set_request_relay(rf);
                        let peer_addr = peer.read().await.socket_addr;
                        // H43: the target may be on TCP/WS, not UDP.
                        self.push_to_peer(&target_id, msg_out, peer_addr).await;
                        #[cfg(feature = "nemo-management-api")]
                        {
                            nemo_forwarded = true;
                        }
                    }
                    #[cfg(feature = "nemo-management-api")]
                    if !nemo_id.is_empty() {
                        crate::nemo_management::record_relay_request(
                            &nemo_id,
                            addr,
                            nemo_forwarded,
                        )
                        .await;
                    }
                    return true;
                }
                Some(rendezvous_message::Union::RelayResponse(mut rr)) => {
                    let addr_b = AddrMangle::decode(&rr.socket_addr);
                    rr.socket_addr = Default::default();
                    let id = rr.id().to_owned();
                    if !id.is_empty() {
                        let pk = self.get_pk(&rr.version, id.clone()).await;
                        rr.set_pk(pk);
                    }
                    let mut msg_out = RendezvousMessage::new();
                    if !rr.relay_server.is_empty() {
                        if self.is_lan(addr_b) {
                            // https://github.com/rustdesk/rustdesk-server/issues/24
                            rr.relay_server = self.inner.local_ip.clone();
                        } else if rr.relay_server == self.inner.local_ip {
                            rr.relay_server = self.get_relay_server(addr.ip(), addr_b.ip());
                        }
                    }
                    #[cfg(feature = "nemo-management-api")]
                    if !id.is_empty() {
                        crate::nemo_management::record_relay_response(
                            &id,
                            addr,
                            &rr.relay_server,
                        )
                        .await;
                    }
                    msg_out.set_relay_response(rr);
                    allow_err!(self.send_to_tcp_sync(msg_out, addr_b).await);
                }
                Some(rendezvous_message::Union::PunchHoleSent(phs)) => {
                    allow_err!(self.handle_hole_sent(phs, addr, None).await);
                }
                Some(rendezvous_message::Union::LocalAddr(la)) => {
                    allow_err!(self.handle_local_addr(la, addr, None).await);
                }
                Some(rendezvous_message::Union::TestNatRequest(tar)) => {
                    let mut msg_out = RendezvousMessage::new();
                    let mut res = TestNatResponse {
                        port: addr.port() as _,
                        ..Default::default()
                    };
                    if self.inner.serial > tar.serial {
                        let mut cu = ConfigUpdate::new();
                        cu.serial = self.inner.serial;
                        cu.rendezvous_servers = (*self.rendezvous_servers).clone();
                        res.cu = MessageField::from_option(Some(cu));
                    }
                    msg_out.set_test_nat_response(res);
                    Self::send_to_sink(sink, msg_out).await;
                }
                Some(rendezvous_message::Union::RegisterPeer(rp)) => {
                    // TBFDesk: the periodic presence heartbeat over TCP/WS. Without this
                    // arm a client running with disable-udp=Y could register its key but
                    // would never come online, because RegisterPeer only had a UDP path.
                    if !rp.id.is_empty() {
                        #[cfg(feature = "nemo-management-api")]
                        {
                            crate::nemo_management::record_peer_seen(&rp.id, addr).await;
                            if crate::nemo_management::is_peer_blocked(&self.pm, &rp.id).await {
                                crate::nemo_management::record_policy_rejection(
                                    &rp.id,
                                    addr,
                                    "peer is blocked",
                                )
                                .await;
                                return false;
                            }
                        }
                        // H5: a device key bound to one machine must not be able to
                        // heartbeat as another.
                        if let Some(who) = authed {
                            if who.peer_id != rp.id {
                                log::warn!(
                                    "Refusing {:?}: device key proved peer {} but it \
                                     heartbeats as {}",
                                    addr,
                                    who.peer_id,
                                    rp.id
                                );
                                return false;
                            }
                        }
                        log::trace!("New peer registered over tcp: {:?} {:?}", &rp.id, &addr);
                        // H43: this connection is now how we reach this peer.
                        self.register_peer_push(&rp.id, push_tx).await;
                        let request_pk = self.update_addr_core(&rp.id, addr).await;
                        let mut msg_out = RendezvousMessage::new();
                        msg_out.set_register_peer_response(RegisterPeerResponse {
                            request_pk,
                            ..Default::default()
                        });
                        Self::send_to_sink(sink, msg_out).await;
                        if self.inner.serial > rp.serial {
                            let mut msg_out = RendezvousMessage::new();
                            msg_out.set_configure_update(ConfigUpdate {
                                serial: self.inner.serial,
                                rendezvous_servers: (*self.rendezvous_servers).clone(),
                                ..Default::default()
                            });
                            Self::send_to_sink(sink, msg_out).await;
                        }
                    }
                    // Keep the connection: returning false makes the read loop break, and
                    // a rendezvous client has to hold this socket open for its heartbeat.
                    return true;
                }
                Some(rendezvous_message::Union::RegisterPk(rk)) => {
                    // TBFDesk: registration over TCP/WS is supported so a client can run
                    // with disable-udp=Y and register over the KeyExchange-secured TCP
                    // channel instead of the plaintext UDP one. Same core as the UDP path,
                    // so the blocked-peer, id-length, ip-blocker, uuid/pk-mismatch and
                    // rate-limit checks all still apply. A malformed request gets the same
                    // silence it gets over UDP.
                    //
                    // H43: register the push handle too -- a client whose key is not yet
                    // confirmed sends only RegisterPk, so without this it would stay
                    // unreachable until its first heartbeat.
                    // H5: THIS is what closes the gap. The handshake proves the machine
                    // is a fleet member; this proves it is registering as the id its key
                    // is bound to. Without it a single leaked device key would
                    // authenticate a connection that then claims any id it likes.
                    if let Some(who) = authed {
                        if who.peer_id != rk.id {
                            log::warn!(
                                "Refusing {:?}: device key proved peer {} but it registers as {}",
                                addr,
                                who.peer_id,
                                rk.id
                            );
                            return false;
                        }
                    }
                    let pk_id = rk.id.clone();
                    self.register_peer_push(&pk_id, push_tx).await;
                    if let Some(res) = self.register_pk_core(rk, addr).await {
                        let mut msg_out = RendezvousMessage::new();
                        msg_out.set_register_pk_response(RegisterPkResponse {
                            result: res.into(),
                            ..Default::default()
                        });
                        Self::send_to_sink(sink, msg_out).await;
                    }
                    // Keep the connection open (see the RegisterPeer arm).
                    return true;
                }
                _ => {}
            }
        }
        false
    }

    // TBFDesk: the RegisterPk core, shared by the UDP path and the TCP/WS path.
    // It was previously inlined in the UDP arm only, which is why registering over
    // TCP answered NOT_SUPPORT and a client could never run with disable-udp=Y --
    // and therefore could never do its registration over the KeyExchange-secured
    // TCP channel. Returns the result code to send back, or None for a malformed
    // request that deserves no reply. The caller writes it to whichever sink it owns.
    async fn register_pk_core(
        &mut self,
        rk: RegisterPk,
        addr: SocketAddr,
    ) -> Option<register_pk_response::Result> {
                if rk.uuid.is_empty() || rk.pk.is_empty() {
                    return None;
                }
                let id = rk.id;
                let ip = addr.ip().to_string();
                #[cfg(feature = "nemo-management-api")]
                if crate::nemo_management::is_peer_blocked(&self.pm, &id).await {
                    crate::nemo_management::record_register_pk(&id, addr, false).await;
                    crate::nemo_management::record_policy_rejection(
                        &id,
                        addr,
                        "peer is blocked",
                    )
                    .await;
                    return Some(TOO_FREQUENT);
                }
                if id.len() < 6 {
                    return Some(UUID_MISMATCH);
                } else if !self.check_ip_blocker(&ip, &id).await {
                    return Some(TOO_FREQUENT);
                }
                let peer = self.pm.get_or(&id).await;
                let (changed, ip_changed) = {
                    let peer = peer.read().await;
                    if peer.uuid.is_empty() {
                        (true, false)
                    } else {
                        if peer.uuid == rk.uuid {
                            if peer.info.ip != ip && peer.pk != rk.pk {
                                log::warn!(
                                    "Peer {} ip/pk mismatch: {}/{:?} vs {}/{:?}",
                                    id,
                                    ip,
                                    rk.pk,
                                    peer.info.ip,
                                    peer.pk,
                                );
                                drop(peer);
                                return Some(UUID_MISMATCH);
                            }
                        } else {
                            log::warn!(
                                "Peer {} uuid mismatch: {:?} vs {:?}",
                                id,
                                rk.uuid,
                                peer.uuid
                            );
                            drop(peer);
                            return Some(UUID_MISMATCH);
                        }
                        let ip_changed = peer.info.ip != ip;
                        (
                            peer.uuid != rk.uuid || peer.pk != rk.pk || ip_changed,
                            ip_changed,
                        )
                    }
                };
                let mut req_pk = peer.read().await.reg_pk;
                if req_pk.1.elapsed().as_secs() > 6 {
                    req_pk.0 = 0;
                } else if req_pk.0 > 2 {
                    return Some(TOO_FREQUENT);
                }
                req_pk.0 += 1;
                req_pk.1 = Instant::now();
                peer.write().await.reg_pk = req_pk;
                if ip_changed {
                    let mut lock = IP_CHANGES.lock().await;
                    if let Some((tm, ips)) = lock.get_mut(&id) {
                        if tm.elapsed().as_secs() > IP_CHANGE_DUR {
                            *tm = Instant::now();
                            ips.clear();
                            ips.insert(ip.clone(), 1);
                        } else if let Some(v) = ips.get_mut(&ip) {
                            *v += 1;
                        } else {
                            ips.insert(ip.clone(), 1);
                        }
                    } else {
                        lock.insert(
                            id.clone(),
                            (Instant::now(), HashMap::from([(ip.clone(), 1)])),
                        );
                    }
                }
                #[cfg(feature = "nemo-management-api")]
                let nemo_id = id.clone();
                if changed {
                    self.pm.update_pk(id, peer, addr, rk.uuid, rk.pk, ip).await;
                }
                #[cfg(feature = "nemo-management-api")]
                crate::nemo_management::record_register_pk(&nemo_id, addr, true).await;
        Some(register_pk_response::Result::OK)
    }

    #[inline]
    // TBFDesk: the address bookkeeping of update_addr, split out so the TCP/WS path
    // can reuse it. Returns `request_pk`, i.e. whether the server still wants this
    // peer's public key. The caller sends the RegisterPeerResponse on its own sink.
    async fn update_addr_core(&mut self, id: &str, socket_addr: SocketAddr) -> bool {
        let (request_pk, ip_change) = if let Some(old) = self.pm.get_in_memory(id).await {
            let mut old = old.write().await;
            let ip = socket_addr.ip();
            let ip_change = if old.socket_addr.port() != 0 {
                ip != old.socket_addr.ip()
            } else {
                ip.to_string() != old.info.ip
            } && !ip.is_loopback();
            let request_pk = old.pk.is_empty() || ip_change;
            if !request_pk {
                old.socket_addr = socket_addr;
                old.last_reg_time = Instant::now();
            }
            let ip_change = if ip_change && old.reg_pk.0 <= 2 {
                Some(if old.socket_addr.port() == 0 {
                    old.info.ip.clone()
                } else {
                    old.socket_addr.to_string()
                })
            } else {
                None
            };
            (request_pk, ip_change)
        } else {
            (true, None)
        };
        if let Some(old) = ip_change {
            log::info!("IP change of {} from {} to {}", id, old, socket_addr);
        }
        request_pk
    }

    async fn update_addr(
        &mut self,
        id: String,
        socket_addr: SocketAddr,
        socket: &mut FramedSocket,
    ) -> ResultType<()> {
        let request_pk = self.update_addr_core(&id, socket_addr).await;
        let mut msg_out = RendezvousMessage::new();
        msg_out.set_register_peer_response(RegisterPeerResponse {
            request_pk,
            ..Default::default()
        });
        socket.send(&msg_out, socket_addr).await
    }

    #[inline]
    async fn handle_hole_sent<'a>(
        &mut self,
        phs: PunchHoleSent,
        addr: SocketAddr,
        socket: Option<&'a mut FramedSocket>,
    ) -> ResultType<()> {
        // punch hole sent from B, tell A that B is ready to be connected
        let addr_a = AddrMangle::decode(&phs.socket_addr);
        log::debug!(
            "{} punch hole response to {:?} from {:?}",
            if socket.is_none() { "TCP" } else { "UDP" },
            &addr_a,
            &addr
        );
        #[cfg(feature = "nemo-management-api")]
        {
            crate::nemo_management::record_punch_response(
                &phs.id,
                addr,
                &phs.relay_server,
                phs.nat_type.value(),
            )
            .await;
        }
        let mut msg_out = RendezvousMessage::new();
        let mut p = PunchHoleResponse {
            socket_addr: AddrMangle::encode(addr).into(),
            pk: self.get_pk(&phs.version, phs.id).await,
            relay_server: phs.relay_server.clone(),
            // B's v6 endpoint and UPnP port, reported by B in PunchHoleSent. Both fields
            // were missing from the server proto, so B sent them and the server dropped
            // them -- A only ever learned B's IPv4 address.
            socket_addr_v6: phs.socket_addr_v6.clone(),
            upnp_port: phs.upnp_port,
            ..Default::default()
        };
        if let Ok(t) = phs.nat_type.enum_value() {
            p.set_nat_type(t);
        }
        msg_out.set_punch_hole_response(p);
        if let Some(socket) = socket {
            socket.send(&msg_out, addr_a).await?;
        } else {
            self.send_to_tcp(msg_out, addr_a).await;
        }
        Ok(())
    }

    #[inline]
    async fn handle_local_addr<'a>(
        &mut self,
        la: LocalAddr,
        addr: SocketAddr,
        socket: Option<&'a mut FramedSocket>,
    ) -> ResultType<()> {
        // relay local addrs of B to A
        let addr_a = AddrMangle::decode(&la.socket_addr);
        log::debug!(
            "{} local addrs response to {:?} from {:?}",
            if socket.is_none() { "TCP" } else { "UDP" },
            &addr_a,
            &addr
        );
        #[cfg(feature = "nemo-management-api")]
        {
            crate::nemo_management::record_local_addr_response(&la.id, addr, &la.relay_server)
                .await;
        }
        let mut msg_out = RendezvousMessage::new();
        let mut p = PunchHoleResponse {
            socket_addr: la.local_addr.clone(),
            pk: self.get_pk(&la.version, la.id).await,
            relay_server: la.relay_server,
            // Same for the intranet path: carry B's v6 local address through.
            socket_addr_v6: la.socket_addr_v6.clone(),
            ..Default::default()
        };
        p.set_is_local(true);
        msg_out.set_punch_hole_response(p);
        if let Some(socket) = socket {
            socket.send(&msg_out, addr_a).await?;
        } else {
            self.send_to_tcp(msg_out, addr_a).await;
        }
        Ok(())
    }

    #[inline]
    async fn handle_punch_hole_request(
        &mut self,
        addr: SocketAddr,
        ph: PunchHoleRequest,
        key: &str,
        ws: bool,
        // H44: who this rendezvous connection proved to be with its pinned device key.
        // The controller gates below key off THIS, not off the unsigned source marker
        // in `ph.version`.
        #[cfg_attr(not(feature = "nemo-management-api"), allow(unused_variables))]
        authed: Option<&AuthedDevice>,
    ) -> ResultType<(RendezvousMessage, Option<(String, SocketAddr)>)> {
        let mut ph = ph;
        if !key.is_empty() && ph.licence_key != key {
            log::warn!("Authentication failed from {} for peer {} - invalid key", addr, ph.id);
            #[cfg(feature = "nemo-management-api")]
            crate::nemo_management::record_policy_rejection(&ph.id, addr, "invalid server key")
                .await;
            let mut msg_out = RendezvousMessage::new();
            msg_out.set_punch_hole_response(PunchHoleResponse {
                failure: punch_hole_response::Failure::LICENSE_MISMATCH.into(),
                ..Default::default()
            });
            return Ok((msg_out, None));
        }
        let id = ph.id.clone();
        #[cfg(feature = "nemo-management-api")]
        let nemo_nat_type = ph.nat_type.value();
        #[cfg(feature = "nemo-management-api")]
        if !crate::nemo_management::is_peer_allowed(&self.pm, &id).await {
            crate::nemo_management::record_policy_rejection(
                &id,
                addr,
                "target peer is not allowed by TBF policy",
            )
            .await;
            let mut msg_out = RendezvousMessage::new();
            msg_out.set_punch_hole_response(PunchHoleResponse {
                failure: punch_hole_response::Failure::OFFLINE.into(),
                other_failure: "target peer is not allowed by TBF policy".to_owned(),
                ..Default::default()
            });
            return Ok((msg_out, None));
        }
        #[cfg(feature = "nemo-management-api")]
        if let Some((controller_id, reason)) = crate::nemo_management::controller_policy_rejection_from_field(
            &self.pm,
            &ph.version,
            &id,
            // H44: see the RequestRelay arm. The marker in `ph.version` is a hint now,
            // not the identity.
            authed.map(|who| who.peer_id.as_str()),
        )
        .await
        {
            crate::nemo_management::record_policy_rejection(&controller_id, addr, &reason).await;
            let mut msg_out = RendezvousMessage::new();
            msg_out.set_punch_hole_response(PunchHoleResponse {
                failure: punch_hole_response::Failure::OFFLINE.into(),
                other_failure: reason,
                ..Default::default()
            });
            return Ok((msg_out, None));
        }
        // Nemo per-user connection ACL + require-login (enforced from the token
        // smuggled in the source field).
        #[cfg(feature = "nemo-management-api")]
        if let Some((controller_id, reason)) =
            crate::nemo_management::nemo_user_rejection_from_field(
                &ph.version,
                &id,
                // TASK #19: see the RequestRelay arm.
                authed.map(|who| who.device_pub_b64.as_str()),
            )
        {
            crate::nemo_management::record_policy_rejection(&controller_id, addr, &reason).await;
            let mut msg_out = RendezvousMessage::new();
            msg_out.set_punch_hole_response(PunchHoleResponse {
                failure: punch_hole_response::Failure::OFFLINE.into(),
                other_failure: reason,
                ..Default::default()
            });
            return Ok((msg_out, None));
        }
        // punch hole request from A, relay to B,
        // check if in same intranet first,
        // fetch local addrs if in same intranet.
        // because punch hole won't work if in the same intranet,
        // all routers will drop such self-connections.
        if let Some(peer) = self.pm.get(&id).await {
            let (elapsed, peer_addr) = {
                let r = peer.read().await;
                (r.last_reg_time.elapsed().as_millis() as i64, r.socket_addr)
            };
            if elapsed >= REG_TIMEOUT {
                let mut msg_out = RendezvousMessage::new();
                msg_out.set_punch_hole_response(PunchHoleResponse {
                    failure: punch_hole_response::Failure::OFFLINE.into(),
                    ..Default::default()
                });
                return Ok((msg_out, None));
            }
            
            // record punch hole request (from addr -> peer id/peer_addr)
            {
                let from_ip = try_into_v4(addr).ip().to_string();
                let to_ip = try_into_v4(peer_addr).ip().to_string();
                let to_id_clone = id.clone();
                let mut lock = PUNCH_REQS.lock().await;
                let mut dup = false;
                for e in lock.iter().rev().take(30) { // only check recent tail subset for speed
                    if e.from_ip == from_ip && e.to_id == to_id_clone {
                        if e.tm.elapsed().as_secs() < PUNCH_REQ_DEDUPE_SEC { dup = true; }
                        break;
                    }
                }
                if !dup { lock.push(PunchReqEntry { tm: Instant::now(), from_ip, to_ip, to_id: to_id_clone }); }
                // Nemo hardening (S7): bound the punch-request audit ring so
                // unauthenticated punch traffic cannot grow it without limit.
                const MAX_PUNCH_REQS: usize = 10000;
                if lock.len() > MAX_PUNCH_REQS {
                    let excess = lock.len() - MAX_PUNCH_REQS;
                    lock.drain(0..excess);
                }
            }

            let mut msg_out = RendezvousMessage::new();
            let peer_is_lan = self.is_lan(peer_addr);
            let is_lan = self.is_lan(addr);
            let mut relay_server = self.get_relay_server(addr.ip(), peer_addr.ip());
            #[cfg(feature = "nemo-management-api")]
            let mut forced_relay = false;
            // `ph.force_relay` is the client saying "do not try direct" (set when it is
            // proxied, on websocket, or told to by its own peer config). The field did not
            // exist in the server proto, so that request was silently ignored and the
            // server still answered with a direct path the client would not use.
            if ALWAYS_USE_RELAY.load(Ordering::SeqCst) || ph.force_relay || (peer_is_lan ^ is_lan) {
                #[cfg(feature = "nemo-management-api")]
                {
                    forced_relay = true;
                }
                if peer_is_lan {
                    // https://github.com/rustdesk/rustdesk-server/issues/24
                    relay_server = self.inner.local_ip.clone()
                }
                ph.nat_type = NatType::SYMMETRIC.into(); // will force relay
            }
            let same_intranet: bool = !ws
                && (peer_is_lan && is_lan || {
                    match (peer_addr, addr) {
                        (SocketAddr::V4(a), SocketAddr::V4(b)) => a.ip() == b.ip(),
                        (SocketAddr::V6(a), SocketAddr::V6(b)) => a.ip() == b.ip(),
                        _ => false,
                    }
                });
            let socket_addr = AddrMangle::encode(addr).into();
            // Per-connection permissions for THIS controller, derived from their
            // logged-in user's session policy. Until the proto was synced the server
            // could not express this at all, so every connection arrived with None and
            // only the target's own local toggles applied.
            #[cfg(feature = "nemo-management-api")]
            let control_permissions =
                crate::nemo_management::control_permissions_for(&ph.version);
            #[cfg(not(feature = "nemo-management-api"))]
            let control_permissions: Option<ControlPermissions> = None;
            #[cfg(feature = "nemo-management-api")]
            crate::nemo_management::record_connection_negotiation(
                &id,
                &ph.version,
                addr,
                peer_addr,
                nemo_nat_type,
                forced_relay,
                same_intranet,
                &relay_server,
            )
            .await;
            if same_intranet {
                log::debug!(
                    "Fetch local addr {:?} {:?} request from {:?}",
                    id,
                    peer_addr,
                    addr
                );
                msg_out.set_fetch_local_addr(FetchLocalAddr {
                    socket_addr,
                    relay_server,
                    control_permissions: control_permissions.clone().into(),
                    // Carry the caller's IPv6 address through. The server proto used to
                    // lack this field entirely, so protobuf dropped it silently and the
                    // v6 path could never be attempted.
                    socket_addr_v6: ph.socket_addr_v6.clone(),
                    ..Default::default()
                });
            } else {
                log::debug!(
                    "Punch hole {:?} {:?} request from {:?}",
                    id,
                    peer_addr,
                    addr
                );
                msg_out.set_punch_hole(PunchHole {
                    socket_addr,
                    nat_type: ph.nat_type,
                    relay_server,
                    control_permissions: control_permissions.into(),
                    // These four were absent from the server proto, so the client sent
                    // them and protobuf discarded them. The target therefore always saw
                    // udp_port == 0 and never took the UDP punch arm -- traversal was
                    // TCP-only, IPv6 was unreachable, UPnP was unused, and a client
                    // asking for relay was ignored. They are pass-through: the server
                    // decides nothing here, it only has to stop losing them.
                    udp_port: ph.udp_port,
                    upnp_port: ph.upnp_port,
                    socket_addr_v6: ph.socket_addr_v6.clone(),
                    force_relay: ph.force_relay,
                    ..Default::default()
                });
            }
            // H43: the id travels with the address so the caller can prefer the
            // peer's own rendezvous connection over a UDP datagram.
            Ok((msg_out, Some((id, peer_addr))))
        } else {
            let mut msg_out = RendezvousMessage::new();
            msg_out.set_punch_hole_response(PunchHoleResponse {
                failure: punch_hole_response::Failure::ID_NOT_EXIST.into(),
                ..Default::default()
            });
            Ok((msg_out, None))
        }
    }

    #[inline]
    async fn handle_online_request(
        &mut self,
        stream: &mut FramedStream,
        peers: Vec<String>,
    ) -> ResultType<()> {
        let mut states = BytesMut::zeroed((peers.len() + 7) / 8);
        for (i, peer_id) in peers.iter().enumerate() {
            if let Some(peer) = self.pm.get_in_memory(peer_id).await {
                let elapsed = peer.read().await.last_reg_time.elapsed().as_millis() as i64;
                // bytes index from left to right
                let states_idx = i / 8;
                let bit_idx = 7 - i % 8;
                if elapsed < REG_TIMEOUT {
                    states[states_idx] |= 0x01 << bit_idx;
                }
            }
        }

        let mut msg_out = RendezvousMessage::new();
        msg_out.set_online_response(OnlineResponse {
            states: states.into(),
            ..Default::default()
        });
        stream.send(&msg_out).await?;

        Ok(())
    }

    #[inline]
    /// H43: push a message TO a peer. Prefers the peer's live TCP/WS rendezvous
    /// connection when it has one and falls back to UDP for peers that registered that
    /// way, so both transports keep working and neither is privileged by accident.
    async fn push_to_peer(&self, id: &str, msg: RendezvousMessage, addr: SocketAddr) {
        let mut msg = msg;
        if !id.is_empty() {
            let mut map = self.tcp_peers.lock().await;
            if let Some(tx) = map.get(id) {
                match tx.send(msg) {
                    Ok(()) => return,
                    // Receiver gone: the connection closed between the lookup and now.
                    // Drop the stale entry and let UDP have it.
                    Err(err) => {
                        map.remove(id);
                        msg = err.0;
                    }
                }
            }
        }
        self.tx.send(Data::Msg(msg.into(), addr)).ok();
    }

    /// Remember that `id` is reachable on this connection. Sweeping here rather than on
    /// task exit keeps a closing task from removing an entry a reconnect just replaced.
    async fn register_peer_push(&self, id: &str, tx: &PeerPush) {
        if id.is_empty() {
            return;
        }
        let mut map = self.tcp_peers.lock().await;
        map.retain(|_, t| !t.is_closed());
        map.insert(id.to_owned(), tx.clone());
    }

    async fn send_to_tcp(&mut self, msg: RendezvousMessage, addr: SocketAddr) {
        let mut tcp = self.tcp_punch.lock().await.remove(&try_into_v4(addr));
        tokio::spawn(async move {
            Self::send_to_sink(&mut tcp, msg).await;
        });
    }

    #[inline]
    async fn send_to_sink(sink: &mut Option<Sink>, msg: RendezvousMessage) {
        if let Some(sink) = sink.as_mut() {
            if let Ok(bytes) = msg.write_to_bytes() {
                match sink {
                    Sink::TcpStream(s, cipher) => {
                        // C (--key-exchange): the one funnel every TCP reply goes
                        // through, so sealing here covers every call site with no
                        // edit of its own. `cipher` is None unless this connection
                        // completed the handshake -- that is today's behaviour.
                        let bytes = match cipher.as_mut() {
                            Some(cipher) => cipher.enc(&bytes),
                            None => bytes,
                        };
                        allow_err!(s.send(Bytes::from(bytes)).await);
                    }
                    Sink::Ws(ws) => {
                        allow_err!(ws.send(tungstenite::Message::Binary(bytes)).await);
                    }
                }
            }
        }
    }

    #[inline]
    async fn send_to_tcp_sync(
        &mut self,
        msg: RendezvousMessage,
        addr: SocketAddr,
    ) -> ResultType<()> {
        let mut sink = self.tcp_punch.lock().await.remove(&try_into_v4(addr));
        Self::send_to_sink(&mut sink, msg).await;
        Ok(())
    }

    #[inline]
    async fn handle_tcp_punch_hole_request(
        &mut self,
        addr: SocketAddr,
        ph: PunchHoleRequest,
        key: &str,
        ws: bool,
        authed: Option<&AuthedDevice>,
    ) -> ResultType<()> {
        let (msg, to_peer) = self
            .handle_punch_hole_request(addr, ph, key, ws, authed)
            .await?;
        if let Some((id, peer_addr)) = to_peer {
            self.push_to_peer(&id, msg, peer_addr).await;
        } else {
            self.send_to_tcp_sync(msg, addr).await?;
        }
        Ok(())
    }

    // H44: `handle_udp_punch_hole_request` used to live here. It had NO callers -- the
    // UDP PunchHoleRequest arm has been a deliberate no-op since the upstream
    // reflection/amplification fix (80d3a50) -- and it was the one route into
    // `handle_punch_hole_request` that carries no device-key proof to bind the
    // controller to. Deleted rather than wired up with `authed: None`: an unreachable
    // unauthenticated punch path is a landmine for whoever re-enables UDP next.

    async fn check_ip_blocker(&self, ip: &str, id: &str) -> bool {
        let mut lock = IP_BLOCKER.lock().await;
        let now = Instant::now();
        if let Some(old) = lock.get_mut(ip) {
            let counter = &mut old.0;
            if counter.1.elapsed().as_secs() > IP_BLOCK_DUR {
                counter.0 = 0;
            } else if counter.0 > 30 {
                return false;
            }
            counter.0 += 1;
            counter.1 = now;

            let counter = &mut old.1;
            let is_new = counter.0.get(id).is_none();
            if counter.1.elapsed().as_secs() > DAY_SECONDS {
                counter.0.clear();
            } else if counter.0.len() > 300 {
                return !is_new;
            }
            if is_new {
                counter.0.insert(id.to_owned());
            }
            counter.1 = now;
        } else {
            lock.insert(ip.to_owned(), ((0, now), (Default::default(), now)));
        }
        true
    }

    fn parse_relay_servers(&mut self, relay_servers: &str) {
        let rs = get_servers(relay_servers, "relay-servers");
        self.relay_servers0 = Arc::new(rs);
        self.relay_servers = self.relay_servers0.clone();
    }

    fn get_relay_server(&self, _pa: IpAddr, _pb: IpAddr) -> String {
        if self.relay_servers.is_empty() {
            return "".to_owned();
        } else if self.relay_servers.len() == 1 {
            return self.relay_servers[0].clone();
        }
        let i = ROTATION_RELAY_SERVER.fetch_add(1, Ordering::SeqCst) % self.relay_servers.len();
        self.relay_servers[i].clone()
    }

    async fn check_cmd(&self, cmd: &str) -> String {
        use std::fmt::Write as _;

        let mut res = "".to_owned();
        let mut fds = cmd.trim().split(' ');
        match fds.next() {
            Some("h") => {
                res = format!(
                    "{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
                    "relay-servers(rs) <separated by ,>",
                    "reload-geo(rg)",
                    "ip-blocker(ib) [<ip>|<number>] [-]",
                    "ip-changes(ic) [<id>|<number>] [-]",
                    "punch-requests(pr) [<number>] [-]",
                    "always-use-relay(aur)",
                    "test-geo(tg) <ip1> <ip2>"
                )
            }
            Some("relay-servers" | "rs") => {
                if let Some(rs) = fds.next() {
                    self.tx.send(Data::RelayServers0(rs.to_owned())).ok();
                } else {
                    for ip in self.relay_servers.iter() {
                        let _ = writeln!(res, "{ip}");
                    }
                }
            }
            Some("ip-blocker" | "ib") => {
                let mut lock = IP_BLOCKER.lock().await;
                lock.retain(|&_, (a, b)| {
                    a.1.elapsed().as_secs() <= IP_BLOCK_DUR
                        || b.1.elapsed().as_secs() <= DAY_SECONDS
                });
                res = format!("{}\n", lock.len());
                let ip = fds.next();
                let mut start = ip.map(|x| x.parse::<i32>().unwrap_or(-1)).unwrap_or(-1);
                if start < 0 {
                    if let Some(ip) = ip {
                        if let Some((a, b)) = lock.get(ip) {
                            let _ = writeln!(
                                res,
                                "{}/{}s {}/{}s",
                                a.0,
                                a.1.elapsed().as_secs(),
                                b.0.len(),
                                b.1.elapsed().as_secs()
                            );
                        }
                        if fds.next() == Some("-") {
                            lock.remove(ip);
                        }
                    } else {
                        start = 0;
                    }
                }
                if start >= 0 {
                    let mut it = lock.iter();
                    for i in 0..(start + 10) {
                        let x = it.next();
                        if x.is_none() {
                            break;
                        }
                        if i < start {
                            continue;
                        }
                        if let Some((ip, (a, b))) = x {
                            let _ = writeln!(
                                res,
                                "{}: {}/{}s {}/{}s",
                                ip,
                                a.0,
                                a.1.elapsed().as_secs(),
                                b.0.len(),
                                b.1.elapsed().as_secs()
                            );
                        }
                    }
                }
            }
            Some("ip-changes" | "ic") => {
                let mut lock = IP_CHANGES.lock().await;
                lock.retain(|&_, v| v.0.elapsed().as_secs() < IP_CHANGE_DUR_X2 && v.1.len() > 1);
                res = format!("{}\n", lock.len());
                let id = fds.next();
                let mut start = id.map(|x| x.parse::<i32>().unwrap_or(-1)).unwrap_or(-1);
                if !(0..=10_000_000).contains(&start) {
                    if let Some(id) = id {
                        if let Some((tm, ips)) = lock.get(id) {
                            let _ = writeln!(res, "{}s {:?}", tm.elapsed().as_secs(), ips);
                        }
                        if fds.next() == Some("-") {
                            lock.remove(id);
                        }
                    } else {
                        start = 0;
                    }
                }
                if start >= 0 {
                    let mut it = lock.iter();
                    for i in 0..(start + 10) {
                        let x = it.next();
                        if x.is_none() {
                            break;
                        }
                        if i < start {
                            continue;
                        }
                        if let Some((id, (tm, ips))) = x {
                            let _ = writeln!(res, "{}: {}s {:?}", id, tm.elapsed().as_secs(), ips,);
                        }
                    }
                }
            }
            Some("punch-requests" | "pr") => {
                use std::fmt::Write as _;
                let mut lock = PUNCH_REQS.lock().await;
                let arg = fds.next();
                if let Some("-") = arg { lock.clear(); }
                else {
                    let mut start = arg.and_then(|x| x.parse::<usize>().ok()).unwrap_or(0);
                    let mut page_size = fds.next().and_then(|x| x.parse::<usize>().ok()).unwrap_or(10);
                    if page_size == 0 { page_size = 10; }
                    for (_, e) in lock.iter().enumerate().skip(start).take(page_size) {
                        let age = e.tm.elapsed();
                        let event_system = std::time::SystemTime::now() - age;
                        let event_iso = chrono::DateTime::<chrono::Utc>::from(event_system)
                            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                        let _ = writeln!(res, "{} {} -> {}@{}", event_iso, e.from_ip, e.to_id, e.to_ip);
                    }
                }
            }
            Some("always-use-relay" | "aur") => {
                if let Some(rs) = fds.next() {
                    if rs.to_uppercase() == "Y" {
                        ALWAYS_USE_RELAY.store(true, Ordering::SeqCst);
                    } else {
                        ALWAYS_USE_RELAY.store(false, Ordering::SeqCst);
                    }
                    // Do NOT forward this argument to RelayServers0: it is the Y/N flag,
                    // not a relay address. Upstream did, so `aur Y` silently replaced the
                    // whole relay-server list with the literal string "Y" (leaving it
                    // empty) and an operator enabling always-use-relay lost their relay
                    // configuration. Only `relay-servers`/`rs` may set that list.
                } else {
                    let _ = writeln!(
                        res,
                        "ALWAYS_USE_RELAY: {:?}",
                        ALWAYS_USE_RELAY.load(Ordering::SeqCst)
                    );
                }
            }
            Some("test-geo" | "tg") => {
                if let Some(rs) = fds.next() {
                    if let Ok(a) = rs.parse::<IpAddr>() {
                        if let Some(rs) = fds.next() {
                            if let Ok(b) = rs.parse::<IpAddr>() {
                                res = format!("{:?}", self.get_relay_server(a, b));
                            }
                        } else {
                            res = format!("{:?}", self.get_relay_server(a, a));
                        }
                    }
                }
            }
            _ => {}
        }
        res
    }

    async fn handle_listener2(&self, stream: TcpStream, addr: SocketAddr) {
        let mut rs = self.clone();
        let ip = try_into_v4(addr).ip();
        if ip.is_loopback() {
            tokio::spawn(async move {
                let mut stream = stream;
                let mut buffer = [0; 1024];
                if let Ok(Ok(n)) = timeout(1000, stream.read(&mut buffer[..])).await {
                    if let Ok(data) = std::str::from_utf8(&buffer[..n]) {
                        let res = rs.check_cmd(data).await;
                        stream.write(res.as_bytes()).await.ok();
                    }
                }
            });
            return;
        }
        let stream = FramedStream::from(stream, addr);
        tokio::spawn(async move {
            let mut stream = stream;
            if let Some(Ok(bytes)) = stream.next_timeout(30_000).await {
                if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
                    match msg_in.union {
                        Some(rendezvous_message::Union::TestNatRequest(_)) => {
                            let mut msg_out = RendezvousMessage::new();
                            msg_out.set_test_nat_response(TestNatResponse {
                                port: addr.port() as _,
                                ..Default::default()
                            });
                            stream.send(&msg_out).await.ok();
                        }
                        Some(rendezvous_message::Union::OnlineRequest(or)) => {
                            allow_err!(rs.handle_online_request(&mut stream, or.peers).await);
                        }
                        _ => {}
                    }
                }
            }
        });
    }

    async fn handle_listener(&self, stream: TcpStream, addr: SocketAddr, key: &str, ws: bool) {
        log::debug!("Tcp connection from {:?}, ws: {}", addr, ws);
        let mut rs = self.clone();
        let key = key.to_owned();
        tokio::spawn(async move {
            allow_err!(rs.handle_listener_inner(stream, addr, &key, ws).await);
        });
    }

    #[inline]
    async fn handle_listener_inner(
        &mut self,
        stream: TcpStream,
        mut addr: SocketAddr,
        key: &str,
        ws: bool,
    ) -> ResultType<()> {
        // H43: one push channel per rendezvous connection. The connection task owns its
        // sink, so other tasks hand it a message instead of sharing the sink -- which
        // would be unsound anyway, since handle_tcp can move the sink into tcp_punch.
        let (push_tx, mut push_rx) = tokio::sync::mpsc::unbounded_channel::<RendezvousMessage>();
        let mut sink;
        if ws {
            // H42/H5: REFUSED. This branch never ran a key exchange, never installed an
            // Encrypt (Sink::Ws has no cipher slot) and passed `authed: None` -- so both
            // --key-exchange=require and require_device_key were silently unenforced on
            // this listener, and a keyless client could register, punch and relay with no
            // Layer 1 proof at all. It was the one rendezvous plane with neither
            // encryption nor device auth.
            //
            // Refusing rather than fixing, deliberately: nothing in this deployment uses
            // ws rendezvous (21118/21119 are not even forwarded), the client already
            // fails closed on plain ws:// for a bare IP, and "put TLS in front of it"
            // cannot substitute -- TLS terminates upstream and cannot present a device
            // key. Making it work means giving Sink::Ws an Option<Encrypt> and running
            // the same KeyExchange + NemoClientAuth over it; until someone needs it, an
            // unauthenticated plane is not worth keeping alive.
            log::warn!(
                "Refusing websocket rendezvous from {:?}: this transport carries no key \
                 exchange and no device-key proof. Use the TCP rendezvous.",
                addr
            );
            return Ok(());
        } else {
            let (a, mut b) = Framed::new(stream, BytesCodec::new()).split();
            sink = Some(Sink::TcpStream(a, None));
            // C (--key-exchange): offer the rendezvous handshake before the read loop
            // takes over the stream. `off` sends nothing and leaves `rx_enc`, `pending`
            // AND `authed` None -- and since the NemoClientAuth arm and the
            // require-device-key refusal both live inside this block, `off` disables
            // Layer 1 on this transport as well as the encryption. Debugging only.
            let mode = key_exchange_mode();
            // Recv half of the connection cipher; the send half rides with the sink.
            let mut rx_enc: Option<Encrypt> = None;
            // H5: who this connection proved to be, if anyone.
            let mut authed: Option<AuthedDevice> = None;
            // A frame read while waiting for the handshake, replayed into the loop.
            let mut pending: Option<BytesMut> = None;
            if mode != KeyExchangeMode::Off {
                if let Some(sk) = self.inner.sk.as_ref() {
                    let (msg_out, our_pk_b, our_sk_b) = Self::key_exchange_offer_msg(sk);
                    // The offer goes out in the clear -- the sink's cipher is still
                    // None, and send_to_sink is what would otherwise seal it.
                    Self::send_to_sink(&mut sink, msg_out).await;
                    let mut secured = false;
                    // Exactly one bounded read: the client replies immediately, and a
                    // client that never learned this handshake replies with its real
                    // first request (or with nothing at all).
                    if let Ok(Some(Ok(bytes))) = timeout(KEY_EXCHANGE_TIMEOUT, b.next()).await {
                        let union = RendezvousMessage::parse_from_bytes(&bytes)
                            .ok()
                            .and_then(|msg_in| msg_in.union);
                        // T23: a NemoSealedAuth is a NemoClientAuth inside an envelope
                        // sealed to our long-term key. Open it HERE, so the existing arm
                        // below handles both shapes identically and the device-key
                        // verification is written exactly once. A sealed frame that does
                        // not open is refused outright: only a client holding our pinned
                        // public key could have produced one, so a failure here is
                        // tampering or the wrong server -- never a legacy client, which
                        // sends the flat frame instead.
                        #[cfg(feature = "nemo-management-api")]
                        let union = match union {
                            Some(rendezvous_message::Union::NemoSealedAuth(sealed)) => {
                                match Self::nemo_open_sealed_auth(&sealed.sealed, sk) {
                                    Ok(inner) => {
                                        Some(rendezvous_message::Union::NemoClientAuth(inner))
                                    }
                                    Err(err) => {
                                        log::warn!(
                                            "Refusing {:?}: sealed device-key frame does not open: {}",
                                            addr,
                                            err
                                        );
                                        return Ok(());
                                    }
                                }
                            }
                            other => other,
                        };
                        match union {
                            Some(rendezvous_message::Union::KeyExchange(ex)) => {
                                match Self::key_exchange_open(&ex, &our_sk_b) {
                                    Ok(sym) => {
                                        // One derived key, two `Encrypt`: `enc` and
                                        // `dec` count on separate fields (tcp.rs), so
                                        // a send-only instance riding with the sink
                                        // plus a recv-only instance staying here
                                        // reproduce exactly the nonce sequence of the
                                        // client's single FramedStream cipher. Neither
                                        // is ever cloned or reset afterwards.
                                        // SEC-14: `sym` carries the responder role and
                                        // whether the client sealed the v1 marker, so
                                        // both halves derive the same per-direction
                                        // nonce spaces the client is using.
                                        if let Some(Sink::TcpStream(_, cipher)) = sink.as_mut() {
                                            *cipher = Some(Encrypt::new(sym.clone()));
                                        }
                                        rx_enc = Some(Encrypt::new(sym));
                                        secured = true;
                                        log::debug!("Connection from {:?} secured", addr);
                                    }
                                    Err(err) => {
                                        // The peer ran `conn.set_key` the moment it
                                        // sent this (client common.rs), so it encrypts
                                        // from here on: falling back to plaintext
                                        // would only yield garbage. Close either mode.
                                        log::debug!(
                                            "Key exchange from {:?} failed: {}",
                                            addr,
                                            err
                                        );
                                        return Ok(());
                                    }
                                }
                            }
                            // H5: the authenticated reply. Same two values as the
                            // KeyExchange arm above, plus the device-key proof.
                            #[cfg(feature = "nemo-management-api")]
                            Some(rendezvous_message::Union::NemoClientAuth(auth)) => {
                                match Self::nemo_client_auth_open(&auth, &our_pk_b, &our_sk_b) {
                                    Ok((sym, who)) => {
                                        if let Some(Sink::TcpStream(_, cipher)) = sink.as_mut() {
                                            *cipher = Some(Encrypt::new(sym.clone()));
                                        }
                                        rx_enc = Some(Encrypt::new(sym));
                                        secured = true;
                                        log::debug!(
                                            "Connection from {:?} secured and device-authenticated \
                                             as peer {} with key {}...",
                                            addr,
                                            who.peer_id,
                                            // Short prefix only: enough to correlate with
                                            // the pinned key in the registry, not enough
                                            // to be worth logging in full.
                                            &who.device_pub_b64
                                                [..who.device_pub_b64.len().min(12)]
                                        );
                                        authed = Some(who);
                                    }
                                    Err(err) => {
                                        // Refuse rather than fall back: the peer already
                                        // installed its key, so plaintext would be
                                        // garbage, and a failed proof is exactly what we
                                        // are here to stop.
                                        log::warn!(
                                            "Refusing {:?}: device-key handshake failed: {}",
                                            addr,
                                            err
                                        );
                                        return Ok(());
                                    }
                                }
                            }
                            // A client that does not know this handshake sends its
                            // real first request instead. Replay it rather than
                            // swallow it, so `offer` really is today's behaviour
                            // for the clients already in the field.
                            _ => pending = Some(bytes),
                        }
                    }
                    // H5: Layer 1 at the transport, with the SAME semantics the
                    // management API already uses -- one flag, one concept. With
                    // require_device_key on, a connection that proved nothing does not
                    // get to register, punch or relay. With it off the connection is
                    // allowed and the straggler is named, which is what makes a staged
                    // rollout possible: provision, then flip the flag.
                    #[cfg(feature = "nemo-management-api")]
                    if authed.is_none() {
                        if crate::nemo_integration::require_device_key() {
                            log::warn!(
                                "Refusing {:?}: require-device-key is on and this client \
                                 presented no valid device key",
                                addr
                            );
                            return Ok(());
                        }
                        log::warn!(
                            "Rendezvous connection from {:?} carries NO device key \
                             (Layer 1 unproven). Provision this machine before turning \
                             require-device-key on.",
                            addr
                        );
                    }
                    if !secured && mode == KeyExchangeMode::Require {
                        log::debug!(
                            "Refusing {:?}: --key-exchange=require and the peer did not complete the handshake",
                            addr
                        );
                        return Ok(());
                    }
                } else if mode == KeyExchangeMode::Require {
                    // Unreachable: start() refuses to boot on require-with-no-key.
                    // Fail closed anyway rather than silently serving plaintext.
                    return Ok(());
                }
            }
            loop {
                let mut bytes = match pending.take() {
                    Some(bytes) => bytes,
                    None => tokio::select! {
                        res = timeout(30_000, b.next()) => match res {
                            Ok(Some(Ok(bytes))) => bytes,
                            _ => break,
                        },
                        // H43: something hbbs wants to send TO this peer. It registered
                        // over TCP, so this connection is the only way to reach it -- a
                        // UDP datagram to its registered address would go nowhere,
                        // because that address IS this TCP socket's.
                        Some(msg) = push_rx.recv() => {
                            if sink.is_none() {
                                log::warn!(
                                    "dropping a push to {:?}: this connection has no sink",
                                    addr
                                );
                            }
                            Self::send_to_sink(&mut sink, msg).await;
                            continue;
                        }
                    },
                };
                if let Some(rx_enc) = rx_enc.as_mut() {
                    if let Err(err) = rx_enc.dec(&mut bytes) {
                        log::debug!("Failed to decrypt from {:?}: {}", addr, err);
                        break;
                    }
                }
                if !self.handle_tcp(&bytes, &mut sink, addr, key, ws, &push_tx, authed.as_ref()).await {
                    break;
                }
            }
        }
        if sink.is_none() {
            self.tcp_punch.lock().await.remove(&try_into_v4(addr));
        }
        log::debug!("Tcp connection from {:?} closed", addr);
        Ok(())
    }

    /// C (--key-exchange), server half of the client's `secure_tcp_impl`: build the
    /// offer it waits for. The client opens it with `sign::verify(&keys[0], rs_pk)`
    /// and then requires exactly 32 bytes inside, so the signature must cover the raw
    /// ephemeral X25519 pubkey and nothing else, in a message carrying exactly one
    /// key. The matching secret never leaves the accepting task.
    fn key_exchange_offer_msg(
        sk: &sign::SecretKey,
    ) -> (RendezvousMessage, box_::PublicKey, box_::SecretKey) {
        let (our_pk_b, our_sk_b) = box_::gen_keypair();
        let mut msg_out = RendezvousMessage::new();
        msg_out.set_key_exchange(KeyExchange {
            keys: vec![Bytes::from(sign::sign(&our_pk_b.0, sk))],
            ..Default::default()
        });
        // H5: the PUBLIC half goes back too. It is fresh per connection, and the client's
        // device signature covers it -- that is what makes the proof unreplayable.
        (msg_out, our_pk_b, our_sk_b)
    }

    /// C: open the client's reply. The client sends `keys = [its X25519 pubkey, the
    /// symmetric key sealed to ours]` (client `create_symmetric_key_msg`), while
    /// `Encrypt::decode` takes them in the OTHER order -- (symmetric, their_pk,
    /// our_sk). Swapping the two is silent until a real client connects, so the order
    /// is pinned by `key_exchange_opens_the_clients_reply` in the tests below.
    fn key_exchange_open(
        ex: &KeyExchange,
        our_sk_b: &box_::SecretKey,
    ) -> ResultType<hbb_common::tcp::SessionKey> {
        if ex.keys.len() != 2 {
            bail!(
                "Key exchange reply carries {} keys, expected 2",
                ex.keys.len()
            );
        }
        Encrypt::decode(&ex.keys[1], &ex.keys[0], our_sk_b)
    }

    /// H5: open the client's AUTHENTICATED reply and verify the device-key proof.
    ///
    /// Order matters for cost: the registry lookup is a cheap linear scan, the Ed25519
    /// verify is not, so an unknown key is rejected before any signature work. Otherwise
    /// an unauthenticated peer could use this as a CPU amplifier.
    ///
    /// The payload the signature covers is built by the shared helper so the two ends
    /// cannot drift -- the SEC-14 argument-order bug is the standing reminder.
    #[cfg(feature = "nemo-management-api")]
    // T23: open a NemoSealedAuth envelope. The client sealed the serialized inner
    // NemoClientAuth to our long-term Ed25519 key converted to Curve25519, so device_pub
    // and peer_id no longer cross the wire in the clear. The SESSION key inside is still
    // sealed to the per-connection ephemeral: this envelope adds confidentiality for the
    // identity fields and changes nothing about forward secrecy or the signature payload.
    #[cfg(feature = "nemo-management-api")]
    fn nemo_open_sealed_auth(sealed: &[u8], sk: &sign::SecretKey) -> ResultType<NemoClientAuth> {
        use sodiumoxide::crypto::sealedbox;
        let Ok(curve_sk) = sign::to_curve25519_sk(sk) else {
            bail!("server secret key does not convert to curve25519");
        };
        let Ok(curve_pk) = sign::to_curve25519_pk(&sk.public_key()) else {
            bail!("server public key does not convert to curve25519");
        };
        let Ok(bytes) = sealedbox::open(sealed, &curve_pk, &curve_sk) else {
            bail!("envelope is not sealed to this server's key");
        };
        Ok(NemoClientAuth::parse_from_bytes(&bytes)?)
    }

    fn nemo_client_auth_open(
        auth: &NemoClientAuth,
        server_eph_pk: &box_::PublicKey,
        our_sk_b: &box_::SecretKey,
    ) -> ResultType<(hbb_common::tcp::SessionKey, AuthedDevice)> {
        let device_pub_b64 = base64::encode(&auth.device_pub[..]);
        if !crate::nemo_integration::is_device_key_pinned(&device_pub_b64) {
            bail!("device key is not pinned on this server");
        }
        // TASK #14: bound-peer check, the ONE rule the management API applies too
        // (device_key_binding_check). A key registered against one machine must not
        // authenticate another, and an UNBOUND key authenticates nothing unless the
        // operator started hbbs with --allow-unbound-device-keys Y.
        let Some(bound) = crate::nemo_integration::device_key_binding(&device_pub_b64) else {
            bail!("device key vanished from the registry mid-handshake");
        };
        if let Err(reason) = crate::nemo_integration::device_key_binding_check(
            &bound,
            &auth.peer_id,
            crate::nemo_integration::allow_unbound_device_keys(),
        ) {
            bail!("{}", reason);
        }
        let Some(device_pk) = sign::PublicKey::from_slice(&auth.device_pub) else {
            bail!("device public key is not a valid Ed25519 key");
        };
        let payload = nemo_device_auth_payload(
            &server_eph_pk.0,
            &auth.client_box_pk,
            &auth.sealed_key,
            &auth.peer_id,
        );
        let opened = sign::verify(&auth.sig, &device_pk)
            .map_err(|_| hbb_common::anyhow::anyhow!("device signature does not verify"))?;
        if opened != payload {
            bail!("device signature covers the wrong payload");
        }
        let session = Encrypt::decode(&auth.sealed_key, &auth.client_box_pk, our_sk_b)?;
        Ok((
            session,
            AuthedDevice {
                device_pub_b64,
                peer_id: auth.peer_id.clone(),
            },
        ))
    }

    #[inline]
    async fn get_pk(&mut self, version: &str, id: String) -> Bytes {
        if version.is_empty() || self.inner.sk.is_none() {
            Bytes::new()
        } else {
            match self.pm.get(&id).await {
                Some(peer) => {
                    let pk = peer.read().await.pk.clone();
                    sign::sign(
                        &hbb_common::message_proto::IdPk {
                            id,
                            pk,
                            ..Default::default()
                        }
                        .write_to_bytes()
                        .unwrap_or_default(),
                        self.inner.sk.as_ref().unwrap(),
                    )
                    .into()
                }
                _ => Bytes::new(),
            }
        }
    }

    #[inline]
    fn get_server_sk(key: &str) -> (String, Option<sign::SecretKey>) {
        let mut out_sk = None;
        let mut key = key.to_owned();
        if let Ok(sk) = base64::decode(&key) {
            if sk.len() == sign::SECRETKEYBYTES {
                log::info!("The key is a crypto private key");
                key = base64::encode(&sk[(sign::SECRETKEYBYTES / 2)..]);
                let mut tmp = [0u8; sign::SECRETKEYBYTES];
                tmp[..].copy_from_slice(&sk);
                out_sk = Some(sign::SecretKey(tmp));
            }
        }

        if key.is_empty() || key == "-" || key == "_" {
            let (pk, sk) = crate::common::gen_sk(0);
            out_sk = sk;
            if !key.is_empty() {
                key = pk;
            }
        }

        if !key.is_empty() {
            log::info!("Key: {}", key);
        }
        (key, out_sk)
    }

    #[inline]
    fn is_lan(&self, addr: SocketAddr) -> bool {
        if let Some(network) = &self.inner.mask {
            match addr {
                SocketAddr::V4(v4_socket_addr) => {
                    return network.contains(*v4_socket_addr.ip());
                }

                SocketAddr::V6(v6_socket_addr) => {
                    if let Some(v4_addr) = v6_socket_addr.ip().to_ipv4() {
                        return network.contains(v4_addr);
                    }
                }
            }
        }
        false
    }
}

async fn check_relay_servers(rs0: Arc<RelayServers>, tx: Sender) {
    let mut futs = Vec::new();
    let rs = Arc::new(Mutex::new(Vec::new()));
    for x in rs0.iter() {
        let mut host = x.to_owned();
        if !host.contains(':') {
            host = format!("{}:{}", host, config::RELAY_PORT);
        }
        let rs = rs.clone();
        let x = x.clone();
        futs.push(tokio::spawn(async move {
            if FramedStream::new(&host, None, CHECK_RELAY_TIMEOUT)
                .await
                .is_ok()
            {
                rs.lock().await.push(x);
            }
        }));
    }
    join_all(futs).await;
    log::debug!("check_relay_servers");
    let rs = std::mem::take(&mut *rs.lock().await);
    if !rs.is_empty() {
        tx.send(Data::RelayServers(rs)).ok();
    }
}

// temp solution to solve udp socket failure
async fn test_hbbs(addr: SocketAddr) -> ResultType<()> {
    let mut addr = addr;
    if addr.ip().is_unspecified() {
        addr.set_ip(if addr.is_ipv4() {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        } else {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        });
    }

    let mut socket = FramedSocket::new(config::Config::get_any_listen_addr(addr.is_ipv4())).await?;
    let mut msg_out = RendezvousMessage::new();
    msg_out.set_register_peer(RegisterPeer {
        id: "(:test_hbbs:)".to_owned(),
        ..Default::default()
    });
    let mut last_time_recv = Instant::now();

    let mut timer = interval(Duration::from_secs(1));
    loop {
        tokio::select! {
          _ = timer.tick() => {
              if last_time_recv.elapsed().as_secs() > 12 {
                  bail!("Timeout of test_hbbs");
              }
              socket.send(&msg_out, addr).await?;
          }
          Some(Ok((bytes, _))) = socket.next() => {
              if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
                 log::trace!("Recv {:?} of test_hbbs", msg_in);
                 last_time_recv = Instant::now();
              }
          }
        }
    }
}

#[inline]
async fn send_rk_res(
    socket: &mut FramedSocket,
    addr: SocketAddr,
    res: register_pk_response::Result,
) -> ResultType<()> {
    let mut msg_out = RendezvousMessage::new();
    msg_out.set_register_pk_response(RegisterPkResponse {
        result: res.into(),
        ..Default::default()
    });
    socket.send(&msg_out, addr).await
}

async fn create_udp_listener(port: i32, rmem: usize) -> ResultType<FramedSocket> {
    let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port as _);
    if let Ok(s) = FramedSocket::new_reuse(&addr, true, rmem).await {
        log::debug!("listen on udp {:?}", s.local_addr());
        return Ok(s);
    }
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port as _);
    let s = FramedSocket::new_reuse(&addr, true, rmem).await?;
    log::debug!("listen on udp {:?}", s.local_addr());
    Ok(s)
}

#[inline]
async fn create_tcp_listener(port: i32) -> ResultType<TcpListener> {
    let s = listen_any(port as _).await?;
    log::debug!("listen on tcp {:?}", s.local_addr());
    Ok(s)
}

#[cfg(test)]
mod tests {
    //! Layer 2 (TDD): protocol-handler tests for the direct-vs-relay decision
    //! core, `handle_punch_hole_request`. These run fully in-process — no
    //! sockets — against a temp-DB `PeerMap`, and assert on the returned
    //! `(RendezvousMessage, Option<(String, SocketAddr)>)`.
    //!
    //! Peers are pinned with explicit status (`Some(1)`/`Some(0)`) so the
    //! outcome does not depend on the process-global `COMPANY_ONLY`; the one
    //! case that inherently does (an unregistered target) sets it explicitly.
    //! Each test uses its own temp sqlite file under the gitignored `target/`.
    use super::*;
    // Test-only: the key-exchange test builds session keys and ciphers by hand.
    use hbb_common::tcp::{Role, SessionKey};
    use sodiumoxide::crypto::secretbox;
    use std::sync::atomic::AtomicU32;

    static DB_COUNTER: AtomicU32 = AtomicU32::new(0);

    struct TempDb(String);
    impl Drop for TempDb {
        fn drop(&mut self) {
            for suffix in ["", "-wal", "-shm", "-journal"] {
                let _ = std::fs::remove_file(format!("{}{}", self.0, suffix));
            }
        }
    }
    fn temp_db() -> TempDb {
        let n = DB_COUNTER.fetch_add(1, Ordering::SeqCst);
        let _ = std::fs::create_dir_all("target");
        TempDb(format!("target/nemo_rs_test_{}_{}.sqlite3", std::process::id(), n))
    }

    /// Build a `RendezvousServer` wired for tests: the given LAN mask, a single
    /// stub relay server, no signing key. `tx`'s receiver is dropped — the
    /// handler under test never sends on it.
    fn test_server(pm: PeerMap, mask: &str) -> RendezvousServer {
        // Isolate handler tests from any PERSISTED integration state so they exercise
        // the pure NAT/punch logic deterministically. Without this, a real
        // nemo_integration.json with require_login=true (or company-only on) makes the
        // RBAC/require-login gate return OFFLINE for the tokenless punches these tests
        // send, before the NAT/existence logic under test is ever reached. Only these
        // handler tests read these globals, so resetting them here is race-free.
        crate::nemo_management::set_company_only_for_test(false);
        crate::nemo_integration::set_require_login_for_test(false);
        let (tx, _rx) = mpsc::unbounded_channel::<Data>();
        let mut rs = RendezvousServer {
            tcp_punch: Arc::new(Mutex::new(HashMap::new())),
            tcp_peers: Arc::new(Mutex::new(HashMap::new())),
            pm,
            tx,
            relay_servers: Default::default(),
            relay_servers0: Default::default(),
            rendezvous_servers: Arc::new(vec![]),
            inner: Arc::new(Inner {
                serial: 0,
                version: "1.0.0-test".to_owned(),
                software_url: String::new(),
                mask: Some(mask.parse().expect("valid CIDR")),
                local_ip: "192.168.0.1".to_owned(),
                sk: None,
            }),
        };
        rs.parse_relay_servers("198.51.100.50:21117");
        rs
    }

    /// Register an in-memory peer (as a live registration would) with a chosen
    /// public address and status. `fresh = false` leaves the default expired
    /// `last_reg_time`, modelling a stale/offline peer.
    async fn register(pm: &PeerMap, id: &str, addr: &str, status: Option<i64>, fresh: bool) {
        let peer = pm.get_or(id).await;
        let mut w = peer.write().await;
        w.socket_addr = addr.parse().expect("valid socket addr");
        w.status = status;
        if fresh {
            w.last_reg_time = Instant::now();
        }
    }

    // H44: a controller that proved its device key, which is what every client does at
    // shipped defaults. Before H44 these tests passed `None` here and the gates were
    // skipped entirely -- that was the bypass, so the tests have to model the real thing.
    const TEST_CONTROLLER: &str = "tech-01";

    /// `register` above only touches the in-memory PeerMap, but the controller gate reads
    /// the DATABASE (`get_registered` -> `get_registered_peer`), so a controller has to be
    /// written through `update_pk` to exist as far as the gate is concerned.
    async fn register_controller(pm: &mut PeerMap, addr: &str) {
        let peer = pm.get_or(TEST_CONTROLLER).await;
        pm.update_pk(
            TEST_CONTROLLER.to_owned(),
            peer,
            addr.parse().expect("valid socket addr"),
            Bytes::from_static(b"tech-uuid"),
            Bytes::from_static(b"tech-pk"),
            addr.split(':').next().unwrap_or_default().to_owned(),
        )
        .await;
        // update_pk inserts the row with status 0, which the controller gate reads as
        // BLOCKED. A real controller is an approved peer, so mark it so.
        pm.set_peer_status(TEST_CONTROLLER, Some(1), None)
            .await
            .expect("set controller status");
    }

    fn authed_controller() -> AuthedDevice {
        AuthedDevice {
            device_pub_b64: "dGVzdC1kZXZpY2Uta2V5".to_owned(),
            peer_id: TEST_CONTROLLER.to_owned(),
        }
    }

    // T23: the sealed-auth envelope. Three properties, pinned: a frame sealed to THIS
    // server's key opens to the exact inner message; one sealed to a different key is
    // refused; and garbage is refused rather than parsed. The session key inside stays
    // sealed to the per-connection ephemeral, which is why nemo_client_auth_open is
    // untouched by this change -- the envelope only hides the identity fields.
    #[cfg(feature = "nemo-management-api")]
    #[test]
    fn sealed_auth_opens_only_for_this_server() {
        use sodiumoxide::crypto::sealedbox;
        let (server_pk, server_sk) = sign::gen_keypair();
        let inner = NemoClientAuth {
            client_box_pk: Bytes::from_static(b"client-box-pk"),
            sealed_key: Bytes::from_static(b"sealed-session-key"),
            device_pub: Bytes::from_static(b"device-pub"),
            peer_id: "ws-01".to_owned(),
            sig: Bytes::from_static(b"sig"),
            ..Default::default()
        };
        let plain = inner.write_to_bytes().unwrap();
        let curve_pk = sign::to_curve25519_pk(&server_pk).unwrap();
        let sealed = sealedbox::seal(&plain, &curve_pk);

        let opened = RendezvousServer::nemo_open_sealed_auth(&sealed, &server_sk).unwrap();
        assert_eq!(opened, inner, "the envelope must open to the exact inner message");

        let (_other_pk, other_sk) = sign::gen_keypair();
        assert!(
            RendezvousServer::nemo_open_sealed_auth(&sealed, &other_sk).is_err(),
            "a frame sealed to another server's key must be refused"
        );
        assert!(
            RendezvousServer::nemo_open_sealed_auth(b"not a sealedbox", &server_sk).is_err(),
            "garbage must be refused, not parsed"
        );
    }

    fn punch_request(target_id: &str) -> PunchHoleRequest {
        PunchHoleRequest {
            id: target_id.to_owned(),
            nat_type: NatType::ASYMMETRIC.into(),
            version: "1.0.0".to_owned(),
            ..Default::default()
        }
    }

    fn failure_of(msg: &RendezvousMessage) -> Option<(punch_hole_response::Failure, String)> {
        match &msg.union {
            Some(rendezvous_message::Union::PunchHoleResponse(r)) => {
                Some((r.failure.enum_value_or_default(), r.other_failure.clone()))
            }
            _ => None,
        }
    }

    /// C (--key-exchange): drives the handshake end to end against the production
    /// helpers with a real `sign::gen_keypair()`, standing in for the client half
    /// (`common.rs::secure_tcp_impl` + `create_symmetric_key_msg`). It exists to catch
    /// the `Encrypt::decode(symmetric, their_pk, our_sk)` argument-order swap, which is
    /// silent until a real client connects, and to pin the split of one derived key
    /// across a send-only and a recv-only `Encrypt`.
    #[test]
    fn key_exchange_opens_the_clients_reply() {
        let (rs_pk, rs_sk) = sign::gen_keypair();

        // Server: the offer exactly as handle_listener_inner puts it on the wire.
        let (msg_out, _our_pk_b, our_sk_b) = RendezvousServer::key_exchange_offer_msg(&rs_sk);
        let offered = match msg_out.union {
            Some(rendezvous_message::Union::KeyExchange(ex)) => ex.keys,
            other => panic!("expected KeyExchange, got {other:?}"),
        };
        assert_eq!(offered.len(), 1, "the client bails unless keys.len() == 1");

        // Client: verify the signature, then seal a fresh symmetric key to us.
        let their_pk_b = sign::verify(&offered[0], &rs_pk).expect("offer signature verifies");
        assert_eq!(
            their_pk_b.len(),
            box_::PUBLICKEYBYTES,
            "the client's get_pk() requires exactly 32 signed bytes"
        );
        let mut server_pk = [0u8; box_::PUBLICKEYBYTES];
        server_pk.copy_from_slice(&their_pk_b);
        let (client_pk_b, client_sk_b) = box_::gen_keypair();
        let symmetric = secretbox::gen_key();
        // SEC-14: a v1 client seals key || SESSION_KEY_V1. The marker rides INSIDE the
        // box, so an on-path attacker cannot strip it to force the old shared nonce
        // space back without holding the server's secret key.
        let mut v1_payload = symmetric.0.to_vec();
        v1_payload.push(hbb_common::tcp::SESSION_KEY_V1);
        let sealed = box_::seal(
            &v1_payload,
            &box_::Nonce([0u8; box_::NONCEBYTES]),
            &box_::PublicKey(server_pk),
            &client_sk_b,
        );
        let reply = KeyExchange {
            keys: vec![
                Bytes::from(client_pk_b.0.to_vec()),
                Bytes::from(sealed.clone()),
            ],
            ..Default::default()
        };

        // Server: open it. keys[0]/keys[1] the wrong way round fails right here.
        let opened =
            RendezvousServer::key_exchange_open(&reply, &our_sk_b).expect("sealed key opens");
        assert_eq!(
            opened.key, symmetric,
            "server derived a different symmetric key"
        );
        assert_eq!(opened.role, hbb_common::tcp::Role::Responder);

        // ... and the swapped order must not accidentally succeed.
        let swapped = KeyExchange {
            keys: vec![reply.keys[1].clone(), reply.keys[0].clone()],
            ..Default::default()
        };
        assert!(
            RendezvousServer::key_exchange_open(&swapped, &our_sk_b).is_err(),
            "(their_pk, symmetric) must not open -- argument order is load bearing"
        );
        let short = KeyExchange {
            keys: vec![reply.keys[0].clone()],
            ..Default::default()
        };
        assert!(
            RendezvousServer::key_exchange_open(&short, &our_sk_b).is_err(),
            "a reply that is not [pk, sealed] is not a completed handshake"
        );

        // One derived key, two `Encrypt`: the sink's is send-only and the read loop's
        // is recv-only, so together they match the client's single FramedStream cipher.
        let mut sink_enc = Encrypt::new(opened.clone());
        let mut loop_dec = Encrypt::new(opened);
        let mut client = Encrypt::new(SessionKey::new(symmetric.clone(), Role::Initiator));
        let mut from_server = BytesMut::from(&sink_enc.enc(b"punch-hole-response")[..]);
        client
            .dec(&mut from_server)
            .expect("client decrypts our reply");
        assert_eq!(&from_server[..], &b"punch-hole-response"[..]);
        let mut from_client = BytesMut::from(&client.enc(b"punch-hole-request")[..]);
        loop_dec
            .dec(&mut from_client)
            .expect("server decrypts the request");
        assert_eq!(&from_client[..], &b"punch-hole-request"[..]);

        // SEC-14: the two directions must not derive the same nonce from their own
        // counters. (That the OLD shape did is asserted in hbb_common's own tests,
        // which can still construct it; here the shape is no longer reachable.)
        let mut v1_i = Encrypt::new(SessionKey::new(symmetric.clone(), Role::Initiator));
        let mut v1_r = Encrypt::new(SessionKey::new(symmetric.clone(), Role::Responder));
        assert_ne!(
            v1_i.enc(b"same plaintext"),
            v1_r.enc(b"same plaintext"),
            "SEC-14: the two directions must not reuse a nonce with one key"
        );

        // A pre-SEC-14 client seals a bare 32-byte key. Nothing is deployed that does
        // so, and accepting it would silently reinstate the shared nonce space, so the
        // handshake refuses it outright.
        let legacy_sealed = box_::seal(
            &symmetric.0,
            &box_::Nonce([0u8; box_::NONCEBYTES]),
            &box_::PublicKey(server_pk),
            &client_sk_b,
        );
        let legacy_reply = KeyExchange {
            keys: vec![
                Bytes::from(client_pk_b.0.to_vec()),
                Bytes::from(legacy_sealed),
            ],
            ..Default::default()
        };
        assert!(
            RendezvousServer::key_exchange_open(&legacy_reply, &our_sk_b).is_err(),
            "a bare 32-byte session key must not be accepted"
        );

        // An unknown version is refused rather than guessed at, so a future v2 cannot
        // be silently misread as v1.
        let mut v2_payload = symmetric.0.to_vec();
        v2_payload.push(hbb_common::tcp::SESSION_KEY_V1 + 1);
        let v2_sealed = box_::seal(
            &v2_payload,
            &box_::Nonce([0u8; box_::NONCEBYTES]),
            &box_::PublicKey(server_pk),
            &client_sk_b,
        );
        let v2_reply = KeyExchange {
            keys: vec![Bytes::from(client_pk_b.0.to_vec()), Bytes::from(v2_sealed)],
            ..Default::default()
        };
        assert!(
            RendezvousServer::key_exchange_open(&v2_reply, &our_sk_b).is_err(),
            "an unknown session key version must not be accepted"
        );
    }

    /// H5. The rendezvous used to be anonymous: anyone holding the server's PUBLIC key --
    /// which is not a secret, it ships in every client config and inside the
    /// host=..,key=.. licence name -- completed the handshake and could then register.
    /// These assert the four ways a forged or replayed proof must fail, and that an
    /// honest one succeeds.
    #[cfg(feature = "nemo-management-api")]
    #[test]
    fn device_auth_binds_the_key_to_the_connection_and_to_the_peer_id() {
        use crate::nemo_integration::{pin_device_key_for_test, unpin_device_key_for_test, DeviceKey};

        let (device_pk, device_sk) = sign::gen_keypair();
        let device_pub_b64 = base64::encode(device_pk.as_ref());
        pin_device_key_for_test(DeviceKey {
            id: "t1".to_owned(),
            label: "test".to_owned(),
            public_key: device_pub_b64.clone(),
            created_at: String::new(),
            peer_id: "111111111".to_owned(),
        });

        // The server's per-connection ephemeral, and a second one standing in for a
        // DIFFERENT connection.
        let (server_pk, server_sk) = box_::gen_keypair();
        let (other_server_pk, other_server_sk) = box_::gen_keypair();

        let build = |peer_id: &str, eph: &box_::PublicKey| {
            let (client_box_pk, sealed_key, _key) = {
                let (cpk, csk) = box_::gen_keypair();
                let sym = secretbox::gen_key();
                let mut payload = sym.0.to_vec();
                payload.push(hbb_common::tcp::SESSION_KEY_V1);
                let sealed = box_::seal(
                    &payload,
                    &box_::Nonce([0u8; box_::NONCEBYTES]),
                    eph,
                    &csk,
                );
                (
                    Bytes::from(cpk.0.to_vec()),
                    Bytes::from(sealed),
                    sym,
                )
            };
            let sig = sign::sign(
                &nemo_device_auth_payload(&eph.0, &client_box_pk, &sealed_key, peer_id),
                &device_sk,
            );
            NemoClientAuth {
                client_box_pk,
                sealed_key,
                device_pub: Bytes::from(device_pk.as_ref().to_vec()),
                peer_id: peer_id.to_owned(),
                sig: Bytes::from(sig),
                ..Default::default()
            }
        };

        // Honest proof for the bound peer opens, and reports who it is.
        let good = build("111111111", &server_pk);
        let (_session, who) =
            RendezvousServer::nemo_client_auth_open(&good, &server_pk, &server_sk)
                .expect("an honest proof must open");
        assert_eq!(who.peer_id, "111111111");
        assert_eq!(who.device_pub_b64, device_pub_b64);

        // Bound to peer A, claiming peer B: refused. This is what stops one leaked key
        // authenticating the whole fleet.
        let wrong_peer = build("222222222", &server_pk);
        // SessionKey is deliberately not Debug (it holds key material), so match rather
        // than unwrap_err().
        let err = match RendezvousServer::nemo_client_auth_open(&wrong_peer, &server_pk, &server_sk) {
            Ok(_) => panic!("a key bound to another peer must not authenticate"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("bound to peer"), "{}", err);

        // REPLAY into another connection: the same bytes against a different server
        // ephemeral. This is the property the whole design rests on -- freshness comes
        // from the server's per-connection key, not from a clock.
        assert!(
            RendezvousServer::nemo_client_auth_open(&good, &other_server_pk, &other_server_sk)
                .is_err(),
            "a captured proof must not open against a different connection"
        );

        // Tampered signature.
        let mut tampered = build("111111111", &server_pk);
        let mut sig = tampered.sig.to_vec();
        sig[0] ^= 0xff;
        tampered.sig = Bytes::from(sig);
        assert!(
            RendezvousServer::nemo_client_auth_open(&tampered, &server_pk, &server_sk).is_err()
        );

        // Unpinned key: refused before any signature work, so an unknown key cannot be
        // used as a CPU amplifier.
        unpin_device_key_for_test(&device_pub_b64);
        let err = match RendezvousServer::nemo_client_auth_open(&good, &server_pk, &server_sk) {
            Ok(_) => panic!("an unpinned device key must not authenticate"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("not pinned"), "{}", err);
    }

    /// C: the flag parser. `require` is the default (main.rs), and every value that is
    /// not one of the three documented modes -- including an EMPTY one -- is refused at
    /// boot rather than silently downgraded to `off`.
    #[test]
    fn key_exchange_mode_parses_the_three_documented_values() {
        assert!(KeyExchangeMode::parse("").is_err());
        assert!(KeyExchangeMode::parse("   ").is_err());
        assert_eq!(KeyExchangeMode::parse("off").unwrap(), KeyExchangeMode::Off);
        assert_eq!(
            KeyExchangeMode::parse("Offer").unwrap(),
            KeyExchangeMode::Offer
        );
        assert_eq!(
            KeyExchangeMode::parse(" require ").unwrap(),
            KeyExchangeMode::Require
        );
        assert!(KeyExchangeMode::parse("requrie").is_err());
    }

    #[test]
    fn punch_invalid_key_returns_license_mismatch() {
        run_punch_invalid_key_returns_license_mismatch();
    }
    #[tokio::main(flavor = "current_thread")]
    async fn run_punch_invalid_key_returns_license_mismatch() {
        let db = temp_db();
        let mut pm = PeerMap::new_for_test(&db.0).await.unwrap();
        // H44: the controller is a registered peer too -- hbbs refuses a punch from one
        // that is not, so a test that does not register it is testing nothing.
        register_controller(&mut pm, "203.0.113.7:55000").await;
        let mut rs = test_server(pm, "192.168.0.0/16");
        let mut ph = punch_request("ws-01");
        ph.licence_key = "wrong-key".to_owned();
        let (msg, forwarded) = rs
            .handle_punch_hole_request("203.0.113.7:55000".parse().unwrap(), ph, "server-key", false, Some(&authed_controller()))
            .await
            .unwrap();
        assert!(forwarded.is_none());
        assert_eq!(
            failure_of(&msg).map(|f| f.0),
            Some(punch_hole_response::Failure::LICENSE_MISMATCH)
        );
    }

    #[test]
    fn punch_unknown_peer_returns_id_not_exist() {
        run_punch_unknown_peer_returns_id_not_exist();
    }
    #[tokio::main(flavor = "current_thread")]
    async fn run_punch_unknown_peer_returns_id_not_exist() {
        crate::nemo_management::set_company_only_for_test(false);
        let db = temp_db();
        let mut pm = PeerMap::new_for_test(&db.0).await.unwrap();
        // H44: the controller is a registered peer too -- hbbs refuses a punch from one
        // that is not, so a test that does not register it is testing nothing.
        register_controller(&mut pm, "203.0.113.7:55000").await;
        let mut rs = test_server(pm, "192.168.0.0/16");
        let (msg, forwarded) = rs
            .handle_punch_hole_request("203.0.113.7:55000".parse().unwrap(), punch_request("ghost"), "", false, Some(&authed_controller()))
            .await
            .unwrap();
        assert!(forwarded.is_none());
        assert_eq!(
            failure_of(&msg).map(|f| f.0),
            Some(punch_hole_response::Failure::ID_NOT_EXIST)
        );
    }

    #[test]
    fn punch_stale_peer_returns_offline() {
        run_punch_stale_peer_returns_offline();
    }
    #[tokio::main(flavor = "current_thread")]
    async fn run_punch_stale_peer_returns_offline() {
        let db = temp_db();
        let mut pm = PeerMap::new_for_test(&db.0).await.unwrap();
        // Allowed (status=1) but registration is stale -> OFFLINE with no reason.
        register(&pm, "ws-01", "198.51.100.9:41000", Some(1), false).await;
        // H44: the controller is a registered peer too -- hbbs refuses a punch from one
        // that is not, so a test that does not register it is testing nothing.
        register_controller(&mut pm, "203.0.113.7:55000").await;
        let mut rs = test_server(pm, "192.168.0.0/16");
        let (msg, forwarded) = rs
            .handle_punch_hole_request("203.0.113.7:55000".parse().unwrap(), punch_request("ws-01"), "", false, Some(&authed_controller()))
            .await
            .unwrap();
        assert!(forwarded.is_none());
        let (failure, reason) = failure_of(&msg).expect("punch hole response");
        assert_eq!(failure, punch_hole_response::Failure::OFFLINE);
        assert!(reason.is_empty(), "stale-offline carries no policy reason");
    }

    #[test]
    fn punch_blocked_peer_returns_offline_with_reason() {
        run_punch_blocked_peer_returns_offline_with_reason();
    }
    #[tokio::main(flavor = "current_thread")]
    async fn run_punch_blocked_peer_returns_offline_with_reason() {
        let db = temp_db();
        let mut pm = PeerMap::new_for_test(&db.0).await.unwrap();
        register(&pm, "ws-01", "198.51.100.9:41000", Some(0), true).await;
        // H44: the controller is a registered peer too -- hbbs refuses a punch from one
        // that is not, so a test that does not register it is testing nothing.
        register_controller(&mut pm, "203.0.113.7:55000").await;
        let mut rs = test_server(pm, "192.168.0.0/16");
        let (msg, forwarded) = rs
            .handle_punch_hole_request("203.0.113.7:55000".parse().unwrap(), punch_request("ws-01"), "", false, Some(&authed_controller()))
            .await
            .unwrap();
        assert!(forwarded.is_none());
        let (failure, reason) = failure_of(&msg).expect("punch hole response");
        assert_eq!(failure, punch_hole_response::Failure::OFFLINE);
        assert!(reason.contains("not allowed"), "got reason: {reason:?}");
    }

    #[test]
    fn punch_wan_to_wan_passes_nat_type_through() {
        run_punch_wan_to_wan_passes_nat_type_through();
    }
    #[tokio::main(flavor = "current_thread")]
    async fn run_punch_wan_to_wan_passes_nat_type_through() {
        ALWAYS_USE_RELAY.store(false, Ordering::SeqCst);
        let db = temp_db();
        let mut pm = PeerMap::new_for_test(&db.0).await.unwrap();
        // Both endpoints are public (outside the LAN mask), different IPs.
        register(&pm, "ws-01", "198.51.100.9:41000", Some(1), true).await;
        // H44: the controller is a registered peer too -- hbbs refuses a punch from one
        // that is not, so a test that does not register it is testing nothing.
        register_controller(&mut pm, "203.0.113.7:55000").await;
        let mut rs = test_server(pm, "192.168.0.0/16");
        let (msg, forwarded) = rs
            .handle_punch_hole_request("203.0.113.7:55000".parse().unwrap(), punch_request("ws-01"), "", false, Some(&authed_controller()))
            .await
            .unwrap();
        assert!(forwarded.is_some());
        match msg.union {
            Some(rendezvous_message::Union::PunchHole(ph_out)) => {
                // No LAN mismatch and ALWAYS_USE_RELAY off -> nat_type unchanged.
                assert_eq!(ph_out.nat_type.enum_value_or_default(), NatType::ASYMMETRIC);
            }
            other => panic!("expected PunchHole, got {other:?}"),
        }
    }

    #[test]
    fn punch_wan_to_lan_forces_relay() {
        run_punch_wan_to_lan_forces_relay();
    }
    #[tokio::main(flavor = "current_thread")]
    async fn run_punch_wan_to_lan_forces_relay() {
        // Documents the production reality (roadmap Phase 1.5): a workstation on
        // the server's LAN, reached by a controller on the WAN, is forced onto
        // the relay by rewriting the peer's NAT type to SYMMETRIC. When that
        // forcing is made configurable, this test changes with it.
        ALWAYS_USE_RELAY.store(false, Ordering::SeqCst);
        let db = temp_db();
        let mut pm = PeerMap::new_for_test(&db.0).await.unwrap();
        register(&pm, "ws-01", "192.168.0.50:41000", Some(1), true).await;
        // H44: the controller is a registered peer too -- hbbs refuses a punch from one
        // that is not, so a test that does not register it is testing nothing.
        register_controller(&mut pm, "203.0.113.7:55000").await;
        let mut rs = test_server(pm, "192.168.0.0/16");
        let (msg, forwarded) = rs
            .handle_punch_hole_request("203.0.113.7:55000".parse().unwrap(), punch_request("ws-01"), "", false, Some(&authed_controller()))
            .await
            .unwrap();
        assert!(forwarded.is_some());
        match msg.union {
            Some(rendezvous_message::Union::PunchHole(ph_out)) => {
                assert_eq!(
                    ph_out.nat_type.enum_value_or_default(),
                    NatType::SYMMETRIC,
                    "WAN->LAN is forced to relay via SYMMETRIC in the current topology"
                );
            }
            other => panic!("expected PunchHole, got {other:?}"),
        }
    }

    #[test]
    fn punch_lan_to_lan_returns_fetch_local_addr() {
        run_punch_lan_to_lan_returns_fetch_local_addr();
    }
    #[tokio::main(flavor = "current_thread")]
    async fn run_punch_lan_to_lan_returns_fetch_local_addr() {
        ALWAYS_USE_RELAY.store(false, Ordering::SeqCst);
        let db = temp_db();
        let mut pm = PeerMap::new_for_test(&db.0).await.unwrap();
        // Both endpoints on the LAN -> same-intranet direct path.
        register(&pm, "ws-01", "192.168.0.50:41000", Some(1), true).await;
        // H44: the controller is a registered peer too -- hbbs refuses a punch from one
        // that is not, so a test that does not register it is testing nothing.
        register_controller(&mut pm, "192.168.0.60:55000").await;
        let mut rs = test_server(pm, "192.168.0.0/16");
        let (msg, forwarded) = rs
            .handle_punch_hole_request("192.168.0.60:55000".parse().unwrap(), punch_request("ws-01"), "", false, Some(&authed_controller()))
            .await
            .unwrap();
        assert!(forwarded.is_some());
        assert!(
            matches!(msg.union, Some(rendezvous_message::Union::FetchLocalAddr(_))),
            "same-intranet peers should get FetchLocalAddr (direct LAN), not relay"
        );
    }
}
