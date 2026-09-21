//! H9/H32 regression probe: a rendezvous client that sends a BARE RequestRelay --
//! no PunchHoleRequest first.
//!
//! That is exactly the shape the finding is about: a registered but logged-out client
//! that asks hbbs for a relay instead of punching. A stock client cannot produce it --
//! client.rs only calls request_relay AFTER a successful punch, so the punch-path gate
//! always fires first -- which is why the bypass can only be exercised, and the fix
//! only re-verified, by speaking the protocol directly.
//!
//! An `example`, not a `bin`, so it never lands in a release build. Build it with
//! `cargo build --example relayprobe`.
//!
//! Expected results against a server where both peers are allowed:
//!
//! | require_login | with the gate            | with the gate removed |
//! |---------------|--------------------------|-----------------------|
//! | false         | forwarded, relay pairs   | forwarded, relay pairs|
//! | true          | "log in to TBFDesk to connect", not forwarded | forwarded, relay pairs |
//!
//! Note when running this on one host: hbbr treats any LOOPBACK connection as its
//! command port (relay_server.rs `handle_connection`), so RELAY_SERVER must be a
//! routable address of the machine, not 127.0.0.1, or nothing will ever pair.
//!
//! Usage: relayprobe <hbbs addr> <server pk b64> <my id> <target id> [token]
//! Env:   RELAY_SERVER=<host:port>  also dial hbbr and report whether the pair formed,
//!        SERVER_KEY=<b64>          the server key hbbr expects in RequestRelay.licence_key
use hbb_common::{
    bytes::Bytes,
    protobuf::Message as _,
    rendezvous_proto::*,
    sodiumoxide::{
        base64,
        crypto::{box_, secretbox, sign},
    },
    tcp::{FramedStream, Role, SessionKey, SESSION_KEY_V1},
    tokio, ResultType,
};

const UUID: &[u8] = b"relayprobe-uuid-1";

async fn connect_secure(addr: &str, rs_pk: &sign::PublicKey) -> ResultType<FramedStream> {
    let mut conn = FramedStream::new(addr, None, 5_000).await?;
    let bytes = match conn.next_timeout(5_000).await {
        Some(Ok(b)) => b,
        _ => hbb_common::bail!("no key exchange offer from {}", addr),
    };
    let msg = RendezvousMessage::parse_from_bytes(&bytes)?;
    let Some(rendezvous_message::Union::KeyExchange(ex)) = msg.union else {
        hbb_common::bail!("expected a KeyExchange offer, got something else");
    };
    if ex.keys.len() != 1 {
        hbb_common::bail!("offer carries {} keys", ex.keys.len());
    }
    let their_pk_b = sign::verify(&ex.keys[0], rs_pk)
        .map_err(|_| hbb_common::anyhow::anyhow!("offer signature mismatch"))?;
    let mut pk = [0u8; box_::PUBLICKEYBYTES];
    pk.copy_from_slice(&their_pk_b);
    let (our_pk_b, our_sk_b) = box_::gen_keypair();
    let key = secretbox::gen_key();
    // SEC-14: seal key || version, exactly as the real client does.
    let mut payload = key.0.to_vec();
    payload.push(SESSION_KEY_V1);
    let sealed = box_::seal(
        &payload,
        &box_::Nonce([0u8; box_::NONCEBYTES]),
        &box_::PublicKey(pk),
        &our_sk_b,
    );
    let mut out = RendezvousMessage::new();
    out.set_key_exchange(KeyExchange {
        keys: vec![Bytes::from(our_pk_b.0.to_vec()), Bytes::from(sealed)],
        ..Default::default()
    });
    conn.send(&out).await?;
    conn.set_key(SessionKey::new(key, Role::Initiator));
    Ok(conn)
}

#[tokio::main]
async fn main() -> ResultType<()> {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 5 {
        hbb_common::bail!("usage: relayprobe <addr> <server-pk-b64> <my-id> <target-id> [token]");
    }
    let (addr, pk_b64, my_id, target) = (&a[1], &a[2], &a[3], &a[4]);
    let token = a.get(5).cloned().unwrap_or_default();
    let raw = base64::decode(pk_b64, base64::Variant::Original)
        .map_err(|_| hbb_common::anyhow::anyhow!("bad server pk"))?;
    let rs_pk = sign::PublicKey::from_slice(&raw)
        .ok_or_else(|| hbb_common::anyhow::anyhow!("bad server pk length"))?;

    // 1. Register, so we are a known, policy-checkable controller.
    let mut conn = connect_secure(addr, &rs_pk).await?;
    let (sign_pk, _sign_sk) = sign::gen_keypair();
    let mut out = RendezvousMessage::new();
    out.set_register_pk(RegisterPk {
        id: my_id.clone(),
        uuid: Bytes::from(UUID.to_vec()),
        pk: Bytes::from(sign_pk.0.to_vec()),
        ..Default::default()
    });
    conn.send(&out).await?;
    match conn.next_timeout(5_000).await {
        Some(Ok(b)) => {
            let m = RendezvousMessage::parse_from_bytes(&b)?;
            println!("register_pk -> {:?}", m.union);
        }
        _ => println!("register_pk -> no response"),
    }
    drop(conn);

    // 2. A BARE RequestRelay. No PunchHoleRequest before it -- that is the point.
    let mut conn = connect_secure(addr, &rs_pk).await?;
    let marker = if token.is_empty() {
        format!(
            "nemo-source-v1:{}:{}",
            my_id,
            base64::encode(UUID, base64::Variant::Original)
        )
    } else {
        format!(
            "nemo-source-v1:{}:{}:{}",
            my_id,
            base64::encode(UUID, base64::Variant::Original),
            token
        )
    };
    let relay_server = std::env::var("RELAY_SERVER").unwrap_or_default();
    let mut out = RendezvousMessage::new();
    out.set_request_relay(RequestRelay {
        id: target.clone(),
        uuid: "relayprobe-session".to_owned(),
        relay_server: relay_server.clone(),
        licence_key: marker.clone(),
        secure: true,
        ..Default::default()
    });
    println!("sending bare RequestRelay id={} marker={}", target, marker);
    conn.send(&out).await?;
    match conn.next_timeout(6_000).await {
        Some(Ok(b)) => {
            let m = RendezvousMessage::parse_from_bytes(&b)?;
            match m.union {
                Some(rendezvous_message::Union::RelayResponse(rr)) => {
                    println!(
                        "RESULT: RelayResponse refuse_reason={:?} relay_server={:?}",
                        rr.refuse_reason, rr.relay_server
                    );
                }
                other => println!("RESULT: unexpected {:?}", other),
            }
        }
        _ => println!("RESULT: no response (hbbs forwarded it to the target and said nothing back)"),
    }

    // If a relay was named, dial hbbr with the same uuid. The target, having received
    // the forwarded RequestRelay, dials the same relay with the same uuid -- so a
    // successful pair proves the request really did reach it.
    if !relay_server.is_empty() {
        let key = std::env::var("SERVER_KEY").unwrap_or_default();
        match FramedStream::new(&relay_server, None, 5_000).await {
            Ok(mut r) => {
                // hbbr offers its own signed key exchange first (relay control frame).
                if let Some(Ok(b)) = r.next_timeout(5_000).await {
                    if let Ok(m) = RendezvousMessage::parse_from_bytes(&b) {
                        if let Some(rendezvous_message::Union::KeyExchange(ex)) = m.union {
                            if let Ok(their) = sign::verify(&ex.keys[0], &rs_pk) {
                                let mut pk = [0u8; box_::PUBLICKEYBYTES];
                                pk.copy_from_slice(&their);
                                let (opk, osk) = box_::gen_keypair();
                                let k = secretbox::gen_key();
                                let mut payload = k.0.to_vec();
                                payload.push(SESSION_KEY_V1);
                                let sealed = box_::seal(
                                    &payload,
                                    &box_::Nonce([0u8; box_::NONCEBYTES]),
                                    &box_::PublicKey(pk),
                                    &osk,
                                );
                                let mut o = RendezvousMessage::new();
                                o.set_key_exchange(KeyExchange {
                                    keys: vec![
                                        Bytes::from(opk.0.to_vec()),
                                        Bytes::from(sealed),
                                    ],
                                    ..Default::default()
                                });
                                r.send(&o).await?;
                                r.set_key(SessionKey::new(k, Role::Initiator));
                            }
                        }
                    }
                }
                let mut o = RendezvousMessage::new();
                o.set_request_relay(RequestRelay {
                    id: target.clone(),
                    uuid: "relayprobe-session".to_owned(),
                    licence_key: key,
                    ..Default::default()
                });
                r.send(&o).await?;
                r.clear_key();
                // hbbr pairs the two sockets and then pipes bytes. Anything we read
                // back is the peer's first frame, i.e. the pair formed.
                match r.next_timeout(6_000).await {
                    Some(Ok(b)) => println!("RELAY: paired -- {} bytes from the peer", b.len()),
                    _ => println!("RELAY: no peer arrived (not paired)"),
                }
            }
            Err(e) => println!("RELAY: could not dial {}: {}", relay_server, e),
        }
    }
    Ok(())
}
