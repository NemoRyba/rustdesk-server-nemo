use crate::{
    common::{get_arg, get_arg_or},
    database::RegisteredPeer,
    peer::{PeerInfo, PeerMap},
};
use axum::{
    extract::{ConnectInfo, Extension, Path, Query},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::Html,
    routing::{get, post},
    Json, Router,
};
use hbb_common::{
    bail,
    config::keys,
    log,
    rendezvous_proto::{control_permissions, ControlPermissions, NemoSource},
    tokio, ResultType,
};
use once_cell::sync::Lazy;
use serde_derive::{Deserialize, Serialize};
use sodiumoxide::crypto::{box_, sealedbox, sign};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::SocketAddr,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
use tokio::sync::RwLock;

const EVENT_LIMIT: usize = 500;
// SEC-9: nothing bounded a request body, so an UNAUTHENTICATED POST to a public
// route (/api/login, /nemo/api/client/policy, /api/ab/get) was buffered and
// JSON-parsed in full before the handler could reject it. The per-field caps
// (MAX_NONCE_LEN, MAX_SEALED_REQUEST_B64) are checked inside the handler and so
// came far too late to help.
//
// Two tiers, because the two groups of routes have nothing in common. The admin
// tier is sized by the largest LEGITIMATE body -- a PUT of the whole permission
// map, one entry per directory user. The public tier is sized by the sealed-login
// envelope (MAX_SEALED_REQUEST_B64 is 16 KiB), which is the biggest thing a caller
// with no token has any business sending.
const MAX_REQUEST_BODY: usize = 4 * 1024 * 1024;
const MAX_PUBLIC_REQUEST_BODY: usize = 64 * 1024;

/// Body-size tier for a path. "Public" means a route an UNAUTHENTICATED caller can
/// push a body to; everything here is sized for a client poll or a login, not for an
/// administrative payload.
///
/// `/nemo/api/health` is deliberately NOT in this list. The name says probe, but the
/// handler calls `require_auth` and returns the whole security policy -- see `health`.
///
/// TASK-18: the three navigable admin paths serve the tokenless LOGIN SHELL, so they
/// belong in the token-free tier. Enumerated rather than prefix-matched on purpose --
/// the sibling `/nemo/admin/app` carries the real dashboard, is require_auth-gated, and
/// must stay in the admin tier.
fn request_body_cap(path: &str) -> usize {
    let public = path.starts_with("/api/")
        || path.starts_with("/nemo/api/update/file/")
        || path == "/nemo/api/client/policy"
        || path.starts_with("/nemo/api/client/audit/")
        || path == "/nemo/api/update/latest"
        || path == "/nemo"
        || path == "/nemo/admin"
        || path == "/nemo/admin/";
    if public {
        MAX_PUBLIC_REQUEST_BODY
    } else {
        MAX_REQUEST_BODY
    }
}

/// SEC-9. Deliberately a hand-rolled middleware rather than a layer:
/// `RequestBodyLimitLayer` lives in tower-http 0.4 and `http_body::Limited` in
/// http-body 0.4.5, and this tree is pinned to tower-http 0.3.3 / http-body 0.4.4
/// through axum 0.5. Pulling either forward to bound a body is a much bigger change
/// than bounding it here.
///
/// Two stops: reject a declared Content-Length over the cap without reading
/// anything, and cap the accumulation itself so a chunked body with no declared
/// length cannot stream past it either.
async fn limit_request_body(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next<axum::body::Body>,
) -> Result<axum::response::Response, StatusCode> {
    use axum::body::HttpBody;
    // An installer upload is far over every other cap, and this middleware reads the
    // body before any handler can check the token -- so the big cap is granted only to
    // a request that already carries the admin token. Anyone else gets the normal cap
    // and then the handler's 401.
    let cap = if req.uri().path() == UPDATE_UPLOAD_ROUTE && admin_token_presented(req.headers()) {
        MAX_UPDATE_UPLOAD
    } else {
        request_body_cap(req.uri().path())
    };
    if let Some(declared) = req
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
    {
        if declared > cap {
            log::warn!(
                "Refused a {}-byte body on {} (cap {})",
                declared,
                req.uri().path(),
                cap
            );
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
    }
    let (parts, mut body) = req.into_parts();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|_| StatusCode::BAD_REQUEST)?;
        if buf.len().saturating_add(chunk.len()) > cap {
            log::warn!(
                "Refused an undeclared body over {} bytes on {}",
                cap,
                parts.uri.path()
            );
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        buf.extend_from_slice(&chunk);
    }
    let req = axum::http::Request::from_parts(parts, axum::body::Body::from(buf));
    Ok(next.run(req).await)
}
const MAX_MANAGEMENT_POLICY_VALUE_LEN: usize = 4096;
const NEMO_SOURCE_PREFIX: &str = "nemo-source-v1:";
const OPTION_NEMO_OUTBOUND_ENABLED: &str = "nemo-outbound-enabled";
const OPTION_NEMO_OUTBOUND_TARGETS: &str = "nemo-outbound-targets";
// Direct connections. The endpoint map is assembled per-controller from PEER_ENDPOINTS;
// the knock keys are operator-set (global or per-device policy) and are secrets.
const OPTION_NEMO_DIRECT_ENDPOINTS: &str = "nemo-direct-endpoints";
const OPTION_NEMO_KNOCK_KEY: &str = "nemo-knock-key";
const OPTION_NEMO_KNOCK_HMAC_KEY: &str = "nemo-knock-hmac-key";
// Per-peer SPA keys: `id,rijndael_b64,hmac_b64;...`, assembled per-controller from
// PEER_KNOCK_KEYS by knock_key_map, filtered by the same ACL as the endpoint map, and
// pushed inside the SEALED policy. Gives each workstation its own knock key, so a key
// leaked from one machine opens only the one port it belongs to. SECRET.
const OPTION_NEMO_KNOCK_KEYS: &str = "nemo-knock-keys";
// Current client policy keys that are newer than this server fork's embedded
// hbb_common key tables, plus Nemo-only GUI/management options.
const CLIENT_MANAGEMENT_POLICY_KEYS: &[&str] = &[
    // TBFDesk security switches. These were missing, so the server silently DROPPED
    // them from any pushed policy (is_management_policy_key returned false) while the
    // client was fully wired to receive them -- nemo_management_client.rs lists all
    // three in NEMO_MANAGEMENT_SETTINGS and even has a clear-on-omit path for them.
    // The effect was that the fleet-wide kill switch for plaintext rendezvous could
    // only ever be set by hand-editing each client's TOML.
    "nemo-require-secure-rendezvous",
    // The server's own boot warning tells operators to "push disable-udp=Y to the fleet,
    // then restart with --udp-registration=N". That rollout was UNDELIVERABLE: this
    // server's embedded hbb_common files OPTION_DISABLE_UDP under KEYS_BUILDIN_SETTINGS,
    // and is_management_policy_key never looks at that table -- so hbbs silently dropped
    // `disable-udp` from every pushed policy. (The client's hbb_common has the same key
    // under KEYS_SETTINGS; the two submodules disagree.) Naming it here is the narrow
    // fix; widening is_management_policy_key to include KEYS_BUILDIN_SETTINGS would make
    // ~35 unrelated built-in keys remotely settable.
    "disable-udp",
    "nemo-sealed-request",
    "nemo-auto-update",
    // Management authorization on the TARGET (client nemo_control): refuse every
    // session -- direct ones included -- that does not carry a valid control ticket.
    "nemo-require-control-ticket",
    // Lock the TARGET's desktop when a remote-control session to it ends, whatever the
    // controller's own "Lock after session end" toggle says (client nemo_control).
    "nemo-lock-after-session-end",
    // Direct connections + the optional SPA knock (see nemo_direct.rs on the client).
    // Named here so an operator can set them in the Global or a named device policy; the
    // endpoint map is normally assembled per-controller by direct_endpoint_map, but a
    // hand-written value still works when PEER_ENDPOINTS is empty. Pushing these as a
    // policy with allow_user_override is what lets a technician adjust the knock locally
    // while a locked policy keeps the fleet fixed.
    OPTION_NEMO_DIRECT_ENDPOINTS,
    "nemo-direct-timeout-ms",
    "nemo-knock-enabled",
    "nemo-knock-port",
    OPTION_NEMO_KNOCK_KEY,
    OPTION_NEMO_KNOCK_HMAC_KEY,
    "nemo-knock-delay-ms",
    "nemo-knock-user",
    "nemo-knock-source-ip",
    "view_only",
    "show_monitors_toolbar",
    "collapse_toolbar",
    "show_remote_cursor",
    "follow_remote_cursor",
    "follow_remote_window",
    "zoom-cursor",
    "show_quality_monitor",
    "disable_audio",
    "enable-remote-printer",
    "enable-file-copy-paste",
    "disable_clipboard",
    "lock_after_session_end",
    "privacy_mode",
    "touch-mode",
    "i444",
    "reverse_mouse_wheel",
    "swap-left-right-mouse",
    "displays_as_individual_windows",
    "use_all_my_displays_for_the_remote_session",
    "view_style",
    "scroll_style",
    "edge-scroll-edge-thickness",
    "image_quality",
    "custom_image_quality",
    "custom-fps",
    "codec-preference",
    "sync-init-clipboard",
    "theme",
    "lang",
    "remote-menubar-drag-left",
    "remote-menubar-drag-right",
    "hideAbTagsPanel",
    "enable-confirm-closing-tabs",
    "enable-open-new-connections-in-tabs",
    "use-texture-render",
    "allow-d3d-render",
    "enable-check-update",
    "allow-auto-update",
    "sync-ab-with-recent-sessions",
    "sync-ab-tags",
    "filter-ab-by-intersection",
    "access-mode",
    "enable-keyboard",
    "enable-clipboard",
    "enable-file-transfer",
    "enable-camera",
    "enable-terminal",
    "terminal-persistent",
    "enable-audio",
    "enable-tunnel",
    "enable-remote-restart",
    "enable-record-session",
    "enable-block-input",
    "enable-privacy-mode",
    "enable-perm-change-in-accept-window",
    "allow-remote-config-modification",
    "allow-numeric-one-time-password",
    "one-way-file-transfer",
    "nemo-permanent-password",
    "nemo-alias",
    "nemo-require-login",
    "nemo-require-encrypted-session",
    "nemo-logged-in-user",
    // S-B item 5: SHA-256 fingerprint the client pins the nemo-api TLS cert to
    // (colon-separated hex). Pushable via the signed policy so the whole fleet
    // can be pinned centrally; with a pin set the client stops using the
    // accept-any-invalid-cert fallback for the api server.
    "nemo-api-cert-fingerprint",
    OPTION_NEMO_OUTBOUND_ENABLED,
    OPTION_NEMO_OUTBOUND_TARGETS,
    "enable-lan-discovery",
    "direct-server",
    "direct-access-port",
    "whitelist",
    "allow-auto-disconnect",
    "auto-disconnect-timeout",
    "allow-only-conn-window-open",
    "allow-auto-record-incoming",
    "allow-auto-record-outgoing",
    "video-save-directory",
    "enable-abr",
    "allow-remove-wallpaper",
    "allow-always-software-render",
    "allow-linux-headless",
    "enable-hwcodec",
    "approve-mode",
    "verification-method",
    "temporary-password-length",
    "proxy-url",
    "proxy-username",
    "proxy-password",
    "custom-rendezvous-server",
    "api-server",
    "key",
    "allow-websocket",
    "preset-address-book-name",
    "preset-address-book-tag",
    "preset-address-book-alias",
    "preset-address-book-password",
    "preset-address-book-note",
    "preset-device-username",
    "preset-device-name",
    "preset-note",
    "enable-directx-capture",
    "enable-android-software-encoding-half-scale",
    "enable-trusted-devices",
    "av1-test",
    "trackpad-speed",
    "register-device",
    "relay-server",
    "ice-servers",
    "file-transfer-max-files",
    "disable-udp",
    "allow-insecure-tls-fallback",
    "show-virtual-mouse",
    "show-virtual-joystick",
    "enable-flutter-http-on-rust",
    "allow-ask-for-note",
    "display-name",
    "avatar",
    "preset-device-group-name",
    "preset-user-name",
    "preset-strategy-name",
    "remove-preset-password-warning",
    "hide-security-settings",
    "hide-network-settings",
    "hide-server-settings",
    "hide-proxy-settings",
    "hide-remote-printer-settings",
    "hide-websocket-settings",
    "hide-stop-service",
    "enable-udp-punch",
    "enable-ipv6-punch",
    "hide-username-on-card",
    "hide-help-cards",
    "default-connect-password",
    "hide-tray",
    "one-way-clipboard-redirection",
    "allow-logon-screen-password",
    "allow-deep-link-password",
    "allow-deep-link-server-settings",
    "one-way-file-transfer",
    "allow-https-21114",
    "use-raw-tcp-for-api",
    "allow-hostname-as-id",
    "hide-powered-by-me",
    "main-window-always-on-top",
    "disable-change-permanent-password",
    "disable-change-id",
    "disable-unlock-pin",
    "remoteMenubarState",
    "peer-sorting",
    "peer-tab-index",
    "peer-tab-order",
    "peer-tab-visible",
    "peer-card-ui-type",
    "current-ab-name",
    "allow-remote-cm-modification",
    "printer-incomming-job-action",
    "allow-printer-auto-print",
    "printer-selected-name",
    "disable-floating-window",
    "floating-window-size",
    "floating-window-untouchable",
    "floating-window-transparency",
    "floating-window-svg",
    "keep-screen-on",
    "keep-awake-during-incoming-sessions",
    "keep-awake-during-outgoing-sessions",
    "disable-group-panel",
    "disable-discovery-panel",
    "pre-elevate-service",
    "nemo-company-network-only",
    "nemo-management-enabled",
    "nemo-management-server",
    "nemo-management-public-key",
];

static COMPANY_ONLY: AtomicBool = AtomicBool::new(false);
// Admin-configurable number of recent connection negotiations retained for the
// live "Connections" view (retained by COUNT, no time cutoff). Loaded from disk
// at startup so a dashboard change survives a restart.
static CONN_HISTORY_LIMIT: AtomicUsize = AtomicUsize::new(DEFAULT_CONN_HISTORY_LIMIT);
// Admin-configurable number of recent server events (logins, connection setups,
// policy changes) retained for the Log view. Persisted so it survives a restart.
static LOG_HISTORY_LIMIT: AtomicUsize = AtomicUsize::new(DEFAULT_LOG_HISTORY_LIMIT);
// Transport posture captured when the API starts, so the runtime LDAP-enable
// guard (put_ldap_config) can refuse to turn LDAP on when credentials would then
// traverse the network in cleartext.
static API_TLS_ACTIVE: AtomicBool = AtomicBool::new(false);
static API_BIND_LOOPBACK: AtomicBool = AtomicBool::new(true);
static API_ALLOW_INSECURE: AtomicBool = AtomicBool::new(false);
// Summary of the certificate the API is actually serving, captured at TLS setup
// so the client login screen can show "what am I connecting to and why does my
// OS distrust it". Purely informational: a client reads it over the same (maybe
// self-signed) TLS, so it is a diagnostic aid, NOT an authenticated pin — the
// credential is protected by the Ed25519-signed sealed login, not by this.
static API_CERT_INFO: Lazy<std::sync::RwLock<Option<TlsCertInfo>>> =
    Lazy::new(|| std::sync::RwLock::new(None));

// What the login screen shows about the API's serving certificate.
#[derive(Clone, Debug, Serialize, Default)]
struct TlsCertInfo {
    tls: bool,           // is the API served over TLS at all
    mode: String,        // "self-signed" | "provided" | "off"
    subject: String,
    issuer: String,
    self_signed: bool,
    sans: Vec<String>,
    not_before: String,
    not_after: String,
    fingerprint: String, // SHA-256, uppercase colon-separated (matches openssl)
    server_host: String, // hostname the self-signed SANs were built from
    pem: String,         // the serving certificate in PEM, so a client can save/pin it
}

/// Sweep HIGH (Bearer over accept-any-cert): the client login screen defaults to
/// allow-insecure-tls-fallback=Y so a self-signed API works out of the box, and
/// then accepts ANY certificate -- including a man-in-the-middle's. The policy
/// itself is signed by the management key, so it can safely carry the fix:
/// - self-signed API: push its own SHA-256 as nemo-api-cert-fingerprint. The
///   client then uses the pinned TLS client for the API host and never falls
///   back. Back up nemo-api-cert.pem/-key.pem: a regenerated cert strands every
///   pinned client until the pin is cleared locally.
/// - operator-provided (CA) cert: push allow-insecure-tls-fallback=N, since a
///   valid chain never needs the fallback and a MITM would.
/// An explicit value in the global policy always wins.
fn apply_api_tls_defaults(options: &mut HashMap<String, String>, info: Option<&TlsCertInfo>) {
    let Some(info) = info.filter(|i| i.tls) else {
        return;
    };
    if info.mode == "self-signed" && !info.fingerprint.is_empty() {
        options
            .entry("nemo-api-cert-fingerprint".to_owned())
            .or_insert_with(|| info.fingerprint.clone());
    } else if info.mode == "provided" {
        options
            .entry("allow-insecure-tls-fallback".to_owned())
            .or_insert_with(|| "N".to_owned());
    }
}

// Parse the PEM the API is serving and stash a client-facing summary. Best
// effort: on any parse failure we still record tls=true + mode so the login
// screen can explain the situation rather than showing nothing.
fn set_api_cert_info(pem: &str, provided: bool) {
    let mode = if provided { "provided" } else { "self-signed" };
    let mut info = TlsCertInfo {
        tls: true,
        mode: mode.to_owned(),
        server_host: whoami::hostname(),
        pem: pem.to_owned(),
        ..Default::default()
    };
    if let Some(s) = crate::nemo_integration::pem_cert_full_summary(pem) {
        info.subject = s.subject;
        info.issuer = s.issuer;
        info.self_signed = s.self_signed;
        info.sans = s.sans;
        info.not_before = s.not_before;
        info.not_after = s.not_after;
        info.fingerprint = s.fingerprint;
    }
    *API_CERT_INFO.write().unwrap() = Some(info);
}
// Global client policy merged into every peer's managed policy (per-peer options
// win). Lets the operator push settings — api-server, TLS fallback, etc. — to
// all Nemo clients at once, including peers that register later.
static GLOBAL_POLICY: Lazy<std::sync::RwLock<ManagementPolicy>> =
    Lazy::new(|| std::sync::RwLock::new(load_global_policy()));
static STATS: Lazy<RwLock<NemoStatsStore>> = Lazy::new(|| RwLock::new(NemoStatsStore::default()));
// Client-reported hostnames (peer id -> hostname), so the address book can show
// "which computer is this ID". Reported by each peer's management poll (below),
// persisted so labels survive a restart before the next poll re-reports them.
static PEER_HOSTNAMES: Lazy<std::sync::RwLock<HashMap<String, String>>> =
    Lazy::new(|| std::sync::RwLock::new(load_peer_hostnames()));
// S-DUALKEY: which key each peer used on its last poll — "device-key" (its own
// pinned private key) or "default" (the shared server public key). Runtime only.
static PEER_AUTH_MODES: Lazy<std::sync::RwLock<HashMap<String, String>>> =
    Lazy::new(|| std::sync::RwLock::new(HashMap::new()));
// C2: bound the per-peer label maps (hostname / auth-mode). record_peer_hostname and
// record_peer_auth_mode run for every poll BEFORE the require_device_key rejection, so an
// unauthenticated flood of distinct ids could otherwise grow them without limit (and the
// hostname map is disk-backed). Labels are re-reported each poll, so evicting an arbitrary
// entry at the cap is harmless.
const MAX_PEER_LABELS: usize = 50_000;
const MAX_HOSTNAME_LEN: usize = 256;
// Evict one arbitrary entry so a new key can be inserted without unbounded growth.
fn evict_one_if_full(map: &mut HashMap<String, String>, id: &str) {
    if map.len() >= MAX_PEER_LABELS && !map.contains_key(id) {
        if let Some(victim) = map.keys().next().cloned() {
            map.remove(&victim);
        }
    }
}
fn record_peer_auth_mode(id: &str, mode: &str) {
    if id.is_empty() {
        return;
    }
    let mut map = PEER_AUTH_MODES.write().unwrap();
    evict_one_if_full(&mut map, id);
    map.insert(id.to_owned(), mode.to_owned());
}
fn peer_auth_mode(id: &str) -> String {
    PEER_AUTH_MODES
        .read()
        .unwrap()
        .get(id)
        .cloned()
        .unwrap_or_else(|| "unknown".to_owned())
}

// TODO 23: when each peer last proved its device key on the RENDEZVOUS handshake.
//
// `auth_mode` above is written only by the management poll, so a machine that is online,
// allowed and relaying -- having proved its pinned key seconds earlier -- showed up as
// "provisioned, not polled", which reads as a server fault and is not one. The two
// proofs are kept apart rather than merged: the handshake proves the KEY (more strongly,
// in fact -- it signs a fresh server nonce instead of a timestamp), while the poll is
// what delivers policy. An operator needs to see both, because "key fine, never polls"
// is a real and separate condition with its own cause (no api-server on the client).
static PEER_DEVICE_KEY_RENDEZVOUS: Lazy<std::sync::RwLock<HashMap<String, String>>> =
    Lazy::new(|| std::sync::RwLock::new(HashMap::new()));

/// Called from the rendezvous handshake once a device signature has verified against the
/// peer id in its own signed payload (`nemo_client_auth_open`), i.e. never on an
/// unproven id.
pub(crate) fn record_peer_device_key_rendezvous(id: &str) {
    if id.is_empty() {
        return;
    }
    let at = now_iso();
    let mut map = PEER_DEVICE_KEY_RENDEZVOUS.write().unwrap();
    evict_one_if_full(&mut map, id);
    map.insert(id.to_owned(), at);
}

fn peer_device_key_proved_at(id: &str) -> String {
    PEER_DEVICE_KEY_RENDEZVOUS
        .read()
        .unwrap()
        .get(id)
        .cloned()
        .unwrap_or_default()
}

// What each CONTROLLER was last handed in `nemo-direct-endpoints`: "<count> <iso>".
// Configuring a port forward and a controller being able to use it are two separate
// facts -- the map is filtered per controller by the outbound-targets ACL and dropped
// for a blocked target -- and only the first one used to be visible anywhere.
static PEER_ENDPOINTS_DELIVERED: Lazy<std::sync::RwLock<HashMap<String, String>>> =
    Lazy::new(|| std::sync::RwLock::new(HashMap::new()));

fn record_peer_endpoints_delivered(id: &str, endpoints: &str) {
    if id.is_empty() {
        return;
    }
    let count = if endpoints.trim().is_empty() {
        0
    } else {
        endpoints.split(';').filter(|e| !e.trim().is_empty()).count()
    };
    let mut map = PEER_ENDPOINTS_DELIVERED.write().unwrap();
    evict_one_if_full(&mut map, id);
    map.insert(id.to_owned(), format!("{} {}", count, now_iso()));
}

/// `(entries, when)` from the last poll, or `(0, "")` if this id has not polled since
/// the server started. Zero entries with a timestamp is itself an answer: the client
/// polled and was given no endpoint at all.
fn peer_endpoints_delivered(id: &str) -> (usize, String) {
    let raw = PEER_ENDPOINTS_DELIVERED
        .read()
        .unwrap()
        .get(id)
        .cloned()
        .unwrap_or_default();
    match raw.split_once(' ') {
        Some((count, at)) => (count.parse().unwrap_or(0), at.to_owned()),
        None => (0, String::new()),
    }
}

// The client build each machine reported on its last poll ("<version> <iso>"), so the
// dashboard can show who runs what during an update rollout. In memory: every client
// polls every 30 s, so it is complete again half a minute after a restart.
static PEER_CLIENT_VERSIONS: Lazy<std::sync::RwLock<HashMap<String, String>>> =
    Lazy::new(|| std::sync::RwLock::new(HashMap::new()));

fn record_peer_client_version(id: &str, version: &str) {
    let version = version.trim();
    if id.is_empty()
        || version.is_empty()
        || version.len() > 32
        || !version.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return;
    }
    let mut map = PEER_CLIENT_VERSIONS.write().unwrap();
    evict_one_if_full(&mut map, id);
    map.insert(id.to_owned(), format!("{} {}", version, now_iso()));
}

/// `(version, when reported)`, or empty strings if this id has not reported one since
/// the server started (older clients never do).
fn peer_client_version(id: &str) -> (String, String) {
    let raw = PEER_CLIENT_VERSIONS.read().unwrap().get(id).cloned().unwrap_or_default();
    match raw.split_once(' ') {
        Some((v, at)) => (v.to_owned(), at.to_owned()),
        None => (String::new(), String::new()),
    }
}

#[derive(Clone)]
struct HbbsApiState {
    pm: PeerMap,
    token: Option<String>,
    server_public_key: String,
    server_secret_key: Option<sign::SecretKey>,
    // S-B: ephemeral X25519 keypair (per API run) for sealing the client login
    // credential. The public half is published (signed) via /api/login-key; the
    // client seals {username,password,ts} to it so the domain password is
    // confidential regardless of TLS. Regenerated each restart — clients fetch the
    // current key per login, so there is no staleness.
    login_enc_pk: box_::PublicKey,
    login_enc_sk: box_::SecretKey,
}

#[derive(Default)]
struct NemoStatsStore {
    totals: NemoTotals,
    peers: HashMap<String, NemoPeerStats>,
    events: VecDeque<NemoEvent>,
    // Recent connection negotiations the server observed, deduped by
    // (source_id, target_id). The server sees connection SETUP (punch/relay), so
    // this is "who connected to whom, over what path, how recently" — the live
    // admin view. Direct sessions have no server-side teardown signal, so entries
    // age out by CONNECTION_TTL rather than on true session end.
    connections: Vec<ConnectionRecord>,
    // TODO 7: relayed sessions, live and recently ended, as hbbr measures them.
    relay_sessions: Vec<RelaySessionRecord>,
    // TODO 24: the relay-metrics poller's OWN state. A session row with no samples
    // means "hbbr told us nothing about it", which is evidence that the two machines
    // went direct only if hbbr is actually answering. Without this the panel labelled
    // every row "unused — went direct" whenever the poller could not reach the relay
    // at all, i.e. invented good news out of missing data.
    relay_poller: RelayPollerHealth,
}

// Connection history is retained by COUNT (the most-recent N negotiations), not
// by age. The size is admin-configurable at runtime (persisted, see
// CONN_HISTORY_LIMIT) with this default, and hard-capped so unauthenticated
// punch traffic cannot exhaust memory.
const DEFAULT_CONN_HISTORY_LIMIT: usize = 420;
const MAX_CONN_HISTORY_LIMIT: usize = 100_000;
const DEFAULT_LOG_HISTORY_LIMIT: usize = 500;
const MAX_LOG_HISTORY_LIMIT: usize = 100_000;

#[derive(Clone)]
struct ConnectionRecord {
    source_id: String,
    target_id: String,
    source_addr: String,
    target_addr: String,
    path: String, // "direct-local" | "direct-punch" | "direct-endpoint" | "direct-failed" | "relay"
    relay_server: String,
    nat_type: String,
    first_seen: std::time::Instant,
    last_seen: std::time::Instant,
    negotiations: u64,
}

#[derive(Clone, Default, Serialize)]
struct NemoTotals {
    // TODO 7: bytes hbbr actually carried, counted once per session. The per-peer twin
    // below charges both ends, so these two do not add up to each other.
    relay_bytes: u64,
    registered_messages: u64,
    register_pk_messages: u64,
    direct_attempts: u64,
    local_addr_attempts: u64,
    relay_forced: u64,
    relay_requests: u64,
    relay_responses: u64,
    punch_responses: u64,
    local_addr_responses: u64,
    policy_rejections: u64,
}

#[derive(Clone, Default, Serialize)]
pub(crate) struct NemoPeerStats {
    // TODO 7: bytes relayed in sessions this peer took part in, as either end. This is
    // the number that says a machine is NOT going direct - `relay_forced` only ever
    // said a relay was offered.
    relay_bytes: u64,
    registered_messages: u64,
    register_pk_messages: u64,
    direct_attempts: u64,
    local_addr_attempts: u64,
    relay_forced: u64,
    relay_requests: u64,
    relay_responses: u64,
    punch_responses: u64,
    local_addr_responses: u64,
    policy_rejections: u64,
    last_event_at: Option<String>,
    last_public_addr: Option<String>,
    last_punch_from_addr: Option<String>,
    last_punch_to_addr: Option<String>,
    last_nat_type: Option<String>,
    last_relay_server: Option<String>,
    last_forced_relay: bool,
    last_same_intranet: bool,
    // Sessions controllers established / failed to establish over this machine's
    // published direct endpoint, as THEY reported it (kind "direct" audit). The
    // rendezvous never sees these.
    direct_endpoint_ok: u64,
    direct_endpoint_failed: u64,
    last_direct_report: Option<String>,
}

#[derive(Clone, Serialize)]
struct NemoEvent {
    at: String,
    kind: String,
    peer_id: Option<String>,
    remote_addr: Option<String>,
    detail: String,
}

#[derive(Serialize)]
struct ApiError {
    error: String,
}

#[derive(Deserialize)]
struct ListQuery {
    limit: Option<usize>,
    offset: Option<usize>,
}

#[derive(Deserialize)]
struct EventsQuery {
    limit: Option<usize>,
}

#[derive(Deserialize)]
struct PolicyRequest {
    company_only: Option<bool>,
    #[serde(default)]
    connection_history_limit: Option<usize>,
    #[serde(default)]
    log_history_limit: Option<usize>,
    #[serde(default)]
    require_device_key: Option<bool>,
    #[serde(default)]
    strip_unsealed_secrets: Option<bool>,
    /// M1-CLAIM: whether an unbound pinned key may request a binding on first use.
    #[serde(default)]
    claim_unbound_device_keys: Option<bool>,
    /// S-B (scope b): the two fail-closed switches for encrypted client requests.
    /// Option, like the rest: a PUT that omits them leaves them untouched.
    #[serde(default)]
    require_sealed_login: Option<bool>,
    #[serde(default)]
    require_sealed_request: Option<bool>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct ManagementPolicy {
    #[serde(default)]
    allow_user_override: bool,
    #[serde(default)]
    options: HashMap<String, String>,
}

#[derive(Deserialize)]
struct ManagementPolicyRequest {
    #[serde(default)]
    allow_user_override: bool,
    #[serde(default)]
    options: HashMap<String, String>,
}

#[derive(Deserialize)]
struct ClientPolicyRequest {
    id: String,
    uuid: String,
    #[serde(default)]
    policy_version: Option<String>,
    /// The logged-in user's session token, so the server can deliver that user's
    /// policy (identity-based policy). A1: superseded by `sealed_token` when present.
    #[serde(default)]
    access_token: Option<String>,
    /// A1: base64 sealedbox({token, ts}) to the server's management key. When present
    /// it supersedes the plaintext access_token, so the session token is confidential
    /// on the wire regardless of TLS.
    #[serde(default)]
    sealed_token: Option<String>,
    /// The peer's own hostname, so the server can label the address book with
    /// "which computer is this ID".
    #[serde(default)]
    hostname: Option<String>,
    /// S-DUALKEY: the client's provisioned device public key (base64 Ed25519) and
    /// an attached signature over "nemo-poll:{id}:{ts}". When present and pinned +
    /// fresh, the client is authenticated with its OWN key (auth mode device-key);
    /// otherwise it falls back to the shared server key (auth mode default).
    #[serde(default)]
    device_key_pub: Option<String>,
    #[serde(default)]
    device_key_sig: Option<String>,
    /// S-B/S-DUALKEY step 3: "v1" = this client can unseal a policy response sealed
    /// to its device key (NaCl sealedbox over the Ed25519-signed payload). Absent on
    /// older clients, which keep receiving the signed-plaintext shape.
    #[serde(default)]
    sealed: Option<String>,
    /// The client's build (crate::VERSION), for the dashboard's rollout view. Absent on
    /// clients older than 1.4.15.
    #[serde(default)]
    client_version: Option<String>,
}

#[derive(Serialize)]
struct ClientPolicyPayload {
    id: String,
    issued_at: String,
    /// Epoch seconds twin of issued_at: lets a seal-capable client reject a
    /// replayed old sealed response without parsing RFC3339 (sealedbox itself has
    /// no replay protection; the signed timestamp inside the seal is what does).
    #[serde(default)]
    issued_ts: u64,
    /// Session revocation order for this peer: it must terminate every session it
    /// currently holds when this value is newer than the one it last honoured. Sits
    /// inside the signed (and, when sealed, encrypted) payload, so it cannot be
    /// forged or stripped by a MITM. 0 = nothing to revoke.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    terminate_sessions_before: u64,
    policy: ManagementPolicy,
}

fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

#[derive(Serialize)]
struct ClientPolicyResponse {
    server_public_key: String,
    signed_payload: String,
    /// Cleartext payload (legacy shape). None when the response is sealed — the
    /// payload then exists ONLY inside `sealed_payload`, so the pushed managed
    /// password and config are ciphertext to anything but this client's device key.
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<ClientPolicyPayload>,
    /// base64(NaCl sealedbox(sign::sign(payload_json), client device key)) —
    /// sign-then-seal: the Ed25519 signature stays INSIDE the seal so the payload
    /// is neither readable nor recoverable from an attached signature by a MITM.
    #[serde(skip_serializing_if = "Option::is_none")]
    sealed_payload: Option<String>,
}

#[derive(Serialize)]
struct PeerListResponse {
    limit: usize,
    offset: usize,
    company_only: bool,
    peers: Vec<PeerResponse>,
}

#[derive(Serialize)]
struct PeerResponse {
    id: String,
    // The peer's self-reported hostname (from its management poll), so the dashboard
    // can label it (e.g. in the Connections view) with "which computer is this id".
    hostname: String,
    guid: String,
    uuid: String,
    public_key: String,
    user: Option<String>,
    created_at: Option<String>,
    note: Option<String>,
    status: Option<i64>,
    policy: String,
    allowed_for_control: bool,
    management_policy: ManagementPolicy,
    registered_ip: Option<String>,
    public_addr: Option<String>,
    online: bool,
    last_seen_ms_ago: Option<u64>,
    stats: NemoPeerStats,
    // S-DUALKEY: which key this peer used on its last poll — "device-key" / "default".
    auth_mode: String,
    // TODO 23: when it last proved that key on the rendezvous handshake (ISO, empty =
    // never since this server started). Kept separate from auth_mode on purpose: this
    // says the KEY is good, auth_mode says a POLL arrived, and a machine can have the
    // first without the second (no api-server configured) — which is precisely the
    // state the dashboard used to describe as "provisioned, not polled".
    device_key_proved_at: String,
    // M1-CLAIM: provisioning state read from the PINNED REGISTRY rather than from the
    // last poll, so unlike auth_mode above it survives a server restart: a machine that
    // has a key bound to it is provisioned even if it has not polled since boot.
    provisioned: bool,
    device_key_id: String,
    device_key_label: String,
    /// Set when this peer has proved a pinned-but-unbound key and is waiting for the
    /// operator to confirm the pairing. It is NOT authenticated while this is set — the
    /// peers panel shows it as "unverified — key claim pending" with Approve / Deny.
    pending_claim_key_id: String,
    pending_claim_key_label: String,
    pending_claim_first_seen: String,
    pending_claim_attempts: u32,
    pending_claim_via: String,
    pending_claim_denied: bool,
    // Where controllers may reach this workstation without the relay, as the operator
    // configured it ("host:port[,knockport]"). Empty => hole punch / relay only.
    direct_endpoint: String,
    // Whether this peer has its OWN SPA knock key (so a key leaked elsewhere can't open
    // its port). False => it falls back to the fleet-wide knock key. The key is a secret
    // and is never returned, only this flag.
    knock_key_configured: bool,
    // How many direct endpoints THIS machine was handed on its last management poll,
    // and when. The other half of the direct-access question: `direct_endpoint` says
    // where this machine can be reached, these say whether it (as a controller) was
    // actually told where to reach anything.
    endpoints_delivered: usize,
    endpoints_delivered_at: String,
    // The client build this machine reported on its last poll (1.4.15+), and when.
    client_version: String,
    client_version_at: String,
}

#[derive(Serialize)]
struct PeerPolicyResponse {
    id: String,
    status: Option<i64>,
    policy: String,
    allowed_for_control: bool,
}

/// Typed by the operator into the dashboard's dialog and required by the API, so neither a
/// misclick nor a stray authenticated POST can revoke a fleet.
const ROTATE_CONFIRMATION: &str = "ROTATE";

#[derive(Deserialize)]
struct RotateServerKeyRequest {
    #[serde(default)]
    confirm: String,
}

#[derive(Serialize)]
struct RotateServerKeyResponse {
    previous_public_key: String,
    new_public_key: String,
    /// Where the retired secret was kept, so it can be restored if this was a mistake.
    archived_secret_key: String,
    /// Always true: hbbs reads its key once at startup.
    restart_required: bool,
}

#[derive(Deserialize)]
struct PeerEndpointRequest {
    /// `host:port[,knockport]`. `None` or empty clears the endpoint.
    #[serde(default)]
    endpoint: Option<String>,
}

#[derive(Serialize)]
struct PeerEndpointResponse {
    id: String,
    /// The stored, normalized value — empty when cleared.
    endpoint: String,
}

#[derive(Deserialize)]
struct PeerKnockKeyRequest {
    /// base64 Rijndael (AES-256) key. Empty/absent (with `hmac_key` too) clears the pair.
    #[serde(default)]
    key: Option<String>,
    /// base64 HMAC-SHA256 key.
    #[serde(default)]
    hmac_key: Option<String>,
}

#[derive(Serialize)]
struct PeerKnockKeyResponse {
    id: String,
    /// Whether a per-peer key pair is now stored for this peer. The keys themselves are
    /// never echoed back — they are secrets.
    configured: bool,
}

#[derive(Serialize)]
struct PolicyResponse {
    /// This server's own Ed25519 identity key, base64 — the value every client needs as
    /// `key` (to verify the rendezvous handshake and the signed id/pk) and as
    /// `nemo-management-public-key` (to verify signed policy).
    ///
    /// It was previously impossible to read anywhere: the dashboard's "Server public key"
    /// field is a policy *input* that pushes a value TO clients, and the only API carrying
    /// the real one was the client policy response, which needs a registered peer. So the
    /// one value required to provision a new client could only be obtained by shelling into
    /// the server and catting the keyfile.
    ///
    /// That is worse than inconvenient, because `hbbs` silently generates a keypair in its
    /// working directory whenever it finds none — so every lab or dev run leaves behind an
    /// `id_ed25519.pub` that looks authoritative and is not. Four such files were in
    /// circulation on 2026-10-15 and a build was nearly configured against the wrong one.
    ///
    /// Public by construction: it is handed to every client on every policy poll, so showing
    /// it to an authenticated operator discloses nothing new.
    server_public_key: String,
    /// The key ON DISK, i.e. what the next start will use. Normally identical to
    /// `server_public_key`; differs after a rotation, because hbbs reads its key once at
    /// startup. The dashboard shows a restart-pending warning on a mismatch — without this
    /// the operator would rotate, see the old key still listed, and have no way to tell
    /// whether the rotation took.
    server_public_key_on_disk: String,
    company_only: bool,
    blocked_status: i64,
    allowed_status: i64,
    connection_history_limit: usize,
    log_history_limit: usize,
    require_device_key: bool,
    strip_unsealed_secrets: bool,
    // M1-CLAIM: on by default. With it off, an unbound key authenticates nothing and
    // files no request — the original fail-closed rule, keys bound by hand only.
    claim_unbound_device_keys: bool,
    /// Requests waiting for a decision right now, so the dashboard can badge the panel
    /// without a second call.
    pending_device_key_claims: usize,
    // S-B (scope b): both ship false, so the dashboard shows "off" on a fleet that
    // has not been updated yet.
    require_sealed_login: bool,
    require_sealed_request: bool,
    // Build id of the running hbbs (git hash + date), so the dashboard header can
    // show which build is applied. GUI ships inside this same binary.
    build_id: &'static str,
}

#[derive(Serialize)]
struct ManagementPolicyResponse {
    id: String,
    policy: ManagementPolicy,
}

#[derive(Deserialize)]
struct DeletePeersRequest {
    ids: Vec<String>,
}

#[derive(Serialize)]
struct DeletePeersResponse {
    deleted: Vec<String>,
    missing: Vec<String>,
}

#[derive(Serialize)]
struct StatsPeerResponse {
    id: String,
    stats: NemoPeerStats,
}

#[derive(Serialize)]
struct StatsResponse {
    // TODO 7: live and recent relayed sessions with their byte counts.
    relay_sessions: Vec<RelaySessionRecord>,
    // TODO 24: whether those counts can be believed. Without it the dashboard cannot
    // tell "the relay carried nothing" from "the relay never told us anything".
    relay_poller: RelayPollerHealth,
    company_only: bool,
    totals: NemoTotals,
    peers: Vec<StatsPeerResponse>,
}

#[derive(Serialize)]
struct EventsResponse {
    events: Vec<NemoEvent>,
}

type ApiFailure = (StatusCode, Json<ApiError>);
type ApiResult<T> = Result<Json<T>, ApiFailure>;

fn company_only_path() -> String {
    get_arg_or("nemo-company-only-file", "nemo_company_only".to_owned())
}

fn load_persisted_company_only() -> Option<bool> {
    std::fs::read_to_string(company_only_path())
        .ok()
        .map(|s| is_truthy(s.trim()))
}

// Nemo hardening (S6): persist the company-only flag so a dashboard toggle
// survives a server restart (previously it reverted to the CLI default).
fn persist_company_only(value: bool) {
    let path = company_only_path();
    if let Err(e) = std::fs::write(&path, if value { "Y" } else { "N" }) {
        log::error!("failed to persist company-only flag to {}: {}", path, e);
    }
}

fn conn_history_limit_path() -> String {
    get_arg_or(
        "nemo-conn-history-file",
        "nemo_conn_history_limit".to_owned(),
    )
}

fn load_persisted_conn_history_limit() -> Option<usize> {
    std::fs::read_to_string(conn_history_limit_path())
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .map(|n| n.clamp(1, MAX_CONN_HISTORY_LIMIT))
}

// Persist the connection-history size so a dashboard change survives a restart.
fn persist_conn_history_limit(value: usize) {
    let path = conn_history_limit_path();
    if let Err(e) = std::fs::write(&path, value.to_string()) {
        log::error!("failed to persist connection-history limit to {}: {}", path, e);
    }
}

fn log_history_limit_path() -> String {
    get_arg_or("nemo-log-history-file", "nemo_log_history_limit".to_owned())
}

fn load_persisted_log_history_limit() -> Option<usize> {
    std::fs::read_to_string(log_history_limit_path())
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .map(|n| n.clamp(1, MAX_LOG_HISTORY_LIMIT))
}

fn persist_log_history_limit(value: usize) {
    let path = log_history_limit_path();
    if let Err(e) = std::fs::write(&path, value.to_string()) {
        log::error!("failed to persist log-history limit to {}: {}", path, e);
    }
}

fn log_history_limit() -> usize {
    LOG_HISTORY_LIMIT.load(Ordering::SeqCst)
}

// Per-peer session revocation: "terminate any session open on this peer as of this
// epoch second". Persisted, because a revocation must survive a server restart --
// direct sessions do not die with the server, so forgetting the order would silently
// un-revoke them.
static PEER_TERMINATE: Lazy<std::sync::RwLock<HashMap<String, u64>>> =
    Lazy::new(|| std::sync::RwLock::new(load_peer_terminate()));

fn peer_terminate_path() -> String {
    get_arg_or("nemo-peer-terminate-file", "nemo_peer_terminate.json".to_owned())
}

fn load_peer_terminate() -> HashMap<String, u64> {
    std::fs::read_to_string(peer_terminate_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Order the peer to drop every session it currently has. Monotonic: the stored value
/// only ever moves forward, so a clock wobble cannot un-revoke.
fn set_peer_terminate(id: &str) -> u64 {
    let now = now_epoch_secs();
    let snapshot = {
        let mut map = PEER_TERMINATE.write().unwrap();
        let slot = map.entry(id.to_owned()).or_insert(0);
        if now > *slot {
            *slot = now;
        }
        map.clone()
    };
    if let Ok(text) = serde_json::to_string(&snapshot) {
        if let Err(err) = std::fs::write(peer_terminate_path(), text) {
            log::error!("failed to persist session revocation for {}: {}", id, err);
        }
    }
    snapshot.get(id).copied().unwrap_or(now)
}

fn peer_terminate_before(id: &str) -> u64 {
    PEER_TERMINATE.read().unwrap().get(id).copied().unwrap_or(0)
}

fn peer_hostnames_path() -> String {
    get_arg_or("nemo-peer-hostnames-file", "nemo_peer_hostnames.json".to_owned())
}

fn load_peer_hostnames() -> HashMap<String, String> {
    std::fs::read_to_string(peer_hostnames_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

// Record a peer's self-reported hostname (from its management poll). Only writes
// to disk when the value actually changes, so the 30s poll cadence doesn't churn
// the file.
fn record_peer_hostname(id: &str, hostname: &str) {
    let hostname = hostname.trim();
    if id.is_empty() || hostname.is_empty() {
        return;
    }
    // C2: bound the stored value so a peer cannot make us persist a multi-MB "hostname".
    let hostname: String = hostname.chars().take(MAX_HOSTNAME_LEN).collect();
    let hostname = hostname.as_str();
    {
        let map = PEER_HOSTNAMES.read().unwrap();
        if map.get(id).map(|h| h == hostname).unwrap_or(false) {
            return;
        }
    }
    let snapshot = {
        let mut map = PEER_HOSTNAMES.write().unwrap();
        evict_one_if_full(&mut map, id);
        map.insert(id.to_owned(), hostname.to_owned());
        map.clone()
    };
    if let Ok(json) = serde_json::to_string(&snapshot) {
        let path = peer_hostnames_path();
        if let Err(e) = std::fs::write(&path, json) {
            log::warn!("failed to persist peer hostnames to {}: {}", path, e);
        }
    }
}

fn peer_hostname(id: &str) -> String {
    PEER_HOSTNAMES
        .read()
        .unwrap()
        .get(id)
        .cloned()
        .unwrap_or_default()
}

// ---- Server identity key: read it, and (break-glass) rotate it ----
//
// `hbbs` keeps its Ed25519 signing key in `id_ed25519` in its working directory and reads
// it ONCE at startup (see common::gen_sk), so a rotation here does not take effect until
// the process restarts. Everything below is written so that the on-disk state is always
// consistent and recoverable, and so the dashboard can tell the operator that the running
// key no longer matches the file.

fn server_key_file() -> &'static str {
    // Must match common::gen_sk, which hardcodes this name relative to the cwd.
    "id_ed25519"
}

/// The public key currently ON DISK, which is what the next start will use. Read from
/// `id_ed25519.pub` if present, otherwise derived from the secret (the public half is the
/// second 32 bytes), so a missing `.pub` does not make this lie.
fn server_public_key_on_disk() -> String {
    server_public_key_on_disk_at(server_key_file())
}

/// Path-explicit so it is testable without mutating the process-wide cwd, which other
/// tests in this binary run against in parallel.
fn server_public_key_on_disk_at(sk_file: &str) -> String {
    if let Ok(pk) = std::fs::read_to_string(format!("{sk_file}.pub")) {
        let pk = pk.trim().to_owned();
        if !pk.is_empty() {
            return pk;
        }
    }
    std::fs::read_to_string(sk_file)
        .ok()
        .and_then(|sk| base64::decode(sk.trim()).ok())
        .filter(|sk| sk.len() == sign::SECRETKEYBYTES)
        .map(|sk| base64::encode(&sk[sign::SECRETKEYBYTES / 2..]))
        .unwrap_or_default()
}

/// A fresh keypair whose base64 public half contains neither `/` nor `:`, because the key
/// travels inside licence names of the form `host=...,key=...` where both are separators.
/// Same filter as common::generate_and_publish_sk; keep them in step.
fn gen_url_safe_keypair() -> (String, sign::SecretKey) {
    for _ in 0..300 {
        let (pk, sk) = sign::gen_keypair();
        let pk_b64 = base64::encode(pk);
        if !pk_b64.contains('/') && !pk_b64.contains(':') {
            return (pk_b64, sk);
        }
    }
    let (pk, sk) = sign::gen_keypair();
    (base64::encode(pk), sk)
}

fn write_private(path: &str, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    let mut f = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?
    };
    #[cfg(not(unix))]
    let mut f = std::fs::File::create(path)?;
    f.write_all(contents)
}

/// Mint a new server identity key and retire the current one.
///
/// This is a deliberate fleet-wide revocation: every client still provisioned with the old
/// key stops being able to complete the rendezvous handshake and stops accepting signed
/// policy. There is no way to push the new key out through the normal channel, because that
/// channel is authenticated BY the key being replaced — so re-provisioning is necessarily
/// out of band (new installer with `key=` in the licence name, or config push via RMM/GPO).
///
/// The old key is **archived, not destroyed** (`id_ed25519.rotated-<epoch>`, 0600). Deleting
/// it would turn an operator misclick into a permanently unrecoverable fleet; retiring it
/// from service is what revokes access, and anyone who can read the archive already has root
/// on the server. Shred the archive separately if the key is believed compromised.
///
/// Write order is chosen so no failure can leave the server with NO key, which would be
/// fatal at next start (gen_sk exits when the file is missing and `--generate-key` is not
/// set): the replacement is written to a temp file first, the old key is moved aside only
/// once that succeeded, and the move is rolled back if publishing the new one then fails.
fn rotate_server_key() -> Result<(String, String), String> {
    rotate_server_key_at(server_key_file())
}

/// Path-explicit, for the same reason as `server_public_key_on_disk_at`.
fn rotate_server_key_at(sk_file: &str) -> Result<(String, String), String> {
    let previous_pub = server_public_key_on_disk_at(sk_file);
    let (new_pub, new_sk) = gen_url_safe_keypair();

    let tmp = format!("{sk_file}.rotating-{}", std::process::id());
    write_private(&tmp, base64::encode(&new_sk).as_bytes())
        .map_err(|e| format!("could not write the replacement key: {e}"))?;

    let stamp = now_epoch_secs();
    let archive = format!("{sk_file}.rotated-{stamp}");
    let had_old = std::path::Path::new(sk_file).exists();
    if had_old {
        if let Err(e) = std::fs::rename(sk_file, &archive) {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("could not archive the current key to {archive}: {e}"));
        }
    }
    if let Err(e) = std::fs::rename(&tmp, sk_file) {
        // Put the old key back; better the previous state than none at all.
        if had_old {
            let _ = std::fs::rename(&archive, sk_file);
        }
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("could not publish the replacement key: {e}"));
    }
    // The .pub is a convenience copy; a stale one would mislead, so overwrite it. Failure
    // here is not fatal -- server_public_key_on_disk derives the public half from the
    // secret when the .pub is missing or unreadable.
    if let Err(e) = std::fs::write(format!("{sk_file}.pub"), new_pub.as_bytes()) {
        log::warn!("rotated the server key but could not update {sk_file}.pub: {e}");
    }
    if had_old {
        log::warn!(
            "SERVER IDENTITY KEY ROTATED. Old key archived at {archive}. Every client still \
             provisioned with {} is now locked out until it is re-provisioned with {}. \
             Restart hbbs to put the new key into service.",
            if previous_pub.is_empty() { "the previous key" } else { &previous_pub },
            new_pub
        );
    }
    Ok((new_pub, if had_old { archive } else { String::new() }))
}

// ---- Direct endpoints: where a workstation is reachable without the relay ----
//
// The relay costs ~36% of the link (measured: 7.1 of 11.1 Mbit/s on the lab WAN path),
// so a workstation behind a port forward should be dialled directly. This map holds
// "host:port[,knockport]" per peer id and is pushed to controllers inside the signed
// policy as `nemo-direct-endpoints`.
//
// Operator-supplied, NEVER self-reported: a peer that could nominate its own endpoint
// could point controllers at an address it does not own. Nothing in the poll path writes
// here -- only the authenticated dashboard route does.
static PEER_ENDPOINTS: Lazy<std::sync::RwLock<HashMap<String, String>>> =
    Lazy::new(|| std::sync::RwLock::new(load_peer_endpoints()));

// "some.very.long.hostname:65535,65535" with room to spare. Bounds what one entry can
// contribute to the policy string every client downloads.
const MAX_ENDPOINT_LEN: usize = 128;

fn peer_endpoints_path() -> String {
    get_arg_or(
        "nemo-peer-endpoints-file",
        "nemo_peer_endpoints.json".to_owned(),
    )
}

fn load_peer_endpoints() -> HashMap<String, String> {
    std::fs::read_to_string(peer_endpoints_path())
        .ok()
        .and_then(|s| serde_json::from_str::<HashMap<String, String>>(&s).ok())
        .map(|map| {
            // Re-validate on load: a hand-edited file must not be able to inject a
            // separator and smuggle extra entries into every client's policy.
            map.into_iter()
                .filter_map(|(id, ep)| normalize_direct_endpoint(&ep).map(|ep| (id, ep)))
                .collect()
        })
        .unwrap_or_default()
}

/// Validate and normalize `host:port[,knockport]`, the exact shape
/// `nemo_direct::parse_endpoints` reads on the client.
///
/// The client parser is deliberately lenient — one bad row there must not cost the fleet
/// its other endpoints — which means a typo would be silently dropped and the operator
/// would see "it still relays" with no explanation. So validation lives here, at the one
/// place a human types the value, and a rejected endpoint is an API error.
fn normalize_direct_endpoint(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > MAX_ENDPOINT_LEN {
        return None;
    }
    // `;` separates entries and `,` separates fields in the pushed map, so a value
    // containing either could forge additional entries. Whitespace inside would break
    // the version-string style parsing the client does on it.
    if raw.contains(';') || raw.chars().any(char::is_whitespace) {
        return None;
    }
    let mut fields = raw.split(',');
    let addr = fields.next()?;
    let knock_port = match fields.next() {
        Some(p) => Some(p.parse::<u16>().ok().filter(|p| *p > 0)?),
        None => None,
    };
    if fields.next().is_some() {
        return None; // more than host:port,knockport
    }
    // rsplit so a bracketed IPv6 literal survives: "[2001:db8::1]:21118".
    let (host, port) = addr.rsplit_once(':')?;
    let port = port.parse::<u16>().ok().filter(|p| *p > 0)?;
    if host.is_empty() {
        return None;
    }
    Some(match knock_port {
        Some(kp) => format!("{host}:{port},{kp}"),
        None => format!("{host}:{port}"),
    })
}

fn save_peer_endpoints(snapshot: &HashMap<String, String>) {
    match serde_json::to_string_pretty(snapshot) {
        Ok(json) => {
            let path = peer_endpoints_path();
            if let Err(e) = std::fs::write(&path, json) {
                log::error!("failed to persist peer endpoints to {}: {}", path, e);
            }
        }
        Err(e) => log::error!("failed to serialize peer endpoints: {}", e),
    }
}

/// Set (`Some`) or clear (`None`) one peer's direct endpoint. `Err` carries the reason a
/// value was rejected, so the dashboard can show it instead of accepting a dead entry.
fn set_peer_endpoint(id: &str, endpoint: Option<&str>) -> Result<String, String> {
    let id = id.trim();
    if id.is_empty() {
        return Err("peer id is required".to_owned());
    }
    let normalized = match endpoint.map(str::trim).filter(|e| !e.is_empty()) {
        Some(raw) => Some(normalize_direct_endpoint(raw).ok_or_else(|| {
            format!(
                "'{raw}' is not a valid direct endpoint: expected host:port, optionally \
                 followed by ,knockport (e.g. 203.0.113.5:21118 or 203.0.113.5:21118,62201)"
            )
        })?),
        None => None,
    };
    let snapshot = {
        let mut map = PEER_ENDPOINTS.write().unwrap();
        match &normalized {
            Some(ep) => {
                evict_one_if_full(&mut map, id);
                map.insert(id.to_owned(), ep.clone());
            }
            None => {
                map.remove(id);
            }
        }
        map.clone()
    };
    save_peer_endpoints(&snapshot);
    Ok(normalized.unwrap_or_default())
}

fn peer_endpoint(id: &str) -> String {
    PEER_ENDPOINTS
        .read()
        .unwrap()
        .get(id)
        .cloned()
        .unwrap_or_default()
}

/// Build the `nemo-direct-endpoints` value for ONE controller.
///
/// Filtered, unlike `nemo-peer-keys`: a public key is harmless to hand out, but "here is
/// a WAN address with a remote-desktop port behind it" is reconnaissance, so a client
/// only learns the endpoints its own outbound-targets policy already lets it dial.
///
/// Blocked peers are withheld outright. A controller holding a blocked peer's endpoint
/// would dial it directly, and the punch gate that enforces the block is not in that
/// path — the controlled side still refuses via `nemo-blocked-ids`, but withholding the
/// address keeps the block from depending on a single client-side check.
///
/// Sorted by id so the value is byte-identical between polls; an unstable string would
/// make every client rewrite its stored policy every 30 seconds.
fn direct_endpoint_map(blocked: &[String], targets: Option<&String>) -> String {
    let endpoints = PEER_ENDPOINTS.read().unwrap().clone();
    if endpoints.is_empty() {
        return String::new();
    }
    let blocked: HashSet<&str> = blocked.iter().map(String::as_str).collect();
    let mut rows: Vec<String> = endpoints
        .into_iter()
        .filter(|(id, _)| !blocked.contains(id.as_str()))
        .filter(|(id, _)| target_allowed_by_controller_policy(targets, id))
        .map(|(id, endpoint)| format!("{id},{endpoint}"))
        .collect();
    rows.sort();
    rows.join(";")
}

// ---- Per-peer SPA knock keys ------------------------------------------------
//
// PEER_KNOCK_KEYS holds `id -> (rijndael_b64, hmac_b64)`, operator-set exactly like
// PEER_ENDPOINTS (never self-reported — a peer that could set its own knock key could
// make the edge open for traffic it should gate). knock_key_map assembles the
// `nemo-knock-keys` value for ONE controller, filtered by the same blocked + outbound-
// targets ACL as the endpoint map, so a controller only ever receives the keys for the
// workstations it is allowed to dial. That filtering is what makes a leaked key useless
// beyond its own machine. The value is a secret, pushed only inside the sealed policy.

// base64 of a 128-byte key is ~172 chars; leave headroom but keep one row bounded.
const MAX_KNOCK_KEY_B64_LEN: usize = 256;
// Matches the client's MAX_SPA_KEY_LEN: fwknop refuses keys longer than this.
const MAX_SPA_KEY_LEN: usize = 128;

static PEER_KNOCK_KEYS: Lazy<std::sync::RwLock<HashMap<String, (String, String)>>> =
    Lazy::new(|| std::sync::RwLock::new(load_peer_knock_keys()));

fn peer_knock_keys_path() -> String {
    get_arg_or(
        "nemo-peer-knock-keys-file",
        "nemo_peer_knock_keys.json".to_owned(),
    )
}

fn load_peer_knock_keys() -> HashMap<String, (String, String)> {
    std::fs::read_to_string(peer_knock_keys_path())
        .ok()
        .and_then(|s| serde_json::from_str::<HashMap<String, (String, String)>>(&s).ok())
        .map(|map| {
            // Re-validate on load: a hand-edited file must not be able to inject a
            // separator and smuggle extra rows into every controller's sealed policy.
            map.into_iter()
                .filter_map(|(id, (k, h))| normalize_knock_key_pair(&k, &h).map(|p| (id, p)))
                .collect()
        })
        .unwrap_or_default()
}

/// Validate one base64 SPA key: non-empty, no separator/whitespace (which could forge
/// extra rows or fields), decodes as base64 to 1..=MAX_SPA_KEY_LEN bytes. Returns the
/// trimmed base64, unchanged — the client decodes it with the same rules.
fn normalize_knock_key(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > MAX_KNOCK_KEY_B64_LEN {
        return None;
    }
    if raw.contains(';') || raw.contains(',') || raw.chars().any(char::is_whitespace) {
        return None;
    }
    let decoded = base64::decode(raw).ok()?;
    if decoded.is_empty() || decoded.len() > MAX_SPA_KEY_LEN {
        return None;
    }
    Some(raw.to_owned())
}

fn normalize_knock_key_pair(rijndael: &str, hmac: &str) -> Option<(String, String)> {
    Some((normalize_knock_key(rijndael)?, normalize_knock_key(hmac)?))
}

fn save_peer_knock_keys(snapshot: &HashMap<String, (String, String)>) {
    match serde_json::to_string_pretty(snapshot) {
        Ok(json) => {
            let path = peer_knock_keys_path();
            // The file holds shared secrets; keep it owner-only like the server key.
            if let Err(e) = write_private(&path, json.as_bytes()) {
                log::error!("failed to persist peer knock keys to {}: {}", path, e);
            }
        }
        Err(e) => log::error!("failed to serialize peer knock keys: {}", e),
    }
}

/// Set (`Some`) or clear (`None`) one peer's per-peer SPA key pair. `Err` carries the
/// reason a value was rejected, so the dashboard can show it instead of storing a key the
/// client would silently drop (leaving the peer on the fleet-wide key with no symptom).
fn set_peer_knock_key(id: &str, pair: Option<(&str, &str)>) -> Result<bool, String> {
    let id = id.trim();
    if id.is_empty() {
        return Err("peer id is required".to_owned());
    }
    let normalized = match pair {
        Some((k, h)) if !k.trim().is_empty() || !h.trim().is_empty() => {
            Some(normalize_knock_key_pair(k, h).ok_or_else(|| {
                "both the Rijndael and HMAC keys must be base64 of 1..=128 bytes with no \
                 comma, semicolon or whitespace"
                    .to_owned()
            })?)
        }
        _ => None,
    };
    let snapshot = {
        let mut map = PEER_KNOCK_KEYS.write().unwrap();
        match &normalized {
            Some(pair) => {
                if map.len() >= MAX_PEER_LABELS && !map.contains_key(id) {
                    if let Some(victim) = map.keys().next().cloned() {
                        map.remove(&victim);
                    }
                }
                map.insert(id.to_owned(), pair.clone());
            }
            None => {
                map.remove(id);
            }
        }
        map.clone()
    };
    save_peer_knock_keys(&snapshot);
    Ok(normalized.is_some())
}

/// Build the `nemo-knock-keys` value for ONE controller.
///
/// Filtered exactly like `direct_endpoint_map`: blocked peers withheld, and a key handed
/// over only for targets this controller's own outbound policy already lets it dial. That
/// is the whole security property — pc2's controller never receives pc7's key, so a key
/// lifted off pc2 can open only pc2's forwarded port. Sorted by id for a byte-stable
/// value (an unstable string would rewrite every client's sealed policy each poll).
fn knock_key_map(blocked: &[String], targets: Option<&String>) -> String {
    let keys = PEER_KNOCK_KEYS.read().unwrap().clone();
    if keys.is_empty() {
        return String::new();
    }
    let blocked: HashSet<&str> = blocked.iter().map(String::as_str).collect();
    let mut rows: Vec<String> = keys
        .into_iter()
        .filter(|(id, _)| !blocked.contains(id.as_str()))
        .filter(|(id, _)| target_allowed_by_controller_policy(targets, id))
        .map(|(id, (k, h))| format!("{id},{k},{h}"))
        .collect();
    rows.sort();
    rows.join(";")
}

fn peer_has_knock_key(id: &str) -> bool {
    PEER_KNOCK_KEYS.read().unwrap().contains_key(id)
}

pub(crate) fn init_from_args() {
    // CLI default first, then a persisted dashboard toggle wins if present.
    COMPANY_ONLY.store(is_truthy(&get_arg("nemo-company-only")), Ordering::SeqCst);
    if let Some(persisted) = load_persisted_company_only() {
        COMPANY_ONLY.store(persisted, Ordering::SeqCst);
    }
    if let Some(limit) = load_persisted_conn_history_limit() {
        CONN_HISTORY_LIMIT.store(limit, Ordering::SeqCst);
    }
    if let Some(limit) = load_persisted_log_history_limit() {
        LOG_HISTORY_LIMIT.store(limit, Ordering::SeqCst);
    }
    log::info!(
        "Nemo company-only policy: {}; connection history size: {}",
        if company_only() { "enabled" } else { "disabled" },
        conn_history_limit(),
    );
    // TASK #14: unbound device keys authenticate nothing unless the escape hatch is on;
    // say at boot how many pinned keys that affects instead of going dark silently.
    let unbound = integration::unclaimed_device_key_count();
    if integration::allow_unbound_device_keys() {
        log::warn!(
            "allow-unbound-device-keys=Y: every pinned device key with no peer-id binding \
             authenticates ANY peer id, a fleet-wide skeleton key ({} such key(s) right \
             now). Bind or replace them, then drop the flag.",
            unbound
        );
    } else if unbound > 0 && integration::claim_unbound_device_keys() {
        // M1-CLAIM: unbound is now the NORMAL provisioning state, not a misconfiguration:
        // each such key is a one-shot token waiting for the first client that proves it,
        // and that client is refused until the operator confirms the pairing. So say what
        // is waiting on whom instead of advising the skeleton-key flag.
        log::warn!(
            "{} pinned device key(s) have no peer-id binding: each is a one-shot \
             provisioning token. The first client that proves one files a claim and stays \
             REFUSED until you approve it in the admin dashboard ({} claim(s) waiting now).",
            unbound,
            integration::pending_device_key_claim_count()
        );
    } else if unbound > 0 {
        log::warn!(
            "{} pinned device key(s) have no peer-id binding and will NOT authenticate, \
             because first-use claiming is switched off. Bind each to its peer id in the \
             admin dashboard, or switch claiming back on there.",
            unbound
        );
    }
}

pub(crate) async fn spawn_hbbs_api(
    pm: PeerMap,
    server_public_key: String,
    server_secret_key: Option<sign::SecretKey>,
) -> ResultType<()> {
    if !is_truthy(&get_arg_or("nemo-api", "N".to_owned())) {
        return Ok(());
    }

    let bind = get_arg_or("nemo-api-bind", "127.0.0.1:21120".to_owned());
    let addr: SocketAddr = bind.parse()?;
    let token = match get_arg("nemo-api-token") {
        token if token.is_empty() => None,
        token => Some(token),
    };
    if token.is_none() && !addr.ip().is_loopback() {
        bail!(
            "Refusing to bind Nemo management API to {} without --nemo-api-token",
            addr
        );
    }
    // L-fix: the admin API must never run tokenless (require_auth fails closed).
    // With no configured token, generate an ephemeral one and print it so the
    // local-dev dashboard workflow still works — copy it from the log.
    let token = Some(token.unwrap_or_else(|| {
        let generated = base64::encode(sodiumoxide::randombytes::randombytes(24));
        log::warn!(
            "--nemo-api-token not set; generated an ephemeral admin API token for this run: {}",
            generated
        );
        generated
    }));

    let (login_enc_pk, login_enc_sk) = box_::gen_keypair();
    if let Some(t) = token.as_ref() {
        let _ = ADMIN_TOKEN.set(t.clone());
    }
    let state = HbbsApiState {
        pm,
        token,
        server_public_key,
        server_secret_key,
        login_enc_pk,
        login_enc_sk,
    };
    // SPLIT-PORT: the routes CLIENTS call, as their own router, so they can also be
    // served on a second bind that carries nothing else.
    //
    // Why this exists: the policy poll, the login and the address book share a listener
    // with the dashboard and every /nemo/api admin route. An operator who restricts the
    // admin port to their own address — the right instinct, since that port is a
    // complete map of the management surface — also cuts off every REMOTE client's
    // poll, login and device-key claim, with no way to allow one without the other.
    // Two binds let the firewall tell them apart.
    //
    // Authentication does not change and does not depend on which bind a request
    // arrives on: these routes authenticate the CLIENT (device-key signature, or the
    // login credential), never the admin token, so exposing this set is not exposing
    // the admin API.
    let client_routes = || {
        Router::new()
            // The client's first call: "is this TLS certificate yours?" (it pins the
            // fingerprint from the setup bundle). Unauthenticated by necessity — it is
            // what bootstraps trust — and it reveals only the cert the TLS handshake
            // already presented.
            .route(
                "/api/tls-cert-info",
                get(api_tls_cert_info).post(api_tls_cert_info),
            )
            .route("/api/login-key", get(api_login_key).post(api_login_key))
            .route("/api/login", post(api_login))
            .route("/api/logout", post(api_logout))
            .route("/api/currentUser", post(api_current_user))
            .route("/api/ab/get", post(api_ab_get))
            .route("/nemo/api/client/policy", post(client_policy))
            .route("/nemo/api/client/audit/:kind", post(client_audit))
            // Clients poll this for the update manifest; publishing one is an admin
            // route (POST /nemo/api/update) and is deliberately NOT here.
            .route("/nemo/api/update/latest", get(get_update_latest))
            // The published installer itself. Same unauthenticated audience as the
            // manifest; streamed from disk (HEAD and Content-Length included, no path
            // traversal) so many clients updating at once do not each hold a copy of
            // it in memory.
            .nest(
                UPDATE_FILE_ROUTE,
                axum::routing::get_service(tower_http::services::ServeDir::new(update_files_dir()))
                    .handle_error(|e: std::io::Error| async move {
                        (StatusCode::INTERNAL_SERVER_ERROR, format!("cannot read the installer: {e}"))
                    }),
            )
    };

    let app = Router::new()
        .merge(client_routes())
        // TASK-18: the dashboard HTML is a complete map of the management surface
        // -- every /nemo/api route, every pushed policy key, the LDAP and device-key
        // workflows, the running build id -- and the shipped systemd unit binds
        // 0.0.0.0:21120, so it must not be served to a tokenless caller. A browser
        // navigation cannot carry an Authorization header, so the three navigable
        // paths serve a structureless login shell and the shell XHRs the real page
        // from /nemo/admin/app WITH the header. One credential, one predicate
        // (require_auth), no cookie and therefore no CSRF surface.
        .route("/nemo", get(admin_shell))
        .route("/nemo/admin", get(admin_shell))
        .route("/nemo/admin/", get(admin_shell))
        .route("/nemo/admin/app", get(admin_gui))
        .route("/nemo/api/health", get(health))
        .route("/nemo/api/peers", get(list_peers))
        .route("/nemo/api/peers/delete", post(delete_peers))
        .route("/nemo/api/peers/:id", get(get_peer))
        .route("/nemo/api/peers/:id/delete", post(delete_peer))
        .route("/nemo/api/peers/:id/block", post(block_peer))
        .route("/nemo/api/peers/:id/allow", post(allow_peer))
        .route("/nemo/api/peers/:id/reset-policy", post(reset_peer_policy))
        // Where this workstation is reachable without the relay (a port forward the
        // operator configured on its site's routers).
        .route(
            "/nemo/api/peers/:id/direct-endpoint",
            post(set_peer_direct_endpoint),
        )
        .route(
            "/nemo/api/peers/:id/knock-key",
            post(set_peer_knock_key_route),
        )
        .route(
            "/nemo/api/peers/:id/management-policy",
            get(get_peer_management_policy).put(update_peer_management_policy),
        )
        .route("/nemo/api/policy", get(get_policy).put(update_policy))
        // Break-glass: mint a new server identity key and retire the current one. Locks out
        // every client still carrying the old key, so it needs an explicit confirmation in
        // the body on top of the dashboard's dialog.
        .route("/nemo/api/server-key/rotate", post(rotate_server_key_route))
        .route("/nemo/api/stats", get(get_stats))
        .route("/nemo/api/events", get(get_events))
        // Nemo integration: LDAP config + per-user RBAC (admin dashboard).
        .route(
            "/nemo/api/integration/ldap",
            get(get_ldap_config).put(put_ldap_config),
        )
        .route("/nemo/api/integration/ldap/test", post(test_ldap_login))
        .route("/nemo/api/integration/ldap/fetch-cert", post(fetch_ldap_cert))
        .route("/nemo/api/integration/ldap/users", post(list_ldap_users))
        .route("/nemo/api/integration/ldap/users/set", post(set_ldap_user))
        .route(
            "/nemo/api/integration/permissions",
            get(get_permissions).put(put_permissions),
        )
        .route(
            "/nemo/api/device-keys",
            get(list_device_keys).post(generate_device_key),
        )
        .route("/nemo/api/device-keys/:id/delete", post(delete_device_key))
        // The first-run settings bundle: GET for the defaults + a key-less string, POST
        // to apply the operator's edits.
        .route(
            "/nemo/api/client-setup",
            get(get_client_setup).post(post_client_setup),
        )
        // M1-CLAIM: the pending-claim queue and the editable "Bound to ID" field.
        .route("/nemo/api/device-key-claims", get(list_device_key_claims))
        .route(
            "/nemo/api/device-keys/:id/claim/approve",
            post(approve_device_key_claim),
        )
        .route(
            "/nemo/api/device-keys/:id/claim/deny",
            post(deny_device_key_claim),
        )
        .route(
            "/nemo/api/device-keys/:id/claim/forget",
            post(forget_device_key_claim),
        )
        .route("/nemo/api/device-keys/:id/peer-id", post(set_device_key_peer_id))
        .route(
            "/nemo/api/policies",
            get(get_policies).put(put_policies),
        )
        .route("/nemo/api/policies/device", post(set_device_policy_route))
        .route(
            "/nemo/api/global-policy",
            get(get_global_policy).put(put_global_policy),
        )
        .route("/nemo/api/connections", get(get_connections))
        .route("/nemo/api/connections/cut", post(cut_connection))
        .route("/nemo/api/update", post(put_update_manifest))
        .route("/nemo/api/update/delete", post(delete_update_manifest))
        .route(UPDATE_UPLOAD_ROUTE, post(upload_update_installer))
        .layer(axum::middleware::from_fn(bump_epoch_on_authz_change))
        .layer(Extension(state.clone()))
        // SEC-9: applied last so it wraps every route above, including the
        // unauthenticated ones, and runs before any extractor reads the body.
        .layer(axum::middleware::from_fn(limit_request_body));

    // Nemo security: LDAP login credentials and managed secrets must never cross
    // the network in cleartext. Decide the transport, and refuse to serve this API
    // over plaintext HTTP on a routable address.
    let ldap_enabled = crate::nemo_integration::ldap_config().enabled;
    let cert_path = get_arg("nemo-api-tls-cert");
    let key_path = get_arg("nemo-api-tls-key");
    let tls_mode = get_arg("nemo-api-tls"); // "auto" | "off" | "" (auto-decide)
    let explicit_cert = !cert_path.is_empty() && !key_path.is_empty();
    let allow_insecure = is_truthy(&get_arg("nemo-api-allow-insecure"));
    let routable = !addr.ip().is_loopback();
    let use_tls = if tls_mode == "off" {
        false
    } else if explicit_cert || tls_mode == "auto" {
        true
    } else if allow_insecure {
        // The operator has explicitly accepted plaintext on this bind, so do not
        // then turn TLS on behind their back.
        false
    } else {
        // SEC-12: the old default was `ldap_enabled`, which asked the wrong question.
        // LDAP credentials are not the only secret on this socket -- the admin bearer
        // token, every managed policy and the whole dashboard cross it too, and a
        // stolen token can flip require_device_key for the entire fleet. So the
        // trigger is the BIND, not the feature: anything routable gets TLS.
        routable || ldap_enabled
    };
    API_TLS_ACTIVE.store(use_tls, Ordering::SeqCst);
    API_BIND_LOOPBACK.store(addr.ip().is_loopback(), Ordering::SeqCst);
    API_ALLOW_INSECURE.store(allow_insecure, Ordering::SeqCst);
    if !use_tls && routable && !allow_insecure {
        bail!(
            "Refusing to serve the Nemo management API over plaintext HTTP on {}. The admin \
             bearer token{} would cross the network in the clear. Enable TLS (--nemo-api-tls \
             auto, or --nemo-api-tls-cert/--nemo-api-tls-key), bind to loopback and use an SSH \
             tunnel, or set --nemo-api-allow-insecure Y to override.",
            addr,
            if ldap_enabled { " and every LDAP login" } else { "" },
        );
    }
    if !use_tls && routable {
        log::warn!(
            "Nemo management API is serving PLAINTEXT HTTP on the routable address {} \
             (--nemo-api-allow-insecure). The admin bearer token{} is exposed to anyone on \
             the path unless a tunnel protects this bind.",
            addr,
            if ldap_enabled { ", every LDAP login and every managed secret" } else { " and every managed secret" },
        );
    }
    if use_tls && routable && !explicit_cert && tls_mode.is_empty() && !ldap_enabled {
        // Upgrade note: this bind used to default to plaintext. Say so plainly, or an
        // operator whose clients are configured with http:// sees only silence.
        log::warn!(
            "Nemo management API now defaults to TLS on a routable bind ({}). Clients and \
             the dashboard must use https:// -- update any api= URL that still says http://, \
             or pass --nemo-api-tls off --nemo-api-allow-insecure Y to keep plaintext.",
            addr
        );
    }

    // TODO 7: the relayed-byte poller runs with the dashboard, because the dashboard is
    // the only consumer of what it collects. Before the TLS branch below, which returns.
    spawn_relay_usage_poller();

    // SPLIT-PORT: an optional second listener carrying ONLY the client routes, so the
    // admin bind can be firewalled to the operator's own address without cutting off
    // remote clients. Unset (the default) changes nothing: everything stays on one
    // bind, exactly as before.
    //
    // It shares this listener's TLS decision and certificate on purpose: clients pin
    // the fingerprint from their setup bundle, so a second cert would mean a second
    // fingerprint and a bootstrap that fails on the first call it makes
    // (/api/tls-cert-info).
    let client_bind = get_arg("nemo-client-api-bind");
    if !client_bind.is_empty() {
        let client_addr: SocketAddr = client_bind.parse().map_err(|e| {
            hbb_common::anyhow::anyhow!("--nemo-client-api-bind {}: {}", client_bind, e)
        })?;
        if client_addr == addr {
            bail!(
                "--nemo-client-api-bind {} is the same address as --nemo-api-bind; use a \
                 different port, or drop the flag to serve everything on one bind",
                client_addr
            );
        }
        let client_app = client_routes()
            .layer(Extension(state))
            .layer(axum::middleware::from_fn(limit_request_body));
        // No admin token crosses this bind and no admin route is mounted on it, so the
        // plaintext refusal above (which exists to protect that token) does not apply
        // here. Client traffic still carries sealed secrets, so it follows the same TLS
        // decision rather than getting its own weaker one.
        if use_tls {
            #[cfg(feature = "nemo-tls")]
            {
                let config = resolve_rustls(&cert_path, &key_path).await?;
                log::info!(
                    "Nemo CLIENT API listening on https://{} (policy poll, login, address \
                     book, audit, update manifest). The admin API and dashboard are on {} \
                     only.",
                    client_addr,
                    addr
                );
                tokio::spawn(async move {
                    if let Err(err) = axum_server::bind_rustls(client_addr, config)
                        .serve(client_app.into_make_service_with_connect_info::<SocketAddr>())
                        .await
                    {
                        log::error!("Nemo client API (TLS) failed: {}", err);
                    }
                });
            }
            #[cfg(not(feature = "nemo-tls"))]
            {
                bail!(
                    "TLS was requested for the Nemo client API but this build lacks the \
                     nemo-tls feature"
                );
            }
        } else {
            log::info!("Nemo CLIENT API listening on http://{}", client_addr);
            tokio::spawn(async move {
                if let Err(err) = axum::Server::bind(&client_addr)
                    .serve(client_app.into_make_service_with_connect_info::<SocketAddr>())
                    .await
                {
                    log::error!("Nemo client API failed: {}", err);
                }
            });
        }
    }

    if use_tls {
        #[cfg(feature = "nemo-tls")]
        {
            let config = resolve_rustls(&cert_path, &key_path).await?;
            log::info!("Nemo management API listening on https://{}", addr);
            tokio::spawn(async move {
                if let Err(err) = axum_server::bind_rustls(addr, config)
                    .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                    .await
                {
                    log::error!("Nemo management API (TLS) failed: {}", err);
                }
            });
            return Ok(());
        }
        #[cfg(not(feature = "nemo-tls"))]
        {
            bail!("TLS was requested for the Nemo API but this build lacks the nemo-tls feature");
        }
    }

    log::info!("Nemo management API listening on http://{}", addr);
    tokio::spawn(async move {
        if let Err(err) = axum::Server::bind(&addr)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
        {
            log::error!("Nemo management API failed: {}", err);
        }
    });
    Ok(())
}

/// Resolve a rustls TLS config for the Nemo API: use the admin-provided PEM
/// files when both are set, otherwise generate (and persist) a self-signed
/// certificate. The RustDesk client accepts the self-signed certificate on
/// first use (it falls back to accepting invalid certs and caches the choice).
#[cfg(feature = "nemo-tls")]
async fn resolve_rustls(
    cert_path: &str,
    key_path: &str,
) -> ResultType<axum_server::tls_rustls::RustlsConfig> {
    use axum_server::tls_rustls::RustlsConfig;
    if !cert_path.is_empty() && !key_path.is_empty() {
        if let Ok(pem) = std::fs::read_to_string(cert_path) {
            set_api_cert_info(&pem, true);
        }
        return Ok(RustlsConfig::from_pem_file(cert_path, key_path).await?);
    }
    let cert_file = get_arg_or("nemo-api-cert-file", "nemo-api-cert.pem".to_owned());
    let key_file = get_arg_or("nemo-api-key-file", "nemo-api-key.pem".to_owned());
    if !(std::path::Path::new(&cert_file).exists() && std::path::Path::new(&key_file).exists()) {
        let mut sans = vec!["localhost".to_owned()];
        let host = whoami::hostname();
        if !host.is_empty() && !sans.contains(&host) {
            sans.push(host);
        }
        let cert = rcgen::generate_simple_self_signed(sans)?;
        std::fs::write(&cert_file, cert.serialize_pem()?)?;
        std::fs::write(&key_file, cert.serialize_private_key_pem())?;
        log::info!(
            "Nemo API generated a self-signed TLS certificate at {} (supply \
             --nemo-api-tls-cert/--nemo-api-tls-key for a CA-signed certificate).",
            cert_file
        );
    }
    // The private key is the sole secret protecting the login TLS channel;
    // restrict it to the server user (0600) so other local accounts cannot read
    // it and impersonate/MITM the API. Applied on every start (not only when the
    // key is first generated) so a previously world-readable key gets fixed.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) =
            std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600))
        {
            log::warn!("could not restrict permissions on {}: {}", key_file, e);
        }
    }
    if let Ok(pem) = std::fs::read_to_string(&cert_file) {
        set_api_cert_info(&pem, false);
    }
    Ok(RustlsConfig::from_pem_file(&cert_file, &key_file).await?)
}

// Client-facing: what certificate is the login screen looking at, and why might
// the OS distrust it. Read over the same TLS, so it is a diagnostic — not proof
// (the credential is protected by the signed sealed login, not by this).
async fn api_tls_cert_info() -> Json<TlsCertInfo> {
    let info = API_CERT_INFO.read().unwrap().clone();
    Json(info.unwrap_or(TlsCertInfo {
        tls: API_TLS_ACTIVE.load(Ordering::SeqCst),
        mode: "off".to_owned(),
        ..Default::default()
    }))
}

// TASK-18. The login shell: the only thing an unauthenticated caller is served.
// It carries no route names, no policy keys, no LDAP fields and no build id --
// just a token box and the one URL it fetches.
//
// 401, not 200, for three reasons: the shell's own XHR then tells "not signed in"
// from "here is the dashboard" by status alone, with no content sniffing; a
// scanner is told the truth; and a browser renders the body of a 401 regardless,
// so a plain navigation still shows the sign-in card. WWW-Authenticate names the
// scheme for tools without triggering a browser dialog (browsers have no native
// Bearer UI -- Basic would pop one and fight our own page).
async fn admin_shell() -> impl axum::response::IntoResponse {
    (
        StatusCode::UNAUTHORIZED,
        [
            (axum::http::header::CACHE_CONTROL, "no-store"),
            (
                axum::http::header::WWW_AUTHENTICATE,
                "Bearer realm=\"TBFDesk admin\"",
            ),
        ],
        Html(include_str!("nemo_admin_shell.html")),
    )
}

// TASK-18. The dashboard itself, admin-token only. This used to be reachable at
// /nemo, /nemo/admin and /nemo/admin/ with no credential at all, which handed an
// attacker on the 0.0.0.0 bind the whole management map and the build id for free.
async fn admin_gui(
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
) -> Result<impl axum::response::IntoResponse, ApiFailure> {
    require_auth(&headers, &state.token)?;
    // Stamp the running build id into the page so the header can show the GUI's own
    // build and detect a browser-cached (stale) page vs the live server build.
    // no-store: this body is credentialed, so no shared cache may keep a copy and
    // then hand it to the next, tokenless, caller -- which matters on the
    // --nemo-api-allow-insecure plaintext bind.
    Ok((
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Html(include_str!("nemo_admin.html").replace("{{NEMO_BUILD_ID}}", nemo_build_id())),
    ))
}

// --------------------------------------------------------------------------
// Nemo integration: LDAP login, server-driven address book, and per-user RBAC.
// The `/api/login`, `/api/ab/get`, `/api/logout` routes deliberately live at the
// root so the RustDesk Sciter client's `api-server` (pointed at this nemo-api)
// finds them; the `/nemo/api/integration/*` routes are the admin dashboard's.
// --------------------------------------------------------------------------

use crate::nemo_integration as integration;

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

fn peer_alias(peer: &RegisteredPeer) -> String {
    management_policy_from_peer(&peer.management_policy)
        .options
        .get("nemo-alias")
        .cloned()
        .unwrap_or_default()
}

fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

// ---- Login / address book (RustDesk-client-compatible) ----

#[derive(Deserialize)]
struct LoginRequest {
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    /// S-B: optional sealed credential — base64 of a NaCl sealedbox of
    /// `{"username","password","ts"}` to the server's login-encryption key
    /// (from /api/login-key). When present it supersedes the plaintext fields, so
    /// the domain password is confidential regardless of TLS.
    #[serde(default)]
    sealed: Option<String>,
    /// The TBFDesk ID of the client the user is signing in from (for logging).
    #[serde(default)]
    id: String,
    /// The client's device uuid (for logging / auditing which machine signed in).
    #[serde(default)]
    uuid: String,
}

#[derive(Serialize)]
struct LoginKeyResponse {
    /// base64 of the server's X25519 login-encryption public key (raw; dev use).
    key: String,
    /// base64 of the Ed25519-signed (ATTACHED) key bytes. The client verifies this
    /// with the management public key it already trusts and uses the recovered key,
    /// so the login-encryption key is authenticated. Empty with no signing key.
    signed_key: String,
}

// S-B: sealed login payload the client encrypts to `login_enc_pk`.
#[derive(Deserialize)]
struct SealedLogin {
    username: String,
    password: String,
    #[serde(default)]
    ts: u64,
    /// L-fix (replay): a random client nonce; the server remembers nonces seen
    /// inside the freshness window and rejects duplicates, so a captured sealed
    /// blob cannot be re-POSTed even within the timestamp window. Optional for
    /// older clients (absent = timestamp window only, logged).
    #[serde(default)]
    nonce: String,
    /// S-B (scope b): base64 of an EPHEMERAL X25519 public key the client generated
    /// for this one login. It rides INSIDE the seal, so a MITM can neither read nor
    /// swap it. Present = the session token comes back sealed to it instead of in the
    /// clear; absent (older client) = exactly today's response.
    #[serde(default)]
    reply_pk: String,
    /// Layer 1: the client's device proof for THIS sign-in — base64 Ed25519 public
    /// key and base64 attached signature over "nemo-login:{id}:{ts}" (the client's
    /// nemo_device_sign, the same shape the poll sends as "nemo-poll"). It rides
    /// INSIDE the seal so a MITM can neither read nor strip it. Optional on the wire
    /// so an older sealed client still parses; whether its absence is fatal is
    /// decided by require_device_key in api_login, not here.
    #[serde(default)]
    device_key_pub: String,
    #[serde(default)]
    device_key_sig: String,
}

#[derive(Serialize)]
struct LoginUser {
    name: String,
    display_name: String,
    email: String,
    note: String,
    status: i32,
    is_admin: bool,
}

#[derive(Serialize)]
struct LoginResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    access_token: Option<String>,
    /// S-B (scope b): base64(sealedbox(session token, the client's `reply_pk`)).
    /// Sent INSTEAD OF the cleartext `access_token` when the sealed login carried a
    /// reply key, so a MITM recording the response cannot lift a usable session.
    /// Skipped when absent, so an old client sees an unchanged response shape.
    #[serde(skip_serializing_if = "Option::is_none")]
    sealed_access_token: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<LoginUser>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl LoginResult {
    fn err(message: impl Into<String>) -> Self {
        Self {
            access_token: None,
            sealed_access_token: None,
            kind: None,
            user: None,
            error: Some(message.into()),
        }
    }
}

// S-B: publish the server's login-encryption public key, signed by the server's
// Ed25519 key so the client can verify it against the management public key it
// already trusts before sealing the credential to it.
async fn api_login_key(Extension(state): Extension<HbbsApiState>) -> Json<LoginKeyResponse> {
    let pk_bytes: &[u8] = state.login_enc_pk.as_ref();
    let key = base64::encode(pk_bytes);
    let signed_key = match &state.server_secret_key {
        Some(sk) => base64::encode(sign::sign(pk_bytes, sk)),
        None => String::new(),
    };
    Json(LoginKeyResponse { key, signed_key })
}

// L-fix (replay): nonces seen inside the freshness window. In-memory is enough —
// the sealed-login keypair is per-process too (a restart rotates the key, which
// invalidates every previously captured blob outright).
static SEEN_LOGIN_NONCES: Lazy<std::sync::Mutex<HashMap<String, u64>>> =
    Lazy::new(|| std::sync::Mutex::new(HashMap::new()));

const SEALED_LOGIN_MAX_AGE_SECS: u64 = 300;
const SEALED_LOGIN_MAX_SKEW_SECS: u64 = 60;
// C2: hard cap so an unauthenticated attacker flooding fresh nonces cannot grow the map
// without bound. The retain() below already prunes by time; this bounds memory under a
// burst by evicting the oldest entry when full (the ts window still caps replay).
const MAX_SEEN_NONCES: usize = 100_000;
// Review finding (memory exhaustion): the cap above bounds the NUMBER of entries, not
// their size, and the nonce is an attacker-chosen string that arrives before any peer
// lookup happens. A 1 MB nonce x 100_000 entries is an unauthenticated OOM. Both
// clients emit base64(16 bytes) = 24 chars, so anything longer is not a real client.
const MAX_NONCE_LEN: usize = 64;
// Upper bound on the base64 envelope itself (see resolve_request_body). 16 KiB is far
// above any real request body this fork sends and far below what hurts.
const MAX_SEALED_REQUEST_B64: usize = 16 * 1024;

// Pure replay guard for a sealed login: freshness window on ts (a ts of 0 — the
// old "legacy client" bypass — is now REJECTED) and at-most-once nonces within the
// window. Split out of decode_sealed_login so it is unit-testable.
fn sealed_login_guard(
    ts: u64,
    nonce: &str,
    now: u64,
    seen: &mut HashMap<String, u64>,
) -> Result<(), String> {
    if now.saturating_sub(ts) > SEALED_LOGIN_MAX_AGE_SECS
        || ts.saturating_sub(now) > SEALED_LOGIN_MAX_SKEW_SECS
    {
        return Err("sealed credential expired; please retry".to_owned());
    }
    let nonce = nonce.trim();
    if nonce.len() > MAX_NONCE_LEN {
        // Rejected BEFORE retain()/insert() so an oversized nonce costs neither the
        // allocation nor the O(n) eviction scan.
        return Err("sealed credential nonce is too long".to_owned());
    }
    if nonce.is_empty() {
        // Older client without a nonce: the timestamp window is the only replay
        // bound. Accepted (fleet transition), but visible in the log.
        log::warn!("sealed login without nonce (older client); replayable within the ts window");
        return Ok(());
    }
    // Prune expired entries, then insert-or-reject.
    seen.retain(|_, &mut seen_at| now.saturating_sub(seen_at) <= SEALED_LOGIN_MAX_AGE_SECS);
    if seen.contains_key(nonce) {
        return Err("sealed credential replayed; please retry".to_owned());
    }
    // C2: bound memory under a nonce-flood — evict the oldest when at the cap.
    while seen.len() >= MAX_SEEN_NONCES {
        if let Some(oldest) = seen
            .iter()
            .min_by_key(|(_, &t)| t)
            .map(|(k, _)| k.clone())
        {
            seen.remove(&oldest);
        } else {
            break;
        }
    }
    seen.insert(nonce.to_owned(), now);
    Ok(())
}

// S-B (scope b): nonces seen on sealed REQUEST envelopes. Deliberately a SEPARATE
// cache from SEEN_LOGIN_NONCES: both are bounded by MAX_SEEN_NONCES, so one shared
// map would let a flood of poll nonces evict the login nonces (and vice versa) and
// re-open a replay window on the other endpoint.
static SEEN_REQUEST_NONCES: Lazy<std::sync::Mutex<HashMap<String, u64>>> =
    Lazy::new(|| std::sync::Mutex::new(HashMap::new()));

// S-B (scope b): replay guard for a sealed request envelope. Same freshness window
// and at-most-once rule as a sealed login — sealed_login_guard does that work, here
// against the separate cache above — with one difference: a nonce is MANDATORY. The
// envelope is new wire format and the client always inserts a nonce, so there is no
// older sender to be lenient to, and accepting an empty nonce would leave a captured
// envelope replayable for the whole ts window.
fn sealed_request_guard(
    ts: u64,
    nonce: &str,
    now: u64,
    seen: &mut HashMap<String, u64>,
) -> Result<(), String> {
    if nonce.trim().is_empty() {
        return Err("sealed request envelope without a nonce".to_owned());
    }
    sealed_login_guard(ts, nonce, now, seen)
}

// What a login request resolves to once the seal (if any) is open. A struct rather
// than a growing tuple: Layer 1 makes the device proof the fourth thing api_login
// needs out of it. A plaintext login builds one with an EMPTY proof, so the single
// Layer 1 gate in api_login covers both paths.
struct OpenedLogin {
    username: String,
    password: String,
    reply_pk: Option<box_::PublicKey>,
    /// Both empty when the client sent no device proof (older client / no key).
    device_key_pub: String,
    device_key_sig: String,
}

// S-B: open a sealed login credential to (username, password, reply key, device
// proof). Fails closed on any decode/parse/replay error.
fn decode_sealed_login(state: &HbbsApiState, sealed_b64: &str) -> Result<OpenedLogin, String> {
    let ciphertext =
        base64::decode(sealed_b64.trim()).map_err(|_| "invalid sealed credential".to_owned())?;
    let plain = sealedbox::open(&ciphertext, &state.login_enc_pk, &state.login_enc_sk)
        .map_err(|_| "sealed credential could not be opened (stale login key? re-fetch /api/login-key)".to_owned())?;
    let s: SealedLogin =
        serde_json::from_slice(&plain).map_err(|_| "invalid sealed credential payload".to_owned())?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    sealed_login_guard(s.ts, &s.nonce, now, &mut SEEN_LOGIN_NONCES.lock().unwrap())?;
    // S-B (scope b): the client's ephemeral X25519 reply key, raw (NOT an Ed25519
    // device key, so no to_curve25519_pk here). Present-but-unparseable is a client
    // bug and not an attack — the key is inside the authenticated seal, so nobody can
    // corrupt it in flight — and we fail closed rather than fall back to returning the
    // session token in the clear (the same rule as seal_to_device_key: never send the
    // plaintext you meant to seal).
    let reply_pk = match s.reply_pk.trim() {
        "" => None,
        raw => Some(
            base64::decode(raw)
                .ok()
                .and_then(|b| box_::PublicKey::from_slice(&b))
                .ok_or_else(|| "invalid reply key in sealed credential".to_owned())?,
        ),
    };
    Ok(OpenedLogin {
        username: s.username.trim().to_owned(),
        password: s.password,
        reply_pk,
        device_key_pub: s.device_key_pub.trim().to_owned(),
        device_key_sig: s.device_key_sig.trim().to_owned(),
    })
}

// Layer 1: the login's device proof, checked exactly like the poll's ("nemo-poll")
// and the address book's ("nemo-ab") — pinned key, M1 binding to the claimed id,
// fresh signature — under its own domain so a captured poll signature cannot be
// replayed as a login. `id` is the OUTER request's client id: it is not inside the
// seal, but the signature binds it, so a swapped id simply fails to verify.
fn login_device_key_ok(opened: &OpenedLogin, id: &str) -> bool {
    !opened.device_key_pub.is_empty()
        && !opened.device_key_sig.is_empty()
        && verify_device_signature(
            &opened.device_key_pub,
            &opened.device_key_sig,
            "nemo-login",
            id,
        )
}

// Layer 1: what a user sees when their machine is not provisioned. Names the fix
// (import the key) rather than the mechanism.
const LOGIN_DEVICE_KEY_REQUIRED: &str = "This server only accepts sign-ins from a provisioned computer. Import the device key your administrator issued for this computer (or ask your administrator for one) and sign in again.";

async fn api_login(
    Extension(state): Extension<HbbsApiState>,
    // SEC-10: the source address drives the pre-bind spray limiter. Optional so a
    // build or serve path that cannot supply it degrades to the global tripwire
    // instead of failing every login outright.
    peer: Option<ConnectInfo<SocketAddr>>,
    Json(req): Json<LoginRequest>,
) -> Json<LoginResult> {
    let source_ip = peer.map(|ConnectInfo(addr)| addr.ip().to_string());
    let source_ip = source_ip.as_deref();
    // S-B: prefer a sealed credential (confidential regardless of TLS); fall back
    // to plaintext fields for backward compatibility.
    let opened = match &req.sealed {
        Some(sealed) if !sealed.trim().is_empty() => match decode_sealed_login(&state, sealed) {
            Ok(v) => v,
            Err(e) => return Json(LoginResult::err(e)),
        },
        _ => {
            // S-B (scope b): a client still POSTing its password in the clear. ALWAYS
            // logged (never gated) so an operator can grep the fleet for stragglers
            // BEFORE turning require_sealed_login on.
            log::warn!(
                "Nemo login with a CLEARTEXT credential: user='{}' from client id={} uuid={} - update this client before enabling require-sealed-login",
                req.username.trim(),
                if req.id.trim().is_empty() { "?" } else { req.id.trim() },
                if req.uuid.trim().is_empty() { "?" } else { req.uuid.trim() },
            );
            // Default false = today's behaviour exactly; only an operator flip changes it.
            if integration::require_sealed_login() {
                return Json(LoginResult::err(
                    "This server only accepts encrypted logins. This TBFDesk client is too old to encrypt your password - please update it (or ask your administrator to) and sign in again.",
                ));
            }
            // Layer 1: a plaintext login carries NO device proof (the proof rides
            // inside the seal), so it reaches the gate below with an empty one and
            // is refused there whenever require_device_key is on.
            OpenedLogin {
                username: req.username.trim().to_owned(),
                password: req.password.clone(),
                reply_pk: None,
                device_key_pub: String::new(),
                device_key_sig: String::new(),
            }
        }
    };
    // Layer 1 BEFORE Layer 2: the machine proves it is a fleet member before the
    // directory is even consulted, so an unprovisioned machine cannot probe LDAP
    // credentials (and never reaches the failure backoff). ALWAYS logged, like the
    // cleartext line above, so an operator can find the stragglers on a fleet whose
    // stored require_device_key is still false (R3: upgrades keep the stored value).
    let client_id = req.id.trim();
    let device_key_ok = login_device_key_ok(&opened, client_id);
    // TASK #19: the session token is bound to the key that PROVED this login, never
    // to the raw field (with require_device_key off an unverified key must not be
    // baked into the session). Empty = unbound, reachable only through the gate below.
    let proven_device_key = if device_key_ok {
        opened.device_key_pub.clone()
    } else {
        String::new()
    };
    if !device_key_ok {
        log::warn!(
            "Nemo login WITHOUT a valid pinned device key: user='{}' from client id={} uuid={} (proof {}) - provision this machine before enabling require-device-key",
            opened.username,
            if client_id.is_empty() { "?" } else { client_id },
            if req.uuid.trim().is_empty() { "?" } else { req.uuid.trim() },
            if opened.device_key_pub.is_empty() || opened.device_key_sig.is_empty() {
                "missing"
            } else {
                "not valid for a pinned key"
            },
        );
        if integration::require_device_key() {
            return Json(LoginResult::err(LOGIN_DEVICE_KEY_REQUIRED));
        }
    }
    let OpenedLogin {
        username,
        password,
        reply_pk,
        ..
    } = opened;
    if username.is_empty() || password.is_empty() {
        return Json(LoginResult::err("Username and password required"));
    }
    // SEC-10: refuse BEFORE the directory bind. The per-username backoff further
    // down runs only once the DC has already been asked, so on its own it lets a
    // sprayer walk the whole directory and lock accounts out; this is the gate that
    // actually keeps those binds from happening.
    if let Some(reason) = integration::login_spray_block(source_ip) {
        log::warn!(
            "Nemo login refused before the directory bind (spray limiter): user='{}' from {}",
            username,
            source_ip.unwrap_or("?"),
        );
        return Json(LoginResult::err(reason));
    }
    let cfg = integration::ldap_config();
    match integration::authenticate_ldap(&cfg, &username, &password).await {
        Ok(user) => {
            integration::clear_login_failures(&user.username);
            // Update the profile/last-login of an ALREADY-allowlisted user. A user
            // the admin has not added via the directory picker is NOT auto-created
            // (the allowlist stays exactly the set the admin selected), so an
            // unknown account comes back not-enabled and is refused below.
            let (_exists, enabled, is_admin) =
                integration::record_login(&user.username, &user.display_name, &user.email);
            // The allowlist gate applies once mandatory login is turned on. Until
            // then login is open (any authenticated directory user), so enabling
            // require-login is what activates the "only these users" allowlist.
            if integration::require_login() && !enabled {
                log::warn!("Nemo login refused (not on allowlist): {}", user.username);
                return Json(LoginResult::err(
                    "Your account is not authorized to use TBFDesk. Contact your administrator.",
                ));
            }
            let token = integration::create_session(
                user.username.clone(),
                user.display_name.clone(),
                user.email.clone(),
                proven_device_key,
            );
            log::info!(
                "Nemo login OK: user='{}' admin={} from client id={} uuid={}",
                user.username,
                is_admin,
                if req.id.trim().is_empty() { "?" } else { req.id.trim() },
                if req.uuid.trim().is_empty() { "?" } else { req.uuid.trim() },
            );
            // S-B (scope b): when the sealed login carried a reply key the session
            // token goes back sealed to it and the cleartext field is OMITTED, so a
            // MITM that records the response cannot lift a valid session. This needs
            // no flag — the client's own request selects the shape, and a client that
            // sent no reply_pk gets exactly today's response.
            let (access_token, sealed_access_token) = match &reply_pk {
                Some(pk) => (
                    None,
                    Some(base64::encode(sealedbox::seal(token.as_bytes(), pk))),
                ),
                None => (Some(token), None),
            };
            Json(LoginResult {
                access_token,
                sealed_access_token,
                kind: Some("access_token".to_owned()),
                user: Some(LoginUser {
                    name: user.username,
                    display_name: user.display_name,
                    email: user.email,
                    note: String::new(),
                    status: 1,
                    is_admin,
                }),
                error: None,
            })
        }
        Err(reason) => {
            log::warn!("Nemo login failed for {}: {}", username, reason);
            // Per-username exponential backoff: slows online brute force / credential
            // stuffing hard, but never hard-locks (a correct password succeeds
            // instantly and clears the counter, so real users are never blocked).
            integration::note_login_spray(source_ip, &username);
            let failures = integration::note_login_failure(&username);
            let delay = integration::login_backoff_ms(failures);
            if delay > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            }
            Json(LoginResult::err(reason))
        }
    }
}

async fn api_logout(headers: HeaderMap) -> Json<serde_json::Value> {
    if let Some(token) = bearer_token(&headers) {
        integration::remove_session(&token);
    }
    Json(serde_json::json!({}))
}

// Session restore on client restart: the Sciter client calls this with its
// stored token; on success it re-populates the account + address book without a
// re-login. `verifier` is checked by the client's `verify_login`, which is a
// no-op for custom clients (always true).
async fn api_current_user(headers: HeaderMap) -> Json<serde_json::Value> {
    let Some(token) = bearer_token(&headers) else {
        return Json(serde_json::json!({ "error": "Invalid token" }));
    };
    let Some(session) = integration::session_for_token(&token) else {
        return Json(serde_json::json!({ "error": "Invalid token" }));
    };
    // R6-9: a user disabled after this token was issued must not still be able to
    // read their own account back. In the normal ACL-save/directory-toggle path the
    // token is already evicted by then (evict_sessions_with_changed_permissions), so
    // this mostly guards the gap between those two events and any future write path
    // that changes `enabled` without going through that eviction.
    if !integration::user_is_enabled(&session.username) {
        return Json(serde_json::json!({ "error": "Invalid token" }));
    }
    let (is_admin, _targets) = integration::effective_permission(&session.username);
    Json(serde_json::json!({
        "name": session.username,
        "display_name": session.display_name,
        "email": session.email,
        "note": "",
        "status": 1,
        "is_admin": is_admin,
        "verifier": "",
    }))
}

#[derive(Serialize)]
struct AbPeer {
    id: String,
    username: String,
    hostname: String,
    platform: String,
    alias: String,
    tags: Vec<String>,
}

#[derive(Serialize)]
struct AbData {
    tags: Vec<String>,
    peers: Vec<AbPeer>,
}

#[derive(Serialize)]
struct AbResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    updated_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<String>,
    /// S-B (P0): base64(NaCl sealedbox(address-book JSON, client device key)).
    /// Present instead of `data` when the requester proved a pinned device key and
    /// asked for a sealed response — the peer list is then ciphertext to a MITM.
    #[serde(skip_serializing_if = "Option::is_none")]
    sealed_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl AbResult {
    fn err(message: impl Into<String>) -> Self {
        Self {
            updated_at: None,
            data: None,
            sealed_data: None,
            error: Some(message.into()),
        }
    }
}

/// Optional body of /api/ab/get. The stock client posts `{}`; a seal-capable
/// client identifies its device and signs "nemo-ab:{id}:{ts}" with its device key
/// (a domain distinct from the policy poll, so signatures are not cross-replayable).
#[derive(Default, Deserialize)]
struct AbGetRequest {
    #[serde(default)]
    sealed: Option<String>,
    #[serde(default)]
    id: String,
    #[serde(default)]
    device_key_pub: String,
    #[serde(default)]
    device_key_sig: String,
}

async fn api_ab_get(
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
    // S-B (scope b): the body is either today's AbGetRequest or a sealed envelope, so
    // it arrives untyped and is deserialized after resolve_request_body has picked
    // (and authenticated) the right one. Still Option<..>: the stock client posts `{}`
    // or no body at all.
    body: Option<Json<serde_json::Value>>,
) -> Json<AbResult> {
    let raw = body.map(|Json(b)| b).unwrap_or_else(|| serde_json::json!({}));
    let raw = match resolve_request_body(&state, raw) {
        Ok(v) => v,
        Err(e) => {
            log::warn!("address book request rejected: {}", e);
            return Json(AbResult::err(e));
        }
    };
    // Review finding: sealing the login RESPONSE bought nothing while the very next
    // request put the same token back on the wire as a cleartext `Authorization:
    // Bearer`. A client that sealed its envelope carries the token INSIDE it instead,
    // so prefer that and fall back to the header for every other (older) client.
    let token = match raw.get("access_token").and_then(|v| v.as_str()) {
        Some(t) if !t.trim().is_empty() => t.trim().to_owned(),
        _ => match bearer_token(&headers) {
            Some(t) => t,
            None => return Json(AbResult::err("Invalid token")),
        },
    };
    let Some(session) = integration::session_for_token(&token) else {
        return Json(AbResult::err("Invalid token"));
    };
    // As before, a body that is not shaped like an AbGetRequest falls back to the
    // defaults rather than failing the request.
    let req: AbGetRequest = serde_json::from_value(raw).unwrap_or_default();
    let device_key_ok = !req.device_key_pub.is_empty()
        && !req.device_key_sig.is_empty()
        && verify_device_signature(&req.device_key_pub, &req.device_key_sig, "nemo-ab", &req.id);
    // The same enforcement as the policy poll: when the operator requires
    // provisioned device keys, an address book is not served to anything else.
    if integration::require_device_key() && !device_key_ok {
        return Json(AbResult::err("a provisioned device key is required"));
    }
    let seal_this = device_key_ok && req.sealed.as_deref() == Some("v1");
    // A token lifted from one machine is not an address book on another, and a
    // disabled user gets none.
    let proven = device_key_ok.then_some(req.device_key_pub.as_str());
    if !session_device_binding_ok(&session.device_key_pub, proven) {
        log::warn!("address book refused: user '{}' token spent from another device", session.username);
        return Json(AbResult::err("this sign-in is bound to another computer; sign in again from this one"));
    }
    if !integration::user_is_enabled(&session.username) {
        return Json(AbResult::err("Invalid token"));
    }

    let peers = match state.pm.list_registered(1000, 0).await {
        Ok(peers) => peers,
        Err(err) => {
            return Json(AbResult::err(err.to_string()));
        }
    };
    // Re-resolve permissions from live config (not the login-time snapshot) so
    // access changes and user removal take effect immediately.
    let (is_admin, allowed_targets) = integration::effective_permission(&session.username);
    let mut ab_peers = Vec::new();
    for peer in peers {
        if !integration::user_allowed_target(is_admin, &allowed_targets, &peer.id) {
            continue;
        }
        let alias = peer_alias(&peer);
        let hostname = peer_hostname(&peer.id);
        ab_peers.push(AbPeer {
            id: peer.id.clone(),
            username: String::new(),
            hostname,
            platform: String::new(),
            alias,
            tags: Vec::new(),
        });
    }
    let data = serde_json::to_string(&AbData {
        tags: Vec::new(),
        peers: ab_peers,
    })
    .unwrap_or_else(|_| "{\"tags\":[],\"peers\":[]}".to_owned());
    if seal_this {
        // A6: SIGN-then-seal (mirror the policy poll). A bare sealedbox gives
        // confidentiality but NO sender authentication — the device pubkey is public,
        // so anyone could forge a sealed list. Sign the JSON with the server key first,
        // then seal the signed blob to the device key; the client verifies the inner
        // signature after unsealing. Fail closed if there is no signing key.
        let Some(secret_key) = state.server_secret_key.as_ref() else {
            return Json(AbResult::err(
                "server has no signing key; cannot seal the address book",
            ));
        };
        let signed = sign::sign(data.as_bytes(), secret_key);
        let Some(sealed) = seal_to_device_key(&req.device_key_pub, &signed) else {
            return Json(AbResult::err(
                "could not seal the address book to the device key",
            ));
        };
        return Json(AbResult {
            updated_at: Some(now_epoch_secs()),
            data: None,
            sealed_data: Some(sealed),
            error: None,
        });
    }
    Json(AbResult {
        updated_at: Some(now_epoch_secs()),
        data: Some(data),
        sealed_data: None,
        error: None,
    })
}

// ---- Dashboard: LDAP config ----

async fn get_ldap_config(
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
) -> ApiResult<integration::LdapConfigView> {
    require_auth(&headers, &state.token)?;
    Ok(Json(integration::ldap_config_view()))
}

async fn put_ldap_config(
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
    Json(update): Json<integration::LdapConfigUpdate>,
) -> ApiResult<integration::LdapConfigView> {
    require_auth(&headers, &state.token)?;
    // Fail-closed: refuse to enable LDAP at runtime while the live listener would
    // carry login credentials in cleartext (non-TLS, routable bind, no override).
    // The transport is fixed at startup, so enabling here cannot flip it to TLS.
    if update.enabled == Some(true)
        && !API_TLS_ACTIVE.load(Ordering::SeqCst)
        && !API_BIND_LOOPBACK.load(Ordering::SeqCst)
        && !API_ALLOW_INSECURE.load(Ordering::SeqCst)
    {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "Refusing to enable LDAP login while the API serves plaintext HTTP on a routable \
             address. Restart hbbs with --nemo-api-tls auto (or a cert), bind to loopback for \
             a tunnel, or set --nemo-api-allow-insecure Y.",
        ));
    }
    Ok(Json(integration::update_ldap_config(update)))
}

#[derive(Deserialize)]
struct LdapTestRequest {
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
}

#[derive(Serialize)]
struct LdapTestResponse {
    success: bool,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
}

async fn test_ldap_login(
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
    Json(req): Json<LdapTestRequest>,
) -> ApiResult<LdapTestResponse> {
    require_auth(&headers, &state.token)?;
    let cfg = integration::ldap_config();
    match integration::authenticate_ldap(&cfg, req.username.trim(), &req.password).await {
        Ok(user) => Ok(Json(LdapTestResponse {
            success: true,
            message: format!("Authenticated as {}", user.username),
            username: Some(user.username),
            display_name: Some(user.display_name),
            email: Some(user.email),
        })),
        Err(reason) => Ok(Json(LdapTestResponse {
            success: false,
            message: reason,
            username: None,
            display_name: None,
            email: None,
        })),
    }
}

#[derive(Serialize)]
struct FetchCertResponse {
    success: bool,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cert: Option<integration::CertSummary>,
}

// Connect to the configured directory and return its TLS certificate so the
// admin can review the fingerprint and pin it (Trust) — the secure alternative
// to disabling verification.
async fn fetch_ldap_cert(
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
) -> ApiResult<FetchCertResponse> {
    require_auth(&headers, &state.token)?;
    let url = integration::ldap_config().server_url;
    if url.trim().is_empty() {
        return Ok(Json(FetchCertResponse {
            success: false,
            message: "Set and save the server URL first".to_owned(),
            pem: None,
            cert: None,
        }));
    }
    let result = tokio::task::spawn_blocking(move || integration::fetch_server_cert(&url)).await;
    Ok(Json(match result {
        Ok(Ok((pem, cert))) => FetchCertResponse {
            success: true,
            message: format!(
                "Fetched {} — review it, then Save to pin",
                if cert.self_signed {
                    "a self-signed certificate"
                } else {
                    "the certificate"
                }
            ),
            pem: Some(pem),
            cert: Some(cert),
        },
        Ok(Err(e)) => FetchCertResponse {
            success: false,
            message: e,
            pem: None,
            cert: None,
        },
        Err(e) => FetchCertResponse {
            success: false,
            message: format!("fetch task failed: {}", e),
            pem: None,
            cert: None,
        },
    }))
}

// ---- Dashboard: LDAP directory picker (select users to allow) ----

#[derive(Deserialize)]
struct LdapUsersRequest {
    #[serde(default)]
    query: String,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Serialize)]
struct DirectoryUserView {
    username: String,
    display_name: String,
    email: String,
    /// Whether this directory user is enabled to use TBFDesk.
    enabled: bool,
    is_admin: bool,
    /// Whether the user already has an allowlist entry (vs. never selected).
    in_acl: bool,
}

#[derive(Serialize)]
struct LdapUsersResponse {
    success: bool,
    message: String,
    users: Vec<DirectoryUserView>,
}

// Search the directory (service-account bind) and annotate each hit with its
// current allowlist state so the admin can enable/disable at a glance.
async fn list_ldap_users(
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
    Json(req): Json<LdapUsersRequest>,
) -> ApiResult<LdapUsersResponse> {
    require_auth(&headers, &state.token)?;
    let cfg = integration::ldap_config();
    let limit = req.limit.unwrap_or(200).clamp(1, 1000);
    match integration::search_ldap_users(&cfg, req.query.trim(), limit).await {
        Ok(found) => {
            let perms = integration::permissions_snapshot();
            let users = found
                .into_iter()
                .map(|u| {
                    let p = perms.get(&u.username);
                    DirectoryUserView {
                        enabled: p.map(|x| x.enabled).unwrap_or(false),
                        is_admin: p.map(|x| x.is_admin).unwrap_or(false),
                        in_acl: p.is_some(),
                        username: u.username,
                        display_name: u.display_name,
                        email: u.email,
                    }
                })
                .collect();
            Ok(Json(LdapUsersResponse {
                success: true,
                message: String::new(),
                users,
            }))
        }
        Err(reason) => Ok(Json(LdapUsersResponse {
            success: false,
            message: reason,
            users: Vec::new(),
        })),
    }
}

#[derive(Deserialize)]
struct SetLdapUserRequest {
    username: String,
    enabled: bool,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    email: String,
}

// Enable/disable a directory user for TBFDesk (upserts the allowlist entry).
async fn set_ldap_user(
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
    Json(req): Json<SetLdapUserRequest>,
) -> ApiResult<serde_json::Value> {
    require_auth(&headers, &state.token)?;
    let username = req.username.trim();
    if username.is_empty() {
        return Ok(Json(
            serde_json::json!({ "success": false, "message": "username required" }),
        ));
    }
    let (key, perm, version, evicted_keys) = integration::set_user_enabled(
        username,
        req.enabled,
        req.display_name.trim(),
        req.email.trim(),
    );
    let controllers = integration::peer_ids_for_device_keys(&evicted_keys);
    terminate_sessions_from_controllers(&controllers, "user access changed").await;
    Ok(Json(serde_json::json!({
        "success": true,
        "username": username,
        "enabled": perm.enabled,
        "key": key,
        "permission": perm,
        "permissions_version": version,
    })))
}

// ---- Dashboard: per-user permissions (RBAC) ----

#[derive(Serialize)]
struct PeerBrief {
    id: String,
    alias: String,
    online: bool,
}

#[derive(Serialize)]
struct PermissionsResponse {
    permissions: HashMap<String, integration::UserPermission>,
    permissions_version: u64,
    default_targets: Vec<String>,
    require_login: bool,
    default_policy_name: Option<String>,
    admin_policy: integration::UserManagedPolicy,
    peers: Vec<PeerBrief>,
}

async fn get_permissions(
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
) -> ApiResult<PermissionsResponse> {
    require_auth(&headers, &state.token)?;
    let peers = state
        .pm
        .list_registered(1000, 0)
        .await
        .map_err(server_error)?;
    let mut briefs = Vec::with_capacity(peers.len());
    for peer in peers {
        let online = state
            .pm
            .runtime_snapshot(&peer.id)
            .await
            .map(|s| s.online)
            .unwrap_or(false);
        briefs.push(PeerBrief {
            alias: peer_alias(&peer),
            id: peer.id,
            online,
        });
    }
    Ok(Json(PermissionsResponse {
        permissions: integration::permissions_snapshot(),
        permissions_version: integration::permissions_version(),
        default_targets: integration::default_targets(),
        require_login: integration::require_login(),
        default_policy_name: integration::default_policy_name(),
        admin_policy: integration::admin_policy(),
        peers: briefs,
    }))
}

#[derive(Serialize)]
struct PermissionsPutResponse {
    permissions: HashMap<String, integration::UserPermission>,
    permissions_version: u64,
}

// The admin UI replaces its in-memory map with `permissions` and sends
// `permissions_version` back on the next save, so both must be here: a bare map
// left the UI holding {} and a stale version.
async fn put_permissions(
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
    Json(update): Json<integration::PermissionsUpdate>,
) -> ApiResult<PermissionsPutResponse> {
    require_auth(&headers, &state.token)?;
    match integration::update_permissions(update) {
        Ok((permissions, permissions_version, evicted_keys)) => {
            let controllers = integration::peer_ids_for_device_keys(&evicted_keys);
            terminate_sessions_from_controllers(&controllers, "permissions changed").await;
            Ok(Json(PermissionsPutResponse {
                permissions,
                permissions_version,
            }))
        }
        Err(e) => Err(api_error(StatusCode::CONFLICT, &format!("Conflict: {}", e))),
    }
}

// --- Client setup bundle: everything a fresh client needs, in one string -----
//
// A first install needs SIX values typed in by hand before it can reach this server at
// all: the ID/rendezvous server, the relay, the api-server URL, the management server
// URL, the server's identity key, and (for a self-signed API) the certificate pin --
// and then the device key on top. Every one of them is exact, most are long, and a
// single typo fails as "cannot reach the server", which is indistinguishable from a
// network problem. That is the whole first-run experience of this fork, repeated per
// machine.
//
// So the server, which knows all of them, hands them over as one string the client can
// import the same way it imports a device key. Generating a device key produces the
// string WITH the key in it, so a provisioning run is: generate here, paste there.
//
// It is NOT signed, and signing it would be theatre: the thing a client would verify a
// signature against is the identity key that is *inside* the bundle. The bundle is the
// trust anchor, so it has to be moved like one -- the same rule the device key already
// has, and the same rule the host=..,key=.. exe name has had all along.
const CLIENT_SETUP_PREFIX: &str = "tbfdesk-setup-v1:";

/// The server-side half: what every client on this server needs, regardless of which
/// machine it is. Serialized into the bundle and also returned on its own, so the
/// dashboard can show the operator exactly what it is about to hand out.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct ClientSetupServer {
    /// `custom-rendezvous-server` -- host, or host:port when the port is not the default.
    id_server: String,
    /// `relay-server`. Empty is valid and common: hbbs hands out its own `-r` at
    /// runtime, so a client with no relay configured still relays.
    relay_server: String,
    /// `api-server` AND `nemo-management-server` (login, address book, signed policy).
    api_server: String,
    /// The server's Ed25519 identity key, base64: the client's `key` (verifies the
    /// rendezvous handshake and the signed id/pk) and `nemo-management-public-key`
    /// (verifies signed policy). One value, two option names.
    key: String,
    /// `nemo-api-cert-fingerprint` -- only for a self-signed API, where it is what lets
    /// the client stop accepting any certificate. Empty when the API serves a CA-signed
    /// certificate (the client validates normally) or no TLS at all.
    api_cert_fingerprint: String,
}

/// The whole bundle. `device_key` is present only in the string generated together with
/// a key -- it is that key's PRIVATE half, shown once and never stored here.
#[derive(Debug, Default, Serialize, Deserialize)]
struct ClientSetupBundle {
    v: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    label: String,
    issued_at: String,
    /// The address the operator generated this from, for the log line on the client
    /// side: a bundle made from a LAN dashboard session is wrong for a roaming client,
    /// and this is the only clue to that after the fact.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    issued_from: String,
    /// "internal" or "external": which address set this bundle carries. The client logs
    /// it, which is the only way to tell afterwards that a machine was handed the wrong
    /// one of the two.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    scope: String,
    server: ClientSetupServer,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    device_key: String,
}

fn encode_client_setup(bundle: &ClientSetupBundle) -> Result<String, String> {
    let json = serde_json::to_string(bundle).map_err(|e| e.to_string())?;
    Ok(format!(
        "{}{}",
        CLIENT_SETUP_PREFIX,
        base64::encode(json.as_bytes())
    ))
}

/// Which side of the network the bundle is for. A deployment like this one has two
/// addresses for the same server -- a LAN address and a public one -- and a client
/// carries ONE set of them, so which one a machine is given is not a detail: give a
/// workstation the public address and every session hairpins out through the router and
/// back; give a roaming laptop the LAN address and it simply cannot reach the server.
///
/// So both are exported, side by side, and the operator hands over the one that matches
/// where the machine connects FROM. (The real fix for a machine that does both is one
/// split-horizon DNS name resolving to each address from each side, which both profiles
/// then carry identically -- see TOPOLOGY-DEPLOYMENT.md.)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClientSetupScope {
    /// Inside the network: the server's LAN address.
    Internal,
    /// From the internet: its public address.
    External,
}

impl ClientSetupScope {
    fn parse(value: Option<&str>) -> Self {
        match value.unwrap_or_default().trim().to_ascii_lowercase().as_str() {
            "external" | "public" | "wan" | "internet" => Self::External,
            _ => Self::Internal,
        }
    }
    fn as_str(self) -> &'static str {
        match self {
            Self::Internal => "internal",
            Self::External => "external",
        }
    }
    /// The flag suffix, so one arg name pair covers both: `--nemo-client-api` and
    /// `--nemo-client-api-external`.
    fn arg_suffix(self) -> &'static str {
        match self {
            Self::Internal => "",
            Self::External => "-external",
        }
    }
    fn file_tag(self) -> &'static str {
        match self {
            Self::Internal => "lan",
            Self::External => "wan",
        }
    }
}

/// Everything the operator may override, and what the server fills in when they do not.
///
/// The defaults come from the **Host header of the dashboard request**, which is a
/// better guess than anything configured: the operator is reaching the API over exactly
/// the address and port a client would have to use, so that is the address to hand out.
/// It is still only a guess -- a LAN dashboard session cannot know a roaming client's
/// public address -- which is why the dashboard shows the three fields and lets them be
/// edited before anything is generated.
fn client_setup_server(
    overrides: &ClientSetupRequest,
    host_header: &str,
    server_public_key: &str,
    scope: ClientSetupScope,
) -> ClientSetupServer {
    let sfx = scope.arg_suffix();
    // The LAN profile is derived from the dashboard address (the operator usually
    // administers from inside) and from --local-ip; the public one from `-r`, which in a
    // deployment like this one is exactly the public address hbbs hands out to clients.
    // Either way an explicit --nemo-client-* flag wins, and the operator's edit in the
    // dashboard wins over that.
    let scoped_relay_default = match scope {
        ClientSetupScope::Internal => get_arg("local-ip"),
        ClientSetupScope::External => String::new(),
    };
    let host_header = host_header.trim();
    // host:port -> (host, port). An IPv6 literal in a Host header is bracketed, so the
    // last colon is only a port separator when it comes after the closing bracket.
    let (host, port) = match host_header.rfind(':') {
        Some(idx) if idx > host_header.rfind(']').unwrap_or(0) => {
            (&host_header[..idx], &host_header[idx + 1..])
        }
        _ => (host_header, ""),
    };
    let host = host.trim_matches(|c| c == '[' || c == ']');
    // The API port is the one thing both profiles share, so only the HOST differs.
    //
    // Normally it is the port of the address the operator administers from, because
    // that is an address a client has been PROVEN to reach this API on — including a
    // reverse proxy on 443, where appending the listener's own port would be wrong.
    // `host_header` above is really the request authority, so this now also works over
    // HTTP/2, where there is no Host header at all (it is the `:authority`
    // pseudo-header) and every exported bundle used to lose its port and point at 443.
    //
    // A dedicated client bind overrides it: that listener is the one clients must use,
    // and the address the admin happens to browse cannot imply its port.
    let api_port = api_port_suffix(dedicated_client_api_port(), port);
    let public_host = relay_host(&get_arg("relay-servers"));
    let api_default = match scope {
        ClientSetupScope::Internal => {
            let h = first_non_empty(&[host, &get_arg("local-ip")]);
            if h.is_empty() {
                String::new()
            } else {
                format!("https://{}{}", h, api_port)
            }
        }
        // Deliberately NOT the dashboard host: an operator reading this over the LAN
        // would otherwise get the LAN address baked into the "from the internet" bundle,
        // which is the one mistake this whole split exists to prevent. Better to hand
        // back an empty field the dashboard asks them to fill in.
        ClientSetupScope::External => {
            if public_host.is_empty() {
                String::new()
            } else {
                format!("https://{}{}", public_host, api_port)
            }
        }
    };
    let api_server = first_non_empty(&[
        overrides.api_server.as_deref().unwrap_or_default(),
        &get_arg(&format!("nemo-client-api{}", sfx)),
        &api_default,
    ]);
    // The rendezvous port is NOT the API port, so it is never taken from the Host
    // header; the client's own default (21116) covers the normal case and is left
    // implicit, exactly as a hand-typed address would be.
    let rendezvous_port = get_arg_or("port", hbb_common::config::RENDEZVOUS_PORT.to_string());
    let id_host = match scope {
        ClientSetupScope::Internal => first_non_empty(&[host, &get_arg("local-ip")]),
        ClientSetupScope::External => public_host.clone(),
    };
    let id_default = if id_host.is_empty() {
        String::new()
    } else if rendezvous_port == hbb_common::config::RENDEZVOUS_PORT.to_string() {
        id_host.clone()
    } else {
        format!("{}:{}", id_host, rendezvous_port)
    };
    let id_server = first_non_empty(&[
        overrides.id_server.as_deref().unwrap_or_default(),
        &get_arg(&format!("nemo-client-id-server{}", sfx)),
        &id_default,
    ]);
    // For a client on the internet, empty is the right default: hbbs hands out its own
    // `-r` (the public relay) at runtime. For one on the LAN it is not - that would send
    // an internal session out through the router and back - so --local-ip is used when
    // the operator set one.
    let relay_server = first_non_empty(&[
        overrides.relay_server.as_deref().unwrap_or_default(),
        &get_arg(&format!("nemo-client-relay{}", sfx)),
        &scoped_relay_default,
    ]);
    // Only a self-signed certificate needs pinning; with a CA-signed one the client
    // validates the normal way, and pinning it would strand the client at renewal.
    let pin_default = API_CERT_INFO
        .read()
        .unwrap()
        .as_ref()
        .filter(|info| info.tls && info.mode == "self-signed")
        .map(|info| info.fingerprint.clone())
        .unwrap_or_default();
    let api_cert_fingerprint = match overrides.api_cert_fingerprint.as_deref() {
        // An explicit empty string means "do not pin", which is a real choice (a
        // reverse proxy in front with its own certificate), so it is not overridden by
        // the default below.
        Some(explicit) => explicit.trim().to_owned(),
        None => pin_default,
    };
    ClientSetupServer {
        id_server,
        relay_server,
        api_server,
        key: server_public_key.trim().to_owned(),
        api_cert_fingerprint,
    }
}

/// The host out of `-r`/`--relay-servers`: it can carry several, comma separated, and
/// each may have a port the client does not need here (it dials the relay on 21117).
fn relay_host(relay_servers: &str) -> String {
    let first = relay_servers
        .split(',')
        .map(str::trim)
        .find(|s| !s.is_empty())
        .unwrap_or_default();
    match first.rfind(':') {
        // Not a port separator inside an IPv6 literal.
        Some(idx) if idx > first.rfind(']').unwrap_or(0) => first[..idx].to_owned(),
        _ => first.to_owned(),
    }
    .trim_matches(|c| c == '[' || c == ']')
    .to_owned()
}

fn first_non_empty(candidates: &[&str]) -> String {
    candidates
        .iter()
        .map(|c| c.trim())
        .find(|c| !c.is_empty())
        .unwrap_or_default()
        .to_owned()
}

/// A filename an operator can keep apart from the next machine's.
fn client_setup_filename(label: &str, with_key: bool, scope: ClientSetupScope) -> String {
    let slug: String = label
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' })
        .collect();
    let slug = slug.trim_matches('-').to_owned();
    let stem = if slug.is_empty() { "tbfdesk".to_owned() } else { format!("tbfdesk-{}", slug) };
    // The tag is not decoration: two files for the same machine differ only in which
    // side of the network they are for, and handing over the wrong one is the failure
    // this split exists to prevent.
    if with_key {
        format!("{}-setup-{}-with-key.tbfsetup", stem, scope.file_tag())
    } else {
        format!("{}-setup-{}.tbfsetup", stem, scope.file_tag())
    }
}

#[derive(Clone, Default, Deserialize)]
struct ClientSetupRequest {
    /// "internal" (default) or "external".
    #[serde(default)]
    scope: Option<String>,
    /// `None` = use the server's default; `Some("")` = deliberately blank.
    #[serde(default)]
    id_server: Option<String>,
    #[serde(default)]
    relay_server: Option<String>,
    #[serde(default)]
    api_server: Option<String>,
    #[serde(default)]
    api_cert_fingerprint: Option<String>,
    #[serde(default)]
    label: Option<String>,
}

#[derive(Default, Serialize)]
struct ClientSetupProfile {
    scope: String,
    server: ClientSetupServer,
    /// The importable string. Carries no device key: this is the one an operator can
    /// hand out freely to machines whose keys already exist.
    setup_string: String,
    filename: String,
    /// Why this profile could not be built, when it could not. The public profile is
    /// routinely in this state on a server started without `-r`: there is no public
    /// address to guess, and guessing the LAN one would be worse than an empty field.
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
}

#[derive(Serialize)]
struct ClientSetupResponse {
    /// Both sides, side by side. A client carries ONE address set, so the operator picks
    /// the profile that matches where the machine connects from.
    internal: ClientSetupProfile,
    external: ClientSetupProfile,
    /// What the defaults were derived from, so the dashboard can say so.
    issued_from: String,
}

/// Which port an exported bundle tells clients to use, as a `":port"` suffix (empty =
/// none, i.e. the scheme default). Pure, so the precedence is testable without
/// touching the process-global argument table.
///
/// A dedicated client listener wins: that is the socket clients must reach, and the
/// address the operator browsed says nothing about it. Otherwise the authority's own
/// port is used — which is empty behind a reverse proxy on 443, and must STAY empty
/// there rather than having a listener port appended.
fn api_port_suffix(dedicated: Option<u16>, authority_port: &str) -> String {
    match dedicated {
        Some(port) => format!(":{}", port),
        None if authority_port.is_empty() => String::new(),
        None => format!(":{}", authority_port),
    }
}

/// SPLIT-PORT: the port of the dedicated client listener, when one is configured.
/// `None` means there is no second bind, so the client API is wherever the admin API
/// is. Parsed from the same argument the listener itself uses, so the two cannot drift.
fn dedicated_client_api_port() -> Option<u16> {
    let bind = get_arg("nemo-client-api-bind");
    if bind.is_empty() {
        return None;
    }
    bind.parse::<SocketAddr>().ok().map(|a| a.port())
}

/// The address this request was addressed to: the `:authority` pseudo-header on
/// HTTP/2, the `Host` header on HTTP/1.
///
/// Reading only `Host` was a real bug: axum exposes h2's `:authority` through the URI,
/// never as a HOST header, so on an h2 dashboard connection every caller of this saw
/// an empty string — which is why exported setup bundles lost their API port and the
/// LAN profile reported "cannot work out this server's address".
fn request_authority(uri: &axum::http::Uri, headers: &HeaderMap) -> String {
    match uri.authority() {
        Some(authority) => authority.to_string(),
        None => host_header(headers),
    }
}

fn host_header(headers: &HeaderMap) -> String {
    headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

fn build_client_setup(
    overrides: &ClientSetupRequest,
    authority: &str,
    server_public_key: &str,
    device_key: &str,
    scope: ClientSetupScope,
) -> Result<(ClientSetupServer, String, String), String> {
    let server = client_setup_server(overrides, authority, server_public_key, scope);
    if server.id_server.is_empty() || server.api_server.is_empty() {
        return Err(match scope {
            ClientSetupScope::Internal => "cannot work out this server's address on the \
                 local network; fill the ID server and api-server fields in, or start \
                 hbbs with --local-ip (or --nemo-client-id-server / --nemo-client-api)"
                .to_owned(),
            // Not derivable and deliberately not guessed: the dashboard address is the
            // wrong answer here, and a public bundle carrying a LAN address is the one
            // failure this split exists to prevent.
            ClientSetupScope::External => "this server does not know its own public \
                 address: fill the ID server and api-server fields in, or start hbbs \
                 with -r <public-host:21117> (or --nemo-client-id-server-external / \
                 --nemo-client-api-external)"
                .to_owned(),
        });
    }
    let label = overrides.label.clone().unwrap_or_default();
    let bundle = ClientSetupBundle {
        v: 1,
        label: label.clone(),
        issued_at: now_iso(),
        issued_from: authority.to_owned(),
        scope: scope.as_str().to_owned(),
        server: server.clone(),
        device_key: device_key.to_owned(),
    };
    let string = encode_client_setup(&bundle)?;
    Ok((
        server,
        string,
        client_setup_filename(&label, !device_key.is_empty(), scope),
    ))
}

/// One profile, with its failure carried inside it rather than failing the request: the
/// public profile being underivable must not stop the LAN one from being handed out.
fn client_setup_profile(
    overrides: &ClientSetupRequest,
    authority: &str,
    server_public_key: &str,
    device_key: &str,
    scope: ClientSetupScope,
) -> ClientSetupProfile {
    match build_client_setup(overrides, authority, server_public_key, device_key, scope) {
        Ok((server, setup_string, filename)) => ClientSetupProfile {
            scope: scope.as_str().to_owned(),
            server,
            setup_string,
            filename,
            error: String::new(),
        },
        Err(error) => ClientSetupProfile {
            scope: scope.as_str().to_owned(),
            server: client_setup_server(overrides, authority, server_public_key, scope),
            error,
            ..Default::default()
        },
    }
}

/// GET: both profiles' defaults, each with a ready-to-copy string that carries no device
/// key. Nothing here can fail as a whole - a profile that cannot be derived says so in
/// its own `error` and the other one is still usable.
async fn get_client_setup(
    Extension(state): Extension<HbbsApiState>,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
    headers: HeaderMap,
) -> ApiResult<ClientSetupResponse> {
    require_auth(&headers, &state.token)?;
    let authority = request_authority(&uri, &headers);
    let blank = ClientSetupRequest::default();
    Ok(Json(ClientSetupResponse {
        internal: client_setup_profile(
            &blank,
            &authority,
            &state.server_public_key,
            "",
            ClientSetupScope::Internal,
        ),
        external: client_setup_profile(
            &blank,
            &authority,
            &state.server_public_key,
            "",
            ClientSetupScope::External,
        ),
        issued_from: authority.clone(),
    }))
}

/// POST: ONE profile, with the operator's edits applied - the dashboard's two blocks
/// each send their own, so editing the LAN fields cannot disturb the public ones.
/// `scope` picks which; omitting it means the LAN profile.
async fn post_client_setup(
    Extension(state): Extension<HbbsApiState>,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
    headers: HeaderMap,
    Json(req): Json<ClientSetupRequest>,
) -> ApiResult<ClientSetupProfile> {
    require_auth(&headers, &state.token)?;
    let authority = request_authority(&uri, &headers);
    let scope = ClientSetupScope::parse(req.scope.as_deref());
    let (server, setup_string, filename) =
        build_client_setup(&req, &authority, &state.server_public_key, "", scope)
            .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e))?;
    Ok(Json(ClientSetupProfile {
        scope: scope.as_str().to_owned(),
        server,
        setup_string,
        filename,
        error: String::new(),
    }))
}

// --- S-DUALKEY: provisioned device keys -------------------------------------
#[derive(Deserialize)]
struct GenerateDeviceKeyRequest {
    #[serde(default)]
    label: String,
    /// M1: the peer id this key is generated FOR. Empty = unbound legacy key.
    #[serde(default)]
    peer_id: String,
    /// The client-setup values to bake into this key's setup strings, per side of the
    /// network. Omitted fields fall back to the server's defaults, so a caller that
    /// sends nothing still gets whatever this server can work out on its own.
    #[serde(default)]
    setup: ClientSetupPair,
}

/// The operator's edits for both profiles, as the dashboard holds them.
#[derive(Clone, Default, Deserialize)]
struct ClientSetupPair {
    #[serde(default)]
    internal: ClientSetupRequest,
    #[serde(default)]
    external: ClientSetupRequest,
}
#[derive(Serialize)]
struct GenerateDeviceKeyResponse {
    id: String,
    label: String,
    public_key: String,
    private_key: String,
    created_at: String,
    peer_id: String,
    /// The whole first run in one string: this key's private half plus the server values
    /// a fresh client would otherwise have to be told by hand. Shown once, with the
    /// private key, and never stored.
    ///
    /// Two of them, because this server has two addresses: hand over the one that
    /// matches where the machine will connect from. Each carries its own `error` when it
    /// could not be built - the key is pinned either way, so losing the convenience must
    /// never lose the key.
    setup_internal: ClientSetupProfile,
    setup_external: ClientSetupProfile,
}
async fn generate_device_key(
    Extension(state): Extension<HbbsApiState>,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
    headers: HeaderMap,
    Json(req): Json<GenerateDeviceKeyRequest>,
) -> ApiResult<GenerateDeviceKeyResponse> {
    require_auth(&headers, &state.token)?;
    let (pk, sk) = sign::gen_keypair();
    let public_key = base64::encode(pk.as_ref());
    let private_key = base64::encode(sk.as_ref());
    let created_at = now_iso();
    let dk = integration::add_device_key(
        req.label.trim().to_owned(),
        public_key.clone(),
        created_at.clone(),
        req.peer_id,
    );
    // The key is pinned at this point. The setup strings are a convenience on top, so a
    // failure to build one is reported inside that profile rather than losing the key.
    let labelled = |mut overrides: ClientSetupRequest| {
        if overrides.label.as_deref().unwrap_or_default().is_empty() {
            overrides.label = Some(if dk.label.is_empty() {
                dk.peer_id.clone()
            } else {
                dk.label.clone()
            });
        }
        overrides
    };
    let setup_internal = client_setup_profile(
        &labelled(req.setup.internal.clone()),
        &request_authority(&uri, &headers),
        &state.server_public_key,
        &private_key,
        ClientSetupScope::Internal,
    );
    let setup_external = client_setup_profile(
        &labelled(req.setup.external.clone()),
        &request_authority(&uri, &headers),
        &state.server_public_key,
        &private_key,
        ClientSetupScope::External,
    );
    Ok(Json(GenerateDeviceKeyResponse {
        id: dk.id,
        label: dk.label,
        public_key,
        private_key,
        created_at,
        peer_id: dk.peer_id,
        setup_internal,
        setup_external,
    }))
}
async fn list_device_keys(
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
) -> ApiResult<Vec<integration::DeviceKey>> {
    require_auth(&headers, &state.token)?;
    Ok(Json(integration::list_device_keys()))
}
async fn delete_device_key(
    Path(id): Path<String>,
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
) -> ApiResult<serde_json::Value> {
    require_auth(&headers, &state.token)?;
    let removed = integration::remove_device_key(&id);
    // M69: end what the key is doing right now, not just its future logins.
    let mut ended = Vec::new();
    if let Some(k) = removed.as_ref().filter(|k| !k.peer_id.is_empty()) {
        ended = terminate_sessions_from_controllers(&[k.peer_id.clone()], "device key revoked").await;
    }
    Ok(Json(serde_json::json!({ "removed": removed.is_some(), "sessions_ended_on": ended })))
}

// --- M1-CLAIM: pending binding requests, and binding by hand -----------------
//
// The provisioning deadlock these exist for: generating a key asks for the TBFDesk id,
// but a client shows no id until it is past the provisioning gate, and it cannot pass
// the gate without a key. So an unbound key is a one-shot provisioning token: the first
// client that PROVES it files a request here, and the operator's confirmation -- not the
// client -- writes the binding.

#[derive(Deserialize)]
struct DeviceKeyClaimRequest {
    /// Which of the key's pending rows this decision is about. Required: one key can
    /// have several ids waiting, and approving "the pending one" would be a guess.
    #[serde(default)]
    peer_id: String,
}

#[derive(Serialize)]
struct DeviceKeyClaimsResponse {
    claims: Vec<integration::PendingDeviceKeyClaim>,
    /// So the dashboard can explain an empty list ("first-use claiming is off") instead
    /// of leaving the operator to guess why nothing ever appears.
    claim_unbound_device_keys: bool,
}

async fn list_device_key_claims(
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
) -> ApiResult<DeviceKeyClaimsResponse> {
    require_auth(&headers, &state.token)?;
    Ok(Json(DeviceKeyClaimsResponse {
        claims: integration::pending_device_key_claims(),
        claim_unbound_device_keys: integration::claim_unbound_device_keys(),
    }))
}

async fn approve_device_key_claim(
    Path(id): Path<String>,
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
    Json(req): Json<DeviceKeyClaimRequest>,
) -> ApiResult<integration::DeviceKey> {
    require_auth(&headers, &state.token)?;
    let peer_id = req.peer_id.trim().to_owned();
    // Read the row's own `via` before approving: approval drops the key's pending rows,
    // and the audit line is more use with the endpoint the client actually came in on.
    let via = integration::pending_device_key_claims()
        .into_iter()
        .find(|c| c.key_id == id && c.peer_id == peer_id)
        .map(|c| c.via)
        .unwrap_or_else(|| "management API".to_owned());
    let key = integration::approve_device_key_claim(&id, &peer_id, now_iso())
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e))?;
    record_device_key_claim(&peer_id, &key.public_key, &via).await;
    Ok(Json(key))
}

async fn deny_device_key_claim(
    Path(id): Path<String>,
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
    Json(req): Json<DeviceKeyClaimRequest>,
) -> ApiResult<integration::PendingDeviceKeyClaim> {
    require_auth(&headers, &state.token)?;
    let peer_id = req.peer_id.trim().to_owned();
    let claim = integration::deny_device_key_claim(&id, &peer_id)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e))?;
    let mut store = STATS.write().await;
    record_event_locked(
        &mut store,
        "device-key-claim-denied",
        Some(&peer_id),
        None,
        format!(
            "operator denied device key {} for this peer; it stays refused and will not ask \
             again until the request is forgotten",
            id
        ),
    );
    drop(store);
    Ok(Json(claim))
}

async fn forget_device_key_claim(
    Path(id): Path<String>,
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
    Json(req): Json<DeviceKeyClaimRequest>,
) -> ApiResult<serde_json::Value> {
    require_auth(&headers, &state.token)?;
    let peer_id = req.peer_id.trim().to_owned();
    integration::forget_device_key_claim(&id, &peer_id)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e))?;
    let mut store = STATS.write().await;
    record_event_locked(
        &mut store,
        "device-key-claim-forgotten",
        Some(&peer_id),
        None,
        format!("operator cleared the device key {} request for this peer; it may ask again", id),
    );
    drop(store);
    Ok(Json(serde_json::json!({ "forgotten": true })))
}

#[derive(Deserialize)]
struct DeviceKeyPeerIdRequest {
    /// Empty clears the binding, which re-arms the key as a claimable provisioning
    /// token (and drops its pending rows, denials included).
    #[serde(default)]
    peer_id: String,
}

async fn set_device_key_peer_id(
    Path(id): Path<String>,
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
    Json(req): Json<DeviceKeyPeerIdRequest>,
) -> ApiResult<integration::DeviceKey> {
    require_auth(&headers, &state.token)?;
    let key = integration::set_device_key_peer_id(&id, &req.peer_id)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e))?;
    // Audit the id that was STORED, not the one that was typed: the operator may have
    // entered it the way the client displays it ("456 456 456"), and
    // `normalize_peer_id` strips that. Reporting the raw string would put a spaced id
    // in the event line nobody can then grep for, and -- because the peer id argument
    // creates the per-peer stats entry -- would also key that entry on an id no peer
    // can ever have.
    let peer_id = key.peer_id.clone();
    let mut store = STATS.write().await;
    record_event_locked(
        &mut store,
        "device-key-binding",
        if peer_id.is_empty() { None } else { Some(&peer_id) },
        None,
        if peer_id.is_empty() {
            format!("device key {} binding cleared; it is a claimable provisioning token again", id)
        } else {
            format!("device key {} bound to peer {} by the operator", id, peer_id)
        },
    );
    drop(store);
    Ok(Json(key))
}

// ---- Auto-update manifest (a Layer 1 consumer) ----
//
// The stock updater is unreachable from this fork (no api.rustdesk.com; the stock
// `allow-auto-update` policy key is denied on the client). Updates come ONLY from
// this server: the operator places {"version","url","sha256"} in nemo_update.json
// (working directory, --nemo-update-file to relocate, or the dashboard's POST) and
// GET /nemo/api/update/latest serves it PLUS `sig`, computed at request time with
// the management secret key over "version|url|sha256". The client verifies `sig`
// with its pinned management public key, checks `url` is on this server's origin
// and the artifact's SHA-256, and only then runs the installer. A manifest the
// server cannot sign is never served.

fn update_manifest_path() -> String {
    get_arg_or("nemo-update-file", "nemo_update.json".to_owned())
}

// Bounds on what goes into the signed string; both are generous for real values
// and keep an admin-supplied manifest from becoming a large per-poll response.
const MAX_UPDATE_VERSION_LEN: usize = 128;
const MAX_UPDATE_URL_LEN: usize = 2048;

/// The operator-authored manifest, exactly as stored on disk (no `sig` — that is
/// never persisted; it is recomputed per request, so nothing on disk goes stale
/// if the management key is ever rotated).
///
/// The top-level url/sha256 is the WINDOWS installer: that is where every client older
/// than 1.4.16 looks, so it stays there. Other platforms (Linux packages) live in
/// `platforms`, keyed by UPDATE_PLATFORMS, all for the same `version`. The top level is
/// empty when only non-Windows packages are published.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
struct UpdateManifest {
    #[serde(default)]
    version: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    sha256: String,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    platforms: std::collections::BTreeMap<String, UpdateArtifact>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
struct UpdateArtifact {
    #[serde(default)]
    url: String,
    #[serde(default)]
    sha256: String,
}

/// The platform keys an installer can be published for. "windows-x64" is the top level
/// of the manifest; the others go into `platforms`.
const UPDATE_PLATFORM_WINDOWS: &str = "windows-x64";
const UPDATE_PLATFORMS: &[&str] = &[UPDATE_PLATFORM_WINDOWS, "linux-deb", "linux-rpm", "linux-arch"];

#[derive(Serialize)]
struct SignedUpdateArtifact {
    url: String,
    sha256: String,
    sig: String,
}

/// What GET /nemo/api/update/latest returns: the manifest plus its signature.
#[derive(Serialize)]
struct SignedUpdateManifest {
    version: String,
    url: String,
    sha256: String,
    /// base64 of the DETACHED Ed25519 signature (64 bytes) over
    /// update_manifest_message() — the cross-fork contract with the client's
    /// nemo_verify_update_manifest.
    sig: String,
    /// Non-Windows packages, each signed over "version|url|sha256" exactly like the top
    /// level, so the client verifies them with the same function.
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    platforms: std::collections::BTreeMap<String, SignedUpdateArtifact>,
}

// The exact byte string both sides sign/verify. validate_update_manifest forbids
// '|' (and whitespace/control characters) in version and url, so the joined string
// cannot be re-split into a different (version, url, sha256) triple under the same
// signature.
fn update_manifest_message(m: &UpdateManifest) -> String {
    format!("{}|{}|{}", m.version, m.url, m.sha256)
}

fn sign_update_artifact(version: &str, url: &str, sha256: &str, sk: &sign::SecretKey) -> String {
    let sig = sign::sign_detached(format!("{version}|{url}|{sha256}").as_bytes(), sk);
    base64::encode(sig.as_ref())
}

fn sign_update_manifest(m: &UpdateManifest, sk: &sign::SecretKey) -> SignedUpdateManifest {
    // No Windows installer published: an empty, unsigned top level, which every client
    // refuses -- older Windows clients then simply see no update.
    let sig = if m.url.is_empty() {
        String::new()
    } else {
        sign_update_artifact(&m.version, &m.url, &m.sha256, sk)
    };
    SignedUpdateManifest {
        version: m.version.clone(),
        url: m.url.clone(),
        sha256: m.sha256.clone(),
        sig,
        platforms: m
            .platforms
            .iter()
            .map(|(k, a)| {
                (
                    k.clone(),
                    SignedUpdateArtifact {
                        url: a.url.clone(),
                        sha256: a.sha256.clone(),
                        sig: sign_update_artifact(&m.version, &a.url, &a.sha256, sk),
                    },
                )
            })
            .collect(),
    }
}

// Canonicalise and validate what the operator wrote: trimmed, non-empty version;
// an http(s) url; sha256 of exactly 64 hex digits, lower-cased so the signed
// string is the same however it was pasted. Returns the canonical manifest — the
// form that is stored, signed and served.
fn validate_update_manifest(m: &UpdateManifest) -> Result<UpdateManifest, String> {
    let version = m.version.trim().to_owned();
    let clean = |s: &str| !s.chars().any(|c| c == '|' || c.is_whitespace() || c.is_control());
    if version.is_empty() || version.len() > MAX_UPDATE_VERSION_LEN || !clean(&version) {
        return Err(
            "update manifest: version must be non-empty, without '|' or whitespace".to_owned(),
        );
    }
    let mut platforms = std::collections::BTreeMap::new();
    for (k, a) in &m.platforms {
        if k == UPDATE_PLATFORM_WINDOWS || !UPDATE_PLATFORMS.contains(&k.as_str()) {
            return Err(format!("update manifest: unknown platform '{k}'"));
        }
        let (url, sha256) = validate_update_artifact(&a.url, &a.sha256)?;
        platforms.insert(k.clone(), UpdateArtifact { url, sha256 });
    }
    // The Windows installer (top level) may be absent when Linux packages are published.
    let (url, sha256) = if m.url.trim().is_empty() && m.sha256.trim().is_empty() && !platforms.is_empty() {
        (String::new(), String::new())
    } else {
        validate_update_artifact(&m.url, &m.sha256)?
    };
    Ok(UpdateManifest {
        version,
        url,
        sha256,
        platforms,
    })
}

/// One installer's url and sha256, canonicalised: an http(s) url (on this server's
/// origin when api-server is set) and 64 lower-case hex digits.
fn validate_update_artifact(url: &str, sha256: &str) -> Result<(String, String), String> {
    let url = url.trim().to_owned();
    let sha256 = sha256.trim().to_ascii_lowercase();
    let clean = |s: &str| !s.chars().any(|c| c == '|' || c.is_whitespace() || c.is_control());
    let host_and_path = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or("");
    if host_and_path.is_empty() || url.len() > MAX_UPDATE_URL_LEN || !clean(&url) {
        return Err("update manifest: url must be an http(s) URL".to_owned());
    }
    if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("update manifest: sha256 must be 64 hex digits".to_owned());
    }
    // Origin pin. The dashboard tells the operator the URL "must be on this server's
    // origin" and the CLIENT does enforce that, but the server used to accept and
    // SIGN any origin -- so an off-origin manifest was reported as published and then
    // silently discarded by every client. Refuse it here instead, so the operator gets
    // told at save time and the management key never signs a foreign download URL.
    if let Some(expected) = global_policy().options.get("api-server") {
        let expected = expected.trim();
        if !expected.is_empty() {
            match (url_origin(&url), url_origin(expected)) {
                (Some(got), Some(want)) if got != want => {
                    return Err(format!(
                        "update manifest: url must be on this server's origin ({want}), got {got}"
                    ));
                }
                _ => {}
            }
        }
    }
    Ok((url, sha256))
}

/// scheme://host[:port] of an http(s) URL, lowercased. None if it is not http(s).
/// Compared as a parsed origin rather than a prefix, so `https://evil.com/?x=https://good`
/// and `https://good.example.com.evil.com` cannot slip through.
fn url_origin(url: &str) -> Option<String> {
    let (scheme, rest) = if let Some(r) = url.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = url.strip_prefix("http://") {
        ("http", r)
    } else {
        return None;
    };
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .rsplit('@') // drop any userinfo
        .next()
        .unwrap_or("");
    if authority.is_empty() {
        return None;
    }
    Some(format!("{scheme}://{}", authority.to_ascii_lowercase()))
}

// Read the operator's manifest. Ok(None) = nothing published (the file is absent);
// Err = the file exists but is unusable, an operator error that is surfaced as such
// rather than hidden behind a 404.
fn read_update_manifest(path: &std::path::Path) -> Result<Option<UpdateManifest>, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot read {}: {}", path.display(), e)),
    };
    let raw: UpdateManifest = serde_json::from_str(&text)
        .map_err(|e| format!("{} is not a valid update manifest: {}", path.display(), e))?;
    validate_update_manifest(&raw).map(Some)
}

// Public data (every client fetches it unauthenticated), so unlike
// nemo_integration.json this gets no restrict_file: there is nothing to hide.
fn write_update_manifest(path: &std::path::Path, m: &UpdateManifest) -> Result<(), String> {
    let text = serde_json::to_string_pretty(m).map_err(|e| e.to_string())?;
    std::fs::write(path, text).map_err(|e| format!("cannot write {}: {}", path.display(), e))
}

// GET /nemo/api/update/latest — deliberately NO require_auth: every client polls
// it. Signed at request time; 404 when nothing is published.
async fn get_update_latest(
    Extension(state): Extension<HbbsApiState>,
) -> ApiResult<SignedUpdateManifest> {
    let path = std::path::PathBuf::from(update_manifest_path());
    let manifest = read_update_manifest(&path)
        .map_err(|e| {
            log::error!("update manifest not served: {}", e);
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "the update manifest on the server is invalid; ask your administrator to re-publish it",
            )
        })?
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "no update published"))?;
    // Never serve a manifest the server cannot sign: no client would accept it, and
    // an unsigned shape on the wire only invites a client-side "fix" that accepts it.
    let Some(secret_key) = state.server_secret_key.as_ref() else {
        return Err(api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server has no signing key; cannot sign the update manifest",
        ));
    };
    Ok(Json(sign_update_manifest(&manifest, secret_key)))
}

// POST /nemo/api/update (admin): publish a manifest from the dashboard. Validated
// and canonicalised before it touches disk; answers with the signed form so the
// operator sees exactly what clients will receive.
async fn put_update_manifest(
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
    Json(req): Json<UpdateManifest>,
) -> ApiResult<SignedUpdateManifest> {
    require_auth(&headers, &state.token)?;
    let manifest =
        validate_update_manifest(&req).map_err(|e| api_error(StatusCode::BAD_REQUEST, &e))?;
    // Refuse up front rather than publish something no client will ever accept.
    let Some(secret_key) = state.server_secret_key.as_ref() else {
        return Err(api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server has no signing key; cannot sign the update manifest",
        ));
    };
    let path = std::path::PathBuf::from(update_manifest_path());
    write_update_manifest(&path, &manifest).map_err(|e| {
        log::error!("failed to persist update manifest: {}", e);
        server_error(e)
    })?;
    log::info!(
        "Nemo update manifest published: version={} url={}",
        manifest.version,
        manifest.url
    );
    Ok(Json(sign_update_manifest(&manifest, secret_key)))
}

// POST /nemo/api/update/delete (admin): withdraw a published update (a bad build
// must be pullable without shell access to the server). Idempotent.
async fn delete_update_manifest(
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
) -> ApiResult<serde_json::Value> {
    require_auth(&headers, &state.token)?;
    let path = std::path::PathBuf::from(update_manifest_path());
    let removed = match std::fs::remove_file(&path) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => {
            log::error!("failed to remove update manifest {}: {}", path.display(), e);
            return Err(server_error(e));
        }
    };
    if removed {
        log::info!("Nemo update manifest withdrawn");
    }
    Ok(Json(serde_json::json!({ "removed": removed })))
}

// ---- Hosted installers: upload in the dashboard, served by this server ----
//
// The operator uploads the Windows installer; the server stores it under
// --nemo-update-dir (default ./nemo_updates), hashes it and publishes the manifest
// itself, with the url pointing at UPDATE_FILE_ROUTE. A client of 1.4.15+ fetches that
// PATH from the management server it is configured with, not from the host written in
// the url: a server between two NATs is one address to the company network and another
// to the internet, and each client only knows its own. The integrity check is the
// signed sha256, never the URL.

const UPDATE_UPLOAD_ROUTE: &str = "/nemo/api/update/upload";
const UPDATE_FILE_ROUTE: &str = "/nemo/api/update/file";
const MAX_UPDATE_UPLOAD: usize = 160 * 1024 * 1024;

static ADMIN_TOKEN: once_cell::sync::OnceCell<String> = once_cell::sync::OnceCell::new();

fn admin_token_presented(headers: &HeaderMap) -> bool {
    let Some(token) = ADMIN_TOKEN.get() else {
        return false;
    };
    headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|v| constant_time_eq(v, &format!("Bearer {}", token)))
        .unwrap_or(false)
}

fn update_files_dir() -> String {
    get_arg_or("nemo-update-dir", "nemo_updates".to_owned())
}

/// A version that is safe as part of a file name and in the signed manifest.
fn valid_upload_version(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 32
        && v.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
        && !v.starts_with('.')
}

/// The stored file name for `platform`, after checking that `body` is that kind of
/// package (by its magic bytes). Err = a message for the operator.
fn hosted_installer_name(version: &str, platform: &str, body: &[u8]) -> Result<String, String> {
    let (ok, name, what) = match platform {
        "windows-x64" => (
            body.starts_with(b"MZ"),
            format!("tbfdesk-{version}-x64-install.exe"),
            "a Windows installer (tbfdesk-<version>-x64-install.exe)",
        ),
        "linux-deb" => (
            body.starts_with(b"!<arch>\ndebian-binary"),
            format!("tbfdesk-{version}-amd64.deb"),
            "a Debian/Ubuntu package (.deb)",
        ),
        "linux-rpm" => (
            body.starts_with(&[0xED, 0xAB, 0xEE, 0xDB]),
            format!("tbfdesk-{version}-x86_64.rpm"),
            "an RPM package (.rpm)",
        ),
        "linux-arch" => {
            let zst = body.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]);
            let xz = body.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]);
            (
                zst || xz,
                format!("tbfdesk-{version}-x86_64.pkg.tar.{}", if xz { "xz" } else { "zst" }),
                "an Arch package (.pkg.tar.zst)",
            )
        }
        _ => return Err(format!("unknown platform '{platform}' (one of {})", UPDATE_PLATFORMS.join(", "))),
    };
    if body.len() < 64 * 1024 || !ok {
        return Err(format!("that is not {what}"));
    }
    Ok(name)
}

/// Every file a manifest refers to (for pruning the update directory).
fn manifest_files(m: &UpdateManifest) -> Vec<String> {
    std::iter::once(m.url.as_str())
        .chain(m.platforms.values().map(|a| a.url.as_str()))
        .filter(|u| !u.is_empty())
        .filter_map(|u| u.rsplit('/').next().map(str::to_owned))
        .collect()
}

/// The origin written into the manifest url. Only clients older than 1.4.15 use it
/// (newer ones take the path and their own server address): the configured api-server
/// if there is one (validate_update_manifest pins it), else the address the operator's
/// browser used.
fn upload_origin(headers: &HeaderMap, uri: &axum::http::Uri) -> Option<String> {
    if let Some(api) = global_policy().options.get("api-server") {
        if let Some(o) = url_origin(api.trim()) {
            return Some(o);
        }
    }
    if let Some(o) = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .and_then(url_origin)
    {
        return Some(o);
    }
    // HTTP/2 carries the address as the request's :authority, not as a Host header.
    if let Some(authority) = uri.authority() {
        return url_origin(&format!("{}://{}", uri.scheme_str().unwrap_or("https"), authority));
    }
    let host = headers.get(axum::http::header::HOST)?.to_str().ok()?;
    url_origin(&format!("https://{host}"))
}

fn sha256_hex(data: &[u8]) -> String {
    sodiumoxide::crypto::hash::sha256::hash(data)
        .0
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[derive(Deserialize)]
struct UpdateUploadQuery {
    #[serde(default)]
    version: String,
    /// windows-x64 (default), linux-deb, linux-rpm or linux-arch.
    #[serde(default)]
    platform: String,
}

// POST /nemo/api/update/upload?version=1.4.16&platform=linux-deb (admin), body = the
// installer or package. Stores it, publishes it in the signed manifest, and answers with
// what clients will receive. A release is one version: the same version adds or replaces
// that platform's file; a newer version starts a new release (upload each platform
// again); an older one is refused.
async fn upload_update_installer(
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Query(q): Query<UpdateUploadQuery>,
    body: axum::body::Bytes,
) -> ApiResult<SignedUpdateManifest> {
    require_auth(&headers, &state.token)?;
    let version = q.version.trim().to_owned();
    if !valid_upload_version(&version) {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "version must be 1-32 characters of letters, digits, '.', '-' or '_' (e.g. 1.4.15)",
        ));
    }
    let platform = if q.platform.trim().is_empty() {
        UPDATE_PLATFORM_WINDOWS.to_owned()
    } else {
        q.platform.trim().to_owned()
    };
    let name = hosted_installer_name(&version, &platform, &body)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e))?;
    let previous = read_update_manifest(std::path::Path::new(&update_manifest_path()))
        .ok()
        .flatten();
    if let Some(prev) = previous.as_ref() {
        if hbb_common::get_version_number(&version) < hbb_common::get_version_number(&prev.version) {
            return Err(api_error(
                StatusCode::CONFLICT,
                &format!(
                    "{version} is older than the published {}; withdraw that first",
                    prev.version
                ),
            ));
        }
    }
    let Some(secret_key) = state.server_secret_key.as_ref() else {
        return Err(api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server has no signing key; cannot sign the update manifest",
        ));
    };
    let Some(origin) = upload_origin(&headers, &uri) else {
        return Err(api_error(StatusCode::BAD_REQUEST, "cannot tell this server's address from the request"));
    };
    let dir = std::path::PathBuf::from(update_files_dir());
    let sha256 = sha256_hex(&body);
    {
        let dir = dir.clone();
        let name = name.clone();
        let body = body.clone();
        tokio::task::spawn_blocking(move || -> Result<(), String> {
            std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
            // Written aside and renamed, so a client never downloads half a file.
            let tmp = dir.join(format!(".{name}.part"));
            std::fs::write(&tmp, &body).map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
            std::fs::rename(&tmp, dir.join(&name)).map_err(|e| format!("cannot store {name}: {e}"))
        })
        .await
        .map_err(server_error)?
        .map_err(|e| {
            log::error!("installer upload not stored: {e}");
            server_error(e)
        })?;
    }
    // Same version: add to that release. Newer (or nothing published): a new release.
    let mut next = match previous.as_ref() {
        Some(prev) if prev.version == version => prev.clone(),
        _ => UpdateManifest {
            version: version.clone(),
            ..Default::default()
        },
    };
    let url = format!("{origin}{UPDATE_FILE_ROUTE}/{name}");
    if platform == UPDATE_PLATFORM_WINDOWS {
        next.url = url;
        next.sha256 = sha256.clone();
    } else {
        next.platforms.insert(platform.clone(), UpdateArtifact { url, sha256: sha256.clone() });
    }
    let manifest =
        validate_update_manifest(&next).map_err(|e| api_error(StatusCode::BAD_REQUEST, &e))?;
    write_update_manifest(std::path::Path::new(&update_manifest_path()), &manifest).map_err(|e| {
        log::error!("failed to persist update manifest: {}", e);
        server_error(e)
    })?;
    // Keep every file of the new release and of the one before it (a client may be
    // halfway through downloading that); older uploads go.
    let mut keep = manifest_files(&manifest);
    if let Some(prev) = previous.as_ref() {
        keep.extend(manifest_files(prev));
    }
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for e in entries.flatten() {
            let f = e.file_name().to_string_lossy().to_string();
            if f.starts_with("tbfdesk-") && !keep.contains(&f) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    log::info!(
        "Nemo update {} for {} uploaded ({} bytes, sha256 {}) and published",
        version,
        platform,
        body.len(),
        sha256
    );
    Ok(Json(sign_update_manifest(&manifest, secret_key)))
}

// Verify a client's device-key signature over "{domain}:{id}:{ts}" (domain is
// "nemo-poll" for the policy poll, "nemo-ab" for the address-book fetch and, Layer
// 1, "nemo-login" for the sign-in — distinct domains so a captured signature for
// one cannot be replayed against another endpoint). True only if the public key is pinned, its M1 binding (if any)
// matches the claimed peer id, the signature is valid, the id matches, and the ts
// is fresh (replay window). A non-numeric ts is REJECTED (it used to silently skip
// the freshness check).
fn verify_device_signature(pub_b64: &str, sig_b64: &str, domain: &str, id: &str) -> bool {
    verify_device_signature_proof(pub_b64, sig_b64, domain, id).ok
}

/// The result of checking a device proof. `claim` is set when the request proved a
/// pinned-but-unbound key and therefore filed a binding REQUEST (M1-CLAIM): `ok` is
/// still false — a pending claim grants nothing — but the handler reports a different
/// refusal for it, so the client can say "waiting for your administrator" instead of
/// showing a bare 403, and audits the moment a new one is filed.
struct DeviceProof {
    ok: bool,
    claim: Option<integration::PendingOutcome>,
}

const PROOF_REFUSED: DeviceProof = DeviceProof {
    ok: false,
    claim: None,
};

/// Which endpoint a binding request came in on, for the dashboard's pending row. Taken
/// from the signature domain so it cannot disagree with what was actually verified.
fn claim_via_label(domain: &str) -> &'static str {
    match domain {
        "nemo-poll" => "settings poll",
        "nemo-ab" => "address book",
        "nemo-login" => "sign-in",
        "nemo-audit" => "audit upload",
        _ => "management API",
    }
}

fn verify_device_signature_proof(
    pub_b64: &str,
    sig_b64: &str,
    domain: &str,
    id: &str,
) -> DeviceProof {
    if !integration::is_device_key_pinned(pub_b64) {
        return PROOF_REFUSED;
    }
    // TASK #14: the binding rule is shared with the rendezvous handshake
    // (integration::device_key_binding_decision): a bound key authenticates only its
    // peer; an unbound one is a one-shot provisioning token when claiming is on
    // (M1-CLAIM), and nothing at all when it is off, unless
    // --allow-unbound-device-keys is set.
    let Some(bound) = integration::device_key_binding(pub_b64) else {
        return PROOF_REFUSED; // unpinned (racing delete)
    };
    let claim_needed = match integration::device_key_binding_decision(
        &bound,
        id,
        integration::allow_unbound_device_keys(),
        integration::claim_unbound_device_keys(),
    ) {
        integration::BindingDecision::Proven => false,
        integration::BindingDecision::ClaimOnProof => true,
        integration::BindingDecision::Refused(reason) => {
            log::debug!("device signature refused: {}", reason);
            return PROOF_REFUSED;
        }
    };
    let (Ok(pk_bytes), Ok(sig_bytes)) =
        (base64::decode(pub_b64.trim()), base64::decode(sig_b64.trim()))
    else {
        return PROOF_REFUSED;
    };
    let Some(pk) = sign::PublicKey::from_slice(&pk_bytes) else {
        return PROOF_REFUSED;
    };
    let Ok(msg) = sign::verify(&sig_bytes, &pk) else {
        return PROOF_REFUSED;
    };
    let msg = String::from_utf8_lossy(&msg);
    let parts: Vec<&str> = msg.splitn(3, ':').collect();
    if parts.len() != 3 || parts[0] != domain || parts[1] != id {
        return PROOF_REFUSED;
    }
    let Ok(ts) = parts[2].parse::<u64>() else {
        return PROOF_REFUSED;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if now.saturating_sub(ts) > 300 || ts.saturating_sub(now) > 60 {
        return PROOF_REFUSED;
    }
    // M1-CLAIM: the signature is valid, fresh, for this domain AND for the id the
    // client claims — only now may it ASK for the token. Filing the request after the
    // checks above is the whole security argument: a claim requires the private half,
    // so naming someone else's unclaimed key cannot take it or even raise a request
    // against it. The request is not the grant: this request stays refused, which is
    // what keeps the TASK #14 rule intact for every client the operator has not yet
    // confirmed.
    if claim_needed {
        let outcome = integration::register_pending_claim(
            pub_b64,
            id,
            claim_via_label(domain),
            now_iso(),
        );
        return DeviceProof {
            ok: false,
            claim: Some(outcome),
        };
    }
    DeviceProof {
        ok: true,
        claim: None,
    }
}

// TASK-25: the client's audit uploads (connection open/close/login, file
// transfers, login-failure alarms, controller notes). Authenticated like the
// policy poll's device proof under its own domain "nemo-audit"; no key = no
// event, deliberately (an unproven audit line is worse than none). Recorded in
// the events ring the dashboard shows (/nemo/api/events): in-memory, bounded by
// log_history_limit(), like every other event there.
// "direct": a CONTROLLER's report of one attempt at a published direct endpoint. A direct
// session never touches the rendezvous, so without it the server has no record of the
// sessions that matter most (see record_direct_report).
const CLIENT_AUDIT_KINDS: &[&str] = &["conn", "file", "alarm", "direct"];
const MAX_AUDIT_DETAIL: usize = 4096;

// The proven peer id of an audit body, or None when the body carries no valid
// device-key proof for the id it claims.
fn client_audit_identity(body: &serde_json::Value) -> Option<String> {
    let f = |k: &str| body.get(k).and_then(|v| v.as_str()).unwrap_or("").trim().to_owned();
    let (id, pub_b64, sig_b64) = (f("id"), f("device_key_pub"), f("device_key_sig"));
    if id.is_empty() || !verify_device_signature(&pub_b64, &sig_b64, "nemo-audit", &id) {
        return None;
    }
    Some(id)
}

/// TASK #19 at the HTTP routes: a session bound to a device key may only be
/// spent by a request that proved THAT key. Unbound sessions (issued while
/// require_device_key was off) pass, as at the rendezvous gate.
fn session_device_binding_ok(bound: &str, proven: Option<&str>) -> bool {
    bound.is_empty() || proven == Some(bound)
}

fn verify_device_key(request: &ClientPolicyRequest) -> DeviceProof {
    let (Some(pub_b64), Some(sig_b64)) = (
        request.device_key_pub.as_deref(),
        request.device_key_sig.as_deref(),
    ) else {
        return PROOF_REFUSED;
    };
    verify_device_signature_proof(pub_b64, sig_b64, "nemo-poll", &request.id)
}

// TASK-25: the event detail of an audit body: everything but the proof fields,
// bounded so a file audit (10 names + paths + info) cannot bloat the ring.
fn client_audit_detail(body: &mut serde_json::Value) -> String {
    if let Some(obj) = body.as_object_mut() {
        obj.remove("device_key_pub");
        obj.remove("device_key_sig");
    }
    let mut detail = body.to_string();
    if detail.len() > MAX_AUDIT_DETAIL {
        let mut cut = MAX_AUDIT_DETAIL;
        while !detail.is_char_boundary(cut) {
            cut -= 1;
        }
        detail.truncate(cut);
        detail.push_str("...");
    }
    detail
}

// S-B/S-DUALKEY step 3: seal `data` to a client's Ed25519 device key with a NaCl
// sealedbox (Ed25519 -> Curve25519 conversion). Returns base64 ciphertext, or None
// if the key is unusable — the caller must then FAIL CLOSED (never fall back to
// sending the plaintext it meant to seal).
fn seal_to_device_key(pub_b64: &str, data: &[u8]) -> Option<String> {
    let pk_bytes = base64::decode(pub_b64.trim()).ok()?;
    let pk = sign::PublicKey::from_slice(&pk_bytes)?;
    let curve_pk = sign::to_curve25519_pk(&pk).ok()?;
    Some(base64::encode(sealedbox::seal(data, &curve_pk)))
}

// A1: open a request secret the client sealed to our MANAGEMENT key (the client sealed
// to the Curve25519 form of `server_public_key`; we open with the Curve25519 form of our
// Ed25519 secret key + public key). Returns the plaintext, or None on any failure.
fn open_sealed_to_mgmt_key(state: &HbbsApiState, sealed_b64: &str) -> Option<Vec<u8>> {
    let sk = state.server_secret_key.as_ref()?;
    let curve_sk = sign::to_curve25519_sk(sk).ok()?;
    let pk_bytes = base64::decode(state.server_public_key.trim()).ok()?;
    let pk = sign::PublicKey::from_slice(&pk_bytes)?;
    let curve_pk = sign::to_curve25519_pk(&pk).ok()?;
    let ciphertext = base64::decode(sealed_b64.trim()).ok()?;
    sealedbox::open(&ciphertext, &curve_pk, &curve_sk).ok()
}

// S-B (scope b): the pure half of the sealed request envelope — parse the opened
// plaintext and apply the freshness/replay rules. Split out exactly like
// sealed_login_guard so the wire contract is unit-testable without an HbbsApiState.
// Returns the inner JSON object: the body this request would have been today, plus
// the envelope's own "ts"/"nonce" (harmless - none of the typed request structs deny
// unknown fields).
fn parse_sealed_request(
    plain: &[u8],
    now: u64,
    seen: &mut HashMap<String, u64>,
) -> Result<serde_json::Value, String> {
    let inner: serde_json::Value =
        serde_json::from_slice(plain).map_err(|_| "invalid sealed request payload".to_owned())?;
    // A missing or non-numeric ts stays 0, which the guard rejects — fail closed.
    let ts = inner.get("ts").and_then(|v| v.as_u64()).unwrap_or(0);
    let nonce = inner.get("nonce").and_then(|v| v.as_str()).unwrap_or("");
    sealed_request_guard(ts, nonce, now, seen)?;
    Ok(inner)
}

// S-B (scope b): what to do with a body that carries NO envelope. Pure (and so
// testable) because this is the R3 default path: require_sealed_request ships false,
// and then today's plaintext body is passed through byte-identical.
fn unsealed_request_body(
    body: serde_json::Value,
    require_sealed: bool,
) -> Result<serde_json::Value, String> {
    if require_sealed {
        return Err(
            "this server requires an encrypted request; please update TBFDesk on this computer"
                .to_owned(),
        );
    }
    Ok(body)
}

// S-B (scope b): the ONE envelope entry point, shared by the policy poll and
// /api/ab/get. A seal-capable client replaces its whole POST body with
// {"sealed_request": "<base64 sealedbox to the management key>"}, so nothing it sends
// is readable on the wire. Returns the body the caller should continue with:
//   * envelope present -> the opened inner JSON. The OUTER body is attacker-writable and
//     is never merged into it. NOTE: a sealedbox is ANONYMOUS — anyone holding the
//     management PUBLIC key can produce a valid envelope, so opening one proves
//     confidentiality, NOT sender identity. Callers must still authenticate the request
//     on its own terms (the poll via validate_client_policy_request, /api/ab/get via the
//     session token and verify_device_signature). Do not treat "it opened" as "it is
//     from a legitimate client".
//   * no envelope -> today's plaintext body, unless the operator turned on
//     require_sealed_request, in which case this fails closed.
fn resolve_request_body(
    state: &HbbsApiState,
    body: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let sealed = body
        .get("sealed_request")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_owned();
    if sealed.is_empty() {
        return unsealed_request_body(body, integration::require_sealed_request());
    }
    // Review finding (memory/CPU exhaustion): this runs BEFORE any peer lookup, so it is
    // unauthenticated work. A real envelope is a sealedbox over a small JSON object; cap
    // it so an attacker cannot make us base64-decode and open a huge blob per request.
    // (The whole-body limit belongs on the router, but axum 0.5's RequestBodyLimitLayer
    // changes the body type for every handler — tracked separately.)
    if sealed.len() > MAX_SEALED_REQUEST_B64 {
        return Err("sealed request envelope is too large".to_owned());
    }
    let plain = open_sealed_to_mgmt_key(state, &sealed)
        .ok_or_else(|| "sealed request could not be opened (wrong management key?)".to_owned())?;
    parse_sealed_request(
        &plain,
        now_epoch_secs(),
        &mut SEEN_REQUEST_NONCES.lock().unwrap(),
    )
}

// A1: the effective session token for this poll — prefer the sealed one (confidential
// regardless of TLS), fall back to the plaintext field for older clients / no mgmt key.
fn resolve_access_token(state: &HbbsApiState, request: &ClientPolicyRequest) -> Option<String> {
    #[derive(Deserialize)]
    struct SealedToken {
        token: String,
    }
    if let Some(sealed) = request.sealed_token.as_deref() {
        if !sealed.trim().is_empty() {
            let opened = open_sealed_to_mgmt_key(state, sealed)?;
            let parsed: SealedToken = serde_json::from_slice(&opened).ok()?;
            return Some(parsed.token);
        }
    }
    request.access_token.clone().filter(|t| !t.trim().is_empty())
}

// H4: remove secret values from a policy that is about to leave the server WITHOUT
// device-key sealing. Returns how many secrets were stripped.
fn strip_secret_options(policy: &mut ManagementPolicy) -> usize {
    let mut stripped = 0;
    for key in SECRET_POLICY_KEYS {
        if policy.options.remove(*key).is_some() {
            stripped += 1;
        }
    }
    stripped
}

// ---- Named policies (reusable templates assignable to users + devices) ----

#[derive(Serialize)]
struct PoliciesResponse {
    policies: HashMap<String, integration::UserManagedPolicy>,
    device_policies: HashMap<String, String>,
}

#[derive(Deserialize)]
struct PoliciesUpdate {
    #[serde(default)]
    policies: HashMap<String, integration::UserManagedPolicy>,
}

#[derive(Deserialize)]
struct DevicePolicyUpdate {
    peer_id: String,
    #[serde(default)]
    policy_name: Option<String>,
}

fn policies_response() -> PoliciesResponse {
    PoliciesResponse {
        policies: integration::list_policies(),
        device_policies: integration::list_device_policies(),
    }
}

async fn get_policies(
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
) -> ApiResult<PoliciesResponse> {
    require_auth(&headers, &state.token)?;
    Ok(Json(policies_response()))
}

// Full replace of the named-policy DEFINITIONS. Device assignments and users'
// policy_name references are left intact (dangling references fall back).
async fn put_policies(
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
    Json(update): Json<PoliciesUpdate>,
) -> ApiResult<PoliciesResponse> {
    require_auth(&headers, &state.token)?;
    integration::set_policies(update.policies);
    Ok(Json(policies_response()))
}

// Set or clear ONE device -> named-policy assignment (from the Peers tab), so the
// per-peer assignment never clobbers the whole map or the policy definitions.
async fn set_device_policy_route(
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
    Json(update): Json<DevicePolicyUpdate>,
) -> ApiResult<PoliciesResponse> {
    require_auth(&headers, &state.token)?;
    integration::set_device_policy(update.peer_id.trim(), update.policy_name.as_deref());
    Ok(Json(policies_response()))
}

// ---- Global client policy (pushed to every client) ----

fn global_policy_path() -> String {
    get_arg_or("nemo-global-policy-file", "nemo_global_policy.json".to_owned())
}

fn load_global_policy() -> ManagementPolicy {
    match std::fs::read_to_string(global_policy_path()) {
        Ok(text) => serde_json::from_str::<ManagementPolicy>(&text)
            .map(sanitize_management_policy)
            .unwrap_or_default(),
        Err(_) => ManagementPolicy::default(),
    }
}

fn global_policy() -> ManagementPolicy {
    GLOBAL_POLICY.read().unwrap().clone()
}

fn save_global_policy(policy: &ManagementPolicy) {
    match serde_json::to_string_pretty(policy) {
        Ok(text) => {
            let path = global_policy_path();
            if let Err(e) = std::fs::write(&path, text) {
                log::error!("failed to persist global policy to {}: {}", path, e);
            }
        }
        Err(e) => log::error!("failed to serialize global policy: {}", e),
    }
}

async fn get_global_policy(
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
) -> ApiResult<ManagementPolicy> {
    require_auth(&headers, &state.token)?;
    // S4 masking applied to the GLOBAL policy too. It was only applied per-peer, which
    // was survivable while the global policy held nothing secret — the knock keys (shared
    // secrets with the fwknopd on the edge, and the natural thing to set fleet-wide) make
    // that no longer true.
    Ok(Json(mask_secret_policy(global_policy())))
}

async fn put_global_policy(
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
    Json(request): Json<ManagementPolicyRequest>,
) -> ApiResult<ManagementPolicy> {
    require_auth(&headers, &state.token)?;
    let policy = sanitize_management_policy(ManagementPolicy {
        allow_user_override: request.allow_user_override,
        options: request.options,
    });
    // The dashboard was shown masks, so it sends masks back for anything it did not
    // change. Without this a round-trip through the form would store the literal
    // "<managed-secret>" as the fleet's SPA key and every knock would be rejected.
    let policy = restore_masked_secrets_from(policy, &global_policy());
    *GLOBAL_POLICY.write().unwrap() = policy.clone();
    save_global_policy(&policy);
    Ok(Json(mask_secret_policy(policy)))
}

// ---- Live connections (see + cut) ----

#[derive(Serialize)]
struct ConnectionResponse {
    source_id: String,
    target_id: String,
    source_addr: String,
    target_addr: String,
    path: String,
    relay_server: String,
    nat_type: String,
    age_ms: u64,
    duration_ms: u64,
    negotiations: u64,
}

#[derive(Serialize, Default)]
struct ConnectionTotals {
    active: usize,
    direct: usize,
    relay: usize,
}

#[derive(Serialize)]
struct ConnectionsResponse {
    connections: Vec<ConnectionResponse>,
    totals: ConnectionTotals,
}

async fn get_connections(
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
) -> ApiResult<ConnectionsResponse> {
    require_auth(&headers, &state.token)?;
    let store = STATS.read().await;
    let now = std::time::Instant::now();
    let mut connections: Vec<ConnectionResponse> = store
        .connections
        .iter()
        .map(|c| ConnectionResponse {
            source_id: c.source_id.clone(),
            target_id: c.target_id.clone(),
            source_addr: c.source_addr.clone(),
            target_addr: c.target_addr.clone(),
            path: c.path.clone(),
            relay_server: c.relay_server.clone(),
            nat_type: c.nat_type.clone(),
            age_ms: now.duration_since(c.last_seen).as_millis() as u64,
            duration_ms: c.last_seen.duration_since(c.first_seen).as_millis() as u64,
            negotiations: c.negotiations,
        })
        .collect();
    connections.sort_by_key(|c| c.age_ms); // most recent first
    let direct = connections
        .iter()
        .filter(|c| c.path.starts_with("direct") && c.path != "direct-failed")
        .count();
    let relay = connections.iter().filter(|c| c.path == "relay").count();
    let totals = ConnectionTotals {
        active: connections.len(),
        direct,
        relay,
    };
    Ok(Json(ConnectionsResponse {
        connections,
        totals,
    }))
}

#[derive(Deserialize)]
struct CutConnectionRequest {
    target_id: String,
    #[serde(default)]
    source_id: Option<String>,
}

/// H23 / M69: end the live sessions that the given CONTROLLER machines hold, by
/// issuing a session revocation to every target the connection store shows them
/// connected to (the same lever /connections/cut pulls, without blocking the
/// target). The target ends all its authenticated sessions older than the
/// revocation on its next poll, so other controllers there reconnect too:
/// over-revocation, never under. Returns the targets revoked.
async fn terminate_sessions_from_controllers(controllers: &[String], why: &str) -> Vec<String> {
    if controllers.is_empty() {
        return Vec::new();
    }
    let mut store = STATS.write().await;
    let mut targets: Vec<String> = Vec::new();
    for c in store.connections.iter() {
        if controllers.contains(&c.source_id) && !targets.contains(&c.target_id) {
            targets.push(c.target_id.clone());
        }
    }
    for t in &targets {
        let ts = set_peer_terminate(t);
        let detail = format!("sessions revoked as of {} ({}; controllers {:?})", ts, why, controllers);
        record_event_locked(&mut store, "connection-cut", Some(t), None, detail);
    }
    store.connections.retain(|c| !controllers.contains(&c.source_id));
    targets
}

async fn cut_connection(
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
    Json(req): Json<CutConnectionRequest>,
) -> ApiResult<PeerPolicyResponse> {
    require_auth(&headers, &state.token)?;
    // TODO 25: cut ENDS the live sessions, and changes nothing else.
    //
    // It used to also write status=0, i.e. BLOCK the target. So an operator who cut one
    // screen-share found the machine locked out of the fleet afterwards and had to go
    // and allow it again -- a permanent admission change for what reads as "hang up
    // this call". Admission stays the separate, explicit Block action the Peers panel
    // already has; an operator who wants both presses both.
    //
    // The lever that actually ends a session in progress is the revocation below: a
    // direct session has no server-side data path to interrupt, so the teardown is
    // performed by the controlled machine on its next management poll -- which is the
    // right place anyway, since that is the asset the operator owns and the controller
    // cannot veto it.
    //
    // The peer is looked up first so an unknown id still answers 404 (the contract the
    // dashboard and the API reference describe) instead of silently writing a
    // revocation for an id that was never registered.
    if state
        .pm
        .get_registered(&req.target_id)
        .await
        .map_err(server_error)?
        .is_none()
    {
        return Err(api_error(StatusCode::NOT_FOUND, "peer not found"));
    }
    let terminate_ts = set_peer_terminate(&req.target_id);
    {
        let mut store = STATS.write().await;
        store.connections.retain(|c| c.target_id != req.target_id);
        let detail = match &req.source_id {
            Some(s) => format!(
                "cut sessions of target {} (source {}) from dashboard; revoked as of {} \
                 (admission unchanged)",
                req.target_id, s, terminate_ts
            ),
            None => format!(
                "cut sessions of target {} from dashboard; revoked as of {} \
                 (admission unchanged)",
                req.target_id, terminate_ts
            ),
        };
        record_event_locked(&mut store, "connection-cut", Some(&req.target_id), None, detail);
    }
    // The peer's policy, UNCHANGED -- so the dashboard's peer row does not flip to
    // "blocked" after a cut.
    let status = state
        .pm
        .peer_status(&req.target_id)
        .await
        .map_err(server_error)?;
    Ok(Json(peer_policy_response(req.target_id.clone(), status)))
}

pub(crate) fn company_only() -> bool {
    COMPANY_ONLY.load(Ordering::SeqCst)
}

fn conn_history_limit() -> usize {
    CONN_HISTORY_LIMIT.load(Ordering::SeqCst)
}

#[cfg(test)]
pub(crate) fn set_conn_history_limit_for_test(value: usize) {
    CONN_HISTORY_LIMIT.store(value, Ordering::SeqCst);
}

/// Test-only setter for the process-global company-only flag, so cross-module
/// tests (e.g. the rendezvous handler tests) can pin it deterministically.
#[cfg(test)]
pub(crate) fn set_company_only_for_test(value: bool) {
    COMPANY_ONLY.store(value, Ordering::SeqCst);
}

pub(crate) async fn is_peer_blocked(pm: &PeerMap, id: &str) -> bool {
    pm.is_peer_blocked(id).await
}

// Every currently-blocked TBFDesk ID, pushed to clients (#2) so a controlled
// machine can reject incoming connections from a blocked source even if that
// source bypasses the server. (Small deployments: a per-poll scan is fine; add a
// bump-on-change cache if the peer table ever grows large.)
async fn list_blocked_ids(pm: &PeerMap) -> Vec<String> {
    match pm.list_registered(100_000, 0).await {
        Ok(peers) => peers
            .into_iter()
            .filter(|p| matches!(p.status, Some(0)))
            .map(|p| p.id)
            .collect(),
        Err(e) => {
            log::error!("list_blocked_ids failed: {}", e);
            Vec::new()
        }
    }
}

// B (encrypted direct-IP): build the `{id -> Ed25519 pubkey}` map pushed to clients so a
// controller can verify a direct-IP peer's self-signed SignedId and establish an
// encrypted session with NO rendezvous broker (server-anchored, no TOFU/MITM window).
// Format: "id,pkB64;id,pkB64" (pk = the peer's registered identity key). The keys are
// public and the whole map rides inside the signed client policy, so it can't be forged.
// (Small deployments: a per-poll scan is fine; add a bump-on-change cache if the peer
// table ever grows large, same as `list_blocked_ids`.)
async fn peer_key_map(pm: &PeerMap) -> String {
    match pm.list_registered(100_000, 0).await {
        Ok(peers) => peers
            .into_iter()
            .filter(|p| p.pk.len() == 32)
            .map(|p| format!("{},{}", p.id, base64::encode(&p.pk)))
            .collect::<Vec<_>>()
            .join(";"),
        Err(e) => {
            log::error!("peer_key_map failed: {}", e);
            String::new()
        }
    }
}

pub(crate) async fn is_peer_allowed(pm: &PeerMap, id: &str) -> bool {
    pm.is_peer_allowed_for_control(id, company_only()).await
}

fn target_allowed_by_controller_policy(targets: Option<&String>, target_id: &str) -> bool {
    let Some(targets) = targets else {
        return true;
    };
    if targets.trim().is_empty() {
        return true;
    }
    targets
        .split(|ch: char| ch == ',' || ch == ';' || ch.is_whitespace())
        .map(str::trim)
        .filter(|target| !target.is_empty())
        .any(|target| target == "*" || target == target_id)
}

// Parse the smuggled controller identity: `nemo-source-v1:<id>:<b64 uuid>[:<user
// token>]`. The optional trailing token is the logged-in user's session token,
// used to enforce the per-user connection ACL / require-login at the punch.
fn controller_source_identity(source_field: &str) -> Option<(String, Vec<u8>, Option<String>)> {
    let start = source_field.find(NEMO_SOURCE_PREFIX)? + NEMO_SOURCE_PREFIX.len();
    // The source marker is a single whitespace-free token.
    let payload = source_field[start..].split_whitespace().next()?;
    let mut parts = payload.splitn(3, ':');
    let source_id = parts.next()?.trim();
    let source_uuid = parts.next()?.trim();
    let token = parts
        .next()
        .map(|t| t.trim().to_owned())
        .filter(|t| !t.is_empty());
    if source_id.is_empty() || source_uuid.is_empty() {
        return None;
    }
    let source_uuid = base64::decode(source_uuid).ok()?;
    Some((source_id.to_owned(), source_uuid, token))
}

/// TODO 8: the controller identity, from the TYPED field when the client sends one and
/// from the legacy smuggled marker otherwise.
///
/// Both are client-asserted and neither is proved - what proves a controller is the
/// device-key handshake, which `resolve_controller_identity` prefers over either of
/// these. So this is only about which of the two the client managed to express, and the
/// typed field wins because it cannot be confused with the version string it used to
/// share. A client that sends both and disagrees with itself is a bug worth seeing in
/// the log, not a refusal: the gates run on one of the two either way.
fn controller_source_any(
    proto: Option<&NemoSource>,
    source_field: &str,
) -> Option<(String, Vec<u8>, Option<String>)> {
    let legacy = controller_source_identity(source_field);
    let Some(src) = proto.filter(|s| !s.id.trim().is_empty()) else {
        return legacy;
    };
    if let Some((claimed, _, _)) = legacy.as_ref() {
        if claimed != src.id.trim() {
            log::warn!(
                "controller sent NemoSource id {} and legacy marker id {}; using the field",
                src.id.trim(),
                claimed
            );
        }
    }
    Some((
        src.id.trim().to_owned(),
        src.uuid.to_vec(),
        Some(src.token.trim().to_owned()).filter(|t| !t.is_empty()),
    ))
}

// Per-user connection ACL + require-login, enforced at the punch. `token` is the
// controller's logged-in user session token (if any).
fn nemo_user_connection_rejection(
    token: Option<&str>,
    authed_device_pub: Option<&str>,
    target_id: &str,
) -> Option<String> {
    let user = token
        .and_then(integration::session_for_token)
        .filter(|s| integration::user_is_enabled(&s.username));
    match user {
        Some(session) => {
            // TASK #19: the token is bound to the key that proved its login; only a
            // connection that proved THAT key (AuthedDevice) may spend it. No proof =
            // refused (fail closed). Unbound sessions: require_device_key off only.
            if !session.device_key_pub.is_empty()
                && authed_device_pub != Some(session.device_key_pub.as_str())
            {
                log::warn!(
                    "user '{}' spent a token bound to key {}... on a connection proving {}",
                    session.username,
                    &session.device_key_pub[..session.device_key_pub.len().min(12)],
                    if authed_device_pub.is_some() { "another key" } else { "no key" },
                );
                return Some("this sign-in is bound to another computer; sign in again from this one".to_owned());
            }
            let (is_admin, allowed) = integration::effective_permission(&session.username);
            if integration::user_allowed_target(is_admin, &allowed, target_id) {
                None
            } else {
                Some("you are not permitted to connect to this computer".to_owned())
            }
        }
        None => {
            if integration::require_login() {
                Some("log in to TBFDesk to connect".to_owned())
            } else {
                None
            }
        }
    }
}

/// User-level connection check from the smuggled source field. Returns
/// `Some((source_id, reason))` when the connection must be refused.
/// Map a resolved session policy onto the wire ControlPermissions bitmask.
///
/// Encoding (must match the client's `get_control_permission`): two bits per
/// permission at `enum_value * 2` — 1 = disable, 2 = enable, 0 = not set. "Not set"
/// is meaningful: the client then falls back to the CONTROLLED machine's own local
/// setting, so a policy that says nothing about a permission does not silently grant it.
const CONTROL_PERMISSION_KEYS: &[(&str, control_permissions::Permission)] = &[
    ("enable-keyboard", control_permissions::Permission::keyboard),
    ("enable-remote-printer", control_permissions::Permission::remote_printer),
    ("enable-clipboard", control_permissions::Permission::clipboard),
    ("enable-file-transfer", control_permissions::Permission::file),
    ("enable-audio", control_permissions::Permission::audio),
    ("enable-camera", control_permissions::Permission::camera),
    ("enable-terminal", control_permissions::Permission::terminal),
    ("enable-tunnel", control_permissions::Permission::tunnel),
    ("enable-remote-restart", control_permissions::Permission::restart),
    ("enable-record-session", control_permissions::Permission::recording),
    ("enable-block-input", control_permissions::Permission::block_input),
    ("enable-privacy-mode", control_permissions::Permission::privacy_mode),
    ("allow-remote-config-modification", control_permissions::Permission::remote_modify),
];

/// Build the per-connection ControlPermissions for the controller behind `source_field`.
///
/// Until now the server could not do this at all: `ControlPermissions` did not exist in
/// the server's copy of rendezvous.proto, so the field was dropped on the wire and every
/// connection arrived with `control_permissions: None` — i.e. the fork's per-session
/// permission feature was inert and only the target's own local toggles applied.
///
/// Returns None when no logged-in user can be resolved, or when their policy says
/// nothing about any permission. None is the correct "no opinion" answer — it leaves the
/// controlled machine's local settings in charge rather than implicitly granting access.
/// TODO 7/8: just the controller's asserted id, for attribution (a metric, a log line,
/// a relay-session row) rather than for a gate. Gates go through
/// `resolve_controller_identity`, which prefers the PROVED identity over this.
pub(crate) fn controller_source_id(proto: Option<&NemoSource>, source_field: &str) -> String {
    controller_source_any(proto, source_field)
        .map(|(id, _, _)| id)
        .unwrap_or_default()
}

pub(crate) fn control_permissions_for(
    proto: Option<&NemoSource>,
    source_field: &str,
) -> Option<ControlPermissions> {
    let (_, _, token) = controller_source_any(proto, source_field)?;
    let session = integration::session_for_token(token.as_deref()?)?;
    if !integration::user_is_enabled(&session.username) {
        return None;
    }
    let bits = control_bits_for_user(&session.username);
    if bits == 0 {
        return None;
    }
    Some(ControlPermissions {
        permissions: bits,
        ..Default::default()
    })
}

/// The ControlPermissions bits a user's policy decides (0 = decides nothing). Shared by
/// the rendezvous (control_permissions_for) and the control ticket, so a direct session
/// gets exactly the permissions a relayed one would.
fn control_bits_for_user(username: &str) -> u64 {
    use hbb_common::protobuf::Enum;
    let policy = integration::user_policy(username);
    let mut bits: u64 = 0;
    for (key, permission) in CONTROL_PERMISSION_KEYS {
        let Some(value) = policy.options.get(*key) else {
            continue; // not mentioned -> leave the two bits at 0 (not set)
        };
        let index = permission.value();
        if !(0..32).contains(&index) {
            continue;
        }
        // Same truthiness the client uses for these options: "N" disables, anything
        // else that is present enables.
        let encoded: u64 = if value.eq_ignore_ascii_case("N") { 1 } else { 2 };
        bits |= encoded << (index * 2) as u64;
    }
    bits
}

// --- Management authorization for every session ("control tickets") ---------------
//
// A direct session never passes this server, so the user gates and permissions the
// rendezvous enforces above never applied to one. The controller now gets a ticket
// with its poll: who it is (peer id + device key), which LDAP user is signed in, the
// permissions that user's policy decides, and the machines it may control -- the same
// decisions controller_policy_rejection / nemo_user_connection_rejection /
// control_permissions_for make at the rendezvous. The TARGET verifies the ticket
// against its pinned management key at login (client nemo_control) and applies it;
// with nemo-require-control-ticket it refuses any session without one.
//
// Revocation: CONTROL_EPOCH moves whenever authorization-relevant state changes
// (bump_epoch_on_authz_change) and is pushed to every machine; a target refuses a
// ticket older than the epoch it knows. Tickets are otherwise stable for an hour, so
// a client does not rewrite its persisted policy on every poll.

static CONTROL_EPOCH: Lazy<std::sync::atomic::AtomicU64> =
    Lazy::new(|| std::sync::atomic::AtomicU64::new(now_secs()));

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn control_epoch() -> u64 {
    CONTROL_EPOCH.load(Ordering::SeqCst)
}

fn bump_control_epoch() {
    // Strictly increasing even for two changes within the same second.
    let now = now_secs();
    let _ = CONTROL_EPOCH.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |e| Some(now.max(e + 1)));
}

const CONTROL_TICKET_BUCKET_SECS: u64 = 3600;
const CONTROL_TICKET_LIFETIME_SECS: u64 = 4 * 3600;
const OPTION_NEMO_CONTROL_TICKET: &str = "nemo-control-ticket";
const OPTION_NEMO_CONTROL_EPOCH: &str = "nemo-control-epoch";
/// The published client version, pushed with every poll (see the update manifest).
const OPTION_NEMO_UPDATE_VERSION: &str = "nemo-update-version";

/// Admin routes whose success can change who may control what.
fn is_authz_path(path: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "/nemo/api/peers",
        "/nemo/api/policy",
        "/nemo/api/global-policy",
        "/nemo/api/policies",
        "/nemo/api/integration/permissions",
        "/nemo/api/integration/ldap/users/set",
        "/nemo/api/device-keys",
        "/nemo/api/server-key/rotate",
    ];
    path == "/nemo/api/integration/ldap" || PREFIXES.iter().any(|p| path.starts_with(p))
}

async fn bump_epoch_on_authz_change(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next<axum::body::Body>,
) -> axum::response::Response {
    let mutating = req.method() != axum::http::Method::GET && req.method() != axum::http::Method::HEAD;
    let relevant = is_authz_path(req.uri().path());
    let res = next.run(req).await;
    if mutating && relevant && res.status().is_success() {
        bump_control_epoch();
    }
    res
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct ControlTicket {
    v: u32,
    ctl: String,
    dk: String,
    user: String,
    admin: bool,
    targets: Vec<String>,
    perm: u64,
    iat: u64,
    exp: u64,
    epoch: u64,
}

fn sign_control_ticket(t: &ControlTicket, sk: &sign::SecretKey) -> String {
    let payload = serde_json::to_vec(t).unwrap_or_default();
    let sig = sign::sign_detached(&payload, sk);
    format!("{}.{}", base64::encode(&payload), base64::encode(sig.as_ref()))
}

/// The machines a controller may control: what the user is allowed (admin = all) and
/// what the controller's own policy allows (outbound targets), minus blocked machines.
/// `["*"]` when nothing restricts it, so machines registered later are covered too.
fn ticket_targets(
    controller_id: &str,
    user: Option<(bool, &[String])>,
    outbound_targets: Option<&String>,
    blocked: &[String],
    registered: &[String],
) -> Vec<String> {
    let outbound_open = outbound_targets
        .map(|t| t.trim().is_empty() || t.split(|c: char| c == ',' || c == ';' || c.is_whitespace()).any(|x| x.trim() == "*"))
        .unwrap_or(true);
    let user_open = match user {
        None => true,
        Some((is_admin, allowed)) => is_admin || allowed.iter().any(|t| t == "*"),
    };
    if outbound_open && user_open && blocked.is_empty() {
        return vec!["*".to_owned()];
    }
    registered
        .iter()
        .filter(|t| t.as_str() != controller_id)
        .filter(|t| !blocked.contains(t))
        .filter(|t| target_allowed_by_controller_policy(outbound_targets, t))
        .filter(|t| match user {
            None => true,
            Some((is_admin, allowed)) => integration::user_allowed_target(is_admin, allowed, t),
        })
        .cloned()
        .collect()
}

/// Build this controller's ticket, or None when it must not get one (no proven device
/// key, blocked, outgoing disabled, or sign-in required but nobody signed in).
fn build_control_ticket(
    controller_id: &str,
    controller_blocked: bool,
    device_key_pub: Option<&str>,
    username: Option<&str>,
    require_login: bool,
    policy_options: &HashMap<String, String>,
    blocked: &[String],
    registered: &[String],
    now: u64,
) -> Option<ControlTicket> {
    let dk = device_key_pub.filter(|k| !k.trim().is_empty())?;
    if controller_blocked {
        return None;
    }
    if policy_options.get(OPTION_NEMO_OUTBOUND_ENABLED).map(|v| v == "N").unwrap_or(false) {
        return None;
    }
    if username.is_none() && require_login {
        return None;
    }
    let (user, admin, allowed, perm) = match username {
        Some(u) => {
            let (is_admin, allowed) = integration::effective_permission(u);
            (u.to_owned(), is_admin, allowed, control_bits_for_user(u))
        }
        None => (String::new(), false, Vec::new(), 0),
    };
    let targets = ticket_targets(
        controller_id,
        username.map(|_| (admin, allowed.as_slice())),
        policy_options.get(OPTION_NEMO_OUTBOUND_TARGETS),
        blocked,
        registered,
    );
    let iat = (now / CONTROL_TICKET_BUCKET_SECS) * CONTROL_TICKET_BUCKET_SECS;
    Some(ControlTicket {
        v: 1,
        ctl: controller_id.to_owned(),
        dk: dk.trim().to_owned(),
        user,
        admin,
        targets,
        perm,
        iat,
        exp: iat + CONTROL_TICKET_LIFETIME_SECS,
        epoch: control_epoch(),
    })
}

pub(crate) fn nemo_user_rejection_from_field(
    proto: Option<&NemoSource>,
    source_field: &str,
    target_id: &str,
    // TASK #19: the device key this rendezvous connection proved, if any.
    authed_device_pub: Option<&str>,
) -> Option<(String, String)> {
    // Parse best-effort: a controller with no source marker still gets the
    // require-login gate (token = None) so it cannot bypass mandatory login.
    let parsed = controller_source_any(proto, source_field);
    let token = parsed.as_ref().and_then(|(_, _, t)| t.clone());
    let source_id = parsed.map(|(id, _, _)| id).unwrap_or_default();
    let reason = nemo_user_connection_rejection(token.as_deref(), authed_device_pub, target_id)?;
    Some((source_id, reason))
}

/// The four controller gates. `source_uuid` is `None` when the controller proved itself
/// with its pinned device key at the rendezvous handshake: that Ed25519 proof already
/// binds the connection to `source_id` and is strictly stronger than the uuid the client
/// asserts in the marker, so there is nothing left for the uuid to add.
async fn controller_policy_rejection(
    pm: &PeerMap,
    source_id: &str,
    source_uuid: Option<&[u8]>,
    target_id: &str,
) -> Option<String> {
    let source_id = source_id.trim();
    if source_id.is_empty() {
        // H44: fail closed. An empty id is not "no controller to check", it is a
        // controller we could not name, and every gate below keys off this id. It used
        // to be unreachable because the marker parser rejects an empty id; it is not
        // any more, now that the id can come from the handshake -- a pinned device key
        // with a BLANK binding authenticates whatever peer_id the client claims,
        // including "" (rendezvous_server.rs, nemo_client_auth_open).
        return Some("controller did not identify itself".to_owned());
    }
    let source = match pm.get_registered(source_id).await {
        Ok(Some(source)) => source,
        Ok(None) => return Some("controller is not registered by TBF policy".to_owned()),
        Err(err) => {
            log::error!("failed to verify controller {}: {}", source_id, err);
            return Some("controller policy could not be verified".to_owned());
        }
    };
    if let Some(source_uuid) = source_uuid {
        if source_uuid.is_empty() || source.uuid.as_slice() != source_uuid {
            return Some("controller identity rejected by TBF policy".to_owned());
        }
    }
    if matches!(source.status, Some(0)) {
        return Some("controller is blocked by TBF policy".to_owned());
    }
    let policy = management_policy_from_peer(&source.management_policy);
    if policy
        .options
        .get(OPTION_NEMO_OUTBOUND_ENABLED)
        .map(|value| value == "N")
        .unwrap_or(false)
    {
        return Some("outgoing connections are disabled by TBF policy".to_owned());
    }
    if !target_allowed_by_controller_policy(policy.options.get(OPTION_NEMO_OUTBOUND_TARGETS), target_id)
    {
        return Some("target is not allowed by TBF policy".to_owned());
    }
    None
}

/// H44: decide WHO the controller is, before any of the four gates run.
///
/// `authed_peer_id` is the id this rendezvous connection PROVED with its pinned device
/// key (`AuthedDevice::peer_id`). `None` means it proved nothing -- either the operator
/// turned require-device-key off for a staged rollout, or --key-exchange=off. The marker
/// inside `source_field` is written by the client and signed by nobody, so it is only
/// ever the identity of last resort.
///
/// `Ok((id, uuid))` names the controller to run the gates on; `uuid = None` means "do not
/// cross-check the registered uuid", because the device key already bound the connection
/// to that id. `Err((id, reason))` is a refusal decided before any database lookup.
///
/// Split out as a pure fn so the decision is unit-testable without a PeerMap.
fn resolve_controller_identity(
    proto: Option<&NemoSource>,
    source_field: &str,
    authed_peer_id: Option<&str>,
) -> Result<(String, Option<Vec<u8>>), (String, String)> {
    match (authed_peer_id, controller_source_any(proto, source_field)) {
        (Some(proven), Some((claimed, uuid, _))) => {
            if claimed != proven {
                log::warn!(
                    "controller {} proved its device key but its source marker claims {}",
                    proven,
                    claimed
                );
                return Err((
                    proven.to_owned(),
                    "controller identity does not match the proven device key".to_owned(),
                ));
            }
            Ok((proven.to_owned(), Some(uuid)))
        }
        (Some(proven), None) => Ok((proven.to_owned(), None)),
        (None, Some((claimed, uuid, _))) => Ok((claimed, Some(uuid))),
        // The bypass this change exists to close. This used to be the `?` that returned
        // None from the whole function, and BOTH call sites read None as "no rejection",
        // i.e. PASS -- so all four controller gates could be skipped by simply leaving
        // the marker out of the punch or relay frame.
        (None, None) => Err((
            "?".to_owned(),
            "controller identity could not be established".to_owned(),
        )),
    }
}

pub(crate) async fn controller_policy_rejection_from_field(
    pm: &PeerMap,
    proto: Option<&NemoSource>,
    source_field: &str,
    target_id: &str,
    authed_peer_id: Option<&str>,
) -> Option<(String, String)> {
    let (source_id, source_uuid) = match resolve_controller_identity(proto, source_field, authed_peer_id)
    {
        Ok(identity) => identity,
        Err(rejection) => return Some(rejection),
    };
    let reason =
        controller_policy_rejection(pm, &source_id, source_uuid.as_deref(), target_id).await?;
    Some((source_id, reason))
}

pub(crate) async fn peer_stats(id: &str) -> NemoPeerStats {
    STATS
        .read()
        .await
        .peers
        .get(id)
        .cloned()
        .unwrap_or_default()
}

pub(crate) async fn record_peer_seen(id: &str, addr: SocketAddr) {
    let mut store = STATS.write().await;
    store.totals.registered_messages += 1;
    let peer = peer_stats_mut(&mut store, id);
    peer.registered_messages += 1;
    peer.last_public_addr = Some(addr.to_string());
    record_event_locked(
        &mut store,
        "register-peer",
        Some(id),
        Some(addr),
        "peer registered rendezvous address".to_owned(),
    );
}

/// M1-CLAIM: the operator confirmed a pairing, so a device key is now bound to a peer
/// it was not generated for. Audited rather than only logged, because this is the one
/// binding nobody typed into the "Bound to ID" field: the dashboard's event list is
/// where it can be seen afterwards that the right machine took the token.
pub(crate) async fn record_device_key_claim(id: &str, device_key_pub: &str, via: &str) {
    // Short prefix only, like the rendezvous handshake log: enough to match the row in
    // the Device keys table, not the whole public key in every event line.
    let short: String = device_key_pub.chars().take(12).collect();
    log::info!(
        "Device key {}... claimed by peer {} on its {} - it now authenticates only that peer",
        short,
        id,
        via
    );
    let mut store = STATS.write().await;
    record_event_locked(
        &mut store,
        "device-key-claimed",
        Some(id),
        None,
        format!(
            "device key {}... bound to this peer by operator confirmation of a claim filed on \
             its {}; it no longer authenticates any other id",
            short, via
        ),
    );
}

/// M1-CLAIM: a client proved a pinned-but-unbound key and asked for it. It was REFUSED
/// and a request was filed. Audited because it is the operator's cue that a machine is
/// sitting in its provisioning gate waiting for them, and because an unexpected id
/// against a key is exactly what they must see while the key can still be deleted.
pub(crate) async fn record_device_key_claim_pending(id: &str, device_key_pub: &str, via: &str) {
    let short: String = device_key_pub.chars().take(12).collect();
    log::info!(
        "Device key {}... was proved by peer {} on its {} and is NOT bound: filed a claim for \
         operator confirmation; the client stays refused until it is approved",
        short,
        id,
        via
    );
    let mut store = STATS.write().await;
    record_event_locked(
        &mut store,
        "device-key-claim-pending",
        Some(id),
        None,
        format!(
            "this peer proved unbound device key {}... on its {} and is waiting for approval; \
             it is refused until then",
            short, via
        ),
    );
}

/// The refusal a client whose claim is waiting (or was denied) gets instead of a bare
/// "a provisioned device key is required". The client matches on these to tell the user
/// that a human has to approve the machine, rather than that its key is wrong.
pub(crate) const DEVICE_KEY_CLAIM_PENDING: &str =
    "device key is awaiting operator confirmation";
pub(crate) const DEVICE_KEY_CLAIM_DENIED: &str =
    "device key claim was denied by the operator";

// --- TODO 7: relayed BYTES, per session and per peer ------------------------
//
// The claim this fork rests on is "sessions go direct; the relay is the fallback".
// Until now the dashboard could only show how many relay NEGOTIATIONS it saw
// (`relay_requests`, `relay_forced`): a negotiation says a path was offered, not that a
// byte went through it. A session that fell back to the relay and pushed 4 GB looked
// exactly like one that was offered the relay and then went direct.
//
// hbbr has the real counters, but it is a separate process -- possibly a separate host
// -- and it deliberately knows no peer ids: a relayed session is a grant and two
// sockets. So the join is done here, with the session LABEL (a hash of the grant hbbs
// minted, see common::relay_session_label) as the key:
//
//   hbbs mints a grant -> remembers label -> (controller id, workstation id)
//   hbbr counts bytes  -> reports         -> (label, bytes, rate)
//
// The transport is hbbr's existing loopback admin channel (`uj`, the machine-readable
// twin of `usage`), which is why this needs no new authentication: that channel already
// only answers connections from 127.0.0.1, and nothing but a hash crosses it.

/// Relay sessions kept for the dashboard, live and recently ended. Bounded: an
/// unauthenticated peer cannot create entries (a grant is minted only for a session
/// hbbs brokered over gated connections), but a busy fleet should still not grow this
/// without limit.
const RELAY_SESSION_MEMORY: usize = 256;

/// One relayed session as the dashboard sees it: who hbbs brokered it for, and what
/// hbbr actually carried.
#[derive(Clone, Default, Serialize)]
pub(crate) struct RelaySessionRecord {
    /// Hash of the grant. Not the grant: that is a live capability to join the session.
    session: String,
    /// The controller, as it identified itself on the RequestRelay. Empty when the
    /// controller is an older client that sends no source marker.
    source_id: String,
    target_id: String,
    brokered_at: String,
    /// Cumulative, as last reported by hbbr. Stays at its final value once the session
    /// ends -- hbbr forgets a session when it closes, so this is the total it carried.
    bytes: u64,
    kbps: u64,
    peak_kbps: u64,
    seconds: u64,
    /// Last time hbbr reported this session. None = it was brokered but never relayed a
    /// byte, which is the GOOD case: the peers went direct and never used the grant.
    last_sample_at: Option<String>,
    /// hbbr still has it open.
    live: bool,
}

/// TODO 24: whether the relay's own counters are reaching us, so the dashboard can tell
/// "the relay carried nothing for this session" apart from "we have no idea what the
/// relay did". They are not the same statement, and only the first one means the two
/// machines went direct.
#[derive(Clone, Default, Serialize)]
pub(crate) struct RelayPollerHealth {
    /// False when `--nemo-relay-metrics ""` turned measurement off. The panel must then
    /// make no claim about paths at all.
    enabled: bool,
    /// Where it polls (`host:port` of hbbr's admin channel), so the operator can see
    /// which relay the verdict is about.
    target: String,
    /// Last time hbbr answered. `None` while `enabled` = it has never answered since
    /// this server started -- exactly the case that produced the false "went direct".
    last_success_at: Option<String>,
    /// Why the most recent attempt failed, and when. Kept after a later success too, as
    /// the record of a flapping relay channel.
    last_error: Option<String>,
    last_error_at: Option<String>,
}

/// True only when hbbr's counters are known to be arriving: measurement is on AND the
/// relay has answered at least once. Everything the dashboard says about a session
/// having gone direct is conditional on this.
fn relay_measurement_trusted(health: &RelayPollerHealth) -> bool {
    health.enabled && health.last_success_at.is_some()
}

/// What hbbr's `uj` command reports per session.
#[derive(Deserialize)]
struct RelayUsageSample {
    #[serde(default)]
    session: String,
    #[serde(default)]
    bytes: u64,
    #[serde(default)]
    kbps: u64,
    #[serde(default)]
    peak_kbps: u64,
    #[serde(default)]
    ms: u64,
}

/// TODO 7: hbbs brokered a relayed session. Recorded BEFORE any byte moves, so a
/// session that was offered the relay and then went direct is visible as exactly that:
/// a row with no samples.
pub(crate) async fn record_relay_grant(session: String, source_id: &str, target_id: &str) {
    let mut store = STATS.write().await;
    // Evict ended sessions first (oldest brokered), then, only if everything is live,
    // the oldest live one: a stale "live" row is a session whose end hbbr never
    // reported, and keeping those forever would crowd out the real ones.
    while store.relay_sessions.len() >= RELAY_SESSION_MEMORY {
        let victim = store
            .relay_sessions
            .iter()
            .enumerate()
            .min_by_key(|(idx, r)| (r.live, r.brokered_at.clone(), *idx))
            .map(|(idx, _)| idx);
        match victim {
            Some(idx) => {
                store.relay_sessions.remove(idx);
            }
            None => break,
        }
    }
    store.relay_sessions.push(RelaySessionRecord {
        session,
        source_id: source_id.to_owned(),
        target_id: target_id.to_owned(),
        brokered_at: now_iso(),
        ..Default::default()
    });
}

/// Fold one sample set into the store: per-session absolutes, per-peer and fleet
/// deltas. Pure over the store so the delta arithmetic is testable without a relay.
fn apply_relay_usage(store: &mut NemoStatsStore, samples: Vec<RelayUsageSample>, at: &str) {
    let mut seen: HashSet<String> = HashSet::new();
    for sample in samples {
        if sample.session.is_empty() {
            continue;
        }
        seen.insert(sample.session.clone());
        let Some(idx) = store
            .relay_sessions
            .iter()
            .position(|r| r.session == sample.session)
        else {
            // A session this hbbs did not broker (another hbbs shares the relay, or we
            // restarted and lost the mapping). Counted in the fleet total, which is
            // measured traffic either way, but not attributed to any peer.
            store.totals.relay_bytes += sample.bytes;
            continue;
        };
        // hbbr reports cumulative totals per session, so the increment is what is new
        // since the last poll. `saturating_sub` covers the one case that would
        // otherwise underflow: a label reused after a restart with a lower count.
        let delta = sample.bytes.saturating_sub(store.relay_sessions[idx].bytes);
        let (source_id, target_id) = {
            let row = &mut store.relay_sessions[idx];
            row.bytes = sample.bytes;
            row.kbps = sample.kbps;
            row.peak_kbps = sample.peak_kbps;
            row.seconds = sample.ms / 1000;
            row.last_sample_at = Some(at.to_owned());
            row.live = true;
            (row.source_id.clone(), row.target_id.clone())
        };
        store.totals.relay_bytes += delta;
        // Charged to BOTH ends: the question a dashboard answers is "is this machine
        // relaying", and both are. So the sum over peers is not the fleet total -- the
        // fleet total is the one that counts bytes once.
        for id in [source_id, target_id] {
            if id.is_empty() {
                continue;
            }
            peer_stats_mut(store, &id).relay_bytes += delta;
        }
    }
    // hbbr drops a session the moment it closes, so "absent from the sample" is how a
    // session ends. The row keeps its final totals.
    for row in store.relay_sessions.iter_mut() {
        if row.live && !seen.contains(&row.session) {
            row.live = false;
            row.kbps = 0;
        }
    }
}

/// Ask hbbr for its per-session counters over the loopback admin channel.
async fn fetch_relay_usage(addr: &str) -> ResultType<Vec<RelayUsageSample>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        tokio::net::TcpStream::connect(addr),
    )
    .await??;
    stream.write_all(b"uj").await?;
    stream.flush().await?;
    let mut body = Vec::new();
    // hbbr answers and closes, so read to EOF; the timeout is the only bound needed.
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        stream.read_to_end(&mut body),
    )
    .await??;
    Ok(serde_json::from_slice(&body)?)
}

/// TODO 7: poll hbbr for relayed bytes and fold them into the dashboard's stats.
///
/// Opt-out, not opt-in: the shipped unit runs hbbs and hbbr on the same host, so the
/// default target is right there, and a fleet that cannot prove it stays direct is the
/// thing this exists to fix. `--nemo-relay-metrics ""` turns it off; point it at
/// another host:port only if that host's admin channel is reachable (it binds loopback,
/// so in practice that means an SSH tunnel).
pub(crate) fn spawn_relay_usage_poller() {
    let addr = get_arg_or("nemo-relay-metrics", "127.0.0.1:21117".to_owned());
    let addr = addr.trim().to_owned();
    if addr.is_empty() || is_truthy_off(&addr) {
        log::info!("Nemo relay byte metrics disabled (--nemo-relay-metrics)");
        // TODO 24: record that it is OFF rather than leaving the default, so the panel
        // says "not measured" instead of letting every row read as "went direct".
        tokio::spawn(async move {
            let mut store = STATS.write().await;
            store.relay_poller = RelayPollerHealth {
                enabled: false,
                target: String::new(),
                ..Default::default()
            };
        });
        return;
    }
    let interval = get_arg("nemo-relay-metrics-interval")
        .parse::<u64>()
        .unwrap_or(5)
        .clamp(1, 3600);
    log::info!(
        "Nemo relay byte metrics: polling hbbr at {} every {}s",
        addr,
        interval
    );
    tokio::spawn(async move {
        {
            // TODO 24: publish the target before the first attempt, so a dashboard
            // opened in the first few seconds already names the relay it is waiting on.
            let mut store = STATS.write().await;
            store.relay_poller.enabled = true;
            store.relay_poller.target = addr.clone();
        }
        // One warning per outage, not one every interval: hbbr not being there (a
        // relay on another host, or simply not started yet) must not fill the log.
        let mut complained = false;
        loop {
            match fetch_relay_usage(&addr).await {
                Ok(samples) => {
                    if complained {
                        log::info!("Nemo relay byte metrics: {} is answering again", addr);
                        complained = false;
                    }
                    let at = now_iso();
                    let mut store = STATS.write().await;
                    apply_relay_usage(&mut store, samples, &at);
                    store.relay_poller.last_success_at = Some(at);
                }
                Err(err) => {
                    {
                        let mut store = STATS.write().await;
                        store.relay_poller.last_error = Some(err.to_string());
                        store.relay_poller.last_error_at = Some(now_iso());
                    }
                    if !complained {
                        log::warn!(
                            "Nemo relay byte metrics: cannot read hbbr usage from {} ({}). \
                             Relayed-byte columns stay empty until it answers; pass \
                             --nemo-relay-metrics \"\" to stop trying.",
                            addr,
                            err
                        );
                        complained = true;
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
        }
    });
}

pub(crate) async fn record_register_pk(id: &str, addr: SocketAddr, accepted: bool) {
    let mut store = STATS.write().await;
    store.totals.register_pk_messages += 1;
    let peer = peer_stats_mut(&mut store, id);
    peer.register_pk_messages += 1;
    peer.last_public_addr = Some(addr.to_string());
    record_event_locked(
        &mut store,
        "register-pk",
        Some(id),
        Some(addr),
        if accepted {
            "public key accepted".to_owned()
        } else {
            "public key rejected".to_owned()
        },
    );
}

pub(crate) async fn record_connection_negotiation(
    id: &str,
    // TODO 8: the typed identity field, when the controller sends one.
    proto: Option<&NemoSource>,
    source_field: &str,
    from_addr: SocketAddr,
    to_addr: SocketAddr,
    nat_type: i32,
    forced_relay: bool,
    same_intranet: bool,
    relay_server: &str,
) {
    // Verbose audit line: the server sees connection SETUP (punch/relay) even for
    // direct sessions, so this records who connected to which machine, over what
    // path — visible in the server log regardless of whether the session is direct.
    // H1: log ONLY the parsed source id, never the raw `source_field` — it carries the
    // logged-in user's session token (`nemo-source-v1:<id>:<uuid>:<token>`), and printing
    // it would leak a live bearer credential into the server log.
    let source_id = controller_source_any(proto, source_field)
        .map(|(sid, _, _)| sid)
        .unwrap_or_else(|| "?".to_owned());
    log::info!(
        "Nemo connect: target={} source={} from={} to={} nat={} path={}",
        id,
        source_id,
        from_addr,
        to_addr,
        nat_type_name(nat_type),
        if forced_relay {
            "relay"
        } else if same_intranet {
            "direct-local"
        } else {
            "direct-punch"
        },
    );
    let mut store = STATS.write().await;
    store.totals.direct_attempts += 1;
    if forced_relay {
        store.totals.relay_forced += 1;
    }
    if same_intranet {
        store.totals.local_addr_attempts += 1;
    }
    let peer = peer_stats_mut(&mut store, id);
    peer.direct_attempts += 1;
    peer.last_punch_from_addr = Some(from_addr.to_string());
    peer.last_punch_to_addr = Some(to_addr.to_string());
    peer.last_nat_type = Some(nat_type_name(nat_type).to_owned());
    peer.last_forced_relay = forced_relay;
    peer.last_same_intranet = same_intranet;
    if forced_relay {
        peer.relay_forced += 1;
    }
    if same_intranet {
        peer.local_addr_attempts += 1;
    }
    if relay_server.is_empty() {
        peer.last_relay_server = None;
    } else {
        peer.last_relay_server = Some(relay_server.to_owned());
    }
    record_event_locked(
        &mut store,
        "connection-negotiation",
        Some(id),
        Some(from_addr),
        format!(
            "target={}, nat={}, forced_relay={}, same_intranet={}, relay={}",
            to_addr,
            nat_type_name(nat_type),
            forced_relay,
            same_intranet,
            relay_server
        ),
    );
    // Live connections view (see-connections). Path priority reflects the fork's
    // goal: direct is best, relay is the fallback.
    let path = if forced_relay {
        "relay"
    } else if same_intranet {
        "direct-local"
    } else {
        "direct-punch"
    };
    let source_id = controller_source_any(proto, source_field)
        .map(|(sid, _, _)| sid)
        .unwrap_or_default();
    upsert_connection(
        &mut store,
        &source_id,
        id,
        &from_addr.to_string(),
        &to_addr.to_string(),
        path,
        relay_server,
        nat_type_name(nat_type),
    );
}

/// A controller's report of one attempt at a published direct endpoint, into the live
/// Connections view and the target's stats. The controller is the proven sender (device
/// key); the target and the numbers are its claim, so they are bounded and only ever
/// informational -- nothing here grants or blocks anything.
fn record_direct_report(
    store: &mut NemoStatsStore,
    controller: &str,
    body: &serde_json::Value,
    from: Option<SocketAddr>,
) {
    let field = |k: &str, max: usize| -> String {
        body.get(k)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .chars()
            .take(max)
            .collect()
    };
    let target = field("peer", 32);
    if target.is_empty() || !target.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return;
    }
    let result = field("result", 16);
    let path = match result.as_str() {
        "established" => "direct-endpoint",
        "failed" => "direct-failed",
        // "not-tried" (a relay-only setting on the controller) stays in the event log
        // only: the relay negotiation that follows records the session itself.
        _ => return,
    };
    let endpoint = field("endpoint", 128);
    let reason = field("detail", 200);
    let ms = body.get("ms").and_then(|v| v.as_u64());
    let source_addr = from.map(|a| a.to_string()).unwrap_or_default();
    upsert_connection(store, controller, &target, &source_addr, &endpoint, path, "", "");
    let summary = match (path, ms) {
        ("direct-endpoint", Some(ms)) => format!("{} established {} ms via {}", controller, ms, endpoint),
        ("direct-endpoint", None) => format!("{} established via {}", controller, endpoint),
        _ => format!("{} failed via {}: {}", controller, endpoint, reason),
    };
    let peer = peer_stats_mut(store, &target);
    if path == "direct-endpoint" {
        peer.direct_endpoint_ok += 1;
    } else {
        peer.direct_endpoint_failed += 1;
    }
    peer.last_direct_report = Some(format!("{} ({})", summary, now_iso()));
}

fn upsert_connection(
    store: &mut NemoStatsStore,
    source_id: &str,
    target_id: &str,
    from_addr: &str,
    to_addr: &str,
    path: &str,
    relay_server: &str,
    nat_type: &str,
) {
    let now = std::time::Instant::now();
    if let Some(existing) = store
        .connections
        .iter_mut()
        .find(|c| c.source_id == source_id && c.target_id == target_id)
    {
        existing.last_seen = now;
        existing.negotiations += 1;
        existing.path = path.to_owned();
        existing.source_addr = from_addr.to_owned();
        existing.target_addr = to_addr.to_owned();
        existing.relay_server = relay_server.to_owned();
        existing.nat_type = nat_type.to_owned();
    } else {
        store.connections.push(ConnectionRecord {
            source_id: source_id.to_owned(),
            target_id: target_id.to_owned(),
            source_addr: from_addr.to_owned(),
            target_addr: to_addr.to_owned(),
            path: path.to_owned(),
            relay_server: relay_server.to_owned(),
            nat_type: nat_type.to_owned(),
            first_seen: now,
            last_seen: now,
            negotiations: 1,
        });
        // Retain only the most-recent N (configurable, no time cutoff); trim in a
        // loop so a lowered limit takes effect promptly. Oldest by last_seen goes.
        let limit = conn_history_limit();
        while store.connections.len() > limit {
            match store
                .connections
                .iter()
                .enumerate()
                .min_by_key(|(_, c)| c.last_seen)
            {
                Some((idx, _)) => {
                    store.connections.remove(idx);
                }
                None => break,
            }
        }
    }
}

pub(crate) async fn record_relay_request(id: &str, addr: SocketAddr, forwarded: bool) {
    let mut store = STATS.write().await;
    store.totals.relay_requests += 1;
    let peer = peer_stats_mut(&mut store, id);
    peer.relay_requests += 1;
    record_event_locked(
        &mut store,
        "relay-request",
        Some(id),
        Some(addr),
        if forwarded {
            "forwarded to target peer".to_owned()
        } else {
            "target peer was not available".to_owned()
        },
    );
}

pub(crate) async fn record_relay_response(id: &str, addr: SocketAddr, relay_server: &str) {
    let mut store = STATS.write().await;
    store.totals.relay_responses += 1;
    let peer = peer_stats_mut(&mut store, id);
    peer.relay_responses += 1;
    if !relay_server.is_empty() {
        peer.last_relay_server = Some(relay_server.to_owned());
    }
    record_event_locked(
        &mut store,
        "relay-response",
        Some(id),
        Some(addr),
        format!("relay={}", relay_server),
    );
}

pub(crate) async fn record_punch_response(
    id: &str,
    addr: SocketAddr,
    relay_server: &str,
    nat_type: i32,
) {
    let mut store = STATS.write().await;
    store.totals.punch_responses += 1;
    let peer = peer_stats_mut(&mut store, id);
    peer.punch_responses += 1;
    peer.last_nat_type = Some(nat_type_name(nat_type).to_owned());
    if !relay_server.is_empty() {
        peer.last_relay_server = Some(relay_server.to_owned());
    }
    record_event_locked(
        &mut store,
        "punch-response",
        Some(id),
        Some(addr),
        format!("nat={}, relay={}", nat_type_name(nat_type), relay_server),
    );
}

pub(crate) async fn record_local_addr_response(id: &str, addr: SocketAddr, relay_server: &str) {
    let mut store = STATS.write().await;
    store.totals.local_addr_responses += 1;
    let peer = peer_stats_mut(&mut store, id);
    peer.local_addr_responses += 1;
    if !relay_server.is_empty() {
        peer.last_relay_server = Some(relay_server.to_owned());
    }
    record_event_locked(
        &mut store,
        "local-addr-response",
        Some(id),
        Some(addr),
        format!("relay={}", relay_server),
    );
}

pub(crate) async fn record_policy_rejection(id: &str, addr: SocketAddr, reason: &str) {
    let mut store = STATS.write().await;
    store.totals.policy_rejections += 1;
    let peer = peer_stats_mut(&mut store, id);
    peer.policy_rejections += 1;
    record_event_locked(
        &mut store,
        "policy-rejection",
        Some(id),
        Some(addr),
        reason.to_owned(),
    );
}

// NOT a liveness probe, despite the name: this returns the full PolicyResponse --
// require_device_key, strip_unsealed_secrets, require_sealed_login,
// require_sealed_request and the build id. Served unauthenticated it would tell any
// caller on the API port exactly which hardening switches are off and which build is
// running, so it stays behind require_auth and stays OUT of request_body_cap's public
// list. Its only caller is the admin dashboard (nemo_admin.html), which sends the
// bearer token. It is also a duplicate of `get_policy`; if one is ever removed, this
// is the one to go.
async fn health(
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
) -> ApiResult<PolicyResponse> {
    require_auth(&headers, &state.token)?;
    Ok(Json(policy_response(&state.server_public_key)))
}

async fn list_peers(
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> ApiResult<PeerListResponse> {
    require_auth(&headers, &state.token)?;
    let limit = query.limit.unwrap_or(100).clamp(1, 1000);
    let offset = query.offset.unwrap_or(0);
    let peers = state
        .pm
        .list_registered(limit, offset)
        .await
        .map_err(server_error)?;
    let mut out = Vec::with_capacity(peers.len());
    for peer in peers {
        out.push(peer_response(&state.pm, peer).await);
    }
    Ok(Json(PeerListResponse {
        limit,
        offset,
        company_only: company_only(),
        peers: out,
    }))
}

async fn get_peer(
    Path(id): Path<String>,
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
) -> ApiResult<PeerResponse> {
    require_auth(&headers, &state.token)?;
    let peer = state
        .pm
        .get_registered(&id)
        .await
        .map_err(server_error)?
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "peer not found"))?;
    Ok(Json(peer_response(&state.pm, peer).await))
}

async fn get_peer_management_policy(
    Path(id): Path<String>,
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
) -> ApiResult<ManagementPolicyResponse> {
    require_auth(&headers, &state.token)?;
    let peer = state
        .pm
        .get_registered(&id)
        .await
        .map_err(server_error)?
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "peer not found"))?;
    Ok(Json(ManagementPolicyResponse {
        id: peer.id,
        policy: management_policy_from_peer(&peer.management_policy),
    }))
}

async fn update_peer_management_policy(
    Path(id): Path<String>,
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
    Json(request): Json<ManagementPolicyRequest>,
) -> ApiResult<ManagementPolicyResponse> {
    require_auth(&headers, &state.token)?;
    let policy = sanitize_management_policy(ManagementPolicy {
        allow_user_override: request.allow_user_override,
        options: request.options,
    });
    // S4: the dashboard sends back masked secrets; restore the stored plaintext
    // for any secret left as the mask so it is not clobbered.
    let existing = state.pm.get_registered(&id).await.map_err(server_error)?;
    let policy = restore_masked_secrets(policy, &existing.and_then(|p| p.management_policy));
    let serialized = serialize_management_policy(&policy)?;
    let updated = state
        .pm
        .set_peer_management_policy(&id, serialized.as_deref())
        .await
        .map_err(server_error)?;
    if !updated {
        return Err(api_error(StatusCode::NOT_FOUND, "peer not found"));
    }
    let mut store = STATS.write().await;
    record_event_locked(
        &mut store,
        "management-policy-update",
        Some(&id),
        None,
        format!("options={}", policy.options.len()),
    );
    Ok(Json(ManagementPolicyResponse { id, policy }))
}

// POST /nemo/api/client/audit/:kind (CLIENT_AUDIT_KINDS): the device-key proof is the auth.
async fn client_audit(
    Extension(state): Extension<HbbsApiState>,
    Path(kind): Path<String>,
    peer_addr: Option<ConnectInfo<SocketAddr>>,
    Json(mut body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    if !CLIENT_AUDIT_KINDS.contains(&kind.as_str()) {
        return Err(api_error(StatusCode::NOT_FOUND, "unknown audit kind"));
    }
    let Some(id) = client_audit_identity(&body) else {
        log::warn!("client audit '{}' rejected: no device-key proof", kind);
        return Err(api_error(StatusCode::FORBIDDEN, "a provisioned device key is required"));
    };
    if state.pm.get_registered(&id).await.map_err(server_error)?.is_none() {
        return Err(api_error(StatusCode::NOT_FOUND, "peer not found"));
    }
    let detail = client_audit_detail(&mut body);
    let from = peer_addr.map(|ConnectInfo(addr)| addr);
    let mut store = STATS.write().await;
    record_event_locked(&mut store, &format!("client-audit-{}", kind), Some(&id), from, detail);
    if kind == "direct" {
        record_direct_report(&mut store, &id, &body, from);
    }
    Ok(Json(serde_json::json!({})))
}

async fn client_policy(
    Extension(state): Extension<HbbsApiState>,
    // S-B (scope b): ClientPolicyRequest's `id`/`uuid` are not #[serde(default)], so a
    // typed extractor would reject a sealed envelope with "missing field id" before
    // this handler ever ran. Take the body as a Value, resolve the envelope, then
    // deserialize the inner (seal-authenticated) object.
    Json(raw): Json<serde_json::Value>,
) -> ApiResult<ClientPolicyResponse> {
    let body = resolve_request_body(&state, raw).map_err(|e| {
        log::warn!("client policy poll rejected: {}", e);
        api_error(StatusCode::FORBIDDEN, &e)
    })?;
    // UNPROCESSABLE_ENTITY, not BAD_REQUEST: that is exactly what axum's typed Json
    // extractor returned for a wrong-shaped body until now, so a malformed request
    // still gets the status it got today.
    let request: ClientPolicyRequest = serde_json::from_value(body)
        .map_err(|e| api_error(StatusCode::UNPROCESSABLE_ENTITY, &e.to_string()))?;
    let peer = state
        .pm
        .get_registered(&request.id)
        .await
        .map_err(server_error)?
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "peer not found"))?;
    validate_client_policy_request(&peer, &request)?;
    // S-DUALKEY: note which key the client authenticated with, and enforce the
    // "require provisioned device key" setting.
    let proof = verify_device_key(&request);
    let device_key_ok = proof.ok;
    record_peer_auth_mode(&request.id, if device_key_ok { "device-key" } else { "default" });
    // M1-CLAIM: the poll is normally the first request a freshly provisioned client
    // makes, so this is usually where an unbound token's binding is first REQUESTED.
    // Audit a new request: this is the one binding the operator did not type, so they
    // have to be able to see which machine asked for which key, and when.
    if proof.claim == Some(integration::PendingOutcome::New) {
        record_device_key_claim_pending(
            &request.id,
            request.device_key_pub.as_deref().unwrap_or(""),
            "settings poll",
        )
        .await;
    }
    if integration::require_device_key() && !device_key_ok {
        // A client whose claim is pending is refused like any unprovisioned one, but it
        // is refused for a reason the operator can act on — so say which, or the client
        // would sit in its provisioning gate with a bare 403 and no idea that a human
        // has to press Approve.
        return Err(match proof.claim {
            Some(integration::PendingOutcome::New) | Some(integration::PendingOutcome::Repeat) => {
                api_error(StatusCode::FORBIDDEN, DEVICE_KEY_CLAIM_PENDING)
            }
            Some(integration::PendingOutcome::Denied) => {
                api_error(StatusCode::FORBIDDEN, DEVICE_KEY_CLAIM_DENIED)
            }
            _ => api_error(
                StatusCode::FORBIDDEN,
                "a provisioned device key is required",
            ),
        });
    }
    // Learn this peer's hostname from its own poll so the address book can show
    // it -- only after the device-key gate, or anyone knowing id+uuid could rename it.
    record_peer_hostname(&request.id, request.hostname.as_deref().unwrap_or(""));
    if let Some(version) = request.policy_version.as_deref() {
        log::trace!("Client {} requested management policy after {}", request.id, version);
    }
    // Global (infrastructure) defaults first — api-server, TLS fallback, etc.
    let mut policy = global_policy();
    apply_api_tls_defaults(&mut policy.options, API_CERT_INFO.read().unwrap().as_ref());

    // Identity-based policy: resolve the logged-in, enabled user from the token.
    // A1: the token may arrive sealed to our mgmt key (confidential on the wire).
    let access_token = resolve_access_token(&state, &request);
    // A token spent from a machine other than the one that proved its login gets
    // the device's policy, never the user's (whose options can carry secrets).
    let proven = if device_key_ok { request.device_key_pub.as_deref() } else { None };
    let user = access_token
        .as_deref()
        .and_then(integration::session_for_token)
        .filter(|s| integration::user_is_enabled(&s.username))
        .filter(|s| {
            let ok = session_device_binding_ok(&s.device_key_pub, proven);
            if !ok {
                log::warn!("user policy withheld: user '{}' token spent from another device", s.username);
            }
            ok
        });
    let require_login = integration::require_login();

    match user {
        Some(session) => {
            // A logged-in user's policy REPLACES the device policy: start from the
            // infrastructure globals and apply the user's settings only.
            let up = integration::user_policy(&session.username);
            policy.allow_user_override = policy.allow_user_override || up.allow_user_override;
            policy.options.extend(up.options);
            policy
                .options
                .insert("nemo-logged-in-user".to_owned(), session.username.clone());
        }
        None => {
            // No logged-in user: use the per-device policy so a controlled host
            // (e.g. an office computer nobody signs into) keeps its incoming
            // config — permanent password, incoming permissions — and stays
            // connectable. If login is required, also flag the client to block
            // *outgoing* use until a user logs in (harmless on a pure host).
            let peer_policy = management_policy_from_peer(&peer.management_policy);
            policy.allow_user_override = policy.allow_user_override || peer_policy.allow_user_override;
            policy.options.extend(peer_policy.options);
            // A named policy assigned to this device wins over its inline policy.
            if let Some(dp) = integration::device_policy(&peer.id) {
                policy.allow_user_override = policy.allow_user_override || dp.allow_user_override;
                policy.options.extend(dp.options);
            }
        }
    }
    // Always report the current require-login state, on BOTH the logged-in and
    // no-user paths, so the client's login gate is reliable. The client only gates
    // when NOT signed in, so sending Y to a signed-in client is harmless; but if we
    // omit it while signed in (as before), the client clears its persisted flag and
    // the gate fails to re-trigger after logoff until the next poll. The stale-heal
    // still keys on `nemo-logged-in-user` (server_saw_user), not on this flag.
    if require_login {
        policy
            .options
            .insert("nemo-require-login".to_owned(), "Y".to_owned());
    } else {
        policy.options.remove("nemo-require-login");
    }
    // #3-push: current address-book/access version. The client compares it to the
    // last value it saw and re-fetches its address book when it changes, so ACL
    // edits reach a logged-in client on its next signed poll (no extra channel).
    policy.options.insert(
        "nemo-ab-version".to_owned(),
        integration::ab_version().to_string(),
    );
    // #2: the set of blocked TBFDesk IDs, pushed (signed) so a controlled machine
    // rejects INCOMING connections from a blocked source even if that source runs a
    // modified client and connects directly, bypassing the server's punch gate.
    let blocked = list_blocked_ids(&state.pm).await;
    if !blocked.is_empty() {
        policy
            .options
            .insert("nemo-blocked-ids".to_owned(), blocked.join(","));
    }
    // B: push the signed `{id -> Ed25519 pubkey}` map so a controller can verify a
    // direct-IP peer's SignedId and encrypt the session with no rendezvous broker
    // (server-anchored). Public keys only; anchored by the policy signature.
    let peer_keys = peer_key_map(&state.pm).await;
    if !peer_keys.is_empty() {
        policy
            .options
            .insert("nemo-peer-keys".to_owned(), peer_keys);
    }
    // Direct endpoints: tell this controller where it can reach each workstation without
    // the relay. Only overwrites when the operator has actually configured endpoints, so
    // a map typed by hand into the global policy still works.
    let endpoints = direct_endpoint_map(&blocked, policy.options.get(OPTION_NEMO_OUTBOUND_TARGETS));
    if !endpoints.is_empty() {
        policy
            .options
            .insert(OPTION_NEMO_DIRECT_ENDPOINTS.to_owned(), endpoints);
    }
    // Per-peer knock keys, filtered by the SAME ACL as the endpoints so a controller gets
    // a key only for a workstation it may dial. Secret: stripped below if the response
    // cannot be sealed, like the fleet-wide knock key. Only overwrites a hand-written
    // value when the operator has actually configured per-peer keys.
    let knock_keys = knock_key_map(&blocked, policy.options.get(OPTION_NEMO_OUTBOUND_TARGETS));
    if !knock_keys.is_empty() {
        policy
            .options
            .insert(OPTION_NEMO_KNOCK_KEYS.to_owned(), knock_keys);
    }
    // Record what this poll actually HANDED OVER. Configuring a port forward in the
    // dashboard and the controller being able to use it are two different facts, and
    // until now only the first was visible: an endpoint typed into the peer's row looked
    // identical whether or not any controller ever received it (it is filtered per
    // controller by the outbound-targets ACL, and dropped entirely for a blocked
    // target). The peers panel reads this back as "endpoints delivered to this client".
    record_peer_endpoints_delivered(
        &peer.id,
        policy
            .options
            .get(OPTION_NEMO_DIRECT_ENDPOINTS)
            .map(|s| s.as_str())
            .unwrap_or(""),
    );
    // Management authorization: every machine learns the current epoch (as a target
    // it refuses older tickets); a controller gets its ticket.
    policy
        .options
        .insert(OPTION_NEMO_CONTROL_EPOCH.to_owned(), control_epoch().to_string());
    // Update rollout: report what this machine runs, and tell it which version is
    // published, so a client with automatic updates checks now instead of at its next
    // daily check. The manifest itself (signed) is still fetched and verified.
    if let Some(v) = request.client_version.as_deref() {
        record_peer_client_version(&peer.id, v);
    }
    if let Ok(Some(m)) = read_update_manifest(std::path::Path::new(&update_manifest_path())) {
        policy
            .options
            .insert(OPTION_NEMO_UPDATE_VERSION.to_owned(), m.version);
    }
    if let Some(sk) = state.server_secret_key.as_ref() {
        let registered: Vec<String> = match state.pm.list_registered(100_000, 0).await {
            Ok(peers) => peers.into_iter().map(|p| p.id).collect(),
            Err(_) => Vec::new(),
        };
        let username = policy.options.get("nemo-logged-in-user").cloned();
        if let Some(ticket) = build_control_ticket(
            &peer.id,
            matches!(peer.status, Some(0)),
            if device_key_ok { request.device_key_pub.as_deref() } else { None },
            username.as_deref(),
            require_login,
            &policy.options,
            &blocked,
            &registered,
            now_secs(),
        ) {
            policy
                .options
                .insert(OPTION_NEMO_CONTROL_TICKET.to_owned(), sign_control_ticket(&ticket, sk));
        }
    }
    // The other half of a direct endpoint is a listener on the far side. Configuring an
    // endpoint for a machine IS the instruction to make it reachable, so turn its direct
    // access server on rather than leaving the operator to discover, after every attempt
    // has timed out, that nothing was listening. `direct-access-port` is deliberately NOT
    // derived from the endpoint: the endpoint's port is the router's EXTERNAL port, which
    // a forward may well translate (31118 -> 21118). Set that in the peer's device policy
    // when it must differ from the 21118 default.
    //
    // An operator who sets `direct-server` explicitly keeps their value, and clearing the
    // endpoint stops this being pushed, which returns the machine to its own setting.
    if !peer_endpoint(&peer.id).is_empty() {
        policy
            .options
            .entry("direct-server".to_owned())
            .or_insert_with(|| "Y".to_owned());
        // ...and the port that listener binds, when the machine's own device policy
        // names one. `direct-access-port` is a property of the MACHINE (where its
        // listener sits behind the forward), not of whoever is signed in on it, but a
        // logged-in user's policy REPLACES the device policy wholesale — so a machine
        // reachable at :21218 silently fell back to listening on 21118 the moment
        // someone signed in, and every direct connection to it then failed. Injected
        // here for the same reason `direct-server` above is: the endpoint is the
        // operator's instruction to make this machine reachable, and it has to survive
        // the policy that happens to be in force.
        if let Some(dp) = integration::device_policy(&peer.id) {
            if let Some(port) = dp.options.get("direct-access-port") {
                if !port.trim().is_empty() {
                    policy
                        .options
                        .entry("direct-access-port".to_owned())
                        .or_insert_with(|| port.trim().to_owned());
                }
            }
        }
    }
    if matches!(peer.status, Some(0)) {
        policy.allow_user_override = false;
        policy
            .options
            .insert(OPTION_NEMO_OUTBOUND_ENABLED.to_owned(), "N".to_owned());
    }
    // S-B/S-DUALKEY step 3: seal the response to the client's device key whenever
    // the client proved possession of a pinned key AND advertised unseal support.
    // Sign-then-seal: the Ed25519 signature (with the payload embedded, attached
    // form) goes INSIDE the sealedbox; the cleartext payload field is omitted.
    let seal_this = device_key_ok && request.sealed.as_deref() == Some("v1");
    // H4: a response that will NOT be sealed must not carry secrets once the
    // operator turns stripping on (until then unprovisioned clients keep the
    // legacy plaintext-over-TLS push so the fleet doesn't break).
    if !seal_this && integration::strip_unsealed_secrets() {
        let stripped = strip_secret_options(&mut policy);
        if stripped > 0 {
            log::info!(
                "policy for {} sent WITHOUT {} secret option(s): client cannot receive a sealed response",
                peer.id,
                stripped
            );
        }
    }
    let payload = ClientPolicyPayload {
        id: peer.id.clone(),
        issued_at: now_iso(),
        issued_ts: now_epoch_secs(),
        terminate_sessions_before: peer_terminate_before(&peer.id),
        policy,
    };
    let payload_bytes = serde_json::to_vec(&payload).map_err(server_error)?;
    let signed_bytes = state
        .server_secret_key
        .as_ref()
        .map(|secret_key| sign::sign(&payload_bytes, secret_key));
    if seal_this {
        let Some(signed_bytes) = signed_bytes.as_deref() else {
            // No signing key: cannot produce the sealed (sign-then-seal) shape.
            // Fail closed rather than answering a seal-capable client in plaintext.
            return Err(api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server has no signing key; cannot seal the policy response",
            ));
        };
        let sealed_payload = request
            .device_key_pub
            .as_deref()
            .and_then(|pub_b64| seal_to_device_key(pub_b64, signed_bytes))
            .ok_or_else(|| {
                api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "could not seal the policy response to the device key",
                )
            })?;
        return Ok(Json(ClientPolicyResponse {
            server_public_key: state.server_public_key,
            signed_payload: String::new(),
            payload: None,
            sealed_payload: Some(sealed_payload),
        }));
    }
    Ok(Json(ClientPolicyResponse {
        server_public_key: state.server_public_key,
        signed_payload: signed_bytes.map(base64::encode).unwrap_or_default(),
        payload: Some(payload),
        sealed_payload: None,
    }))
}

async fn block_peer(
    Path(id): Path<String>,
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
) -> ApiResult<PeerPolicyResponse> {
    require_auth(&headers, &state.token)?;
    let resp = set_peer_policy(&state.pm, &id, Some(0)).await?;
    // Blocking has to END access, not merely stop the next connection. Until this
    // line, /peers/:id/block set the policy and nothing else, so a session already
    // running kept running -- verified on the lab server, where a blocked peer's
    // session went on streaming for another minute with the timer still counting.
    // /connections/cut got this right and block did not, which is the worst split to
    // have: the lever named "block" is the one an operator reaches for to revoke a
    // compromised machine, and it was the one that did not revoke.
    //
    // Same mechanism as cut: a revocation stamp the controlled side honours on its
    // next managed-policy poll (<=30s), where it closes every authorised session.
    let terminate_ts = set_peer_terminate(&id);
    {
        let mut store = STATS.write().await;
        store.connections.retain(|c| c.target_id != id);
        record_event_locked(
            &mut store,
            "peer-blocked",
            Some(&id),
            None,
            format!("blocked; sessions revoked as of {}", terminate_ts),
        );
    }
    Ok(resp)
}

async fn allow_peer(
    Path(id): Path<String>,
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
) -> ApiResult<PeerPolicyResponse> {
    require_auth(&headers, &state.token)?;
    set_peer_policy(&state.pm, &id, Some(1)).await
}

/// Set or clear one workstation's direct endpoint. An empty/absent `endpoint` clears it,
/// which returns that peer to hole punching and the relay.
async fn set_peer_direct_endpoint(
    Path(id): Path<String>,
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
    Json(request): Json<PeerEndpointRequest>,
) -> ApiResult<PeerEndpointResponse> {
    require_auth(&headers, &state.token)?;
    // A rejected value is the operator's typo, not a server fault: 400 with the reason,
    // because the client's parser would otherwise drop it silently and the only symptom
    // would be "it still goes through the relay".
    let endpoint = set_peer_endpoint(&id, request.endpoint.as_deref())
        .map_err(|reason| api_error(StatusCode::BAD_REQUEST, &reason))?;
    {
        let mut store = STATS.write().await;
        record_event_locked(
            &mut store,
            "peer-direct-endpoint",
            Some(&id),
            None,
            if endpoint.is_empty() {
                "direct endpoint cleared; this peer falls back to hole punch / relay"
                    .to_owned()
            } else {
                format!("direct endpoint set to {endpoint}")
            },
        );
    }
    Ok(Json(PeerEndpointResponse { id, endpoint }))
}

/// Set or clear one workstation's per-peer SPA key pair. Sending both keys empty (or
/// omitting them) clears the pair, returning that peer to the fleet-wide knock key.
async fn set_peer_knock_key_route(
    Path(id): Path<String>,
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
    Json(request): Json<PeerKnockKeyRequest>,
) -> ApiResult<PeerKnockKeyResponse> {
    require_auth(&headers, &state.token)?;
    let pair = match (request.key.as_deref(), request.hmac_key.as_deref()) {
        (None, None) => None,
        (k, h) => Some((k.unwrap_or(""), h.unwrap_or(""))),
    };
    let configured = set_peer_knock_key(&id, pair)
        .map_err(|reason| api_error(StatusCode::BAD_REQUEST, &reason))?;
    {
        let mut store = STATS.write().await;
        record_event_locked(
            &mut store,
            "peer-knock-key",
            Some(&id),
            None,
            if configured {
                "per-peer knock key set (only controllers allowed to dial this peer receive it)"
                    .to_owned()
            } else {
                "per-peer knock key cleared; this peer uses the fleet-wide knock key".to_owned()
            },
        );
    }
    Ok(Json(PeerKnockKeyResponse { id, configured }))
}

async fn reset_peer_policy(
    Path(id): Path<String>,
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
) -> ApiResult<PeerPolicyResponse> {
    require_auth(&headers, &state.token)?;
    set_peer_policy(&state.pm, &id, None).await
}

async fn delete_peer(
    Path(id): Path<String>,
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
) -> ApiResult<DeletePeersResponse> {
    require_auth(&headers, &state.token)?;
    delete_peer_ids(&state.pm, vec![id]).await
}

async fn delete_peers(
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
    Json(request): Json<DeletePeersRequest>,
) -> ApiResult<DeletePeersResponse> {
    require_auth(&headers, &state.token)?;
    delete_peer_ids(&state.pm, request.ids).await
}

async fn get_policy(
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
) -> ApiResult<PolicyResponse> {
    require_auth(&headers, &state.token)?;
    Ok(Json(policy_response(&state.server_public_key)))
}

/// `{"confirm": "ROTATE"}` is required in the body. The dashboard already asks, but this
/// endpoint revokes an entire fleet's access, so it must not be reachable by a bare POST
/// from something that merely holds the admin token (a stale script, a mis-aimed curl).
async fn rotate_server_key_route(
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
    Json(request): Json<RotateServerKeyRequest>,
) -> ApiResult<RotateServerKeyResponse> {
    require_auth(&headers, &state.token)?;
    if request.confirm.trim() != ROTATE_CONFIRMATION {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            &format!(
                "refusing to rotate the server identity key without confirmation: send \
                 {{\"confirm\":\"{ROTATE_CONFIRMATION}\"}}. This locks out every client still \
                 provisioned with the current key."
            ),
        ));
    }
    let previous = state.server_public_key.trim().to_owned();
    let (new_public_key, archived) =
        rotate_server_key().map_err(|reason| api_error(StatusCode::INTERNAL_SERVER_ERROR, &reason))?;
    {
        let mut store = STATS.write().await;
        record_event_locked(
            &mut store,
            "server-key-rotated",
            None,
            None,
            format!(
                "new key {new_public_key}; previous {} archived at {}; restart hbbs to activate",
                if previous.is_empty() { "(unknown)" } else { &previous },
                if archived.is_empty() { "(none)" } else { &archived }
            ),
        );
    }
    Ok(Json(RotateServerKeyResponse {
        previous_public_key: previous,
        new_public_key,
        archived_secret_key: archived,
        restart_required: true,
    }))
}

async fn update_policy(
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
    Json(request): Json<PolicyRequest>,
) -> ApiResult<PolicyResponse> {
    require_auth(&headers, &state.token)?;
    if let Some(company_only) = request.company_only {
        COMPANY_ONLY.store(company_only, Ordering::SeqCst);
        persist_company_only(company_only);
        let mut store = STATS.write().await;
        record_event_locked(
            &mut store,
            "policy-update",
            None,
            None,
            format!("company_only={}", company_only),
        );
    }
    if let Some(limit) = request.connection_history_limit {
        let limit = limit.clamp(1, MAX_CONN_HISTORY_LIMIT);
        CONN_HISTORY_LIMIT.store(limit, Ordering::SeqCst);
        persist_conn_history_limit(limit);
        let mut store = STATS.write().await;
        // Apply immediately: trim existing history down to the new limit.
        while store.connections.len() > limit {
            match store
                .connections
                .iter()
                .enumerate()
                .min_by_key(|(_, c)| c.last_seen)
            {
                Some((idx, _)) => {
                    store.connections.remove(idx);
                }
                None => break,
            }
        }
        record_event_locked(
            &mut store,
            "policy-update",
            None,
            None,
            format!("connection_history_limit={}", limit),
        );
    }
    if let Some(limit) = request.log_history_limit {
        let limit = limit.clamp(1, MAX_LOG_HISTORY_LIMIT);
        LOG_HISTORY_LIMIT.store(limit, Ordering::SeqCst);
        persist_log_history_limit(limit);
        let mut store = STATS.write().await;
        while store.events.len() > limit {
            store.events.pop_front();
        }
        record_event_locked(
            &mut store,
            "policy-update",
            None,
            None,
            format!("log_history_limit={}", limit),
        );
    }
    if let Some(require) = request.require_device_key {
        integration::set_require_device_key(require);
    }
    if let Some(strip) = request.strip_unsealed_secrets {
        integration::set_strip_unsealed_secrets(strip);
    }
    // M1-CLAIM: turning this OFF is the fail-closed direction (an unbound key then
    // authenticates nothing and asks for nothing), so it is logged like the S-B
    // switches — that line is what explains a client that suddenly stops provisioning.
    if let Some(claim) = request.claim_unbound_device_keys {
        log::info!("Nemo claim-unbound-device-keys set to {}", claim);
        integration::set_claim_unbound_device_keys(claim);
    }
    // S-B (scope b): these lock out any client that has not been updated, so they are
    // logged at the moment an operator flips them — that log line is what explains a
    // sudden wave of refused logins/polls afterwards.
    if let Some(require) = request.require_sealed_login {
        log::info!("Nemo require-sealed-login set to {}", require);
        integration::set_require_sealed_login(require);
    }
    if let Some(require) = request.require_sealed_request {
        log::info!("Nemo require-sealed-request set to {}", require);
        integration::set_require_sealed_request(require);
    }
    Ok(Json(policy_response(&state.server_public_key)))
}

async fn get_stats(
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
) -> ApiResult<StatsResponse> {
    require_auth(&headers, &state.token)?;
    let store = STATS.read().await;
    let mut peers: Vec<_> = store
        .peers
        .iter()
        .map(|(id, stats)| StatsPeerResponse {
            id: id.clone(),
            stats: stats.clone(),
        })
        .collect();
    peers.sort_by(|a, b| a.id.cmp(&b.id));
    // TODO 7: newest first, and live sessions ahead of ended ones - the dashboard shows
    // the top of this list, and what matters is what is relaying right now.
    let mut relay_sessions = store.relay_sessions.clone();
    relay_sessions.sort_by(|a, b| {
        b.live
            .cmp(&a.live)
            .then(b.brokered_at.cmp(&a.brokered_at))
    });
    Ok(Json(StatsResponse {
        company_only: company_only(),
        totals: store.totals.clone(),
        relay_sessions,
        relay_poller: store.relay_poller.clone(),
        peers,
    }))
}

async fn get_events(
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
    Query(query): Query<EventsQuery>,
) -> ApiResult<EventsResponse> {
    require_auth(&headers, &state.token)?;
    let limit = query.limit.unwrap_or(100).clamp(1, MAX_LOG_HISTORY_LIMIT);
    let store = STATS.read().await;
    let events = store
        .events
        .iter()
        .rev()
        .take(limit)
        .cloned()
        .collect();
    Ok(Json(EventsResponse { events }))
}

async fn delete_peer_ids(pm: &PeerMap, ids: Vec<String>) -> ApiResult<DeletePeersResponse> {
    let mut seen = HashSet::new();
    let mut deleted = Vec::new();
    let mut missing = Vec::new();
    for id in ids {
        let id = id.trim().to_owned();
        if id.is_empty() || !seen.insert(id.clone()) {
            continue;
        }
        let was_deleted = pm.delete_registered(&id).await.map_err(server_error)?;
        if was_deleted {
            deleted.push(id.clone());
            let mut store = STATS.write().await;
            store.peers.remove(&id);
            record_event_locked(&mut store, "peer-delete", Some(&id), None, "deleted".to_owned());
        } else {
            missing.push(id);
        }
    }
    Ok(Json(DeletePeersResponse { deleted, missing }))
}

async fn set_peer_policy(
    pm: &PeerMap,
    id: &str,
    status: Option<i64>,
) -> ApiResult<PeerPolicyResponse> {
    let updated = pm
        .set_peer_status(id, status, None)
        .await
        .map_err(server_error)?;
    if !updated {
        return Err(api_error(StatusCode::NOT_FOUND, "peer not found"));
    }
    let mut store = STATS.write().await;
    record_event_locked(
        &mut store,
        "peer-policy-update",
        Some(id),
        None,
        format!("status={:?}", status),
    );
    Ok(Json(peer_policy_response(id.to_owned(), status)))
}

async fn peer_response(pm: &PeerMap, peer: RegisteredPeer) -> PeerResponse {
    let runtime = pm.runtime_snapshot(&peer.id).await;
    let info = serde_json::from_str::<PeerInfo>(&peer.info).unwrap_or_default();
    let status = runtime
        .as_ref()
        .and_then(|snapshot| snapshot.status)
        .or(peer.status);
    let registered_ip = runtime
        .as_ref()
        .and_then(|snapshot| snapshot.registered_ip.clone())
        .or_else(|| {
            if info.ip.is_empty() {
                None
            } else {
                Some(info.ip)
            }
        });
    // M1-CLAIM: both come from the pinned registry, not from runtime state.
    let device_key = integration::device_key_for_peer(&peer.id);
    let pending = integration::pending_claim_for_peer(&peer.id);
    let delivered = peer_endpoints_delivered(&peer.id);
    let (client_version, client_version_at) = peer_client_version(&peer.id);
    PeerResponse {
        id: peer.id.clone(),
        hostname: peer_hostname(&peer.id),
        guid: base64::encode(peer.guid),
        uuid: base64::encode(peer.uuid),
        public_key: base64::encode(peer.pk),
        user: peer.user.map(base64::encode),
        created_at: peer.created_at,
        note: peer.note,
        status,
        policy: policy_label(status),
        allowed_for_control: allowed_for_status(status),
        management_policy: mask_secret_policy(management_policy_from_peer(&peer.management_policy)),
        registered_ip,
        public_addr: runtime
            .as_ref()
            .and_then(|snapshot| snapshot.public_addr.clone()),
        online: runtime.as_ref().map(|snapshot| snapshot.online).unwrap_or(false),
        last_seen_ms_ago: runtime.and_then(|snapshot| snapshot.last_seen_ms_ago),
        auth_mode: peer_auth_mode(&peer.id),
        device_key_proved_at: peer_device_key_proved_at(&peer.id),
        provisioned: device_key.is_some(),
        device_key_id: device_key.as_ref().map(|k| k.id.clone()).unwrap_or_default(),
        device_key_label: device_key.as_ref().map(|k| k.label.clone()).unwrap_or_default(),
        pending_claim_key_id: pending.as_ref().map(|c| c.key_id.clone()).unwrap_or_default(),
        pending_claim_key_label: pending
            .as_ref()
            .and_then(|c| {
                integration::list_device_keys()
                    .into_iter()
                    .find(|k| k.public_key == c.public_key)
                    .map(|k| k.label)
            })
            .unwrap_or_default(),
        pending_claim_first_seen: pending
            .as_ref()
            .map(|c| c.first_seen.clone())
            .unwrap_or_default(),
        pending_claim_attempts: pending.as_ref().map(|c| c.attempts).unwrap_or(0),
        pending_claim_via: pending.as_ref().map(|c| c.via.clone()).unwrap_or_default(),
        pending_claim_denied: pending.as_ref().map(|c| c.denied).unwrap_or(false),
        direct_endpoint: peer_endpoint(&peer.id),
        knock_key_configured: peer_has_knock_key(&peer.id),
        endpoints_delivered: delivered.0,
        endpoints_delivered_at: delivered.1,
        client_version,
        client_version_at,
        stats: peer_stats(&peer.id).await,
    }
}

fn peer_policy_response(id: String, status: Option<i64>) -> PeerPolicyResponse {
    PeerPolicyResponse {
        id,
        status,
        policy: policy_label(status),
        allowed_for_control: allowed_for_status(status),
    }
}

// Build id of the running hbbs (baked by build.rs). GUI is compiled into the same
// binary, so this identifies both.
pub(crate) fn nemo_build_id() -> &'static str {
    option_env!("NEMO_BUILD_ID").unwrap_or("unknown")
}

fn policy_response(server_public_key: &str) -> PolicyResponse {
    PolicyResponse {
        server_public_key: server_public_key.trim().to_owned(),
        server_public_key_on_disk: server_public_key_on_disk(),
        company_only: company_only(),
        blocked_status: 0,
        allowed_status: 1,
        connection_history_limit: conn_history_limit(),
        log_history_limit: log_history_limit(),
        require_device_key: integration::require_device_key(),
        claim_unbound_device_keys: integration::claim_unbound_device_keys(),
        pending_device_key_claims: integration::pending_device_key_claim_count(),
        strip_unsealed_secrets: integration::strip_unsealed_secrets(),
        require_sealed_login: integration::require_sealed_login(),
        require_sealed_request: integration::require_sealed_request(),
        build_id: nemo_build_id(),
    }
}

// Nemo hardening (S4): policy keys whose values are secrets and must never be
// echoed in API responses (they were previously returned in plaintext).
const SECRET_POLICY_KEYS: &[&str] = &[
    "nemo-permanent-password",
    "default-connect-password",
    "proxy-password",
    "preset-address-book-password",
    // The SPA keys are shared secrets with the fwknopd on the edge: holding them is
    // enough to open the forwarded port for yourself. They must be masked in dashboard
    // responses and stripped from any policy we cannot seal, exactly like a password.
    OPTION_NEMO_KNOCK_KEY,
    OPTION_NEMO_KNOCK_HMAC_KEY,
    // The per-peer SPA key map is assembled into the sealed policy per poll; name it here
    // so it is stripped on the plaintext fallback path exactly like the fleet-wide key.
    OPTION_NEMO_KNOCK_KEYS,
];
const MANAGED_SECRET_MASK: &str = "<managed-secret>";

fn mask_secret_policy(mut policy: ManagementPolicy) -> ManagementPolicy {
    for key in SECRET_POLICY_KEYS {
        if let Some(v) = policy.options.get_mut(*key) {
            if !v.is_empty() {
                *v = MANAGED_SECRET_MASK.to_owned();
            }
        }
    }
    policy
}

// A dashboard round-trip sees the masks, not the plaintext; restore the stored
// value for any secret left as the mask so saving does not clobber it.
fn restore_masked_secrets(
    policy: ManagementPolicy,
    existing: &Option<String>,
) -> ManagementPolicy {
    restore_masked_secrets_from(policy, &management_policy_from_peer(existing))
}

fn restore_masked_secrets_from(
    mut policy: ManagementPolicy,
    current: &ManagementPolicy,
) -> ManagementPolicy {
    for key in SECRET_POLICY_KEYS {
        let is_mask = policy
            .options
            .get(*key)
            .map(|v| v == MANAGED_SECRET_MASK)
            .unwrap_or(false);
        if is_mask {
            match current.options.get(*key) {
                Some(v) => {
                    policy.options.insert((*key).to_owned(), v.clone());
                }
                None => {
                    policy.options.remove(*key);
                }
            }
        }
    }
    policy
}

fn management_policy_from_peer(value: &Option<String>) -> ManagementPolicy {
    let Some(value) = value.as_deref() else {
        return ManagementPolicy::default();
    };
    serde_json::from_str::<ManagementPolicy>(value)
        .map(sanitize_management_policy)
        .unwrap_or_default()
}

fn sanitize_management_policy(mut policy: ManagementPolicy) -> ManagementPolicy {
    policy.options.retain(|key, value| {
        let Some(normalized) = sanitize_management_policy_value(key, value) else {
            return false;
        };
        *value = normalized;
        true
    });
    policy
}

fn sanitize_management_policy_value(key: &str, value: &str) -> Option<String> {
    if !is_management_policy_key(key) {
        return None;
    }
    let value = value.trim();
    if value.len() > MAX_MANAGEMENT_POLICY_VALUE_LEN {
        return None;
    }
    Some(value.to_owned())
}

fn is_management_policy_key(key: &str) -> bool {
    CLIENT_MANAGEMENT_POLICY_KEYS.contains(&key)
        || keys::KEYS_SETTINGS.contains(&key)
        || keys::KEYS_LOCAL_SETTINGS.contains(&key)
        || keys::KEYS_DISPLAY_SETTINGS.contains(&key)
}

fn serialize_management_policy(policy: &ManagementPolicy) -> Result<Option<String>, ApiFailure> {
    if policy.options.is_empty() {
        return Ok(None);
    }
    serde_json::to_string(policy)
        .map(Some)
        .map_err(server_error)
}

fn validate_client_policy_request(
    peer: &RegisteredPeer,
    request: &ClientPolicyRequest,
) -> Result<(), ApiFailure> {
    if request.id.trim().is_empty() {
        return Err(api_error(StatusCode::BAD_REQUEST, "missing peer id"));
    }
    let uuid = base64::decode(request.uuid.trim())
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid uuid"))?;
    if uuid != peer.uuid {
        return Err(api_error(StatusCode::UNAUTHORIZED, "uuid mismatch"));
    }
    Ok(())
}

fn require_auth(headers: &HeaderMap, token: &Option<String>) -> Result<(), ApiFailure> {
    // L-fix: no configured token used to mean OPEN — any local process could
    // administer the server. Now it fails closed; spawn_hbbs_api guarantees a
    // token always exists (auto-generated and logged when the operator sets none).
    let Some(token) = token else {
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "management API token not configured",
        ));
    };
    let bearer = format!("Bearer {}", token);
    let auth = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(|value| constant_time_eq(value, &bearer))
        .unwrap_or(false);
    let nemo_token = headers
        .get("x-nemo-token")
        .and_then(|value| value.to_str().ok())
        .map(|value| constant_time_eq(value, token))
        .unwrap_or(false);
    if auth || nemo_token {
        Ok(())
    } else {
        Err(api_error(StatusCode::UNAUTHORIZED, "unauthorized"))
    }
}

// Nemo hardening (S3): constant-time token comparison so an attacker cannot
// recover the token byte-by-byte via response timing. Length is compared first
// (token length is not sensitive); the content comparison is constant-time.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    a.len() == b.len() && sodiumoxide::utils::memcmp(a, b)
}

fn api_error(status: StatusCode, message: &str) -> ApiFailure {
    (
        status,
        Json(ApiError {
            error: message.to_owned(),
        }),
    )
}

fn server_error(err: impl std::fmt::Display) -> ApiFailure {
    api_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string())
}

// Nemo hardening (S7): bound the per-peer stats map. record_peer_seen runs for
// every RegisterPeer *before* validation, so unauthenticated UDP with random
// ids could otherwise grow this map without limit. At the cap, evict the
// least-recently-active entries down to 3/4 of the cap.
const MAX_PEER_STATS: usize = 5000;

fn prune_peer_stats(store: &mut NemoStatsStore) {
    let mut aged: Vec<(String, String)> = store
        .peers
        .iter()
        .map(|(k, v)| (k.clone(), v.last_event_at.clone().unwrap_or_default()))
        .collect();
    aged.sort_by(|a, b| a.1.cmp(&b.1));
    let target = MAX_PEER_STATS * 3 / 4;
    let remove = store.peers.len().saturating_sub(target);
    for (id, _) in aged.into_iter().take(remove) {
        store.peers.remove(&id);
    }
}

fn peer_stats_mut<'a>(store: &'a mut NemoStatsStore, id: &str) -> &'a mut NemoPeerStats {
    if store.peers.len() >= MAX_PEER_STATS && !store.peers.contains_key(id) {
        prune_peer_stats(store);
    }
    store.peers.entry(id.to_owned()).or_default()
}

fn record_event_locked(
    store: &mut NemoStatsStore,
    kind: &str,
    peer_id: Option<&str>,
    remote_addr: Option<SocketAddr>,
    detail: String,
) {
    let now = now_iso();
    if let Some(peer_id) = peer_id {
        let peer = peer_stats_mut(store, peer_id);
        peer.last_event_at = Some(now.clone());
    }
    store.events.push_back(NemoEvent {
        at: now,
        kind: kind.to_owned(),
        peer_id: peer_id.map(ToOwned::to_owned),
        remote_addr: remote_addr.map(|addr| addr.to_string()),
        detail,
    });
    while store.events.len() > log_history_limit() {
        store.events.pop_front();
    }
}

fn policy_label(status: Option<i64>) -> String {
    match status {
        Some(0) => "blocked".to_owned(),
        Some(1) => "allowed".to_owned(),
        _ if company_only() => "unapproved".to_owned(),
        _ => "open".to_owned(),
    }
}

fn allowed_for_status(status: Option<i64>) -> bool {
    match status {
        Some(0) => false,
        Some(1) => true,
        _ => !company_only(),
    }
}

fn nat_type_name(value: i32) -> &'static str {
    match value {
        1 => "ASYMMETRIC",
        2 => "SYMMETRIC",
        _ => "UNKNOWN_NAT",
    }
}

pub(crate) fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// TODO 7: the off switch for a value that is normally an address, so an operator can
/// write `--nemo-relay-metrics N` as well as `--nemo-relay-metrics ""`.
fn is_truthy_off(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "n" | "no" | "off" | "false" | "0" | "none" | "disabled"
    )
}

pub(crate) fn is_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "y" | "yes" | "true" | "on"
    )
}

#[cfg(test)]
mod tests {

    //! Layer 1 (TDD): pure-function unit tests for the Nemo policy layer.
    //!
    //! These live inline so they can reach the module-private functions without
    //! widening any visibility. They perform no I/O and touch no sockets/DB; the
    //! few that depend on the process-global `COMPANY_ONLY` are grouped into a
    //! single serial test that restores the flag, so the suite stays
    //! deterministic under `cargo test`'s parallel runner.
    use super::*;

    #[test]
    fn api_tls_defaults_pin_self_signed_and_close_fallback_for_provided() {
        let mut o = HashMap::new();
        apply_api_tls_defaults(&mut o, None);
        assert!(o.is_empty());
        let ss = TlsCertInfo { tls: true, mode: "self-signed".into(), fingerprint: "AA:BB".into(), ..Default::default() };
        apply_api_tls_defaults(&mut o, Some(&ss));
        assert_eq!(o.get("nemo-api-cert-fingerprint").map(|s| s.as_str()), Some("AA:BB"));
        assert!(!o.contains_key("allow-insecure-tls-fallback"));
        let mut o = HashMap::new();
        o.insert("nemo-api-cert-fingerprint".to_owned(), "CC".to_owned());
        apply_api_tls_defaults(&mut o, Some(&ss));
        assert_eq!(o["nemo-api-cert-fingerprint"], "CC", "operator value wins");
        let mut o = HashMap::new();
        let ca = TlsCertInfo { tls: true, mode: "provided".into(), fingerprint: "DD".into(), ..Default::default() };
        apply_api_tls_defaults(&mut o, Some(&ca));
        assert_eq!(o["allow-insecure-tls-fallback"], "N");
        assert!(!o.contains_key("nemo-api-cert-fingerprint"), "never pin a renewing CA cert");
    }

    #[test]
    fn session_binding_needs_the_same_proven_key() {
        assert!(session_device_binding_ok("", None));
        assert!(session_device_binding_ok("", Some("k1")));
        assert!(session_device_binding_ok("k1", Some("k1")));
        assert!(!session_device_binding_ok("k1", Some("k2")));
        assert!(!session_device_binding_ok("k1", None));
    }

    // The controller-identity vectors below are a cross-fork CONTRACT: the
    // client fork formats this exact string in
    // `rustdesk-client-nemo/src/client.rs::nemo_source_identity_header`, and the
    // server parses it here. Keep these cases byte-identical to the client-side
    // tests so a divergence in either fork fails a test rather than silently
    // breaking controller policy. When the dedicated `NemoSource` protobuf field
    // lands (roadmap Phase 1.3), convert these into proto round-trip vectors.
    fn source_field(id: &str, uuid: &[u8]) -> String {
        format!("{}{}:{}", NEMO_SOURCE_PREFIX, id, base64::encode(uuid))
    }

    #[test]
    fn target_allowed_none_or_empty_is_open() {
        assert!(target_allowed_by_controller_policy(None, "anything"));
        assert!(target_allowed_by_controller_policy(Some(&String::new()), "anything"));
        assert!(target_allowed_by_controller_policy(Some(&"   ".to_owned()), "anything"));
    }

    #[test]
    fn target_allowed_wildcard_matches_any() {
        assert!(target_allowed_by_controller_policy(Some(&"*".to_owned()), "ws-01"));
        assert!(target_allowed_by_controller_policy(Some(&"ws-02, *".to_owned()), "ws-01"));
    }

    #[test]
    fn target_allowed_exact_and_separators() {
        let targets = "ws-01, ws-02; ws-03\tws-04".to_owned();
        for wanted in ["ws-01", "ws-02", "ws-03", "ws-04"] {
            assert!(
                target_allowed_by_controller_policy(Some(&targets), wanted),
                "expected {wanted} to be allowed"
            );
        }
        assert!(!target_allowed_by_controller_policy(Some(&targets), "ws-99"));
    }

    #[test]
    fn target_allowed_trims_entries() {
        assert!(target_allowed_by_controller_policy(
            Some(&"   ws-01   ,   ws-02   ".to_owned()),
            "ws-02"
        ));
    }

    #[test]
    fn source_identity_parses_bare_and_versioned() {
        let uuid = vec![1u8, 2, 3, 4, 5];
        // Bare form.
        let (id, got, _) = controller_source_identity(&source_field("peer-a", &uuid)).unwrap();
        assert_eq!(id, "peer-a");
        assert_eq!(got, uuid);
        // Embedded after a real version string, as the client actually sends it
        // in `PunchHoleRequest.version` ("<VERSION> nemo-source-v1:...").
        let versioned = format!("1.4.6 {}", source_field("peer-a", &uuid));
        let (id2, got2, _) = controller_source_identity(&versioned).unwrap();
        assert_eq!(id2, "peer-a");
        assert_eq!(got2, uuid);
    }

    #[test]
    fn source_identity_stops_at_trailing_whitespace() {
        // A trailing token after the uuid (e.g. more version data) must not be
        // folded into the base64 uuid.
        let uuid = vec![9u8, 8, 7];
        let field = format!("{} extra-token", source_field("peer-b", &uuid));
        let (id, got, _) = controller_source_identity(&field).unwrap();
        assert_eq!(id, "peer-b");
        assert_eq!(got, uuid);
    }

    // H9/H32: the relay arm now runs the same per-user gate the punch arm does, but
    // the controller's marker rides in RequestRelay.licence_key, NOT in a version
    // string. If the two field shapes parsed differently, adding the gate would have
    // refused every relayed session instead of only unauthorised ones.
    // SEC-9: every route an unauthenticated caller can push a BODY to must land in
    // the small tier. If a public path ever moves, this is what catches it.
    // Two paths are not what their names suggest: `/nemo/admin` needs no token but is
    // a GET serving a static page (no body, so the large tier is harmless), and
    // `/nemo/api/health` reads like a probe but is require_auth-gated and returns the
    // whole security policy -- admin tier.
    #[test]
    fn public_routes_get_the_small_body_cap() {
        for public in [
            "/api/login",
            "/api/logout",
            "/api/ab/get",
            "/api/currentUser",
            "/api/login-key",
            "/api/tls-cert-info",
            "/nemo/api/client/policy",
            "/nemo/api/update/latest",
            // TASK-18: these three now serve the tokenless login shell.
            "/nemo",
            "/nemo/admin",
            "/nemo/admin/",
        ] {
            assert_eq!(request_body_cap(public), MAX_PUBLIC_REQUEST_BODY, "{}", public);
        }
        for admin in [
            "/nemo/api/integration/permissions",
            "/nemo/api/policies",
            "/nemo/api/update",
            "/nemo/api/peers/delete",
            // TASK-18: the dashboard HTML itself is token-gated, unlike the shell.
            "/nemo/admin/app",
            // require_auth-gated (see `health`) and it returns the security policy,
            // so it belongs here and not in the public list it used to sit in.
            "/nemo/api/health",
        ] {
            assert_eq!(request_body_cap(admin), MAX_REQUEST_BODY, "{}", admin);
        }
        // The public tier still has room for a sealed login envelope.
        assert!(MAX_PUBLIC_REQUEST_BODY > MAX_SEALED_REQUEST_B64);
    }

    // TASK-18: the dashboard HTML is a map of the whole management surface, so it is
    // admin-token-only; what an anonymous caller gets is the shell. Guard the shell
    // against acquiring structure by accident -- a future edit that pastes a route
    // list, a policy key or the build stamp into it fails here rather than in the
    // field. No router needed: this is a property of the bytes we compile in.
    #[test]
    fn the_login_shell_discloses_no_management_structure() {
        let shell = include_str!("nemo_admin_shell.html");
        let lower = shell.to_lowercase();
        for leak in [
            "/nemo/api/",
            "{{nemo_build_id}}",
            "ldap",
            "device-key",
            "nemo-permanent-password",
            "view-peers",
        ] {
            assert!(!lower.contains(leak), "the login shell must not mention {leak}");
        }
        // It needs exactly two things: the gated URL it fetches, and the storage key
        // the dashboard already uses, so a returning admin is never asked twice.
        assert!(shell.contains("/nemo/admin/app"));
        assert!(shell.contains("nemoAdminToken"));
        // And the build stamp must still live in the gated page, not the shell.
        assert!(include_str!("nemo_admin.html").contains("{{NEMO_BUILD_ID}}"));
    }

    #[test]
    fn source_identity_is_identical_in_the_punch_and_relay_field_shapes() {
        let uuid = vec![4u8, 5, 6];
        let marker = format!("{}:tok-xyz", source_field("peer-c", &uuid));
        // Punch: "<version> <marker>" (PunchHoleRequest.version).
        let punch = controller_source_identity(&format!("1.4.6 {}", marker)).unwrap();
        // Relay: the bare marker (RequestRelay.licence_key).
        let relay = controller_source_identity(&marker).unwrap();
        assert_eq!(punch, relay);
        assert_eq!(relay.0, "peer-c");
        assert_eq!(relay.1, uuid);
        assert_eq!(relay.2.as_deref(), Some("tok-xyz"));
    }

    // Fail-closed shape: an unparseable field and a forged token must both land on
    // the "not logged in" branch, so choosing the relay path cannot be a way around
    // require-login. (Whether that branch refuses depends on require_login, which is
    // operator state; what is asserted here is that the two are indistinguishable.)
    #[test]
    fn relay_gate_treats_a_missing_marker_and_a_forged_token_alike() {
        assert!(controller_source_identity("1.4.6").is_none());
        assert!(nemo_user_rejection_from_field(None, "1.4.6", "target", None).is_none() == !integration::require_login());
        assert_eq!(
            nemo_user_connection_rejection(None, None, "target"),
            nemo_user_connection_rejection(Some("not-a-real-session-token"), None, "target"),
        );
    }

    #[test]
    fn source_identity_parses_optional_user_token() {
        let uuid = vec![1u8, 2, 3];
        // With a trailing user token.
        let field = format!("1.4.6 {}:tok-abc123", source_field("peer-a", &uuid));
        let (id, got, token) = controller_source_identity(&field).unwrap();
        assert_eq!(id, "peer-a");
        assert_eq!(got, uuid);
        assert_eq!(token.as_deref(), Some("tok-abc123"));
        // Without a token the third element is None (backward compatible).
        let (_, _, none_token) =
            controller_source_identity(&source_field("peer-a", &uuid)).unwrap();
        assert!(none_token.is_none());
    }

    #[test]
    fn source_identity_rejects_malformed() {
        // Missing prefix.
        assert!(controller_source_identity("1.4.6 no-marker-here").is_none());
        // Missing uuid part.
        assert!(controller_source_identity("nemo-source-v1:peer-a").is_none());
        // Empty id.
        assert!(controller_source_identity("nemo-source-v1::dXVpZA==").is_none());
        // Empty uuid.
        assert!(controller_source_identity("nemo-source-v1:peer-a:").is_none());
        // Invalid base64 uuid.
        assert!(controller_source_identity("nemo-source-v1:peer-a:!!!not-base64!!!").is_none());
    }

    // H44: the identity that drives the four controller gates.
    #[test]
    fn controller_identity_prefers_the_proven_device_key() {
        let uuid = vec![1u8, 2, 3];
        let field = format!("1.4.6 {}", source_field("tech-01", &uuid));
        // Proven + matching marker: the proven id wins, uuid still cross-checked.
        assert_eq!(
            resolve_controller_identity(None, &field, Some("tech-01")),
            Ok(("tech-01".to_owned(), Some(uuid.clone()))),
        );
        // Proven + no marker: the device key IS the identity, so there is no uuid to
        // compare and the gates must still run.
        assert_eq!(
            resolve_controller_identity(None, "1.4.6", Some("tech-01")),
            Ok(("tech-01".to_owned(), None)),
        );
        // Unproven + marker: staged rollout with require-device-key off; the marker is
        // all there is, exactly as before.
        assert_eq!(
            resolve_controller_identity(None, &field, None),
            Ok(("tech-01".to_owned(), Some(uuid))),
        );
    }

    #[test]
    fn controller_identity_refuses_a_marker_that_impersonates_someone_else() {
        let field = format!("1.4.6 {}", source_field("tech-02", &[9u8, 9]));
        let err = resolve_controller_identity(None, &field, Some("tech-01")).unwrap_err();
        assert_eq!(err.0, "tech-01");
        assert!(
            err.1.contains("does not match the proven device key"),
            "{}",
            err.1
        );
    }

    // The bypass this change exists to close: no proof AND no marker used to return
    // None from controller_policy_rejection_from_field, which both call sites read as
    // PASS -- so omitting one wire field skipped all four controller gates.
    #[test]
    fn controller_identity_fails_closed_when_nothing_identifies_the_caller() {
        assert!(controller_source_identity("1.4.6").is_none());
        let err = resolve_controller_identity(None, "1.4.6", None).unwrap_err();
        assert_eq!(err.0, "?");
        assert!(err.1.contains("could not be established"), "{}", err.1);
    }

    #[test]
    fn is_truthy_accepts_common_affirmatives() {
        for v in ["1", "y", "Y", "yes", "YES", "true", "TRUE", "on", "  on  "] {
            assert!(is_truthy(v), "{v:?} should be truthy");
        }
        for v in ["0", "n", "no", "false", "off", "", "  ", "maybe"] {
            assert!(!is_truthy(v), "{v:?} should be falsy");
        }
    }

    #[test]
    fn management_policy_key_membership() {
        // Nemo-only keys.
        assert!(is_management_policy_key("nemo-outbound-enabled"));
        assert!(is_management_policy_key("nemo-permanent-password"));
        // Performance key the roadmap pushes via policy.
        assert!(is_management_policy_key("enable-udp-punch"));
        // Unknown key.
        assert!(!is_management_policy_key("totally-bogus-key"));
    }

    #[test]
    fn sanitize_value_trims_and_bounds() {
        // Known key: value is trimmed.
        assert_eq!(
            sanitize_management_policy_value("nemo-outbound-enabled", "  Y  ").as_deref(),
            Some("Y")
        );
        // Unknown key: dropped.
        assert!(sanitize_management_policy_value("totally-bogus-key", "Y").is_none());
        // Overlong value: dropped.
        let long = "a".repeat(MAX_MANAGEMENT_POLICY_VALUE_LEN + 1);
        assert!(sanitize_management_policy_value("nemo-outbound-enabled", &long).is_none());
        // Exactly at the bound: kept.
        let at_bound = "a".repeat(MAX_MANAGEMENT_POLICY_VALUE_LEN);
        assert!(sanitize_management_policy_value("nemo-outbound-enabled", &at_bound).is_some());
    }

    #[test]
    fn management_policy_from_peer_handles_missing_and_invalid() {
        // None -> default (empty options).
        assert!(management_policy_from_peer(&None).options.is_empty());
        // Invalid JSON -> default.
        assert!(management_policy_from_peer(&Some("not json".to_owned()))
            .options
            .is_empty());
    }

    #[test]
    fn management_policy_from_peer_sanitizes_options() {
        let json = r#"{
            "allow_user_override": true,
            "options": {
                "nemo-outbound-enabled": "  N  ",
                "totally-bogus-key": "should-be-dropped"
            }
        }"#;
        let policy = management_policy_from_peer(&Some(json.to_owned()));
        assert!(policy.allow_user_override);
        // Unknown key dropped, known key trimmed.
        assert_eq!(policy.options.get("nemo-outbound-enabled").map(String::as_str), Some("N"));
        assert!(!policy.options.contains_key("totally-bogus-key"));
    }

    #[test]
    fn nat_type_name_maps_known_values() {
        assert_eq!(nat_type_name(1), "ASYMMETRIC");
        assert_eq!(nat_type_name(2), "SYMMETRIC");
        assert_eq!(nat_type_name(0), "UNKNOWN_NAT");
        assert_eq!(nat_type_name(42), "UNKNOWN_NAT");
    }

    // L-fix: a missing token no longer means "open" — the API refuses everything
    // until a token exists (spawn_hbbs_api auto-generates one when unset).
    #[test]
    fn require_auth_fails_closed_when_no_token_configured() {
        let headers = HeaderMap::new();
        assert_eq!(
            require_auth(&headers, &None).unwrap_err().0,
            StatusCode::UNAUTHORIZED
        );
        let mut with_header = HeaderMap::new();
        with_header.insert(AUTHORIZATION, "Bearer anything".parse().unwrap());
        assert_eq!(
            require_auth(&with_header, &None).unwrap_err().0,
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn require_auth_accepts_bearer_and_x_nemo_token() {
        let token = Some("s3cret".to_owned());

        let mut bearer = HeaderMap::new();
        bearer.insert(AUTHORIZATION, "Bearer s3cret".parse().unwrap());
        assert!(require_auth(&bearer, &token).is_ok());

        let mut xnemo = HeaderMap::new();
        xnemo.insert("x-nemo-token", "s3cret".parse().unwrap());
        assert!(require_auth(&xnemo, &token).is_ok());
    }

    #[test]
    fn require_auth_rejects_missing_or_wrong_token() {
        let token = Some("s3cret".to_owned());

        assert_eq!(
            require_auth(&HeaderMap::new(), &token).unwrap_err().0,
            StatusCode::UNAUTHORIZED
        );

        let mut wrong = HeaderMap::new();
        wrong.insert(AUTHORIZATION, "Bearer nope".parse().unwrap());
        assert_eq!(
            require_auth(&wrong, &token).unwrap_err().0,
            StatusCode::UNAUTHORIZED
        );
    }

    // L-fix (sealed-login replay): freshness window enforced (ts=0 no longer
    // bypasses), and a nonce is accepted at most once inside the window.
    #[test]
    fn sealed_login_guard_enforces_window_and_nonce() {
        let now = 1_000_000u64;
        let mut seen = HashMap::new();
        // Fresh, nonce accepted once.
        assert!(sealed_login_guard(now - 10, "n1", now, &mut seen).is_ok());
        // Same nonce again inside the window = replay.
        assert!(sealed_login_guard(now - 5, "n1", now, &mut seen).is_err());
        // Different nonce passes.
        assert!(sealed_login_guard(now - 5, "n2", now, &mut seen).is_ok());
        // Too old / too far in the future / the old ts==0 bypass — all rejected.
        assert!(sealed_login_guard(now - 301, "n3", now, &mut seen).is_err());
        assert!(sealed_login_guard(now + 61, "n4", now, &mut seen).is_err());
        assert!(sealed_login_guard(0, "n5", now, &mut seen).is_err());
        // Empty nonce (older client): timestamp window only, accepted.
        assert!(sealed_login_guard(now - 10, "", now, &mut seen).is_ok());
        // A nonce seen long ago is pruned and usable again.
        let later = now + 400;
        assert!(sealed_login_guard(later - 10, "n1", later, &mut seen).is_ok());
    }

    // S-B/S-DUALKEY step 3: what the server seals to an Ed25519 device key, the
    // holder of the matching secret key (the client) can open — and only them.
    #[test]
    fn seal_to_device_key_roundtrip() {
        sodiumoxide::init().ok();
        let (pk, sk) = sign::gen_keypair();
        let pub_b64 = base64::encode(pk.as_ref());
        let sealed_b64 = seal_to_device_key(&pub_b64, b"secret payload").expect("seal");
        // Client-side recipe: Ed25519 -> Curve25519 for both halves, then open.
        let curve_pk = sign::to_curve25519_pk(&pk).expect("pk conversion");
        let curve_sk = sign::to_curve25519_sk(&sk).expect("sk conversion");
        let opened = sealedbox::open(
            &base64::decode(&sealed_b64).expect("b64"),
            &curve_pk,
            &curve_sk,
        )
        .expect("open");
        assert_eq!(opened, b"secret payload");
        // A different keypair cannot open it.
        let (pk2, sk2) = sign::gen_keypair();
        let other_pk = sign::to_curve25519_pk(&pk2).unwrap();
        let other_sk = sign::to_curve25519_sk(&sk2).unwrap();
        assert!(sealedbox::open(
            &base64::decode(&sealed_b64).unwrap(),
            &other_pk,
            &other_sk
        )
        .is_err());
        // Junk public key -> None, never a bogus seal.
        assert!(seal_to_device_key("!!!", b"x").is_none());
        assert!(seal_to_device_key(&base64::encode([1u8; 7]), b"x").is_none());
    }

    // S-B (scope b): the sealed REQUEST envelope. The wire rules live in the pure
    // core, so they are exercised against a LOCAL nonce cache — never the process
    // global SEEN_REQUEST_NONCES, which the parallel test runner would share.
    #[test]
    fn sealed_request_envelope_opens_to_the_inner_request() {
        let now = 1_700_000_000u64;
        let mut seen = HashMap::new();
        let plain = serde_json::json!({
            "id": "peer-a",
            "uuid": base64::encode([10u8, 20, 30]),
            "access_token": "tok",
            "ts": now - 5,
            "nonce": "n1",
        })
        .to_string();
        let inner = parse_sealed_request(plain.as_bytes(), now, &mut seen).expect("opens");
        // The typed struct ignores the envelope-only ts/nonce (nothing here denies
        // unknown fields), so the handler continues through its existing logic.
        let request: ClientPolicyRequest = serde_json::from_value(inner).expect("inner shape");
        assert_eq!(request.id, "peer-a");
        assert_eq!(request.access_token.as_deref(), Some("tok"));
    }

    #[test]
    fn sealed_request_envelope_refuses_replay_and_stale_ts() {
        let now = 1_700_000_000u64;
        let mut seen = HashMap::new();
        let body = |ts: u64, nonce: &str| {
            serde_json::json!({ "id": "peer-a", "uuid": "", "ts": ts, "nonce": nonce }).to_string()
        };
        assert!(parse_sealed_request(body(now - 5, "n1").as_bytes(), now, &mut seen).is_ok());
        // The same nonce inside the window is a replay.
        assert!(parse_sealed_request(body(now - 5, "n1").as_bytes(), now, &mut seen).is_err());
        // Expired, too far in the future, and the ts==0 bypass.
        assert!(parse_sealed_request(body(now - 301, "n2").as_bytes(), now, &mut seen).is_err());
        assert!(parse_sealed_request(body(now + 61, "n3").as_bytes(), now, &mut seen).is_err());
        assert!(parse_sealed_request(body(0, "n4").as_bytes(), now, &mut seen).is_err());
        // Unlike a sealed LOGIN, an envelope without a nonce is REFUSED: there is no
        // legacy envelope sender to be lenient to.
        assert!(parse_sealed_request(body(now - 5, "").as_bytes(), now, &mut seen).is_err());
        // Garbage inside the seal fails closed too.
        assert!(parse_sealed_request(b"not json", now, &mut seen).is_err());
        // Login and request nonces live in separate caches, so the same string is
        // spendable once on each endpoint and neither can evict the other.
        let mut login_seen = HashMap::new();
        assert!(sealed_login_guard(now - 5, "n1", now, &mut login_seen).is_ok());
    }

    // R3: with no envelope and the operator setting at its shipped default (false),
    // today's plaintext body passes through byte-identical.
    #[test]
    fn unsealed_request_body_defaults_to_todays_plaintext_path() {
        let raw = serde_json::json!({ "id": "peer-a", "uuid": base64::encode([1u8, 2, 3]) });
        let out = unsealed_request_body(raw.clone(), false).expect("plaintext accepted");
        assert_eq!(out, raw);
        let request: ClientPolicyRequest = serde_json::from_value(out).expect("today's shape");
        assert_eq!(request.id, "peer-a");
        assert!(request.sealed_token.is_none());
        // Only once an operator turns it on is the same body refused, with a message
        // the end user can act on.
        let err = unsealed_request_body(raw, true).expect_err("refused when required");
        assert!(err.contains("encrypted request"), "{}", err);
    }

    // S-B (scope b): the login reply key. The session token is sealed to the EPHEMERAL
    // X25519 key the client put inside its sealed login, so only that client can open
    // it — a MITM replaying the response has no usable session. Cross-fork contract:
    // the key is base64 of the RAW box_ public key (NOT an Ed25519 device key), which
    // is what decode_sealed_login parses back with box_::PublicKey::from_slice.
    #[test]
    fn access_token_seals_to_the_client_reply_key() {
        sodiumoxide::init().ok();
        let (pk, sk) = box_::gen_keypair();
        let sealed = base64::encode(sealedbox::seal(b"session-token", &pk));
        let opened = sealedbox::open(&base64::decode(&sealed).unwrap(), &pk, &sk).expect("open");
        assert_eq!(opened, b"session-token");
        // Another keypair cannot open it.
        let (pk2, sk2) = box_::gen_keypair();
        assert!(sealedbox::open(&base64::decode(&sealed).unwrap(), &pk2, &sk2).is_err());
        // Wire round trip of the key itself.
        let wire = base64::encode(pk.as_ref());
        assert_eq!(
            box_::PublicKey::from_slice(&base64::decode(&wire).unwrap()),
            Some(pk)
        );
    }

    // R3: a client that sent no reply_pk sees the response it sees today — the new
    // field is skipped entirely rather than serialized as null.
    #[test]
    fn login_result_without_reply_key_keeps_todays_shape() {
        let json = serde_json::to_value(&LoginResult {
            access_token: Some("tok".to_owned()),
            sealed_access_token: None,
            kind: Some("access_token".to_owned()),
            user: None,
            error: None,
        })
        .expect("serialize");
        assert_eq!(json.get("access_token").and_then(|v| v.as_str()), Some("tok"));
        assert!(json.get("sealed_access_token").is_none());
        // And the error shape keeps carrying neither token.
        let err = serde_json::to_value(&LoginResult::err("nope")).expect("serialize");
        assert!(err.get("access_token").is_none());
        assert!(err.get("sealed_access_token").is_none());
    }

    // Layer 1: the sealed login's device proof is optional ON THE WIRE (an older
    // sealed client still parses) and lands as empty strings, which the gate treats
    // as "no proof".
    #[test]
    fn sealed_login_parses_with_and_without_device_proof() {
        let old: SealedLogin =
            serde_json::from_str(r#"{"username":"alice","password":"pw","ts":1,"nonce":"n"}"#)
                .expect("older sealed client shape");
        assert!(old.device_key_pub.is_empty());
        assert!(old.device_key_sig.is_empty());
        let new: SealedLogin = serde_json::from_str(
            r#"{"username":"alice","password":"pw","ts":1,"nonce":"n","reply_pk":"","device_key_pub":"PK","device_key_sig":"SIG"}"#,
        )
        .expect("provisioned client shape");
        assert_eq!(new.device_key_pub, "PK");
        assert_eq!(new.device_key_sig, "SIG");
    }

    // Layer 1: the login gate accepts only a fresh "nemo-login" signature from a
    // PINNED key — a poll signature for the same key/id is refused (domain
    // separation), and an empty proof (the plaintext-login case) never passes.
    #[test]
    fn login_device_key_ok_requires_pinned_key_under_login_domain() {
        sodiumoxide::init().ok();
        let (pk, sk) = sign::gen_keypair();
        let pub_b64 = base64::encode(pk.as_ref());
        let now = now_secs();
        let opened = |pub_b64: &str, sig: &str| OpenedLogin {
            username: "alice".to_owned(),
            password: "pw".to_owned(),
            reply_pk: None,
            device_key_pub: pub_b64.to_owned(),
            device_key_sig: sig.to_owned(),
        };
        // No proof at all (what a plaintext login resolves to).
        assert!(!login_device_key_ok(&opened("", ""), "peer-a"));
        // Valid signature, key NOT pinned -> refused.
        let login_sig = signed_for(&sk, "nemo-login", "peer-a", now);
        assert!(!login_device_key_ok(
            &opened(&pub_b64, &login_sig),
            "peer-a"
        ));
        integration::pin_device_key_for_test(integration::DeviceKey {
            id: "logintestkey".to_owned(),
            label: "test".to_owned(),
            public_key: pub_b64.clone(),
            created_at: String::new(),
            peer_id: "peer-a".to_owned(),
            claimed_at: String::new(),
        });
        assert!(login_device_key_ok(&opened(&pub_b64, &login_sig), "peer-a"));
        // A captured POLL signature is useless as a login proof.
        let poll_sig = signed_for(&sk, "nemo-poll", "peer-a", now);
        assert!(!login_device_key_ok(&opened(&pub_b64, &poll_sig), "peer-a"));
        // M1: the key is bound to peer-a, so another claimed id fails.
        assert!(!login_device_key_ok(
            &opened(&pub_b64, &login_sig),
            "peer-b"
        ));
        // Half a proof is no proof.
        assert!(!login_device_key_ok(&opened(&pub_b64, ""), "peer-a"));
        integration::unpin_device_key_for_test(&pub_b64);
    }

    // Auto-update: the signed manifest is the cross-fork contract with the client's
    // nemo_verify_update_manifest — a DETACHED Ed25519 signature by the management
    // key over exactly "version|url|sha256", base64 on the wire.
    #[test]
    fn update_manifest_signature_is_detached_over_pipe_joined_fields() {
        sodiumoxide::init().ok();
        let (pk, sk) = sign::gen_keypair();
        let m = UpdateManifest {
            version: "1.4.7".to_owned(),
            url: "https://tbf.example.com:21114/dl/tbfdesk-1.4.7.exe".to_owned(),
            sha256: "ab".repeat(32),
            platforms: Default::default(),
        };
        let signed = sign_update_manifest(&m, &sk);
        assert_eq!(signed.version, m.version);
        assert_eq!(signed.url, m.url);
        assert_eq!(signed.sha256, m.sha256);
        let sig_bytes = base64::decode(&signed.sig).expect("base64 sig");
        assert_eq!(sig_bytes.len(), sign::SIGNATUREBYTES);
        let sig = sign::Signature::from_bytes(&sig_bytes).expect("64-byte signature");
        let expected_msg = format!("1.4.7|{}|{}", m.url, "ab".repeat(32));
        assert!(sign::verify_detached(&sig, expected_msg.as_bytes(), &pk));
        // Any field change, or another key, breaks it.
        let tampered = expected_msg.replace("1.4.7", "1.4.8");
        assert!(!sign::verify_detached(&sig, tampered.as_bytes(), &pk));
        let (other_pk, _) = sign::gen_keypair();
        assert!(!sign::verify_detached(
            &sig,
            expected_msg.as_bytes(),
            &other_pk
        ));
        // Wire shape: exactly {version, url, sha256, sig}, nothing else (in
        // particular no key material).
        let json = serde_json::to_value(&signed).expect("serialize");
        let obj = json.as_object().expect("object");
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["sha256", "sig", "url", "version"]);
    }

    // A release can carry Linux packages next to (or without) the Windows installer. Each
    // entry is signed over the same "version|url|sha256" contract, so the client checks
    // them with the function it already uses for the top level.
    #[test]
    fn a_multi_platform_release_signs_every_package_and_keeps_windows_on_top() {
        sodiumoxide::init().ok();
        let (pk, sk) = sign::gen_keypair();
        let deb = UpdateArtifact {
            url: "https://tbf.example.com/nemo/api/update/file/tbfdesk-1.4.16-amd64.deb".to_owned(),
            sha256: "cd".repeat(32),
        };
        let mut m = UpdateManifest {
            version: "1.4.16".to_owned(),
            url: "https://tbf.example.com/nemo/api/update/file/tbfdesk-1.4.16-x64-install.exe".to_owned(),
            sha256: "ab".repeat(32),
            platforms: Default::default(),
        };
        m.platforms.insert("linux-deb".to_owned(), deb.clone());
        let m = validate_update_manifest(&m).expect("valid");
        let signed = sign_update_manifest(&m, &sk);
        let check = |url: &str, sha: &str, sig: &str| {
            let sig = sign::Signature::from_bytes(&base64::decode(sig).unwrap()).unwrap();
            sign::verify_detached(&sig, format!("1.4.16|{url}|{sha}").as_bytes(), &pk)
        };
        assert!(check(&signed.url, &signed.sha256, &signed.sig), "windows entry");
        let d = &signed.platforms["linux-deb"];
        assert!(check(&d.url, &d.sha256, &d.sig), "deb entry");
        // A Linux-only release: the top level is empty and unsigned (older Windows
        // clients refuse it and see no update), the package is still signed.
        let linux_only = validate_update_manifest(&UpdateManifest {
            version: "1.4.16".to_owned(),
            platforms: [("linux-deb".to_owned(), deb.clone())].into_iter().collect(),
            ..Default::default()
        })
        .expect("linux-only release is valid");
        let signed = sign_update_manifest(&linux_only, &sk);
        assert!(signed.url.is_empty() && signed.sig.is_empty());
        let d = &signed.platforms["linux-deb"];
        assert!(check(&d.url, &d.sha256, &d.sig));
        // Unknown platform names and a nameless empty release are refused.
        for bad in [
            UpdateManifest {
                version: "1.4.16".to_owned(),
                platforms: [("linux-snap".to_owned(), deb.clone())].into_iter().collect(),
                ..Default::default()
            },
            UpdateManifest { version: "1.4.16".to_owned(), ..Default::default() },
        ] {
            assert!(validate_update_manifest(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn uploads_are_recognised_by_their_magic_bytes() {
        let pad = |head: &[u8]| {
            let mut v = head.to_vec();
            v.resize(70 * 1024, 0);
            v
        };
        assert_eq!(
            hosted_installer_name("1.4.16", "windows-x64", &pad(b"MZ")).unwrap(),
            "tbfdesk-1.4.16-x64-install.exe"
        );
        assert_eq!(
            hosted_installer_name("1.4.16", "linux-deb", &pad(b"!<arch>\ndebian-binary   ")).unwrap(),
            "tbfdesk-1.4.16-amd64.deb"
        );
        assert_eq!(
            hosted_installer_name("1.4.16", "linux-rpm", &pad(&[0xED, 0xAB, 0xEE, 0xDB])).unwrap(),
            "tbfdesk-1.4.16-x86_64.rpm"
        );
        assert_eq!(
            hosted_installer_name("1.4.16", "linux-arch", &pad(&[0x28, 0xB5, 0x2F, 0xFD])).unwrap(),
            "tbfdesk-1.4.16-x86_64.pkg.tar.zst"
        );
        // The wrong kind of file for the platform, a tiny file, an unknown platform.
        assert!(hosted_installer_name("1.4.16", "linux-deb", &pad(b"MZ")).is_err());
        assert!(hosted_installer_name("1.4.16", "windows-x64", b"MZ").is_err());
        assert!(hosted_installer_name("1.4.16", "linux-snap", &pad(b"MZ")).is_err());
    }

    #[test]
    fn update_manifest_validation_canonicalises_and_refuses_bad_fields() {
        let ok_url = "https://tbf.example.com/dl/x.exe";
        let ok_sha = "AB".repeat(32);
        let m = validate_update_manifest(&UpdateManifest {
            version: " 1.4.7 ".to_owned(),
            url: format!(" {} ", ok_url),
            sha256: ok_sha.clone(),
            platforms: Default::default(),
        })
        .expect("valid manifest");
        assert_eq!(m.version, "1.4.7");
        assert_eq!(m.url, ok_url);
        assert_eq!(m.sha256, "ab".repeat(32), "sha256 is lower-cased");
        let bad = |version: &str, url: &str, sha256: &str| {
            validate_update_manifest(&UpdateManifest {
                version: version.to_owned(),
                url: url.to_owned(),
                sha256: sha256.to_owned(),
                platforms: Default::default(),
            })
            .is_err()
        };
        assert!(bad("", ok_url, &ok_sha));
        assert!(bad("1|2", ok_url, &ok_sha), "'|' would re-split the signed string");
        assert!(bad("1 2", ok_url, &ok_sha));
        assert!(bad("1.0", "ftp://tbf.example.com/x", &ok_sha));
        assert!(bad("1.0", "https://", &ok_sha));
        assert!(bad("1.0", "https://tbf.example.com/x y", &ok_sha));
        assert!(bad("1.0", "https://tbf.example.com/x|y", &ok_sha));
        assert!(bad("1.0", ok_url, "abc"));
        assert!(bad("1.0", ok_url, &"zz".repeat(32)));
        assert!(bad("1.0", ok_url, ""));
        assert!(bad(&"9".repeat(MAX_UPDATE_VERSION_LEN + 1), ok_url, &ok_sha));
    }

    // Round trip through the operator's file, against a temp path: absent = Ok(None)
    // (the 404 case), present = the canonical manifest, mangled = Err (never a
    // silent 404).
    #[test]
    fn update_manifest_file_roundtrip_and_absent_file() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "nemo_update_test_{}_{}.json",
            std::process::id(),
            nanos
        ));
        assert_eq!(
            read_update_manifest(&path).expect("absent is not an error"),
            None
        );
        let m = UpdateManifest {
            version: "1.4.7".to_owned(),
            url: "https://tbf.example.com/dl/x.exe".to_owned(),
            sha256: "cd".repeat(32),
            platforms: Default::default(),
        };
        write_update_manifest(&path, &m).expect("write");
        // On disk: the three fields and NO sig (it is computed per request).
        let on_disk: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read back"))
                .expect("json");
        assert!(on_disk.get("sig").is_none());
        assert_eq!(
            read_update_manifest(&path).expect("readable"),
            Some(m.clone())
        );
        std::fs::write(&path, "{not json").expect("mangle");
        assert!(read_update_manifest(&path).is_err());
        std::fs::write(&path, r#"{"version":"1","url":"ftp://x","sha256":""}"#)
            .expect("bad fields");
        assert!(read_update_manifest(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }

    // A1: what the CLIENT seals to the server's mgmt key (Ed25519 pub -> Curve25519),
    // the server opens with its Ed25519 secret (-> Curve25519). Mirror both directions.
    #[test]
    fn mgmt_key_seal_roundtrip() {
        sodiumoxide::init().ok();
        let (pk, sk) = sign::gen_keypair();
        // Client side: seal to to_curve25519_pk(server_pub).
        let curve_pk = sign::to_curve25519_pk(&pk).unwrap();
        let sealed = base64::encode(sealedbox::seal(b"session-token", &curve_pk));
        // Server side (open_sealed_to_mgmt_key math): to_curve25519_sk(secret) + pub.
        let curve_sk = sign::to_curve25519_sk(&sk).unwrap();
        let opened = sealedbox::open(
            &base64::decode(&sealed).unwrap(),
            &curve_pk,
            &curve_sk,
        )
        .expect("open");
        assert_eq!(opened, b"session-token");
        // A different server key cannot open it.
        let (_pk2, sk2) = sign::gen_keypair();
        let curve_sk2 = sign::to_curve25519_sk(&sk2).unwrap();
        assert!(sealedbox::open(&base64::decode(&sealed).unwrap(), &curve_pk, &curve_sk2).is_err());
    }

    // H4: stripping removes exactly the secret option values.
    #[test]
    fn strip_secret_options_removes_all_secret_keys() {
        let mut policy = ManagementPolicy::default();
        policy
            .options
            .insert("nemo-permanent-password".to_owned(), "s3cret".to_owned());
        policy
            .options
            .insert("proxy-password".to_owned(), "p".to_owned());
        policy
            .options
            .insert("view_only".to_owned(), "Y".to_owned());
        assert_eq!(strip_secret_options(&mut policy), 2);
        assert!(!policy.options.contains_key("nemo-permanent-password"));
        assert!(!policy.options.contains_key("proxy-password"));
        assert_eq!(policy.options.get("view_only").map(String::as_str), Some("Y"));
        assert_eq!(strip_secret_options(&mut policy), 0);
    }

    // The client's endpoint parser is deliberately lenient (one bad row must not cost the
    // fleet its other endpoints), so a typo would be dropped there in silence and the only
    // symptom would be "it still relays". Validation therefore has to be strict HERE, at
    // the one place a human types the value.
    #[test]
    fn direct_endpoints_are_validated_where_they_are_entered() {
        use super::normalize_direct_endpoint as norm;
        // Accepted, and normalized to the exact shape the client parses.
        assert_eq!(norm("203.0.113.5:21118").as_deref(), Some("203.0.113.5:21118"));
        assert_eq!(
            norm("  203.0.113.5:21118,62201  ").as_deref(),
            Some("203.0.113.5:21118,62201")
        );
        assert_eq!(
            norm("vpn.example.com:31118").as_deref(),
            Some("vpn.example.com:31118")
        );
        // A bracketed IPv6 literal survives the rsplit on ':'.
        assert_eq!(
            norm("[2001:db8::1]:21118,62202").as_deref(),
            Some("[2001:db8::1]:21118,62202")
        );
        // Refused: no port, unparseable or out-of-range port, port 0.
        assert_eq!(norm("203.0.113.5"), None);
        assert_eq!(norm("203.0.113.5:http"), None);
        assert_eq!(norm("203.0.113.5:70000"), None);
        assert_eq!(norm("203.0.113.5:0"), None);
        assert_eq!(norm(":21118"), None);
        assert_eq!(norm(""), None);
        assert_eq!(norm("   "), None);
        // Refused: a bad knock port is an error, not something to quietly drop -- the
        // operator would otherwise get an endpoint that never knocks.
        assert_eq!(norm("203.0.113.5:21118,0"), None);
        assert_eq!(norm("203.0.113.5:21118,nope"), None);
        assert_eq!(norm("203.0.113.5:21118,62201,extra"), None);
        // Refused: separator injection. `;` ends an entry and `,` ends a field in the
        // pushed map, so accepting either would let one stored value forge extra rows in
        // every client's policy.
        assert_eq!(norm("203.0.113.5:21118;evil,198.51.100.1:21118"), None);
        assert_eq!(norm("203.0.113.5:21118 ,62201"), None);
        // Refused: bounded, so one entry cannot bloat the policy every client downloads.
        assert_eq!(norm(&format!("{}:21118", "h".repeat(MAX_ENDPOINT_LEN))), None);
    }

    // What each controller is told. Touches the process-wide PEER_ENDPOINTS, so every
    // assertion that needs it lives in this one test rather than racing sibling tests.
    #[test]
    fn direct_endpoint_map_is_filtered_and_stable() {
        {
            let mut map = PEER_ENDPOINTS.write().unwrap();
            map.clear();
            map.insert("300".to_owned(), "203.0.113.30:21118".to_owned());
            map.insert("100".to_owned(), "203.0.113.10:21118,62201".to_owned());
            map.insert("200".to_owned(), "203.0.113.20:21118".to_owned());
        }
        // No outbound-targets restriction: everything, sorted by id. The order matters --
        // an unstable value would make every client rewrite its stored policy every poll.
        assert_eq!(
            direct_endpoint_map(&[], None),
            "100,203.0.113.10:21118,62201;200,203.0.113.20:21118;300,203.0.113.30:21118"
        );
        // A blocked peer's address is withheld, so a controller cannot route around the
        // block by dialling it directly.
        assert_eq!(
            direct_endpoint_map(&["200".to_owned()], None),
            "100,203.0.113.10:21118,62201;300,203.0.113.30:21118"
        );
        // A controller restricted to one target learns only that target's address; the
        // rest of the fleet's WAN endpoints stay unknown to it.
        let targets = "300".to_owned();
        assert_eq!(
            direct_endpoint_map(&[], Some(&targets)),
            "300,203.0.113.30:21118"
        );
        // "*" is the existing wildcard in that ACL and must keep meaning "all".
        let all = "*".to_owned();
        assert_eq!(direct_endpoint_map(&[], Some(&all)).split(';').count(), 3);
        // Blocked wins over an explicit grant.
        assert_eq!(direct_endpoint_map(&["300".to_owned()], Some(&targets)), "");
        {
            PEER_ENDPOINTS.write().unwrap().clear();
        }
        // Nothing configured => the key is never pushed, so the whole fleet keeps today's
        // hole-punch / relay behaviour untouched.
        assert_eq!(direct_endpoint_map(&[], None), "");
    }

    #[test]
    fn knock_key_normalisation_refuses_what_would_forge_rows() {
        // A valid 32-byte key, base64. Round-trips unchanged.
        let k = base64::encode([7u8; 32]);
        assert_eq!(normalize_knock_key(&format!("  {k}  ")), Some(k.clone()));
        // A separator would forge extra rows/fields; whitespace breaks the parse.
        assert_eq!(normalize_knock_key(&format!("{k},x")), None);
        assert_eq!(normalize_knock_key(&format!("{k};x")), None);
        assert_eq!(normalize_knock_key("not valid base64"), None);
        assert_eq!(normalize_knock_key(""), None);
        // Decoded length bounds: empty decode and over-long are both refused.
        assert_eq!(normalize_knock_key(&base64::encode(Vec::<u8>::new())), None);
        assert_eq!(normalize_knock_key(&base64::encode(vec![0u8; MAX_SPA_KEY_LEN + 1])), None);
        // The pair requires both halves valid.
        assert!(normalize_knock_key_pair(&k, &k).is_some());
        assert!(normalize_knock_key_pair(&k, "bad,key").is_none());
    }

    // The isolation property, server side: a controller receives a per-peer key ONLY for
    // a target its outbound ACL already lets it dial. pc2's controller never learns pc7's
    // key, so a key lifted off pc2 opens only pc2's forwarded port. Touches the
    // process-wide PEER_KNOCK_KEYS, so all of it lives in one test (like the endpoint one).
    #[test]
    fn knock_key_map_is_filtered_like_endpoints() {
        let k2 = base64::encode([0x22u8; 32]);
        let h2 = base64::encode([0x33u8; 32]);
        let k7 = base64::encode([0x77u8; 32]);
        let h7 = base64::encode([0x88u8; 32]);
        {
            let mut map = PEER_KNOCK_KEYS.write().unwrap();
            map.clear();
            map.insert("pc2".to_owned(), (k2.clone(), h2.clone()));
            map.insert("pc7".to_owned(), (k7.clone(), h7.clone()));
        }
        // No ACL: both rows, sorted by id, byte-stable across polls.
        assert_eq!(
            knock_key_map(&[], None),
            format!("pc2,{k2},{h2};pc7,{k7},{h7}")
        );
        // A controller restricted to pc2 gets ONLY pc2's key — pc7's never leaves the
        // server for it. This is the whole point of per-peer keys.
        let targets = "pc2".to_owned();
        assert_eq!(knock_key_map(&[], Some(&targets)), format!("pc2,{k2},{h2}"));
        assert!(!knock_key_map(&[], Some(&targets)).contains("pc7"));
        // A blocked peer's key is withheld even with an explicit grant.
        assert_eq!(knock_key_map(&["pc2".to_owned()], Some(&targets)), "");
        // "*" still means all.
        assert_eq!(knock_key_map(&[], Some(&"*".to_owned())).split(';').count(), 2);
        {
            PEER_KNOCK_KEYS.write().unwrap().clear();
        }
        // Nothing configured => the key is never pushed; the fleet-wide key path is
        // untouched.
        assert_eq!(knock_key_map(&[], None), "");
    }

    // Rotation is a fleet-wide revocation, so the two things that must hold are that it
    // actually changes the key and that it stays RECOVERABLE -- a server left with no key
    // at all is fatal at next start (gen_sk exits), and a destroyed old key turns an
    // operator misclick into a permanently unreachable fleet.
    #[test]
    fn rotating_the_server_key_is_recoverable() {
        // Path-explicit helpers, so this never touches the process cwd that sibling tests
        // run against in parallel.
        let dir = std::env::temp_dir().join(format!("nemo-rotate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let sk_file = dir.join("id_ed25519").to_string_lossy().into_owned();
        let pub_file = format!("{sk_file}.pub");

        // Start from a known key, the way a provisioned server looks.
        let (first_pub, first_sk) = gen_url_safe_keypair();
        write_private(&sk_file, base64::encode(&first_sk).as_bytes()).expect("seed key");
        std::fs::write(&pub_file, first_pub.as_bytes()).expect("seed pub");
        assert_eq!(server_public_key_on_disk_at(&sk_file), first_pub);

        let (new_pub, archive) = rotate_server_key_at(&sk_file).expect("rotate");
        assert_ne!(new_pub, first_pub, "rotation must actually change the key");
        assert_eq!(
            server_public_key_on_disk_at(&sk_file),
            new_pub,
            "the next start must pick up the new key"
        );
        // Recoverable: the old secret is archived, not destroyed, and it is the real one.
        assert!(!archive.is_empty(), "the previous key must be archived");
        let archived = std::fs::read_to_string(&archive).expect("archive readable");
        assert_eq!(archived.trim(), base64::encode(&first_sk));
        // Restoring the archive puts the fleet back exactly where it was.
        std::fs::rename(&archive, &sk_file).expect("restore");
        std::fs::write(&pub_file, first_pub.as_bytes()).expect("restore pub");
        assert_eq!(server_public_key_on_disk_at(&sk_file), first_pub);

        // A .pub that is missing must not make the readout lie -- the public half is
        // derived from the secret instead.
        std::fs::remove_file(&pub_file).expect("drop pub");
        assert_eq!(server_public_key_on_disk_at(&sk_file), first_pub);

        // The key travels inside licence names of the form `host=..,key=..`, so it must
        // contain neither separator.
        for _ in 0..32 {
            let (pk, _) = gen_url_safe_keypair();
            assert!(!pk.contains('/') && !pk.contains(':'), "{pk}");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn policy_with_knock_keys() -> ManagementPolicy {
        let mut policy = ManagementPolicy::default();
        policy
            .options
            .insert(OPTION_NEMO_KNOCK_KEY.to_owned(), "aGVsbG8=".to_owned());
        policy.options.insert(
            OPTION_NEMO_KNOCK_HMAC_KEY.to_owned(),
            "d29ybGQ=".to_owned(),
        );
        policy.options.insert(
            OPTION_NEMO_DIRECT_ENDPOINTS.to_owned(),
            "100,203.0.113.10:21118".to_owned(),
        );
        policy
    }

    // The SPA keys open the forwarded port for whoever holds them, so they have to be
    // handled exactly like a password everywhere a policy is read, written or pushed.
    #[test]
    fn knock_keys_are_treated_as_secrets() {
        let policy = policy_with_knock_keys();
        // Masked in dashboard responses...
        let masked = mask_secret_policy(policy.clone());
        assert_eq!(
            masked.options.get(OPTION_NEMO_KNOCK_KEY).map(String::as_str),
            Some(MANAGED_SECRET_MASK)
        );
        assert_eq!(
            masked
                .options
                .get(OPTION_NEMO_KNOCK_HMAC_KEY)
                .map(String::as_str),
            Some(MANAGED_SECRET_MASK)
        );
        // ...but the endpoint map is not a secret and must stay readable, or the operator
        // cannot see what the fleet was told.
        assert_eq!(
            masked
                .options
                .get(OPTION_NEMO_DIRECT_ENDPOINTS)
                .map(String::as_str),
            Some("100,203.0.113.10:21118")
        );
        // Stripped from a policy we cannot seal, exactly like a password: handing the
        // fleet's knock keys to an unprovisioned client over plaintext would defeat the
        // layer they exist to add.
        let mut policy = policy;
        assert_eq!(strip_secret_options(&mut policy), 2);
        assert!(policy.options.contains_key(OPTION_NEMO_DIRECT_ENDPOINTS));
        // A dashboard round-trip must not store the mask as the key. The form shows a
        // mask for anything already set and sends it back untouched; restoring it is the
        // difference between "kept the fleet's SPA key" and "set it to the literal string
        // <managed-secret>, every knock now rejected".
        let mut edited = ManagementPolicy::default();
        edited
            .options
            .insert(OPTION_NEMO_KNOCK_KEY.to_owned(), MANAGED_SECRET_MASK.to_owned());
        edited
            .options
            .insert(OPTION_NEMO_KNOCK_HMAC_KEY.to_owned(), "bmV3".to_owned());
        let restored = restore_masked_secrets_from(edited, &policy_with_knock_keys());
        assert_eq!(
            restored.options.get(OPTION_NEMO_KNOCK_KEY).map(String::as_str),
            Some("aGVsbG8="),
            "an untouched field must keep the stored key"
        );
        assert_eq!(
            restored
                .options
                .get(OPTION_NEMO_KNOCK_HMAC_KEY)
                .map(String::as_str),
            Some("bmV3"),
            "a field the operator actually edited must be taken as typed"
        );
        // And all nine keys survive sanitize_management_policy, i.e. an operator can
        // actually set them in a global or device policy (an unlisted key is dropped).
        for key in [
            OPTION_NEMO_DIRECT_ENDPOINTS,
            "nemo-direct-timeout-ms",
            "nemo-knock-enabled",
            "nemo-knock-port",
            OPTION_NEMO_KNOCK_KEY,
            OPTION_NEMO_KNOCK_HMAC_KEY,
            "nemo-knock-delay-ms",
            "nemo-knock-user",
            "nemo-knock-source-ip",
        ] {
            let mut p = ManagementPolicy::default();
            p.options.insert(key.to_owned(), "x".to_owned());
            assert!(
                sanitize_management_policy(p).options.contains_key(key),
                "{key} would be silently dropped by the server"
            );
        }
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn signed_for(sk: &sign::SecretKey, domain: &str, id: &str, ts: u64) -> String {
        base64::encode(sign::sign(
            format!("{}:{}:{}", domain, id, ts).as_bytes(),
            sk,
        ))
    }

    // M1-CLAIM, at the enforcement point: proving a pinned-but-UNBOUND key does not
    // authenticate the request -- it files a binding request and the request is refused.
    // This is what keeps the TASK #14 rule above true while first-use provisioning
    // exists: nothing a client can do binds its own key.
    #[test]
    fn an_unbound_key_files_a_claim_and_is_still_refused() {
        sodiumoxide::init().ok();
        let (pk, sk) = sign::gen_keypair();
        let pub_b64 = base64::encode(pk.as_ref());
        let now = now_secs();
        integration::pin_device_key_for_test(integration::DeviceKey {
            id: "claimtest".to_owned(),
            label: "test".to_owned(),
            public_key: pub_b64.clone(),
            created_at: String::new(),
            peer_id: String::new(),
            claimed_at: String::new(),
        });

        // A valid, fresh signature over the id it claims: refused, because unbound.
        assert!(!verify_device_signature(
            &pub_b64,
            &signed_for(&sk, "nemo-poll", "claim-peer-1", now),
            "nemo-poll",
            "claim-peer-1"
        ));
        // ...but it is now visible to the operator, labelled with the endpoint it came
        // in on, which is derived from the verified signature domain.
        let claim = integration::pending_claim_for_peer("claim-peer-1")
            .expect("a proved unbound key must raise a request");
        assert_eq!(claim.key_id, "claimtest");
        assert_eq!(claim.via, "settings poll");
        assert!(!claim.denied);
        // And the key is still unbound: only the operator writes a binding.
        assert_eq!(
            integration::device_key_for_peer("claim-peer-1").map(|k| k.id),
            None
        );

        // A client that does NOT hold the key cannot raise a request against it: the
        // claim is filed only after the signature verifies.
        assert!(!verify_device_signature(
            &pub_b64,
            "bm90LWEtc2lnbmF0dXJl",
            "nemo-poll",
            "claim-peer-2"
        ));
        assert!(integration::pending_claim_for_peer("claim-peer-2").is_none());

        // With claiming switched off, the original fail-closed rule stands and nothing
        // is filed at all.
        integration::set_claim_unbound_device_keys(false);
        assert!(!verify_device_signature(
            &pub_b64,
            &signed_for(&sk, "nemo-poll", "claim-peer-3", now),
            "nemo-poll",
            "claim-peer-3"
        ));
        assert!(integration::pending_claim_for_peer("claim-peer-3").is_none());
        integration::set_claim_unbound_device_keys(true);

        // Approval binds it, and then it is an ordinary bound key.
        integration::approve_device_key_claim("claimtest", "claim-peer-1", now_iso())
            .expect("approval must bind");
        assert!(verify_device_signature(
            &pub_b64,
            &signed_for(&sk, "nemo-poll", "claim-peer-1", now),
            "nemo-poll",
            "claim-peer-1"
        ));
        assert!(!verify_device_signature(
            &pub_b64,
            &signed_for(&sk, "nemo-poll", "claim-peer-9", now),
            "nemo-poll",
            "claim-peer-9"
        ));
        integration::unpin_device_key_for_test(&pub_b64);
    }

    // The first-run settings bundle. The default address comes from the Host header of
    // the dashboard request, because that is the one address the operator has PROVEN a
    // client can reach this API on - but the ports differ (the API is not the rendezvous
    // port), an IPv6 literal is bracketed, and the operator has to be able to override
    // every field for a roaming client. Those are the four things that can go wrong.
    #[test]
    /// SPLIT-PORT + the HTTP/2 bug. Which port a bundle advertises, and where the
    /// address it is derived from comes from.
    #[test]
    fn the_bundle_advertises_the_port_clients_must_actually_use() {
        // No dedicated client bind: the authority's port is used as-is...
        assert_eq!(api_port_suffix(None, "21120"), ":21120");
        // ...and a reverse proxy on 443 keeps NO port. Appending the listener's own
        // port here would send every client to a socket the proxy does not expose.
        assert_eq!(api_port_suffix(None, ""), "");
        // A dedicated client listener wins over both: it is the socket clients must
        // reach, and the address the operator browsed cannot imply its port.
        assert_eq!(api_port_suffix(Some(21121), "21120"), ":21121");
        assert_eq!(api_port_suffix(Some(21121), ""), ":21121");

        // The address itself: HTTP/1 carries it in Host, HTTP/2 only as `:authority`,
        // which axum exposes through the URI. Reading Host alone made every bundle
        // exported over an h2 dashboard connection lose its port (and the LAN profile
        // claim the server could not work out its own address).
        let mut h1 = HeaderMap::new();
        h1.insert(
            axum::http::header::HOST,
            "85.126.226.2:21120".parse().unwrap(),
        );
        let origin_form: axum::http::Uri = "/nemo/api/client-setup".parse().unwrap();
        assert_eq!(request_authority(&origin_form, &h1), "85.126.226.2:21120");

        let absolute: axum::http::Uri = "https://85.126.226.2:21120/nemo/api/client-setup"
            .parse()
            .unwrap();
        assert_eq!(
            request_authority(&absolute, &HeaderMap::new()),
            "85.126.226.2:21120",
            "h2 sends no Host header; the authority has to come from the URI"
        );
        // Neither available: invent nothing, so build_client_setup refuses rather than
        // handing out a bundle that points nowhere.
        assert_eq!(request_authority(&origin_form, &HeaderMap::new()), "");
    }

    #[test]
    fn client_setup_defaults_come_from_the_dashboard_address() {
        let none = ClientSetupRequest::default();
        let lan = ClientSetupScope::Internal;

        // host:port -> api keeps the port, the ID server does NOT (21116 is the
        // client's own default and a hand-typed address would leave it implicit too).
        let s = client_setup_server(&none, "10.0.0.5:21120", " KEYB64 ", lan);
        assert_eq!(s.api_server, "https://10.0.0.5:21120");
        assert_eq!(s.id_server, "10.0.0.5");
        assert_eq!(s.key, "KEYB64", "the key is trimmed, not passed through raw");

        // A Host header with no port at all (a reverse proxy on 443).
        let s = client_setup_server(&none, "tbfdesk.example.com", "k", lan);
        assert_eq!(s.api_server, "https://tbfdesk.example.com");
        assert_eq!(s.id_server, "tbfdesk.example.com");

        // IPv6 literals are bracketed in a Host header, and the colons inside the
        // address are not port separators.
        let s = client_setup_server(&none, "[fd00::1]:21120", "k", lan);
        assert_eq!(s.api_server, "https://fd00::1:21120");
        assert_eq!(s.id_server, "fd00::1");

        // No Host header: nothing is invented, and build_client_setup refuses rather
        // than handing out a bundle that points nowhere.
        let s = client_setup_server(&none, "", "k", lan);
        assert!(s.api_server.is_empty() && s.id_server.is_empty());
        assert!(build_client_setup(&none, "", "k", "", lan).is_err());

        // The operator's edits win - the point of showing the fields at all, since a
        // LAN dashboard session cannot know a roaming client's public address.
        let edited = ClientSetupRequest {
            id_server: Some("85.126.226.2".to_owned()),
            relay_server: Some("85.126.226.2".to_owned()),
            api_server: Some("https://tbfdesk.example.com:21120".to_owned()),
            api_cert_fingerprint: Some("  ".to_owned()),
            label: Some("Reception".to_owned()),
            scope: None,
        };
        let s = client_setup_server(&edited, "10.0.0.5:21120", "k", lan);
        assert_eq!(s.id_server, "85.126.226.2");
        assert_eq!(s.relay_server, "85.126.226.2");
        assert_eq!(s.api_server, "https://tbfdesk.example.com:21120");
        // An explicitly blank pin means "do not pin" (a proxy with its own cert), which
        // must not be silently refilled from this server's self-signed fingerprint.
        assert_eq!(s.api_cert_fingerprint, "");
    }

    // The split itself: one server, two addresses, and a client that carries only one
    // set of them. Handing a workstation the public address hairpins every session out
    // through the router and back; handing a roaming laptop the LAN address locks it
    // out. So the public profile must NOT fall back to the dashboard address, and the
    // LAN profile must not quietly relay via the public one.
    #[test]
    fn the_public_profile_never_falls_back_to_the_dashboard_address() {
        let none = ClientSetupRequest::default();
        let wan = ClientSetupScope::External;
        // Reading the dashboard over the LAN, with no -r and no --nemo-client-*-external
        // configured: the public profile is EMPTY and says why, rather than shipping
        // 10.0.0.5 as "from the internet".
        let s = client_setup_server(&none, "10.0.0.5:21120", "k", wan);
        assert!(s.id_server.is_empty(), "{:?}", s.id_server);
        assert!(s.api_server.is_empty(), "{:?}", s.api_server);
        let err = build_client_setup(&none, "", "k", "", wan).unwrap_err();
        assert!(err.contains("public address"), "{}", err);
        // ...and the failure stays inside that one profile: the LAN one is still built.
        let profile = client_setup_profile(&none, "", "k", "", wan);
        assert_eq!(profile.scope, "external");
        assert!(profile.setup_string.is_empty() && !profile.error.is_empty());

        // The operator fills it in and it is used as given, ports and all.
        let edited = ClientSetupRequest {
            scope: Some("external".to_owned()),
            id_server: Some("tbfdesk.example.com".to_owned()),
            api_server: Some("https://tbfdesk.example.com:21120".to_owned()),
            ..Default::default()
        };
        let s = client_setup_server(&edited, "10.0.0.5:21120", "k", wan);
        assert_eq!(s.id_server, "tbfdesk.example.com");
        assert_eq!(s.api_server, "https://tbfdesk.example.com:21120");

        // `scope` is read leniently, because it arrives from a dashboard field and a
        // typo must not silently produce the WRONG profile - only these spellings mean
        // "external", and anything else means the LAN one.
        for v in ["external", "External", " public ", "wan", "internet"] {
            assert_eq!(ClientSetupScope::parse(Some(v)), ClientSetupScope::External, "{v}");
        }
        for v in ["internal", "lan", "", "exterior", "x"] {
            assert_eq!(ClientSetupScope::parse(Some(v)), ClientSetupScope::Internal, "{v}");
        }
        assert_eq!(ClientSetupScope::parse(None), ClientSetupScope::Internal);
    }

    // `-r` is where the public address comes from when nothing else says it, and it may
    // carry a port the client does not need (it dials the relay on its own port).
    #[test]
    fn the_public_host_is_taken_from_the_relay_flag() {
        assert_eq!(relay_host("85.126.226.2:21117"), "85.126.226.2");
        assert_eq!(relay_host("tbfdesk.example.com"), "tbfdesk.example.com");
        assert_eq!(relay_host(" a.example.com:21117 , b.example.com "), "a.example.com");
        assert_eq!(relay_host("[2001:db8::1]:21117"), "2001:db8::1");
        assert_eq!(relay_host(""), "");
    }

    #[test]
    fn client_setup_string_round_trips_and_names_its_file() {
        let bundle = ClientSetupBundle {
            v: 1,
            label: "Reception PC".to_owned(),
            issued_at: "t0".to_owned(),
            issued_from: "10.0.0.5:21120".to_owned(),
            scope: "internal".to_owned(),
            server: ClientSetupServer {
                id_server: "10.0.0.5".to_owned(),
                relay_server: String::new(),
                api_server: "https://10.0.0.5:21120".to_owned(),
                key: "serverkey".to_owned(),
                api_cert_fingerprint: "AA:BB".to_owned(),
            },
            device_key: "privatekey".to_owned(),
        };
        let encoded = encode_client_setup(&bundle).unwrap();
        assert!(encoded.starts_with("tbfdesk-setup-v1:"));
        // The client decodes exactly this: prefix, then base64 of the JSON.
        let raw = base64::decode(encoded.trim_start_matches("tbfdesk-setup-v1:")).unwrap();
        let back: ClientSetupBundle = serde_json::from_slice(&raw).unwrap();
        assert_eq!(back.v, 1);
        assert_eq!(back.server, bundle.server);
        assert_eq!(back.device_key, "privatekey");

        // An empty device key is OMITTED rather than sent as "", so a key-less bundle
        // cannot be mistaken for one carrying an empty key.
        let keyless = ClientSetupBundle {
            device_key: String::new(),
            ..bundle
        };
        let raw = base64::decode(
            encode_client_setup(&keyless)
                .unwrap()
                .trim_start_matches("tbfdesk-setup-v1:"),
        )
        .unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("device_key"));

        // Filenames: a label becomes a slug, and the with-key variant says so, because
        // one of the two files is a secret and the other is not.
        assert_eq!(
            client_setup_filename("Reception PC", true, ClientSetupScope::Internal),
            "tbfdesk-Reception-PC-setup-lan-with-key.tbfsetup"
        );
        assert_eq!(
            client_setup_filename("", false, ClientSetupScope::External),
            "tbfdesk-setup-wan.tbfsetup"
        );
        assert_eq!(
            client_setup_filename("../etc/passwd", false, ClientSetupScope::Internal),
            "tbfdesk-etc-passwd-setup-lan.tbfsetup"
        );
    }

    // TODO 8: where the controller identity comes from now that there is a field for
    // it. The typed field wins, the legacy marker still works, and a field that names
    // nobody is not an identity.
    #[test]
    fn controller_source_prefers_the_typed_field_over_the_smuggled_marker() {
        let marker = format!(
            "1.4.6 nemo-source-v1:old-peer:{}:old-token",
            base64::encode(b"old-uuid")
        );
        // No field: unchanged behaviour, the marker is parsed as before.
        let (id, uuid, token) = controller_source_any(None, &marker).unwrap();
        assert_eq!(id, "old-peer");
        assert_eq!(uuid, b"old-uuid");
        assert_eq!(token.as_deref(), Some("old-token"));

        // Field present: it decides, and the uuid no longer needs base64 to survive.
        let src = NemoSource {
            id: "new-peer".to_owned(),
            uuid: b"new-uuid".to_vec().into(),
            token: "new-token".to_owned(),
            ..Default::default()
        };
        let (id, uuid, token) = controller_source_any(Some(&src), &marker).unwrap();
        assert_eq!(id, "new-peer");
        assert_eq!(uuid, b"new-uuid");
        assert_eq!(token.as_deref(), Some("new-token"));

        // No token (not signed in, or a plaintext socket the client refuses to put it
        // on) is None, not Some("") -- the user gates key off that difference.
        let anon = NemoSource {
            id: "new-peer".to_owned(),
            uuid: b"new-uuid".to_vec().into(),
            token: "   ".to_owned(),
            ..Default::default()
        };
        assert_eq!(controller_source_any(Some(&anon), "1.4.6").unwrap().2, None);

        // An empty field is not an identity: fall back rather than reporting a
        // controller called "". resolve_controller_identity fails closed on an empty id,
        // so reading the field as authoritative here would refuse a connection that the
        // marker could have identified.
        let blank = NemoSource {
            id: "  ".to_owned(),
            ..Default::default()
        };
        assert_eq!(
            controller_source_any(Some(&blank), &marker).unwrap().0,
            "old-peer"
        );
        assert!(controller_source_any(Some(&blank), "1.4.6").is_none());
    }

    // TODO 7: the relayed-byte bookkeeping. hbbr reports CUMULATIVE totals per session
    // and forgets a session when it closes, so the three things worth pinning down are
    // the delta arithmetic, what "absent from the sample" means, and that a session
    // nobody here brokered still counts as measured traffic.
    #[test]
    fn relay_usage_folds_cumulative_samples_into_deltas() {
        fn sample(session: &str, bytes: u64) -> RelayUsageSample {
            RelayUsageSample {
                session: session.to_owned(),
                bytes,
                kbps: 100,
                peak_kbps: 900,
                ms: 4_000,
            }
        }
        let mut store = NemoStatsStore::default();
        store.relay_sessions.push(RelaySessionRecord {
            session: "aaaa".to_owned(),
            source_id: "ctrl-1".to_owned(),
            target_id: "work-1".to_owned(),
            brokered_at: "t0".to_owned(),
            ..Default::default()
        });

        // First sample: the whole count is new.
        apply_relay_usage(&mut store, vec![sample("aaaa", 1_000)], "t1");
        assert_eq!(store.totals.relay_bytes, 1_000);
        assert_eq!(store.peers["ctrl-1"].relay_bytes, 1_000);
        assert_eq!(store.peers["work-1"].relay_bytes, 1_000);
        assert_eq!(store.relay_sessions[0].seconds, 4);
        assert_eq!(store.relay_sessions[0].peak_kbps, 900);
        assert!(store.relay_sessions[0].live);

        // Second sample of the SAME session adds only what is new - the bug this test
        // exists for would charge 2_500 again and treble the fleet total in 10 seconds.
        apply_relay_usage(&mut store, vec![sample("aaaa", 2_500)], "t2");
        assert_eq!(store.totals.relay_bytes, 2_500);
        assert_eq!(store.peers["ctrl-1"].relay_bytes, 2_500);

        // A session this hbbs never brokered: measured traffic, so it counts in the
        // fleet total, but it is attributed to nobody.
        apply_relay_usage(
            &mut store,
            vec![sample("aaaa", 2_500), sample("bbbb", 70)],
            "t3",
        );
        assert_eq!(store.totals.relay_bytes, 2_570);
        assert_eq!(store.peers.len(), 2);

        // Absent from the sample = hbbr closed it. The row keeps its final total and
        // stops claiming a rate.
        apply_relay_usage(&mut store, vec![], "t4");
        assert!(!store.relay_sessions[0].live);
        assert_eq!(store.relay_sessions[0].bytes, 2_500);
        assert_eq!(store.relay_sessions[0].kbps, 0);
        assert_eq!(store.totals.relay_bytes, 2_570, "an end is not a new sample");

        // A label reused after a restart reports a LOWER cumulative count; that must not
        // underflow the delta.
        apply_relay_usage(&mut store, vec![sample("aaaa", 10)], "t5");
        assert_eq!(store.totals.relay_bytes, 2_570);
        assert_eq!(store.relay_sessions[0].bytes, 10);
    }

    // S-DUALKEY + M1 + domain separation, against a key pinned in-memory.
    #[test]
    fn verify_device_signature_checks_pin_binding_domain_and_freshness() {
        sodiumoxide::init().ok();
        let (pk, sk) = sign::gen_keypair();
        let pub_b64 = base64::encode(pk.as_ref());
        let now = now_secs();

        // Not pinned yet -> refused even with a valid signature.
        assert!(!verify_device_signature(
            &pub_b64,
            &signed_for(&sk, "nemo-poll", "peer-a", now),
            "nemo-poll",
            "peer-a"
        ));

        // TASK #14: pinned UNBOUND -> refused even with a valid fresh signature. The
        // admin peer-id box is optional free text, so a blank binding must never be a
        // skeleton key; only --allow-unbound-device-keys Y (off in tests) reopens it.
        integration::pin_device_key_for_test(integration::DeviceKey {
            id: "testkey".to_owned(),
            label: "test".to_owned(),
            public_key: pub_b64.clone(),
            created_at: String::new(),
            peer_id: String::new(),
            claimed_at: String::new(),
        });
        assert!(!verify_device_signature(
            &pub_b64,
            &signed_for(&sk, "nemo-poll", "peer-a", now),
            "nemo-poll",
            "peer-a"
        ));
        // Re-pin BOUND to peer-a so the checks below fail for the reason they name.
        integration::unpin_device_key_for_test(&pub_b64);
        integration::pin_device_key_for_test(integration::DeviceKey {
            id: "testkey".to_owned(),
            label: "test".to_owned(),
            public_key: pub_b64.clone(),
            created_at: String::new(),
            peer_id: "peer-a".to_owned(),
            claimed_at: String::new(),
        });
        // Domain separation: a poll signature is useless against the ab endpoint.
        assert!(!verify_device_signature(
            &pub_b64,
            &signed_for(&sk, "nemo-poll", "peer-a", now),
            "nemo-ab",
            "peer-a"
        ));
        // Stale and non-numeric timestamps are refused (the old code silently
        // skipped freshness when ts failed to parse).
        assert!(!verify_device_signature(
            &pub_b64,
            &signed_for(&sk, "nemo-poll", "peer-a", now - 301),
            "nemo-poll",
            "peer-a"
        ));
        let non_numeric = base64::encode(sign::sign(b"nemo-poll:peer-a:soon", &sk));
        assert!(!verify_device_signature(
            &pub_b64,
            &non_numeric,
            "nemo-poll",
            "peer-a"
        ));
        // Id mismatch between signature and claim.
        assert!(!verify_device_signature(
            &pub_b64,
            &signed_for(&sk, "nemo-poll", "peer-a", now),
            "nemo-poll",
            "peer-b"
        ));

        // M1: bound to peer-a — peer-a authenticates, a peer-b claim is refused by the
        // binding, and a peer-b signature presented under the bound id by the id check
        // inside the signature.
        assert!(verify_device_signature(
            &pub_b64,
            &signed_for(&sk, "nemo-poll", "peer-a", now),
            "nemo-poll",
            "peer-a"
        ));
        assert!(!verify_device_signature(
            &pub_b64,
            &signed_for(&sk, "nemo-poll", "peer-b", now),
            "nemo-poll",
            "peer-b"
        ));
        assert!(!verify_device_signature(
            &pub_b64,
            &signed_for(&sk, "nemo-poll", "peer-b", now),
            "nemo-poll",
            "peer-a"
        ));
        integration::unpin_device_key_for_test(&pub_b64);
    }

    #[test]
    fn validate_client_policy_request_matches_uuid() {
        let peer = RegisteredPeer {
            uuid: vec![10u8, 20, 30],
            ..Default::default()
        };
        // Matching uuid.
        let ok = ClientPolicyRequest {
            id: "peer-a".to_owned(),
            uuid: base64::encode([10u8, 20, 30]),
            policy_version: None,
            access_token: None,
            hostname: None,
            device_key_pub: None,
            device_key_sig: None,
            sealed_token: None,
            sealed: None,
            client_version: None,
        };
        assert!(validate_client_policy_request(&peer, &ok).is_ok());
        // Empty id.
        let no_id = ClientPolicyRequest {
            id: "  ".to_owned(),
            uuid: base64::encode([10u8, 20, 30]),
            policy_version: None,
            access_token: None,
            hostname: None,
            device_key_pub: None,
            device_key_sig: None,
            sealed_token: None,
            sealed: None,
            client_version: None,
        };
        assert_eq!(
            validate_client_policy_request(&peer, &no_id).unwrap_err().0,
            StatusCode::BAD_REQUEST
        );
        // Bad base64.
        let bad_b64 = ClientPolicyRequest {
            id: "peer-a".to_owned(),
            uuid: "!!!".to_owned(),
            policy_version: None,
            access_token: None,
            hostname: None,
            device_key_pub: None,
            device_key_sig: None,
            sealed_token: None,
            sealed: None,
            client_version: None,
        };
        assert_eq!(
            validate_client_policy_request(&peer, &bad_b64).unwrap_err().0,
            StatusCode::BAD_REQUEST
        );
        // Wrong uuid.
        let mismatch = ClientPolicyRequest {
            id: "peer-a".to_owned(),
            uuid: base64::encode([99u8, 99, 99]),
            policy_version: None,
            access_token: None,
            hostname: None,
            device_key_pub: None,
            device_key_sig: None,
            sealed_token: None,
            sealed: None,
            client_version: None,
        };
        assert_eq!(
            validate_client_policy_request(&peer, &mismatch).unwrap_err().0,
            StatusCode::UNAUTHORIZED
        );
    }

    /// The ticket carries the same decisions the rendezvous makes: who may control which
    /// machine. Unrestricted = "*" (covers machines registered later); a restricted user,
    /// a controller policy with outbound targets, or blocked machines = an explicit list.
    #[test]
    fn a_control_ticket_names_exactly_the_machines_the_rules_allow() {
        let reg: Vec<String> = ["c", "t1", "t2", "t3"].iter().map(|s| s.to_string()).collect();
        let none: Vec<String> = vec![];
        // Admin or no user, nothing restricting: everything.
        assert_eq!(ticket_targets("c", Some((true, &none)), None, &none, &reg), vec!["*"]);
        assert_eq!(ticket_targets("c", None, None, &none, &reg), vec!["*"]);
        // A user allowed t1 and t3 only.
        let allowed = vec!["t1".to_owned(), "t3".to_owned()];
        assert_eq!(ticket_targets("c", Some((false, &allowed)), None, &none, &reg), vec!["t1", "t3"]);
        // ...and the controller's own policy only allows t3.
        let outbound = "t3".to_owned();
        assert_eq!(ticket_targets("c", Some((false, &allowed)), Some(&outbound), &none, &reg), vec!["t3"]);
        // A blocked machine is never in the list, and never "*" while anything is blocked.
        let blocked = vec!["t2".to_owned()];
        assert_eq!(ticket_targets("c", Some((true, &none)), None, &blocked, &reg), vec!["t1", "t3"]);
        // A user with no allowed machines gets none.
        assert!(ticket_targets("c", Some((false, &none)), None, &none, &reg).is_empty());
    }

    #[test]
    fn no_ticket_for_a_controller_the_rendezvous_would_refuse() {
        let opts = HashMap::new();
        let reg = vec!["t1".to_owned()];
        let b = |dk: Option<&str>, blocked: bool, user: Option<&str>, require: bool, o: &HashMap<String, String>| {
            build_control_ticket("c", blocked, dk, user, require, o, &[], &reg, 10_000)
        };
        assert!(b(None, false, None, false, &opts).is_none(), "no proven device key");
        assert!(b(Some("k"), true, None, false, &opts).is_none(), "blocked controller");
        assert!(b(Some("k"), false, None, true, &opts).is_none(), "sign-in required, nobody signed in");
        let mut off = HashMap::new();
        off.insert(OPTION_NEMO_OUTBOUND_ENABLED.to_owned(), "N".to_owned());
        assert!(b(Some("k"), false, None, false, &off).is_none(), "outgoing disabled");
        let t = b(Some("k"), false, None, false, &opts).expect("anonymous allowed when sign-in is optional");
        assert_eq!((t.ctl.as_str(), t.dk.as_str(), t.v), ("c", "k", 1));
        assert_eq!(t.iat % CONTROL_TICKET_BUCKET_SECS, 0, "stable within the hour");
        assert!(t.exp > 10_000);
    }

    /// The wire format the client's nemo_control::parse_and_verify expects:
    /// base64(json).base64(detached Ed25519 signature over the json bytes), with
    /// exactly these field names.
    #[test]
    fn a_signed_control_ticket_matches_the_client_contract() {
        sodiumoxide::init().ok();
        let (pk, sk) = sign::gen_keypair();
        let t = ControlTicket {
            v: 1, ctl: "c".into(), dk: "k".into(), user: "userA".into(), admin: false,
            targets: vec!["t1".into()], perm: 1 << 4, iat: 3600, exp: 18000, epoch: 7,
        };
        let raw = sign_control_ticket(&t, &sk);
        let (p, s) = raw.split_once('.').unwrap();
        let payload = base64::decode(p).unwrap();
        let sig = sign::Signature::from_bytes(&base64::decode(s).unwrap()).unwrap();
        assert!(sign::verify_detached(&sig, &payload, &pk));
        let v: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        for k in ["v", "ctl", "dk", "user", "admin", "targets", "perm", "iat", "exp", "epoch"] {
            assert!(v.get(k).is_some(), "field {k}");
        }
    }

    #[test]
    fn the_authorization_epoch_only_moves_forward() {
        let a = control_epoch();
        bump_control_epoch();
        let b = control_epoch();
        bump_control_epoch();
        assert!(b > a && control_epoch() > b);
        assert!(is_authz_path("/nemo/api/integration/permissions"));
        assert!(is_authz_path("/nemo/api/peers/123/block"));
        assert!(!is_authz_path("/nemo/api/integration/ldap/test"));
        assert!(!is_authz_path("/nemo/api/connections/cut"));
    }

    /// A controller's direct-endpoint report is the only record of a direct session the
    /// server ever gets: it must land in the Connections view and the target's stats, a
    /// failure must not count as a direct session, and a malformed target must be dropped.
    #[test]
    fn a_direct_report_lands_in_connections_and_stats() {
        let mut store = NemoStatsStore::default();
        let from: SocketAddr = "92.180.230.164:51000".parse().unwrap();
        let ok = serde_json::json!({
            "peer": "352069946", "endpoint": "85.126.226.2:21666",
            "result": "established", "ms": 84,
        });
        record_direct_report(&mut store, "480170882", &ok, Some(from));
        assert_eq!(store.connections.len(), 1);
        let c = &store.connections[0];
        assert_eq!((c.source_id.as_str(), c.target_id.as_str()), ("480170882", "352069946"));
        assert_eq!(c.path, "direct-endpoint");
        assert_eq!(c.target_addr, "85.126.226.2:21666");
        assert_eq!(c.source_addr, "92.180.230.164:51000");
        let st = &store.peers["352069946"];
        assert_eq!(st.direct_endpoint_ok, 1);
        assert!(st.last_direct_report.as_deref().unwrap().contains("established 84 ms"));

        let failed = serde_json::json!({
            "peer": "352069946", "endpoint": "85.126.226.2:21666",
            "result": "failed", "detail": "connection refused",
        });
        record_direct_report(&mut store, "480170882", &failed, Some(from));
        assert_eq!(store.connections[0].path, "direct-failed", "same pair, latest outcome");
        assert_eq!(store.peers["352069946"].direct_endpoint_failed, 1);

        // Not a session: a relay-only skip is logged only; a bad target is ignored.
        for body in [
            serde_json::json!({"peer": "352069946", "result": "not-tried"}),
            serde_json::json!({"peer": "35 20; drop", "result": "established"}),
            serde_json::json!({"result": "established"}),
        ] {
            record_direct_report(&mut store, "480170882", &body, Some(from));
        }
        assert_eq!(store.connections.len(), 1);
    }

    #[test]
    fn upsert_connection_dedupes_pair_and_classifies_path() {
        let mut store = NemoStatsStore::default();
        let a: SocketAddr = "192.168.0.102:4646".parse().unwrap();
        let b: SocketAddr = "192.168.0.176:43739".parse().unwrap();
        // First negotiation for the pair.
        upsert_connection(&mut store, "src1", "tgt1", &a.to_string(), &b.to_string(), "direct-local", "", "ASYMMETRIC");
        assert_eq!(store.connections.len(), 1);
        assert_eq!(store.connections[0].negotiations, 1);
        assert_eq!(store.connections[0].path, "direct-local");
        // Same pair re-negotiates -> merged, count bumped, path updated.
        upsert_connection(&mut store, "src1", "tgt1", &a.to_string(), &b.to_string(), "relay", "192.168.0.176:21117", "SYMMETRIC");
        assert_eq!(store.connections.len(), 1);
        assert_eq!(store.connections[0].negotiations, 2);
        assert_eq!(store.connections[0].path, "relay");
        assert_eq!(store.connections[0].relay_server, "192.168.0.176:21117");
        // A different pair is a separate row.
        upsert_connection(&mut store, "src2", "tgt1", &a.to_string(), &b.to_string(), "direct-punch", "", "PORT_RESTRICTED");
        assert_eq!(store.connections.len(), 2);
    }

    // Retention is by COUNT (configurable), not by age: with a limit of 2, a third
    // distinct connection evicts the oldest (there is no TTL cutoff any more).
    #[test]
    fn upsert_connection_caps_by_count_not_ttl() {
        let saved = CONN_HISTORY_LIMIT.load(Ordering::SeqCst);
        set_conn_history_limit_for_test(2);
        let mut store = NemoStatsStore::default();
        let a: SocketAddr = "192.168.0.102:4646".parse().unwrap();
        let b: SocketAddr = "192.168.0.176:43739".parse().unwrap();
        upsert_connection(&mut store, "s1", "t1", &a.to_string(), &b.to_string(), "direct-local", "", "ASYMMETRIC");
        upsert_connection(&mut store, "s2", "t2", &a.to_string(), &b.to_string(), "direct-local", "", "ASYMMETRIC");
        upsert_connection(&mut store, "s3", "t3", &a.to_string(), &b.to_string(), "direct-local", "", "ASYMMETRIC");
        assert_eq!(store.connections.len(), 2);
        // Oldest (t1) evicted; the two most recent remain.
        assert!(!store.connections.iter().any(|c| c.target_id == "t1"));
        assert!(store.connections.iter().any(|c| c.target_id == "t2"));
        assert!(store.connections.iter().any(|c| c.target_id == "t3"));
        set_conn_history_limit_for_test(saved);
    }

    // Grouped serial test for the functions that read the process-global
    // COMPANY_ONLY flag. Kept in one test so parallel tests never observe a
    // half-set global; the original value is restored at the end.
    #[test]
    /// Blocking a peer must REVOKE the sessions it already has, not only stop the
    /// next one. `/peers/:id/block` used to set the policy and nothing else, so a
    /// session in progress kept running -- caught on the lab server, where a blocked
    /// peer streamed on for another minute. `/connections/cut` already did this; the
    /// split meant the lever named "block" was the one that did not revoke.
    ///
    /// The stamp is what the controlled side reads (`terminate_sessions_before` in its
    /// managed-policy poll), so asserting it moved forward is asserting the revocation
    /// is actually delivered.
    #[test]
    fn blocking_a_peer_stamps_a_session_revocation() {
        let id = "block-revokes-test-peer";
        let before = peer_terminate_before(id);
        let stamped = set_peer_terminate(id);
        assert!(
            stamped >= before,
            "the revocation stamp must never go backwards"
        );
        assert_eq!(
            peer_terminate_before(id),
            stamped,
            "what block stamps is exactly what the peer's policy poll will carry, or the \
             controlled side never learns to close its sessions"
        );
        assert!(
            stamped > 0,
            "a zero stamp is the 'nothing revoked' sentinel the client ignores"
        );
    }

    /// TODO 25: "cut" ends the sessions a machine currently has. It must NOT change
    /// admission -- it used to write status=0 as well, so an operator who cut one
    /// screen-share found the machine BLOCKED afterwards and had to go and allow it
    /// again. Admission is the separate Block action; this test is what keeps the two
    /// levers apart.
    #[test]
    fn cutting_a_connection_revokes_sessions_and_leaves_admission_alone() {
        run_cutting_a_connection_revokes_sessions_and_leaves_admission_alone();
    }
    #[tokio::main(flavor = "current_thread")]
    async fn run_cutting_a_connection_revokes_sessions_and_leaves_admission_alone() {
        let db = format!("target/nemo_cut_test_{}.sqlite3", std::process::id());
        let _ = std::fs::create_dir_all("target");
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let _ = std::fs::remove_file(format!("{}{}", db, suffix));
        }
        let mut pm = PeerMap::new_for_test(&db).await.expect("test db");
        let id = "cut-test-peer";
        let peer = pm.get_or(id).await;
        pm.update_pk(
            id.to_owned(),
            peer,
            "203.0.113.9:21116".parse().expect("addr"),
            hbb_common::bytes::Bytes::from_static(b"cut-uuid"),
            hbb_common::bytes::Bytes::from_static(b"cut-pk"),
            "203.0.113.9".to_owned(),
        )
        .await;
        pm.set_peer_status(id, Some(1), None).await.expect("allow");

        let (login_enc_pk, login_enc_sk) = box_::gen_keypair();
        let state = HbbsApiState {
            pm: pm.clone(),
            token: Some("cut-test-token".to_owned()),
            server_public_key: String::new(),
            server_secret_key: None,
            login_enc_pk,
            login_enc_sk,
        };
        // The route is admin-authenticated; a tokenless call is a 401 before anything
        // else, which is the behaviour the rest of the panel relies on.
        let mut auth = HeaderMap::new();
        auth.insert(
            AUTHORIZATION,
            "Bearer cut-test-token".parse().expect("header"),
        );
        {
            let now = std::time::Instant::now();
            let mut store = STATS.write().await;
            store.connections.push(ConnectionRecord {
                source_id: "cut-test-controller".to_owned(),
                target_id: id.to_owned(),
                source_addr: "203.0.113.1:50000".to_owned(),
                target_addr: "203.0.113.9:21116".to_owned(),
                path: "relay".to_owned(),
                relay_server: "192.0.2.1".to_owned(),
                nat_type: "SYMMETRIC".to_owned(),
                first_seen: now,
                last_seen: now,
                negotiations: 1,
            });
        }

        let before = peer_terminate_before(id);
        let resp = match cut_connection(
            Extension(state.clone()),
            auth.clone(),
            Json(CutConnectionRequest {
                target_id: id.to_owned(),
                source_id: Some("cut-test-controller".to_owned()),
            }),
        )
        .await
        {
            Ok(resp) => resp,
            Err((code, Json(err))) => panic!("cut failed: {} {}", code, err.error),
        };

        // The sessions in progress are revoked -- this stamp is what the controlled
        // machine reads in its next poll and acts on.
        assert!(
            peer_terminate_before(id) >= before && peer_terminate_before(id) > 0,
            "cut must stamp a session revocation, or nothing actually ends"
        );
        // ...and the peer is still allowed, in the database AND in what the dashboard
        // is told, so its row does not flip to "blocked" after a cut.
        assert_eq!(
            pm.peer_status(id).await.expect("status"),
            Some(1),
            "cut must not change admission"
        );
        assert_eq!(resp.0.policy, "allowed");
        assert!(resp.0.allowed_for_control);
        // The live connection row is dropped so the panel does not keep showing it.
        assert!(
            !STATS
                .read()
                .await
                .connections
                .iter()
                .any(|c| c.target_id == id),
            "the cut connection must leave the Connections panel"
        );
        // The audit line must not promise a block any more, or the log disagrees with
        // what the server did.
        {
            let store = STATS.read().await;
            let cut_event = store
                .events
                .iter()
                .rev()
                .find(|e| e.kind == "connection-cut" && e.peer_id.as_deref() == Some(id))
                .expect("a cut is audited");
            assert!(
                !cut_event.detail.contains("blocked"),
                "audit said {:?}",
                cut_event.detail
            );
            assert!(cut_event.detail.contains("admission unchanged"));
        }

        // An id that was never registered is still a 404 rather than a silent
        // revocation written against an unknown name.
        let cut_unknown = cut_connection(
            Extension(state),
            auth,
            Json(CutConnectionRequest {
                target_id: "cut-test-no-such-peer".to_owned(),
                source_id: None,
            }),
        )
        .await;
        let Err((code, _)) = cut_unknown else {
            panic!("an unregistered id must not be cuttable");
        };
        assert_eq!(code, StatusCode::NOT_FOUND);

        for suffix in ["", "-wal", "-shm", "-journal"] {
            let _ = std::fs::remove_file(format!("{}{}", db, suffix));
        }
    }

    /// TODO 24: "unused — went direct" is a verdict made out of the ABSENCE of relay
    /// samples, so it is only a verdict while the relay is actually reporting. With
    /// hbbs and hbbr in separate containers the poller never got through and EVERY row
    /// read "went direct" with a `0 B relayed` header -- a dashboard inventing good
    /// news from missing data. The trust rule lives here; the dashboard asks for it
    /// before it labels anything.
    #[test]
    fn a_session_cannot_be_called_direct_unless_the_relay_is_reporting() {
        // Measurement off: no claim either way.
        let off = RelayPollerHealth::default();
        assert!(!relay_measurement_trusted(&off));
        // On, but hbbr has never answered: exactly the container case.
        let blind = RelayPollerHealth {
            enabled: true,
            target: "127.0.0.1:21117".to_owned(),
            last_error: Some("connection refused".to_owned()),
            last_error_at: Some("2026-10-16T12:00:00Z".to_owned()),
            last_success_at: None,
        };
        assert!(!relay_measurement_trusted(&blind));
        // Answered at least once: now an empty session row really does mean direct.
        let good = RelayPollerHealth {
            last_success_at: Some("2026-10-16T12:00:01Z".to_owned()),
            ..blind
        };
        assert!(relay_measurement_trusted(&good));

        // And the dashboard must consult it rather than reading last_sample_at alone.
        let html = include_str!("nemo_admin.html");
        assert!(html.contains("function relayMeasurementTrusted()"));
        assert!(html.contains("no data from the relay"));
        assert!(
            html.contains("} else if (trusted) {"),
            "the 'went direct' branch must be gated on the poller being known-good"
        );
    }

    /// The dashboard's attribute escaper must not CHANGE the value it escapes.
    ///
    /// It used to lower-case and slug its input, which corrupted every case-sensitive
    /// value that went through it. The one that mattered: a device key's id travels to
    /// the Approve button as `data-claim-approve`, so the dashboard asked the server to
    /// approve `evudkktkksqoqp0f` when the key was `eVudkkTkKsqoQp0F` and got back "no
    /// such pending device-key claim" — a claim could not be approved from the
    /// dashboard at all, which is the one step the whole provisioning flow waits on.
    /// It hid for so long because peer ids are digits, where lower-casing is a no-op.
    #[test]
    fn the_dashboard_escaper_does_not_rewrite_the_values_it_escapes() {
        let html = include_str!("nemo_admin.html");
        let body = html
            .split_once("function escapeAttr(value) {")
            .expect("escapeAttr exists")
            .1
            .split_once('}')
            .expect("escapeAttr body")
            .0;
        assert!(
            !body.contains("toLowerCase") && !body.contains("replace("),
            "escapeAttr must only escape; it rewrote the value: {:?}",
            body
        );
        // The slug form still exists for the one thing that wants it: a CSS class.
        assert!(html.contains("function cssToken(value)"));
        assert!(html.contains("class=\"badge ${cssToken(label)}\""));
        // And the id the server reads back is escaped, not slugged.
        assert!(html.contains("data-claim-approve=\"${escapeAttr(c.key_id)}\""));
    }

    /// The other half of the direct-access question. An endpoint typed into a peer's
    /// row used to look identical whether or not any controller ever received it: the
    /// map is filtered per controller by the outbound-targets ACL and dropped entirely
    /// for a blocked target. This records what each poll actually handed over.
    #[test]
    fn the_peers_panel_can_show_which_endpoints_a_client_was_handed() {
        let id = "endpoint-delivery-test-peer";
        assert_eq!(peer_endpoints_delivered(id), (0, String::new()));
        record_peer_endpoints_delivered(id, "200,10.0.0.5:21118;300,10.0.0.6:21118,62201");
        let (count, at) = peer_endpoints_delivered(id);
        assert_eq!(count, 2);
        assert!(!at.is_empty(), "a delivery has to carry when it happened");
        // A client that polled and was given nothing is NOT the same as one that never
        // polled: zero with a timestamp is itself the answer "told about no endpoint".
        record_peer_endpoints_delivered(id, "");
        let (count, at) = peer_endpoints_delivered(id);
        assert_eq!(count, 0);
        assert!(!at.is_empty());
    }

    #[test]
    fn policy_label_and_allowed_respect_company_only() {
        let saved = COMPANY_ONLY.load(Ordering::SeqCst);

        // Explicit statuses are independent of company-only mode.
        assert_eq!(policy_label(Some(0)), "blocked");
        assert_eq!(policy_label(Some(1)), "allowed");
        assert!(!allowed_for_status(Some(0)));
        assert!(allowed_for_status(Some(1)));

        // Unapproved (NULL status) flips with the global.
        COMPANY_ONLY.store(false, Ordering::SeqCst);
        assert_eq!(policy_label(None), "open");
        assert!(allowed_for_status(None));

        COMPANY_ONLY.store(true, Ordering::SeqCst);
        assert_eq!(policy_label(None), "unapproved");
        assert!(!allowed_for_status(None));

        COMPANY_ONLY.store(saved, Ordering::SeqCst);
    }
}
