use crate::{
    common::{get_arg, get_arg_or},
    database::RegisteredPeer,
    peer::{PeerInfo, PeerMap},
};
use axum::{
    extract::{Extension, Path, Query},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::Html,
    routing::{get, post},
    Json, Router,
};
use hbb_common::{bail, config::keys, log, tokio, ResultType};
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
const MAX_MANAGEMENT_POLICY_VALUE_LEN: usize = 4096;
const NEMO_SOURCE_PREFIX: &str = "nemo-source-v1:";
const OPTION_NEMO_OUTBOUND_ENABLED: &str = "nemo-outbound-enabled";
const OPTION_NEMO_OUTBOUND_TARGETS: &str = "nemo-outbound-targets";
// Current client policy keys that are newer than this server fork's embedded
// hbb_common key tables, plus Nemo-only GUI/management options.
const CLIENT_MANAGEMENT_POLICY_KEYS: &[&str] = &[
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
fn record_peer_auth_mode(id: &str, mode: &str) {
    if id.is_empty() {
        return;
    }
    PEER_AUTH_MODES
        .write()
        .unwrap()
        .insert(id.to_owned(), mode.to_owned());
}
fn peer_auth_mode(id: &str) -> String {
    PEER_AUTH_MODES
        .read()
        .unwrap()
        .get(id)
        .cloned()
        .unwrap_or_else(|| "unknown".to_owned())
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
    path: String, // "direct-local" | "direct-punch" | "relay"
    relay_server: String,
    nat_type: String,
    first_seen: std::time::Instant,
    last_seen: std::time::Instant,
    negotiations: u64,
}

#[derive(Clone, Default, Serialize)]
struct NemoTotals {
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
    /// policy (identity-based policy).
    #[serde(default)]
    access_token: Option<String>,
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
}

#[derive(Serialize)]
struct ClientPolicyPayload {
    id: String,
    issued_at: String,
    policy: ManagementPolicy,
}

#[derive(Serialize)]
struct ClientPolicyResponse {
    server_public_key: String,
    signed_payload: String,
    payload: ClientPolicyPayload,
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
}

#[derive(Serialize)]
struct PeerPolicyResponse {
    id: String,
    status: Option<i64>,
    policy: String,
    allowed_for_control: bool,
}

#[derive(Serialize)]
struct PolicyResponse {
    company_only: bool,
    blocked_status: i64,
    allowed_status: i64,
    connection_history_limit: usize,
    log_history_limit: usize,
    require_device_key: bool,
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
    {
        let map = PEER_HOSTNAMES.read().unwrap();
        if map.get(id).map(|h| h == hostname).unwrap_or(false) {
            return;
        }
    }
    let snapshot = {
        let mut map = PEER_HOSTNAMES.write().unwrap();
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

    let (login_enc_pk, login_enc_sk) = box_::gen_keypair();
    let state = HbbsApiState {
        pm,
        token,
        server_public_key,
        server_secret_key,
        login_enc_pk,
        login_enc_sk,
    };
    let app = Router::new()
        .route("/nemo", get(admin_gui))
        .route("/nemo/admin", get(admin_gui))
        .route("/nemo/admin/", get(admin_gui))
        .route("/nemo/api/health", get(health))
        .route("/nemo/api/peers", get(list_peers))
        .route("/nemo/api/peers/delete", post(delete_peers))
        .route("/nemo/api/peers/:id", get(get_peer))
        .route("/nemo/api/peers/:id/delete", post(delete_peer))
        .route("/nemo/api/peers/:id/block", post(block_peer))
        .route("/nemo/api/peers/:id/allow", post(allow_peer))
        .route("/nemo/api/peers/:id/reset-policy", post(reset_peer_policy))
        .route(
            "/nemo/api/peers/:id/management-policy",
            get(get_peer_management_policy).put(update_peer_management_policy),
        )
        .route("/nemo/api/client/policy", post(client_policy))
        .route("/nemo/api/policy", get(get_policy).put(update_policy))
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
        // RustDesk-client-facing login + server-driven address book.
        .route("/api/login-key", get(api_login_key).post(api_login_key))
        .route(
            "/api/tls-cert-info",
            get(api_tls_cert_info).post(api_tls_cert_info),
        )
        .route("/api/login", post(api_login))
        .route("/api/logout", post(api_logout))
        .route("/api/currentUser", post(api_current_user))
        .route("/api/ab/get", post(api_ab_get))
        .layer(Extension(state));

    // Nemo security: LDAP login credentials and managed secrets must never
    // cross the network in cleartext. Decide the transport, and refuse to serve
    // LDAP login over plaintext HTTP on a routable address.
    let ldap_enabled = crate::nemo_integration::ldap_config().enabled;
    let cert_path = get_arg("nemo-api-tls-cert");
    let key_path = get_arg("nemo-api-tls-key");
    let tls_mode = get_arg("nemo-api-tls"); // "auto" | "off" | "" (auto-decide)
    let explicit_cert = !cert_path.is_empty() && !key_path.is_empty();
    let use_tls = if tls_mode == "off" {
        false
    } else if explicit_cert || tls_mode == "auto" {
        true
    } else {
        // Default: turn TLS on automatically whenever LDAP login is enabled.
        ldap_enabled
    };
    let allow_insecure = is_truthy(&get_arg("nemo-api-allow-insecure"));
    API_TLS_ACTIVE.store(use_tls, Ordering::SeqCst);
    API_BIND_LOOPBACK.store(addr.ip().is_loopback(), Ordering::SeqCst);
    API_ALLOW_INSECURE.store(allow_insecure, Ordering::SeqCst);
    if ldap_enabled && !use_tls && !addr.ip().is_loopback() && !allow_insecure {
        bail!(
            "Refusing to serve LDAP login over plaintext HTTP on {}. Enable TLS \
             (--nemo-api-tls auto, or --nemo-api-tls-cert/--nemo-api-tls-key), bind to \
             loopback for an SSH tunnel, or set --nemo-api-allow-insecure Y to override.",
            addr
        );
    }
    if ldap_enabled && !use_tls {
        log::warn!(
            "Nemo LDAP login is enabled but the API is not using TLS ({}); credentials \
             are sent in cleartext unless a tunnel protects this bind.",
            addr
        );
    }

    if use_tls {
        #[cfg(feature = "nemo-tls")]
        {
            let config = resolve_rustls(&cert_path, &key_path).await?;
            log::info!("Nemo management API listening on https://{}", addr);
            tokio::spawn(async move {
                if let Err(err) = axum_server::bind_rustls(addr, config)
                    .serve(app.into_make_service())
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
            .serve(app.into_make_service())
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

async fn admin_gui() -> Html<&'static str> {
    Html(include_str!("nemo_admin.html"))
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

// S-B: open a sealed login credential to (username, password). Fails closed on any
// decode/parse/replay error.
fn decode_sealed_login(state: &HbbsApiState, sealed_b64: &str) -> Result<(String, String), String> {
    let ciphertext =
        base64::decode(sealed_b64.trim()).map_err(|_| "invalid sealed credential".to_owned())?;
    let plain = sealedbox::open(&ciphertext, &state.login_enc_pk, &state.login_enc_sk)
        .map_err(|_| "sealed credential could not be opened (stale login key? re-fetch /api/login-key)".to_owned())?;
    let s: SealedLogin =
        serde_json::from_slice(&plain).map_err(|_| "invalid sealed credential payload".to_owned())?;
    // Replay guard: reject stale timestamps (allow modest clock skew). ts==0 skips
    // the check (older clients) but still gets confidentiality.
    if s.ts != 0 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if now.saturating_sub(s.ts) > 300 || s.ts.saturating_sub(now) > 60 {
            return Err("sealed credential expired; please retry".to_owned());
        }
    }
    Ok((s.username.trim().to_owned(), s.password))
}

async fn api_login(
    Extension(state): Extension<HbbsApiState>,
    Json(req): Json<LoginRequest>,
) -> Json<LoginResult> {
    // S-B: prefer a sealed credential (confidential regardless of TLS); fall back
    // to plaintext fields for backward compatibility.
    let (username, password) = match &req.sealed {
        Some(sealed) if !sealed.trim().is_empty() => match decode_sealed_login(&state, sealed) {
            Ok(v) => v,
            Err(e) => return Json(LoginResult::err(e)),
        },
        _ => (req.username.trim().to_owned(), req.password.clone()),
    };
    if username.is_empty() || password.is_empty() {
        return Json(LoginResult::err("Username and password required"));
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
            );
            log::info!(
                "Nemo login OK: user='{}' name='{}' admin={} from client id={} uuid={}",
                user.username,
                user.display_name,
                is_admin,
                if req.id.trim().is_empty() { "?" } else { req.id.trim() },
                if req.uuid.trim().is_empty() { "?" } else { req.uuid.trim() },
            );
            Json(LoginResult {
                access_token: Some(token),
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
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

async fn api_ab_get(
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
) -> Json<AbResult> {
    let Some(token) = bearer_token(&headers) else {
        return Json(AbResult {
            updated_at: None,
            data: None,
            error: Some("Invalid token".to_owned()),
        });
    };
    let Some(session) = integration::session_for_token(&token) else {
        return Json(AbResult {
            updated_at: None,
            data: None,
            error: Some("Invalid token".to_owned()),
        });
    };

    let peers = match state.pm.list_registered(1000, 0).await {
        Ok(peers) => peers,
        Err(err) => {
            return Json(AbResult {
                updated_at: None,
                data: None,
                error: Some(err.to_string()),
            });
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
    Json(AbResult {
        updated_at: Some(now_epoch_secs()),
        data: Some(data),
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
    let perm = integration::set_user_enabled(
        username,
        req.enabled,
        req.display_name.trim(),
        req.email.trim(),
    );
    Ok(Json(serde_json::json!({
        "success": true,
        "username": username,
        "enabled": perm.enabled,
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
        default_targets: integration::default_targets(),
        require_login: integration::require_login(),
        default_policy_name: integration::default_policy_name(),
        admin_policy: integration::admin_policy(),
        peers: briefs,
    }))
}

async fn put_permissions(
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
    Json(update): Json<integration::PermissionsUpdate>,
) -> ApiResult<HashMap<String, integration::UserPermission>> {
    require_auth(&headers, &state.token)?;
    Ok(Json(integration::update_permissions(update)))
}

// --- S-DUALKEY: provisioned device keys -------------------------------------
#[derive(Deserialize)]
struct GenerateDeviceKeyRequest {
    #[serde(default)]
    label: String,
}
#[derive(Serialize)]
struct GenerateDeviceKeyResponse {
    id: String,
    label: String,
    public_key: String,
    private_key: String,
    created_at: String,
}
async fn generate_device_key(
    Extension(state): Extension<HbbsApiState>,
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
    );
    Ok(Json(GenerateDeviceKeyResponse {
        id: dk.id,
        label: dk.label,
        public_key,
        private_key,
        created_at,
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
    Ok(Json(serde_json::json!({ "removed": removed })))
}
// Verify a client's device-key signature over "nemo-poll:{id}:{ts}". True only if
// the public key is pinned, the signature is valid, the id matches, and the ts is
// fresh (replay window).
fn verify_device_key(request: &ClientPolicyRequest) -> bool {
    let (Some(pub_b64), Some(sig_b64)) = (
        request.device_key_pub.as_deref(),
        request.device_key_sig.as_deref(),
    ) else {
        return false;
    };
    if !integration::is_device_key_pinned(pub_b64) {
        return false;
    }
    let (Ok(pk_bytes), Ok(sig_bytes)) =
        (base64::decode(pub_b64.trim()), base64::decode(sig_b64.trim()))
    else {
        return false;
    };
    let Some(pk) = sign::PublicKey::from_slice(&pk_bytes) else {
        return false;
    };
    let Ok(msg) = sign::verify(&sig_bytes, &pk) else {
        return false;
    };
    let msg = String::from_utf8_lossy(&msg);
    let parts: Vec<&str> = msg.splitn(3, ':').collect();
    if parts.len() != 3 || parts[0] != "nemo-poll" || parts[1] != request.id {
        return false;
    }
    if let Ok(ts) = parts[2].parse::<u64>() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if now.saturating_sub(ts) > 300 || ts.saturating_sub(now) > 60 {
            return false;
        }
    }
    true
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
    Ok(Json(global_policy()))
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
    *GLOBAL_POLICY.write().unwrap() = policy.clone();
    save_global_policy(&policy);
    Ok(Json(policy))
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
        .filter(|c| c.path.starts_with("direct"))
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

async fn cut_connection(
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
    Json(req): Json<CutConnectionRequest>,
) -> ApiResult<PeerPolicyResponse> {
    require_auth(&headers, &state.token)?;
    // The reliable server-side lever is to block the target so it stops
    // negotiating/accepting NEW connections. Active *direct* sessions have no
    // server-side data path to interrupt (that is the point of a direct
    // connection); they end when the session closes or the peer re-checks policy.
    let resp = set_peer_policy(&state.pm, &req.target_id, Some(0)).await?;
    {
        let mut store = STATS.write().await;
        store.connections.retain(|c| c.target_id != req.target_id);
        let detail = match &req.source_id {
            Some(s) => format!("blocked target {} (source {}) from dashboard", req.target_id, s),
            None => format!("blocked target {} from dashboard", req.target_id),
        };
        record_event_locked(&mut store, "connection-cut", Some(&req.target_id), None, detail);
    }
    Ok(resp)
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

// Per-user connection ACL + require-login, enforced at the punch. `token` is the
// controller's logged-in user session token (if any).
fn nemo_user_connection_rejection(token: Option<&str>, target_id: &str) -> Option<String> {
    let user = token
        .and_then(integration::session_for_token)
        .filter(|s| integration::user_is_enabled(&s.username));
    match user {
        Some(session) => {
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
pub(crate) fn nemo_user_rejection_from_field(
    source_field: &str,
    target_id: &str,
) -> Option<(String, String)> {
    // Parse best-effort: a controller with no source marker still gets the
    // require-login gate (token = None) so it cannot bypass mandatory login.
    let parsed = controller_source_identity(source_field);
    let token = parsed.as_ref().and_then(|(_, _, t)| t.clone());
    let source_id = parsed.map(|(id, _, _)| id).unwrap_or_default();
    let reason = nemo_user_connection_rejection(token.as_deref(), target_id)?;
    Some((source_id, reason))
}

async fn controller_policy_rejection(
    pm: &PeerMap,
    source_id: &str,
    source_uuid: &[u8],
    target_id: &str,
) -> Option<String> {
    let source_id = source_id.trim();
    if source_id.is_empty() {
        return None;
    }
    let source = match pm.get_registered(source_id).await {
        Ok(Some(source)) => source,
        Ok(None) => return Some("controller is not registered by TBF policy".to_owned()),
        Err(err) => {
            log::error!("failed to verify controller {}: {}", source_id, err);
            return Some("controller policy could not be verified".to_owned());
        }
    };
    if source_uuid.is_empty() || source.uuid.as_slice() != source_uuid {
        return Some("controller identity rejected by TBF policy".to_owned());
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

pub(crate) async fn controller_policy_rejection_from_field(
    pm: &PeerMap,
    source_field: &str,
    target_id: &str,
) -> Option<(String, String)> {
    let (source_id, source_uuid, _token) = controller_source_identity(source_field)?;
    let reason = controller_policy_rejection(pm, &source_id, &source_uuid, target_id).await?;
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
    log::info!(
        "Nemo connect: target={} source='{}' from={} to={} nat={} path={}",
        id,
        source_field,
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
    let source_id = controller_source_identity(source_field)
        .map(|(sid, _, _)| sid)
        .unwrap_or_default();
    upsert_connection(
        &mut store,
        &source_id,
        id,
        from_addr,
        to_addr,
        path,
        relay_server,
        nat_type_name(nat_type),
    );
}

fn upsert_connection(
    store: &mut NemoStatsStore,
    source_id: &str,
    target_id: &str,
    from_addr: SocketAddr,
    to_addr: SocketAddr,
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
        existing.source_addr = from_addr.to_string();
        existing.target_addr = to_addr.to_string();
        existing.relay_server = relay_server.to_owned();
        existing.nat_type = nat_type.to_owned();
    } else {
        store.connections.push(ConnectionRecord {
            source_id: source_id.to_owned(),
            target_id: target_id.to_owned(),
            source_addr: from_addr.to_string(),
            target_addr: to_addr.to_string(),
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

async fn health(
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
) -> ApiResult<PolicyResponse> {
    require_auth(&headers, &state.token)?;
    Ok(Json(policy_response()))
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

async fn client_policy(
    Extension(state): Extension<HbbsApiState>,
    Json(request): Json<ClientPolicyRequest>,
) -> ApiResult<ClientPolicyResponse> {
    let peer = state
        .pm
        .get_registered(&request.id)
        .await
        .map_err(server_error)?
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "peer not found"))?;
    validate_client_policy_request(&peer, &request)?;
    // Learn this peer's hostname from its own poll so the address book can show it.
    record_peer_hostname(&request.id, request.hostname.as_deref().unwrap_or(""));
    // S-DUALKEY: note which key the client authenticated with, and enforce the
    // "require provisioned device key" setting.
    let device_key_ok = verify_device_key(&request);
    record_peer_auth_mode(&request.id, if device_key_ok { "device-key" } else { "default" });
    if integration::require_device_key() && !device_key_ok {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "a provisioned device key is required",
        ));
    }
    if let Some(version) = request.policy_version.as_deref() {
        log::trace!("Client {} requested management policy after {}", request.id, version);
    }
    // Global (infrastructure) defaults first — api-server, TLS fallback, etc.
    let mut policy = global_policy();

    // Identity-based policy: resolve the logged-in, enabled user from the token.
    let user = request
        .access_token
        .as_deref()
        .and_then(integration::session_for_token)
        .filter(|s| integration::user_is_enabled(&s.username));
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
    if matches!(peer.status, Some(0)) {
        policy.allow_user_override = false;
        policy
            .options
            .insert(OPTION_NEMO_OUTBOUND_ENABLED.to_owned(), "N".to_owned());
    }
    let payload = ClientPolicyPayload {
        id: peer.id.clone(),
        issued_at: now_iso(),
        policy,
    };
    let payload_bytes = serde_json::to_vec(&payload).map_err(server_error)?;
    let signed_payload = state
        .server_secret_key
        .as_ref()
        .map(|secret_key| base64::encode(sign::sign(&payload_bytes, secret_key)))
        .unwrap_or_default();
    Ok(Json(ClientPolicyResponse {
        server_public_key: state.server_public_key,
        signed_payload,
        payload,
    }))
}

async fn block_peer(
    Path(id): Path<String>,
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
) -> ApiResult<PeerPolicyResponse> {
    require_auth(&headers, &state.token)?;
    set_peer_policy(&state.pm, &id, Some(0)).await
}

async fn allow_peer(
    Path(id): Path<String>,
    Extension(state): Extension<HbbsApiState>,
    headers: HeaderMap,
) -> ApiResult<PeerPolicyResponse> {
    require_auth(&headers, &state.token)?;
    set_peer_policy(&state.pm, &id, Some(1)).await
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
    Ok(Json(policy_response()))
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
    Ok(Json(policy_response()))
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
    Ok(Json(StatsResponse {
        company_only: company_only(),
        totals: store.totals.clone(),
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
    PeerResponse {
        id: peer.id.clone(),
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

fn policy_response() -> PolicyResponse {
    PolicyResponse {
        company_only: company_only(),
        blocked_status: 0,
        allowed_status: 1,
        connection_history_limit: conn_history_limit(),
        log_history_limit: log_history_limit(),
        require_device_key: integration::require_device_key(),
    }
}

// Nemo hardening (S4): policy keys whose values are secrets and must never be
// echoed in API responses (they were previously returned in plaintext).
const SECRET_POLICY_KEYS: &[&str] = &[
    "nemo-permanent-password",
    "default-connect-password",
    "proxy-password",
    "preset-address-book-password",
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
    mut policy: ManagementPolicy,
    existing: &Option<String>,
) -> ManagementPolicy {
    let current = management_policy_from_peer(existing);
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
    let Some(token) = token else {
        return Ok(());
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

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn is_truthy(value: &str) -> bool {
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

    #[test]
    fn require_auth_is_open_when_no_token_configured() {
        let headers = HeaderMap::new();
        assert!(require_auth(&headers, &None).is_ok());
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
        };
        assert!(validate_client_policy_request(&peer, &ok).is_ok());
        // Empty id.
        let no_id = ClientPolicyRequest {
            id: "  ".to_owned(),
            uuid: base64::encode([10u8, 20, 30]),
            policy_version: None,
            access_token: None,
            hostname: None,
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
        };
        assert_eq!(
            validate_client_policy_request(&peer, &mismatch).unwrap_err().0,
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn upsert_connection_dedupes_pair_and_classifies_path() {
        let mut store = NemoStatsStore::default();
        let a: SocketAddr = "192.168.0.102:4646".parse().unwrap();
        let b: SocketAddr = "192.168.0.176:43739".parse().unwrap();
        // First negotiation for the pair.
        upsert_connection(&mut store, "src1", "tgt1", a, b, "direct-local", "", "ASYMMETRIC");
        assert_eq!(store.connections.len(), 1);
        assert_eq!(store.connections[0].negotiations, 1);
        assert_eq!(store.connections[0].path, "direct-local");
        // Same pair re-negotiates -> merged, count bumped, path updated.
        upsert_connection(&mut store, "src1", "tgt1", a, b, "relay", "192.168.0.176:21117", "SYMMETRIC");
        assert_eq!(store.connections.len(), 1);
        assert_eq!(store.connections[0].negotiations, 2);
        assert_eq!(store.connections[0].path, "relay");
        assert_eq!(store.connections[0].relay_server, "192.168.0.176:21117");
        // A different pair is a separate row.
        upsert_connection(&mut store, "src2", "tgt1", a, b, "direct-punch", "", "PORT_RESTRICTED");
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
        upsert_connection(&mut store, "s1", "t1", a, b, "direct-local", "", "ASYMMETRIC");
        upsert_connection(&mut store, "s2", "t2", a, b, "direct-local", "", "ASYMMETRIC");
        upsert_connection(&mut store, "s3", "t3", a, b, "direct-local", "", "ASYMMETRIC");
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
