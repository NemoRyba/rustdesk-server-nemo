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
use sodiumoxide::crypto::sign;
use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    sync::atomic::{AtomicBool, Ordering},
};
use tokio::sync::RwLock;

const EVENT_LIMIT: usize = 500;
const MAX_MANAGEMENT_POLICY_VALUE_LEN: usize = 4096;
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
static STATS: Lazy<RwLock<NemoStatsStore>> = Lazy::new(|| RwLock::new(NemoStatsStore::default()));

#[derive(Clone)]
struct HbbsApiState {
    pm: PeerMap,
    token: Option<String>,
    server_public_key: String,
    server_secret_key: Option<sign::SecretKey>,
}

#[derive(Default)]
struct NemoStatsStore {
    totals: NemoTotals,
    peers: HashMap<String, NemoPeerStats>,
    events: VecDeque<NemoEvent>,
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
}

#[derive(Serialize)]
struct ManagementPolicyResponse {
    id: String,
    policy: ManagementPolicy,
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

pub(crate) fn init_from_args() {
    COMPANY_ONLY.store(is_truthy(&get_arg("nemo-company-only")), Ordering::SeqCst);
    log::info!(
        "Nemo company-only policy: {}",
        if company_only() { "enabled" } else { "disabled" }
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

    let state = HbbsApiState {
        pm,
        token,
        server_public_key,
        server_secret_key,
    };
    let app = Router::new()
        .route("/nemo", get(admin_gui))
        .route("/nemo/admin", get(admin_gui))
        .route("/nemo/admin/", get(admin_gui))
        .route("/nemo/api/health", get(health))
        .route("/nemo/api/peers", get(list_peers))
        .route("/nemo/api/peers/:id", get(get_peer))
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
        .layer(Extension(state));

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

async fn admin_gui() -> Html<&'static str> {
    Html(include_str!("nemo_admin.html"))
}

pub(crate) fn company_only() -> bool {
    COMPANY_ONLY.load(Ordering::SeqCst)
}

pub(crate) async fn is_peer_blocked(pm: &PeerMap, id: &str) -> bool {
    pm.is_peer_blocked(id).await
}

pub(crate) async fn is_peer_allowed(pm: &PeerMap, id: &str) -> bool {
    pm.is_peer_allowed_for_control(id, company_only()).await
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
    from_addr: SocketAddr,
    to_addr: SocketAddr,
    nat_type: i32,
    forced_relay: bool,
    same_intranet: bool,
    relay_server: &str,
) {
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
    if let Some(version) = request.policy_version.as_deref() {
        log::trace!("Client {} requested management policy after {}", request.id, version);
    }
    let payload = ClientPolicyPayload {
        id: peer.id.clone(),
        issued_at: now_iso(),
        policy: management_policy_from_peer(&peer.management_policy),
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
        let mut store = STATS.write().await;
        record_event_locked(
            &mut store,
            "policy-update",
            None,
            None,
            format!("company_only={}", company_only),
        );
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
    let limit = query.limit.unwrap_or(100).clamp(1, EVENT_LIMIT);
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
        management_policy: management_policy_from_peer(&peer.management_policy),
        registered_ip,
        public_addr: runtime
            .as_ref()
            .and_then(|snapshot| snapshot.public_addr.clone()),
        online: runtime.as_ref().map(|snapshot| snapshot.online).unwrap_or(false),
        last_seen_ms_ago: runtime.and_then(|snapshot| snapshot.last_seen_ms_ago),
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
    }
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
        .map(|value| value == bearer)
        .unwrap_or(false);
    let nemo_token = headers
        .get("x-nemo-token")
        .and_then(|value| value.to_str().ok())
        .map(|value| value == token)
        .unwrap_or(false);
    if auth || nemo_token {
        Ok(())
    } else {
        Err(api_error(StatusCode::UNAUTHORIZED, "unauthorized"))
    }
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

fn peer_stats_mut<'a>(store: &'a mut NemoStatsStore, id: &str) -> &'a mut NemoPeerStats {
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
    while store.events.len() > EVENT_LIMIT {
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
