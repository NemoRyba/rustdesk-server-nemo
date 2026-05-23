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
use hbb_common::{bail, log, tokio, ResultType};
use once_cell::sync::Lazy;
use serde_derive::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    sync::atomic::{AtomicBool, Ordering},
};
use tokio::sync::RwLock;

const EVENT_LIMIT: usize = 500;
static COMPANY_ONLY: AtomicBool = AtomicBool::new(false);
static STATS: Lazy<RwLock<NemoStatsStore>> = Lazy::new(|| RwLock::new(NemoStatsStore::default()));

#[derive(Clone)]
struct HbbsApiState {
    pm: PeerMap,
    token: Option<String>,
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

pub(crate) async fn spawn_hbbs_api(pm: PeerMap) -> ResultType<()> {
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

    let state = HbbsApiState { pm, token };
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
