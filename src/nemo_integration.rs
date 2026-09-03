//! Nemo integration layer: LDAP (Windows-domain) login, session tokens, and a
//! per-user RBAC map that decides which registered peers a logged-in user may
//! see in their address book.
//!
//! The LDAP flow mirrors the proven ActivityWatch integration
//! (`aw-server/aw_server/settings.py::_authenticate_ldap_user`): bind with a
//! service account, search for the user by a configurable filter, then re-bind
//! as the discovered DN with the user's password to verify the credentials. If
//! no service `bind_dn` is configured we bind directly with a principal derived
//! from the username and the Windows domain.
//!
//! Config (LDAP settings + the RBAC map) is persisted as JSON next to the
//! server's other state; session tokens are ephemeral (process memory only).

use hbb_common::log;
use once_cell::sync::Lazy;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::common::get_arg;

/// Default AD-friendly filter: match sAMAccountName, userPrincipalName, or a
/// synthesised UPN. `{username}` is the raw input; `{raw_username}` is the input
/// stripped of any `DOMAIN\` / `@domain` decoration; `{upn}` is `raw@domain`.
pub const DEFAULT_USER_SEARCH_FILTER: &str = "(&(objectClass=user)(|(sAMAccountName={username})(userPrincipalName={raw_username})(userPrincipalName={upn})))";

/// How long an issued session token stays valid without being refreshed.
const SESSION_TTL_SECS: u64 = 12 * 60 * 60;

// --------------------------------------------------------------------------
// Config model
// --------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LdapConfig {
    #[serde(default)]
    pub enabled: bool,
    /// e.g. `ldaps://dc.example.local:636` (implicit TLS) or `ldap://host:389`.
    #[serde(default)]
    pub server_url: String,
    /// Windows domain, e.g. `example.local`, used to build principals/UPNs.
    #[serde(default)]
    pub windows_domain: String,
    /// Search base, e.g. `DC=example,DC=local`.
    #[serde(default)]
    pub base_dn: String,
    /// Service-account DN or UPN used to search for users. Empty => bind as the
    /// user directly (principal derived from username + domain).
    #[serde(default)]
    pub bind_dn: String,
    /// Service-account password. Persisted in the config file; keep the file
    /// readable only by the server user.
    #[serde(default)]
    pub bind_password: String,
    #[serde(default = "default_user_search_filter")]
    pub user_search_filter: String,
    /// Verify the directory server's TLS certificate. Defaults to ON: without
    /// verification, an on-path attacker can impersonate the DC and authenticate
    /// as any user without a password (and harvest real credentials). Turn OFF
    /// only for a known internal CA you cannot add to the trust store, and
    /// understand the MITM risk.
    #[serde(default = "default_true")]
    pub tls_verify: bool,
    /// PEM certificate(s) to trust for the directory's TLS, in addition to the
    /// system roots. Lets an admin pin a self-signed DC certificate so TLS
    /// verification passes against exactly that cert (much safer than turning
    /// verification off, which accepts any certificate).
    #[serde(default)]
    pub ca_cert: String,
}

fn default_user_search_filter() -> String {
    DEFAULT_USER_SEARCH_FILTER.to_owned()
}

fn default_true() -> bool {
    true
}

impl Default for LdapConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server_url: String::new(),
            windows_domain: String::new(),
            base_dn: String::new(),
            bind_dn: String::new(),
            bind_password: String::new(),
            user_search_filter: default_user_search_filter(),
            tls_verify: true,
            ca_cert: String::new(),
        }
    }
}

/// A user's management policy (session settings) — same shape as the per-device
/// managed policy, but keyed to the LDAP identity. Applied to whatever client the
/// user logs into (replacing the device policy).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct UserManagedPolicy {
    #[serde(default)]
    pub allow_user_override: bool,
    #[serde(default)]
    pub options: HashMap<String, String>,
}

/// Per-user entry: whether the user may use the software at all (`enabled`, the
/// allowlist gate), which peers they may connect to (`allowed_targets`, enforced
/// at connection), their session `policy`, and admin flag.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserPermission {
    /// Allowlist gate: false = this LDAP user is NOT allowed to use the software
    /// (login refused). New auto-created users default to disabled so an admin
    /// explicitly picks who gets access.
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub is_admin: bool,
    #[serde(default)]
    pub allowed_targets: Vec<String>,
    /// Session permissions applied to the client this user logs into. Used only
    /// when `policy_name` is empty (inline/custom policy); otherwise the named
    /// policy of that name is resolved from `IntegrationConfig::policies`.
    #[serde(default)]
    pub policy: UserManagedPolicy,
    /// Name of an assigned named policy (empty/None = use the inline `policy`).
    #[serde(default)]
    pub policy_name: Option<String>,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub last_login: String,
}

impl Default for UserPermission {
    fn default() -> Self {
        Self {
            enabled: false,
            is_admin: false,
            allowed_targets: Vec::new(),
            policy: UserManagedPolicy::default(),
            policy_name: None,
            display_name: String::new(),
            email: String::new(),
            last_login: String::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntegrationConfig {
    #[serde(default)]
    pub ldap: LdapConfig,
    /// username (lower-cased canonical) -> permissions
    #[serde(default)]
    pub permissions: HashMap<String, UserPermission>,
    /// Targets granted to a freshly-seen LDAP user that has no explicit entry
    /// yet. Empty => new users start with no visible peers until an admin grants
    /// access. Set to `["*"]` for allow-all-by-default.
    #[serde(default)]
    pub default_targets: Vec<String>,
    /// When true, clients must have a logged-in (enabled) user before they can be
    /// used at all, and the logged-in user's policy replaces the device policy.
    #[serde(default)]
    pub require_login: bool,
    /// Named, reusable policy templates: policy name -> session settings. Assigned
    /// to users (UserPermission::policy_name) and to devices (device_policies).
    #[serde(default)]
    pub policies: HashMap<String, UserManagedPolicy>,
    /// Device-level assignment: peer id -> named policy. Applied to that peer's
    /// incoming sessions when no user is logged in (user policy wins when logged in).
    #[serde(default)]
    pub device_policies: HashMap<String, String>,
    /// Named policy applied to an enabled user who has NO policy of their own
    /// (no assigned named policy and an empty inline policy). Lets the admin set
    /// one baseline that auto-applies to newly-allowed users.
    #[serde(default)]
    pub default_policy_name: Option<String>,
    /// The single policy applied to ALL admin users. Admins bypass every normal
    /// policy (named/default/inline) and get this one instead — full access by
    /// default, adjustable if the operator wants to restrict admins.
    #[serde(default = "default_admin_policy")]
    pub admin_policy: UserManagedPolicy,
    /// Provisioned per-client device keys the server trusts: the operator
    /// generates a keypair here (pins the public half) and imports the private
    /// half into the client, so the client can prove its identity to the server.
    #[serde(default)]
    pub device_keys: Vec<DeviceKey>,
    /// When true, only clients that sign their poll with a PINNED device key are
    /// accepted; clients with just the server's public key are refused.
    #[serde(default)]
    pub require_device_key: bool,
    /// H4: when true, secret policy values (managed password etc.) are STRIPPED from
    /// any policy response that cannot be sealed to a verified device key, instead of
    /// being sent in plaintext authenticated only by id+uuid. Off by default so an
    /// unprovisioned fleet keeps working; turn on once every client has a device key.
    #[serde(default)]
    pub strip_unsealed_secrets: bool,
}

/// A provisioned client device key (public half pinned server-side).
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct DeviceKey {
    pub id: String,
    pub label: String,
    pub public_key: String, // base64 Ed25519 public key
    pub created_at: String,
    /// M1: the peer id this key is bound to. Empty = legacy unbound key (any id).
    /// A bound key only authenticates polls for exactly this peer id, so one leaked
    /// key no longer satisfies require_device_key for the whole fleet.
    #[serde(default)]
    pub peer_id: String,
}

/// Full-access baseline for admin users: every capability allowed, full control,
/// two-way file transfer. The admin can then tighten specific controls.
pub fn default_admin_policy() -> UserManagedPolicy {
    let mut options = HashMap::new();
    for k in [
        "enable-keyboard",
        "enable-clipboard",
        "enable-file-transfer",
        "enable-audio",
        "enable-camera",
        "enable-terminal",
        "enable-tunnel",
        "enable-remote-printer",
        "enable-remote-restart",
        "enable-record-session",
        "enable-block-input",
        "enable-privacy-mode",
    ] {
        options.insert(k.to_owned(), "Y".to_owned());
    }
    options.insert("view_only".to_owned(), "N".to_owned());
    options.insert("one-way-file-transfer".to_owned(), "N".to_owned());
    UserManagedPolicy {
        allow_user_override: false,
        options,
    }
}

impl Default for IntegrationConfig {
    fn default() -> Self {
        Self {
            ldap: LdapConfig::default(),
            permissions: HashMap::new(),
            default_targets: Vec::new(),
            require_login: false,
            policies: HashMap::new(),
            device_policies: HashMap::new(),
            default_policy_name: None,
            admin_policy: default_admin_policy(),
            device_keys: Vec::new(),
            require_device_key: false,
            strip_unsealed_secrets: false,
        }
    }
}

// --------------------------------------------------------------------------
// Persistence
// --------------------------------------------------------------------------

fn config_path() -> PathBuf {
    let arg = get_arg("nemo-integration-file");
    if arg.is_empty() {
        PathBuf::from("nemo_integration.json")
    } else {
        PathBuf::from(arg)
    }
}

static CONFIG: Lazy<Mutex<IntegrationConfig>> = Lazy::new(|| Mutex::new(load_config()));

// Monotonic address-book / access version. Bumped whenever a change affects what
// a logged-in user may see (their allowed targets), so clients can detect the
// change on their next signed policy poll and re-fetch the address book — an
// encrypted server push of ACL changes without a dedicated channel.
static AB_VERSION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
pub fn ab_version() -> u64 {
    AB_VERSION.load(std::sync::atomic::Ordering::Relaxed)
}
fn bump_ab_version() {
    AB_VERSION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

fn load_config() -> IntegrationConfig {
    let path = config_path();
    match std::fs::read_to_string(&path) {
        Ok(text) => match serde_json::from_str::<IntegrationConfig>(&text) {
            Ok(cfg) => cfg,
            Err(err) => {
                log::error!(
                    "Nemo integration config at {} is invalid ({}); using defaults",
                    path.display(),
                    err
                );
                IntegrationConfig::default()
            }
        },
        Err(_) => IntegrationConfig::default(),
    }
}

// M3 / C1: the integration config holds the LDAP bind password and the sessions file
// holds live bearer tokens. Restrict them to the service account so other local users
// cannot read domain credentials or hijack sessions. The production server runs on Linux
// (0600, like the TLS private key); the Windows branch is defensive for a Windows-hosted
// server (C1: the previous cfg(not(unix)) no-op left these files world-readable there).
fn restrict_file(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
            log::warn!("could not restrict permissions on {}: {}", path.display(), e);
        }
    }
    #[cfg(windows)]
    {
        restrict_file_windows(path);
    }
    #[cfg(not(any(unix, windows)))]
    let _ = path;
}

// C1: strip inherited ACEs and grant Full Control ONLY to SYSTEM, Administrators, and the
// account running the server. Uses icacls (always present on Windows); SIDs are used for
// SYSTEM (S-1-5-18) and Administrators (S-1-5-32-544) so it is locale-independent. Best
// effort with a loud warning on failure — never silently leaves the file world-readable.
#[cfg(windows)]
fn restrict_file_windows(path: &std::path::Path) {
    let Some(path_str) = path.to_str() else {
        log::warn!("could not restrict {}: non-UTF-8 path", path.display());
        return;
    };
    let mut cmd = std::process::Command::new("icacls");
    cmd.arg(path_str)
        .args(["/inheritance:r"])
        .args(["/grant:r", "*S-1-5-18:(F)"])
        .args(["/grant:r", "*S-1-5-32-544:(F)"]);
    // Grant the running account too, so the service can still read/write its own files.
    if let Ok(user) = std::env::var("USERNAME") {
        if !user.trim().is_empty() {
            cmd.args(["/grant:r", &format!("{}:(F)", user.trim())]);
        }
    }
    match cmd.output() {
        Ok(out) if out.status.success() => {}
        Ok(out) => log::warn!(
            "icacls could not restrict {} (exit {:?}): {}",
            path.display(),
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Err(e) => log::warn!("could not run icacls to restrict {}: {}", path.display(), e),
    }
}

fn persist(cfg: &IntegrationConfig) {
    let path = config_path();
    match serde_json::to_string_pretty(cfg) {
        Ok(text) => {
            if let Err(err) = std::fs::write(&path, text) {
                log::error!(
                    "failed to write Nemo integration config to {}: {}",
                    path.display(),
                    err
                );
            } else {
                restrict_file(&path);
            }
        }
        Err(err) => log::error!("failed to serialize Nemo integration config: {}", err),
    }
}

/// Snapshot of the LDAP config with the bind password masked, for API responses.
#[derive(Clone, Debug, Serialize)]
pub struct LdapConfigView {
    pub enabled: bool,
    pub server_url: String,
    pub windows_domain: String,
    pub base_dn: String,
    pub bind_dn: String,
    /// `true` if a bind password is stored (the value itself is never returned).
    pub bind_password_set: bool,
    pub user_search_filter: String,
    pub tls_verify: bool,
    /// `true` if a certificate is pinned for the directory TLS.
    pub ca_cert_set: bool,
    /// SHA-256 fingerprint of the pinned certificate (empty if none / unparsable).
    pub ca_cert_fingerprint: String,
    /// Subject DN of the pinned certificate (e.g. `CN=dc`).
    pub ca_cert_subject: String,
    /// SAN domains of the pinned certificate (e.g. `dc`, `dc.tbfgmbh.local`).
    pub ca_cert_sans: Vec<String>,
}

impl From<&LdapConfig> for LdapConfigView {
    fn from(c: &LdapConfig) -> Self {
        Self {
            enabled: c.enabled,
            server_url: c.server_url.clone(),
            windows_domain: c.windows_domain.clone(),
            base_dn: c.base_dn.clone(),
            bind_dn: c.bind_dn.clone(),
            bind_password_set: !c.bind_password.is_empty(),
            user_search_filter: c.user_search_filter.clone(),
            tls_verify: c.tls_verify,
            ca_cert_set: !c.ca_cert.trim().is_empty(),
            ca_cert_fingerprint: pem_fingerprint(&c.ca_cert),
            ca_cert_subject: {
                let (subject, _) = pem_cert_summary(&c.ca_cert);
                subject
            },
            ca_cert_sans: {
                let (_, sans) = pem_cert_summary(&c.ca_cert);
                sans
            },
        }
    }
}

/// Fields accepted from the dashboard when updating LDAP config. `bind_password`
/// is optional so the UI can leave it blank to keep the stored value.
#[derive(Clone, Debug, Deserialize)]
pub struct LdapConfigUpdate {
    pub enabled: Option<bool>,
    pub server_url: Option<String>,
    pub windows_domain: Option<String>,
    pub base_dn: Option<String>,
    pub bind_dn: Option<String>,
    pub bind_password: Option<String>,
    pub user_search_filter: Option<String>,
    pub tls_verify: Option<bool>,
    pub ca_cert: Option<String>,
}

pub fn ldap_config_view() -> LdapConfigView {
    let cfg = CONFIG.lock().unwrap();
    LdapConfigView::from(&cfg.ldap)
}

pub fn ldap_config() -> LdapConfig {
    CONFIG.lock().unwrap().ldap.clone()
}

/// Apply an update from the dashboard, persist, and return the masked view.
pub fn update_ldap_config(update: LdapConfigUpdate) -> LdapConfigView {
    let mut cfg = CONFIG.lock().unwrap();
    let ldap = &mut cfg.ldap;
    if let Some(v) = update.enabled {
        ldap.enabled = v;
    }
    if let Some(v) = update.server_url {
        ldap.server_url = v.trim().to_owned();
    }
    if let Some(v) = update.windows_domain {
        ldap.windows_domain = v.trim().to_owned();
    }
    if let Some(v) = update.base_dn {
        ldap.base_dn = v.trim().to_owned();
    }
    if let Some(v) = update.bind_dn {
        ldap.bind_dn = v.trim().to_owned();
    }
    // Only overwrite the password when a non-empty value is supplied.
    if let Some(v) = update.bind_password {
        if !v.is_empty() {
            ldap.bind_password = v;
        }
    }
    if let Some(v) = update.user_search_filter {
        let v = v.trim();
        ldap.user_search_filter = if v.is_empty() {
            default_user_search_filter()
        } else {
            v.to_owned()
        };
    }
    if let Some(v) = update.tls_verify {
        ldap.tls_verify = v;
    }
    if let Some(v) = update.ca_cert {
        ldap.ca_cert = v.trim().to_owned();
    }
    let view = LdapConfigView::from(&*ldap);
    persist(&cfg);
    view
}

// --------------------------------------------------------------------------
// Permissions (RBAC)
// --------------------------------------------------------------------------

pub fn permissions_snapshot() -> HashMap<String, UserPermission> {
    CONFIG.lock().unwrap().permissions.clone()
}

pub fn default_targets() -> Vec<String> {
    CONFIG.lock().unwrap().default_targets.clone()
}

#[derive(Clone, Debug, Deserialize)]
pub struct PermissionsUpdate {
    /// Present = replace the whole permission set; absent = leave it (so a panel
    /// can update just default_policy_name / admin_policy without wiping users).
    #[serde(default)]
    pub permissions: Option<HashMap<String, UserPermission>>,
    #[serde(default)]
    pub default_targets: Option<Vec<String>>,
    #[serde(default)]
    pub require_login: Option<bool>,
    /// Present = set the default policy (empty string clears it); absent = leave.
    #[serde(default)]
    pub default_policy_name: Option<String>,
    /// Present = replace the admin policy; absent = leave unchanged.
    #[serde(default)]
    pub admin_policy: Option<UserManagedPolicy>,
}

/// Replace the RBAC map (and optionally the default targets / require-login),
/// persist, return it.
pub fn update_permissions(update: PermissionsUpdate) -> HashMap<String, UserPermission> {
    let mut cfg = CONFIG.lock().unwrap();
    // Normalise keys to canonical lower-case so lookups at login match. Only when
    // permissions are actually provided — a partial update (e.g. just the admin
    // policy) must NOT wipe the whole allowlist.
    if let Some(perms) = update.permissions {
        cfg.permissions = perms
            .into_iter()
            .map(|(k, mut v)| {
                v.allowed_targets = normalize_targets(v.allowed_targets);
                (normalize_lookup_username(&k), v)
            })
            .collect();
    }
    if let Some(targets) = update.default_targets {
        cfg.default_targets = normalize_targets(targets);
    }
    if let Some(require) = update.require_login {
        cfg.require_login = require;
    }
    if let Some(dn) = update.default_policy_name {
        cfg.default_policy_name = if dn.trim().is_empty() { None } else { Some(dn) };
    }
    if let Some(ap) = update.admin_policy {
        cfg.admin_policy = ap;
    }
    let snapshot = cfg.permissions.clone();
    persist(&cfg);
    drop(cfg);
    bump_ab_version(); // signal logged-in clients to re-fetch their address book
    snapshot
}

fn normalize_targets(targets: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for t in targets {
        let t = t.trim();
        if t.is_empty() {
            continue;
        }
        let t = t.to_owned();
        if !out.contains(&t) {
            out.push(t);
        }
    }
    out
}

/// Record a successful LDAP login for an **already-allowlisted** user: refresh
/// profile fields and stamp `last_login`. Deliberately does NOT create a record
/// for an unknown user — the allowlist is curated by the admin via the Integration
/// directory picker, so a login attempt by a non-selected account must never add
/// them to it. Returns `(exists, enabled, is_admin)`; an unknown user is
/// `(false, false, false)` and will be refused by the login gate.
pub fn record_login(username: &str, display_name: &str, email: &str) -> (bool, bool, bool) {
    let key = normalize_lookup_username(username);
    let mut cfg = CONFIG.lock().unwrap();
    match cfg.permissions.get_mut(&key) {
        Some(entry) => {
            if !display_name.is_empty() {
                entry.display_name = display_name.to_owned();
            }
            if !email.is_empty() {
                entry.email = email.to_owned();
            }
            entry.last_login = now_iso8601();
            let result = (true, entry.enabled, entry.is_admin);
            persist(&cfg);
            result
        }
        None => (false, false, false),
    }
}

/// Upsert an allowlist entry for a directory user and set its enabled flag (used
/// by the Integration directory picker). A brand-new entry is seeded with the
/// `default_targets`; `is_admin`, targets and per-user policy are left to the ACL
/// tab. Returns the resulting permission.
pub fn set_user_enabled(
    username: &str,
    enabled: bool,
    display_name: &str,
    email: &str,
) -> UserPermission {
    let key = normalize_lookup_username(username);
    let mut cfg = CONFIG.lock().unwrap();
    let defaults = cfg.default_targets.clone();
    let entry = cfg
        .permissions
        .entry(key)
        .or_insert_with(|| UserPermission {
            allowed_targets: defaults,
            ..UserPermission::default()
        });
    entry.enabled = enabled;
    if !display_name.is_empty() {
        entry.display_name = display_name.to_owned();
    }
    if !email.is_empty() {
        entry.email = email.to_owned();
    }
    let result = entry.clone();
    persist(&cfg);
    result
}

/// Whether clients must have a logged-in, enabled user to be used at all.
pub fn require_login() -> bool {
    CONFIG.lock().unwrap().require_login
}

/// Test-only override so handler tests can isolate the require-login gate from the
/// persisted integration config (mirrors `nemo_management::set_company_only_for_test`).
#[cfg(test)]
pub(crate) fn set_require_login_for_test(value: bool) {
    CONFIG.lock().unwrap().require_login = value;
}

/// The session policy configured for a user (empty if the user has none). When
/// the user has an assigned named policy that still exists, it wins; otherwise
/// the user's inline policy is used.
pub fn user_policy(username: &str) -> UserManagedPolicy {
    let key = normalize_lookup_username(username);
    let cfg = CONFIG.lock().unwrap();
    match cfg.permissions.get(&key) {
        Some(p) => {
            // Admins bypass every normal policy and get the single admin policy
            // (full access by default, adjustable by the operator). It is
            // delivered as *defaults only* (allow_user_override forced true):
            // an admin may flip any setting locally on the client they are
            // logged in to — e.g. test one-way file transfer — regardless of
            // how the stored admin policy is flagged.
            if p.is_admin {
                let mut ap = cfg.admin_policy.clone();
                ap.allow_user_override = true;
                return ap;
            }
            if let Some(name) = p.policy_name.as_deref().filter(|n| !n.is_empty()) {
                if let Some(named) = cfg.policies.get(name) {
                    return named.clone();
                }
            }
            // No policy of their own -> fall back to the admin's default policy
            // for newly-allowed users, if one is set and still exists.
            if p.policy.options.is_empty() {
                if let Some(dn) = cfg.default_policy_name.as_deref().filter(|n| !n.is_empty()) {
                    if let Some(named) = cfg.policies.get(dn) {
                        return named.clone();
                    }
                }
            }
            p.policy.clone()
        }
        None => UserManagedPolicy::default(),
    }
}

/// The admin's default policy name for users without their own policy.
pub fn default_policy_name() -> Option<String> {
    CONFIG.lock().unwrap().default_policy_name.clone()
}

/// The policy applied to all admin users.
pub fn admin_policy() -> UserManagedPolicy {
    CONFIG.lock().unwrap().admin_policy.clone()
}

// --- Provisioned device keys -------------------------------------------------

// URL-safe id for a device key (base64 can contain '/' '+' '=' which break the
// :id route). L-fix: a bare 16-char prefix could collide between two different
// keys and silently REPLACE the previously pinned one — extend the prefix until
// it is unique among the existing keys (extremely unlikely to go past 16 chars,
// but a collision must never unpin someone else's key).
pub(crate) fn device_key_id_for(public_key: &str, existing: &[DeviceKey]) -> String {
    let alnum: String = public_key.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    // B2: an all-symbol / empty public key yields an empty alnum; `.max(1)` would then
    // slice &alnum[..1] and panic. Return empty rather than panic (the only caller
    // supplies a real base64 Ed25519 key, but keep this total for any future path).
    if alnum.is_empty() {
        return String::new();
    }
    let mut len = 16.min(alnum.len()).max(1);
    loop {
        let candidate = &alnum[..len];
        let collides = existing
            .iter()
            .any(|k| k.id == candidate && k.public_key != public_key);
        if !collides || len >= alnum.len() {
            return candidate.to_owned();
        }
        len = (len + 4).min(alnum.len());
    }
}

pub fn add_device_key(
    label: String,
    public_key: String,
    created_at: String,
    peer_id: String,
) -> DeviceKey {
    let mut cfg = CONFIG.lock().unwrap();
    let id = device_key_id_for(&public_key, &cfg.device_keys);
    let dk = DeviceKey {
        id: id.clone(),
        label,
        public_key: public_key.clone(),
        created_at,
        peer_id: peer_id.trim().to_owned(),
    };
    // Re-adding the SAME public key replaces its entry (label/binding update);
    // a different key never displaces an existing one (ids are unique by now).
    cfg.device_keys
        .retain(|k| k.public_key != public_key && k.id != id);
    cfg.device_keys.push(dk.clone());
    persist(&cfg);
    dk
}
pub fn list_device_keys() -> Vec<DeviceKey> {
    CONFIG.lock().unwrap().device_keys.clone()
}
pub fn remove_device_key(id: &str) -> bool {
    let mut cfg = CONFIG.lock().unwrap();
    let before = cfg.device_keys.len();
    cfg.device_keys.retain(|k| k.id != id);
    let removed = cfg.device_keys.len() != before;
    if removed {
        persist(&cfg);
    }
    removed
}
pub fn is_device_key_pinned(public_key: &str) -> bool {
    let pk = public_key.trim();
    !pk.is_empty()
        && CONFIG
            .lock()
            .unwrap()
            .device_keys
            .iter()
            .any(|k| k.public_key == pk)
}
/// Test-only: pin/unpin a device key directly in the in-memory config, without
/// touching the on-disk nemo_integration.json (tests must not write to the repo).
#[cfg(test)]
pub(crate) fn pin_device_key_for_test(dk: DeviceKey) {
    CONFIG.lock().unwrap().device_keys.push(dk);
}
#[cfg(test)]
pub(crate) fn unpin_device_key_for_test(public_key: &str) {
    CONFIG
        .lock()
        .unwrap()
        .device_keys
        .retain(|k| k.public_key != public_key);
}

/// M1: the peer id a pinned key is bound to. None = key not pinned at all;
/// Some("") = pinned but unbound (legacy key, authenticates any id).
pub fn device_key_binding(public_key: &str) -> Option<String> {
    let pk = public_key.trim();
    if pk.is_empty() {
        return None;
    }
    CONFIG
        .lock()
        .unwrap()
        .device_keys
        .iter()
        .find(|k| k.public_key == pk)
        .map(|k| k.peer_id.clone())
}
pub fn require_device_key() -> bool {
    CONFIG.lock().unwrap().require_device_key
}
pub fn set_require_device_key(v: bool) {
    let mut cfg = CONFIG.lock().unwrap();
    cfg.require_device_key = v;
    persist(&cfg);
}
/// H4: strip secret policy values from responses that cannot be sealed.
pub fn strip_unsealed_secrets() -> bool {
    CONFIG.lock().unwrap().strip_unsealed_secrets
}
pub fn set_strip_unsealed_secrets(v: bool) {
    let mut cfg = CONFIG.lock().unwrap();
    cfg.strip_unsealed_secrets = v;
    persist(&cfg);
}

/// The named policy assigned to a device (peer id), if any and it still exists.
/// Applied to that peer's incoming sessions when no user is logged in.
pub fn device_policy(peer_id: &str) -> Option<UserManagedPolicy> {
    let cfg = CONFIG.lock().unwrap();
    cfg.device_policies
        .get(peer_id)
        .and_then(|name| cfg.policies.get(name).cloned())
}

/// All named policies (name -> policy), for the dashboard editor.
pub fn list_policies() -> HashMap<String, UserManagedPolicy> {
    CONFIG.lock().unwrap().policies.clone()
}

/// Current device -> named-policy assignments, for the dashboard.
pub fn list_device_policies() -> HashMap<String, String> {
    CONFIG.lock().unwrap().device_policies.clone()
}

/// Replace the named-policy definitions (full replace, like permissions). Device
/// assignments pointing at a now-deleted policy are pruned; a user's dangling
/// `policy_name` simply falls back to its inline policy at resolve time.
pub fn set_policies(policies: HashMap<String, UserManagedPolicy>) {
    let mut cfg = CONFIG.lock().unwrap();
    cfg.policies = policies;
    let names: std::collections::HashSet<String> = cfg.policies.keys().cloned().collect();
    cfg.device_policies.retain(|_, name| names.contains(name.as_str()));
    persist(&cfg);
}

/// Set or clear a single device -> named-policy assignment. An empty/None name,
/// or a name that does not exist, clears the assignment for that peer.
pub fn set_device_policy(peer_id: &str, policy_name: Option<&str>) {
    if peer_id.is_empty() {
        return;
    }
    let mut cfg = CONFIG.lock().unwrap();
    match policy_name.map(str::trim).filter(|n| !n.is_empty()) {
        Some(name) if cfg.policies.contains_key(name) => {
            cfg.device_policies.insert(peer_id.to_owned(), name.to_owned());
        }
        _ => {
            cfg.device_policies.remove(peer_id);
        }
    }
    persist(&cfg);
}

/// Whether a user is on the allowlist (enabled to use the software).
pub fn user_is_enabled(username: &str) -> bool {
    let key = normalize_lookup_username(username);
    CONFIG
        .lock()
        .unwrap()
        .permissions
        .get(&key)
        .map(|p| p.enabled)
        .unwrap_or(false)
}

/// Whether a user (with the given effective permissions) may see/connect to a
/// target peer id.
pub fn user_allowed_target(is_admin: bool, allowed_targets: &[String], target_id: &str) -> bool {
    if is_admin {
        return true;
    }
    allowed_targets
        .iter()
        .any(|t| t == "*" || t == target_id)
}

// --------------------------------------------------------------------------
// Session tokens
// --------------------------------------------------------------------------

// A session binds a token only to the authenticated identity. Authorization
// (is_admin, allowed_targets) is NOT frozen here — it is re-resolved from live
// config on every request via `effective_permission`, so an admin narrowing a
// user's targets or demoting them takes effect immediately, and a deleted user
// loses access at once (rather than lingering for the token TTL).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    pub username: String,
    pub display_name: String,
    pub email: String,
    pub expires_at: u64,
}

// Sessions are PERSISTED (not just in-memory) so a server restart — e.g. rebooting
// a box that runs both hbbs and a controlled host — does NOT log every user out and
// invalidate their tokens mid-work. Loaded (and pruned) at startup, rewritten on
// create/remove/expiry.
static SESSIONS: Lazy<Mutex<HashMap<String, Session>>> =
    Lazy::new(|| Mutex::new(load_sessions()));

fn sessions_path() -> PathBuf {
    let arg = get_arg("nemo-sessions-file");
    if arg.is_empty() {
        PathBuf::from("nemo_sessions.json")
    } else {
        PathBuf::from(arg)
    }
}

fn load_sessions() -> HashMap<String, Session> {
    let mut sessions: HashMap<String, Session> = std::fs::read_to_string(sessions_path())
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default();
    prune_sessions(&mut sessions);
    sessions
}

fn persist_sessions(sessions: &HashMap<String, Session>) {
    if let Ok(text) = serde_json::to_string(sessions) {
        let path = sessions_path();
        if let Err(err) = std::fs::write(&path, text) {
            log::error!("failed to persist Nemo sessions to {}: {}", path.display(), err);
        } else {
            // M3: live bearer tokens — keep them readable only by the service account.
            restrict_file(&path);
        }
    }
}

pub fn create_session(username: String, display_name: String, email: String) -> String {
    let token = uuid::Uuid::new_v4().simple().to_string();
    let session = Session {
        username,
        display_name,
        email,
        expires_at: now_secs() + SESSION_TTL_SECS,
    };
    let mut sessions = SESSIONS.lock().unwrap();
    prune_sessions(&mut sessions);
    sessions.insert(token.clone(), session);
    persist_sessions(&sessions);
    token
}

/// Resolve the CURRENT effective permissions for a username from live config.
/// Returns (is_admin, allowed_targets). An unknown user (e.g. removed after
/// login) gets no access.
pub fn effective_permission(username: &str) -> (bool, Vec<String>) {
    let key = normalize_lookup_username(username);
    let cfg = CONFIG.lock().unwrap();
    match cfg.permissions.get(&key) {
        Some(p) => (p.is_admin, p.allowed_targets.clone()),
        None => (false, Vec::new()),
    }
}

/// Look up a live session by bearer token, dropping it if expired.
pub fn session_for_token(token: &str) -> Option<Session> {
    let token = token.trim();
    if token.is_empty() {
        return None;
    }
    let mut sessions = SESSIONS.lock().unwrap();
    let now = now_secs();
    match sessions.get(token) {
        Some(s) if s.expires_at > now => Some(s.clone()),
        Some(_) => {
            sessions.remove(token);
            persist_sessions(&sessions);
            None
        }
        None => None,
    }
}

pub fn remove_session(token: &str) {
    let mut sessions = SESSIONS.lock().unwrap();
    if sessions.remove(token.trim()).is_some() {
        persist_sessions(&sessions);
    }
}

fn prune_sessions(sessions: &mut HashMap<String, Session>) {
    let now = now_secs();
    sessions.retain(|_, s| s.expires_at > now);
}

// --------------------------------------------------------------------------
// Login brute-force backoff (per canonical username)
// --------------------------------------------------------------------------
//
// Rather than a hard lockout (which lets an attacker deny a real user by
// guessing their name), we impose an exponentially growing delay on *failed*
// logins for a username. A correct password succeeds instantly and clears the
// counter, so legitimate users are never blocked, while online guessing slows to
// a crawl.

const LOGIN_FAILURE_WINDOW_SECS: u64 = 900;
const LOGIN_BACKOFF_BASE_MS: u64 = 250;
const LOGIN_BACKOFF_MAX_MS: u64 = 30_000;

// username -> (consecutive failures, last failure epoch secs)
static LOGIN_FAILURES: Lazy<Mutex<HashMap<String, (u32, u64)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Record a failed login for `username`, returning the number of consecutive
/// failures within the window (used to compute the backoff).
pub fn note_login_failure(username: &str) -> u32 {
    let key = normalize_lookup_username(username);
    let now = now_secs();
    let mut map = LOGIN_FAILURES.lock().unwrap();
    map.retain(|_, (_, last)| now.saturating_sub(*last) < LOGIN_FAILURE_WINDOW_SECS);
    let entry = map.entry(key).or_insert((0, now));
    if now.saturating_sub(entry.1) >= LOGIN_FAILURE_WINDOW_SECS {
        *entry = (0, now);
    }
    entry.0 = entry.0.saturating_add(1);
    entry.1 = now;
    entry.0
}

/// Clear the failure counter for `username` after a successful login.
pub fn clear_login_failures(username: &str) {
    LOGIN_FAILURES
        .lock()
        .unwrap()
        .remove(&normalize_lookup_username(username));
}

/// Delay to apply before returning a failed login, given the consecutive
/// failure count: `250ms * 2^(n-1)`, capped at 30s.
pub fn login_backoff_ms(failures: u32) -> u64 {
    if failures == 0 {
        return 0;
    }
    let exp = (failures - 1).min(12); // cap so the shift never overflows
    LOGIN_BACKOFF_BASE_MS
        .saturating_mul(1u64 << exp)
        .min(LOGIN_BACKOFF_MAX_MS)
}

// --------------------------------------------------------------------------
// Pure helpers (LDAP filter / principal / username canonicalisation)
// --------------------------------------------------------------------------

/// Strip `DOMAIN\` prefix or `@domain` suffix, returning the bare account name.
pub fn raw_username(input: &str) -> String {
    let input = input.trim();
    if let Some((_, rest)) = input.split_once('\\') {
        return rest.to_owned();
    }
    if let Some((head, _)) = input.split_once('@') {
        return head.to_owned();
    }
    input.to_owned()
}

/// Canonical, case-folded key used for RBAC lookups and session identity.
pub fn normalize_lookup_username(input: &str) -> String {
    raw_username(input).to_lowercase()
}

/// Build the bind principal for direct (no service account) binds. AD accepts
/// `user@domain` (UPN); if no domain is configured, fall back to the raw input.
pub fn auth_principal(username: &str, domain: &str) -> String {
    let username = username.trim();
    if username.contains('@') || username.contains('\\') {
        return username.to_owned();
    }
    let domain = domain.trim();
    if domain.is_empty() {
        username.to_owned()
    } else {
        format!("{}@{}", username, domain)
    }
}

/// Substitute the `{username}`, `{raw_username}`, and `{upn}` placeholders in the
/// configured filter template, escaping each value for safe use in a filter.
pub fn build_search_filter(template: &str, username: &str, domain: &str) -> String {
    let raw = raw_username(username);
    let upn = if domain.trim().is_empty() {
        raw.clone()
    } else {
        format!("{}@{}", raw, domain.trim())
    };
    template
        .replace("{username}", &escape_filter(username.trim()))
        .replace("{raw_username}", &escape_filter(&raw))
        .replace("{upn}", &escape_filter(&upn))
}

/// Escape the LDAP filter special characters per RFC 4515.
fn escape_filter(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '\\' => out.push_str("\\5c"),
            '*' => out.push_str("\\2a"),
            '(' => out.push_str("\\28"),
            ')' => out.push_str("\\29"),
            '\0' => out.push_str("\\00"),
            '/' => out.push_str("\\2f"),
            _ => out.push(ch),
        }
    }
    out
}

fn first_attr(attrs: &HashMap<String, Vec<String>>, key: &str) -> String {
    attrs
        .get(key)
        .and_then(|v| v.first())
        .map(|s| s.trim().to_owned())
        .unwrap_or_default()
}

/// Prefer sAMAccountName, then userPrincipalName, then the raw input, for the
/// canonical username used everywhere else.
pub fn canonical_username(attrs: &HashMap<String, Vec<String>>, raw_input: &str) -> String {
    let sam = first_attr(attrs, "sAMAccountName");
    let upn = first_attr(attrs, "userPrincipalName");
    let chosen = if !sam.is_empty() {
        sam
    } else if !upn.is_empty() {
        upn
    } else {
        raw_input.to_owned()
    };
    normalize_lookup_username(&chosen)
}

// --------------------------------------------------------------------------
// Time helpers
// --------------------------------------------------------------------------

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

fn now_iso8601() -> String {
    // Cheap RFC3339-ish stamp without pulling chrono into this module's surface.
    let secs = now_secs();
    format!("{}", secs) // epoch seconds; the dashboard renders it as "last seen"
}

// --------------------------------------------------------------------------
// Certificate helpers (pin / fetch the directory's TLS certificate)
// --------------------------------------------------------------------------

/// Parse the first CERTIFICATE block out of a PEM blob into DER bytes.
fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let start = pem.find(BEGIN)? + BEGIN.len();
    let rest = &pem[start..];
    let end = rest.find(END)?;
    let b64: String = rest[..end].split_whitespace().collect();
    base64::decode(b64).ok()
}

fn der_to_pem(der: &[u8]) -> String {
    let b64 = base64::encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

fn cert_fingerprint(der: &[u8]) -> String {
    let digest = sodiumoxide::crypto::hash::sha256::hash(der);
    digest
        .0
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// SHA-256 fingerprint of the first cert in a PEM blob (empty if none/invalid).
pub fn pem_fingerprint(pem: &str) -> String {
    match pem_to_der(pem) {
        Some(der) => cert_fingerprint(&der),
        None => String::new(),
    }
}

/// Human-readable summary of an X.509 certificate.
#[derive(Clone, Debug, Serialize, Default)]
pub struct CertSummary {
    pub subject: String,
    pub issuer: String,
    pub sans: Vec<String>,
    pub not_before: String,
    pub not_after: String,
    pub self_signed: bool,
    pub fingerprint: String,
}

#[cfg(feature = "nemo-ldap")]
fn fmt_ip(b: &[u8]) -> String {
    match b.len() {
        4 => format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]),
        16 => (0..16)
            .step_by(2)
            .map(|i| format!("{:02x}{:02x}", b[i], b[i + 1]))
            .collect::<Vec<_>>()
            .join(":"),
        _ => String::new(),
    }
}

/// Parse a DER certificate into a display summary (subject / issuer / SAN
/// domains / validity). Returns None if the parser is not compiled in or the
/// certificate cannot be parsed.
#[cfg(feature = "nemo-ldap")]
fn parse_cert_der(der: &[u8]) -> Option<CertSummary> {
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let mut sans = Vec::new();
    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for gn in &san.general_names {
                match gn {
                    GeneralName::DNSName(d) => sans.push(d.to_string()),
                    GeneralName::IPAddress(ip) => sans.push(fmt_ip(ip)),
                    _ => {}
                }
            }
        }
    }
    Some(CertSummary {
        self_signed: subject == issuer,
        subject,
        issuer,
        sans,
        not_before: cert.validity().not_before.to_string(),
        not_after: cert.validity().not_after.to_string(),
        fingerprint: cert_fingerprint(der),
    })
}

#[cfg(not(feature = "nemo-ldap"))]
fn parse_cert_der(_der: &[u8]) -> Option<CertSummary> {
    None
}

/// Subject + SAN domains of the first cert in a PEM blob (for config views).
pub fn pem_cert_summary(pem: &str) -> (String, Vec<String>) {
    match pem_to_der(pem).and_then(|der| parse_cert_der(&der)) {
        Some(s) => (s.subject, s.sans),
        None => (String::new(), Vec::new()),
    }
}

/// Full X.509 summary (subject/issuer/SANs/validity/SHA-256 fingerprint) of the
/// first certificate in a PEM blob, for the client-facing TLS info view. Returns
/// None when the PEM cannot be parsed or the x509 parser is not compiled in.
pub fn pem_cert_full_summary(pem: &str) -> Option<CertSummary> {
    pem_to_der(pem).and_then(|der| parse_cert_der(&der))
}

/// Split `ldaps://host:port` (or `ldap://…`) into (host, port).
fn ldap_host_port(url: &str) -> Result<(String, u16), String> {
    let u = url.trim();
    let (default_port, rest) = if let Some(r) = u.strip_prefix("ldaps://") {
        (636u16, r)
    } else if let Some(r) = u.strip_prefix("ldap://") {
        (389u16, r)
    } else {
        return Err("URL must start with ldaps:// or ldap://".to_owned());
    };
    let hostport = rest.split('/').next().unwrap_or(rest);
    match hostport.rsplit_once(':') {
        Some((h, p)) => {
            let port = p.parse::<u16>().map_err(|_| "invalid port".to_owned())?;
            Ok((h.to_owned(), port))
        }
        None => Ok((hostport.to_owned(), default_port)),
    }
}

/// Connect to the directory's TLS port (accepting any cert) and return its
/// certificate as PEM plus the SHA-256 fingerprint, so an admin can review and
/// pin it. Blocking — call from a blocking context.
#[cfg(feature = "nemo-ldap")]
pub fn fetch_server_cert(server_url: &str) -> Result<(String, CertSummary), String> {
    let (host, port) = ldap_host_port(server_url)?;
    let connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .map_err(|e| format!("TLS setup failed: {}", e))?;
    let tcp = std::net::TcpStream::connect((host.as_str(), port))
        .map_err(|e| format!("connect failed: {}", e))?;
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(8))).ok();
    tcp.set_write_timeout(Some(std::time::Duration::from_secs(8))).ok();
    let stream = connector
        .connect(&host, tcp)
        .map_err(|e| format!("TLS handshake failed: {}", e))?;
    let cert = stream
        .peer_certificate()
        .map_err(|e| format!("could not read certificate: {}", e))?
        .ok_or_else(|| "server presented no certificate".to_owned())?;
    let der = cert
        .to_der()
        .map_err(|e| format!("certificate encode failed: {}", e))?;
    let summary = parse_cert_der(&der).unwrap_or(CertSummary {
        fingerprint: cert_fingerprint(&der),
        ..Default::default()
    });
    Ok((der_to_pem(&der), summary))
}

#[cfg(not(feature = "nemo-ldap"))]
pub fn fetch_server_cert(_server_url: &str) -> Result<(String, CertSummary), String> {
    Err("LDAP support was not compiled in".to_owned())
}

// --------------------------------------------------------------------------
// LDAP authentication
// --------------------------------------------------------------------------

/// The identity resolved from a successful LDAP authentication.
#[derive(Clone, Debug)]
pub struct LdapUser {
    pub username: String,
    pub display_name: String,
    pub email: String,
    /// Retained for audit/troubleshooting; not surfaced to clients.
    #[allow(dead_code)]
    pub dn: String,
}

/// S-C: whether the operator explicitly allowed running LDAP with certificate
/// verification off. Without this loud, non-default flag, `tls_verify=false`
/// FAILS CLOSED instead of silently accepting any DC cert (a MITM on the DC leg
/// would otherwise harvest every domain login).
#[cfg(feature = "nemo-ldap")]
fn insecure_ldap_allowed() -> bool {
    crate::nemo_management::is_truthy(&get_arg("insecure-ldap-i-accept-mitm"))
}

/// S-C: resolve the effective verification posture. verify-on always passes;
/// verify-off only with the explicit override flag, otherwise an error that
/// tells the operator the two safe options (pin the DC cert, or the loud flag).
pub(crate) fn ldap_tls_verify_effective(
    tls_verify: bool,
    insecure_allowed: bool,
) -> Result<bool, String> {
    if tls_verify {
        Ok(true)
    } else if insecure_allowed {
        Ok(false)
    } else {
        Err("LDAP tls_verify is disabled, but accepting any DC certificate is refused. \
             Pin the DC certificate (ca_cert) and re-enable verification, or start the \
             server with --insecure-ldap-i-accept-mitm Y to explicitly accept the risk."
            .to_owned())
    }
}

/// Build the TLS connector for LDAPS: trust a pinned cert if provided (verify
/// against exactly that certificate — safe for a self-signed DC), or accept any
/// certificate when verification is explicitly disabled. Shared by the login and
/// directory-search paths so both honour the same pinning/verification posture.
#[cfg(feature = "nemo-ldap")]
fn build_ldap_connector(cfg: &LdapConfig) -> Result<native_tls::TlsConnector, String> {
    let mut builder = native_tls::TlsConnector::builder();
    if !ldap_tls_verify_effective(cfg.tls_verify, insecure_ldap_allowed())? {
        log::warn!(
            "LDAP certificate verification is DISABLED via --insecure-ldap-i-accept-mitm; \
             the DC connection is open to man-in-the-middle credential harvesting"
        );
        builder.danger_accept_invalid_certs(true);
        builder.danger_accept_invalid_hostnames(true);
    }
    let ca = cfg.ca_cert.trim();
    if !ca.is_empty() {
        let cert = native_tls::Certificate::from_pem(ca.as_bytes())
            .map_err(|e| format!("pinned certificate is invalid: {}", e))?;
        builder.add_root_certificate(cert);
    }
    builder
        .build()
        .map_err(|e| format!("TLS setup failed: {}", e))
}

/// A directory user returned by the Integration picker's search.
#[derive(Clone, Debug, Serialize)]
pub struct DirectoryUser {
    /// Canonical (case-folded) username used as the RBAC/allowlist key.
    pub username: String,
    pub display_name: String,
    pub email: String,
    /// AD "category" fields, shown in the picker so a role search (e.g.
    /// "techniker") makes clear why each user matched.
    pub department: String,
    pub title: String,
}

/// Search the directory for users matching `query` (empty = list users), using
/// the configured service account. Returns up to `limit` results. Requires a
/// service `bind_dn`/`bind_password` — a directory listing cannot be done with a
/// per-user direct bind. Used by the Integration "select LDAP users" picker.
#[cfg(feature = "nemo-ldap")]
pub async fn search_ldap_users(
    cfg: &LdapConfig,
    query: &str,
    limit: usize,
) -> Result<Vec<DirectoryUser>, String> {
    use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};

    if !cfg.enabled {
        return Err("LDAP integration is disabled".to_owned());
    }
    let url = cfg.server_url.trim();
    if url.is_empty() {
        return Err("LDAP server URL is not configured".to_owned());
    }
    if !url.to_ascii_lowercase().starts_with("ldaps://") {
        return Err("LDAP must use ldaps:// (LDAP over TLS, port 636).".to_owned());
    }
    if cfg.bind_dn.trim().is_empty() {
        return Err(
            "Browsing the directory needs a read-only service account. Set a Bind DN + \
             password in the LDAP settings above, Save, then search."
                .to_owned(),
        );
    }
    let base = cfg.base_dn.trim();
    if base.is_empty() {
        return Err("base DN is not configured".to_owned());
    }

    let connector = build_ldap_connector(cfg)?;
    let settings = LdapConnSettings::new().set_connector(connector);
    let (conn, mut ldap) = LdapConnAsync::with_settings(settings, cfg.server_url.trim())
        .await
        .map_err(|e| format!("connect failed: {}", e))?;
    ldap3::drive!(conn);
    ldap.simple_bind(cfg.bind_dn.trim(), &cfg.bind_password)
        .await
        .map_err(|e| format!("service bind failed: {}", e))?
        .success()
        .map_err(|e| format!("service bind rejected: {}", e))?;

    let filter = directory_search_filter(query);
    let attr_list = vec![
        "sAMAccountName",
        "userPrincipalName",
        "displayName",
        "mail",
        "department",
        "title",
    ];
    let search = ldap
        .search(base, Scope::Subtree, &filter, attr_list)
        .await
        .map_err(|e| format!("directory search failed: {}", e))?
        .success();
    let _ = ldap.unbind().await;
    let (entries, _res) = search.map_err(|e| format!("directory search rejected: {}", e))?;

    let mut users: Vec<DirectoryUser> = Vec::new();
    for entry in entries.into_iter() {
        let se = SearchEntry::construct(entry);
        let username = canonical_username(&se.attrs, "");
        if username.is_empty() {
            continue;
        }
        users.push(DirectoryUser {
            username,
            display_name: first_attr(&se.attrs, "displayName"),
            email: first_attr(&se.attrs, "mail"),
            department: first_attr(&se.attrs, "department"),
            title: first_attr(&se.attrs, "title"),
        });
    }
    users.sort_by(|a, b| a.username.cmp(&b.username));
    users.dedup_by(|a, b| a.username == b.username);
    users.truncate(limit);
    Ok(users)
}

/// LDAP filter metacharacters escaped in a directory query value, but `*` is
/// PRESERVED so the user can type wildcard patterns (regex-lite): `tech*`,
/// `*iker`, `a*b`. Everything else that could break out of the assertion is
/// still escaped, so the query cannot inject filter structure.
#[cfg(feature = "nemo-ldap")]
fn escape_filter_keep_wildcard(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '\\' => out.push_str("\\5c"),
            '(' => out.push_str("\\28"),
            ')' => out.push_str("\\29"),
            '\0' => out.push_str("\\00"),
            '/' => out.push_str("\\2f"),
            '*' => out.push('*'), // keep as an LDAP wildcard
            _ => out.push(ch),
        }
    }
    out
}

/// Attributes the directory picker matches a query against: identity + contact,
/// plus the AD "category" fields (department/title/description/office/company)
/// and group membership — so typing a role like "techniker" finds everyone whose
/// department, title, description, or group contains it.
#[cfg(feature = "nemo-ldap")]
const DIRECTORY_SEARCH_ATTRS: &[&str] = &[
    "sAMAccountName",
    "userPrincipalName",
    "displayName",
    "cn",
    "givenName",
    "sn",
    "mail",
    "department",
    "title",
    "description",
    "physicalDeliveryOfficeName",
    "company",
    "memberOf",
];

/// Baseline: normal, enabled human accounts only. Excludes disabled accounts
/// (userAccountControl ACCOUNTDISABLE bit), built-in/critical system objects
/// (krbtgt, Guest, system trust accounts…), and machine/trust accounts
/// (sAMAccountName ending in `$`). AD-specific, matching the target directory.
#[cfg(feature = "nemo-ldap")]
const DIRECTORY_BASELINE: &str = "(objectCategory=person)(objectClass=user)\
    (!(userAccountControl:1.2.840.113556.1.4.803:=2))\
    (!(isCriticalSystemObject=TRUE))(!(sAMAccountName=*$))";

/// Build a directory search filter. The baseline restricts to normal enabled
/// users. Each whitespace-separated term in `query` must match (AND) somewhere
/// across [`DIRECTORY_SEARCH_ATTRS`] (OR); a term keeps any `*` the user typed
/// (wildcard), otherwise it is substring-matched. Empty query = list all.
#[cfg(feature = "nemo-ldap")]
fn directory_search_filter(query: &str) -> String {
    let q = query.trim();
    if q.is_empty() {
        return format!("(&{})", DIRECTORY_BASELINE);
    }
    let mut terms = String::new();
    for term in q.split_whitespace() {
        let e = escape_filter_keep_wildcard(term);
        let pat = if term.contains('*') { e } else { format!("*{}*", e) };
        terms.push_str("(|");
        for attr in DIRECTORY_SEARCH_ATTRS {
            terms.push_str(&format!("({}={})", attr, pat));
        }
        terms.push(')');
    }
    format!("(&{}{})", DIRECTORY_BASELINE, terms)
}

/// Stub when the `nemo-ldap` feature is disabled at build time.
#[cfg(not(feature = "nemo-ldap"))]
pub async fn search_ldap_users(
    _cfg: &LdapConfig,
    _query: &str,
    _limit: usize,
) -> Result<Vec<DirectoryUser>, String> {
    Err("LDAP support was not compiled in (build with --features nemo-ldap)".to_owned())
}

/// Authenticate `username`/`password` against the configured directory.
/// Returns `Ok(LdapUser)` on success, `Err(reason)` otherwise.
#[cfg(feature = "nemo-ldap")]
pub async fn authenticate_ldap(
    cfg: &LdapConfig,
    username: &str,
    password: &str,
) -> Result<LdapUser, String> {
    use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};

    if username.is_empty() || password.is_empty() {
        return Err("username and password are required".to_owned());
    }
    if !cfg.enabled {
        return Err("LDAP integration is disabled".to_owned());
    }
    let url = cfg.server_url.trim();
    if url.is_empty() {
        return Err("LDAP server URL is not configured".to_owned());
    }
    // Require LDAP-over-TLS. A plaintext ldap:// bind would send the user's
    // domain password across the network in the clear and is trivially MITM'd.
    // AD exposes LDAPS on port 636.
    if !url.to_ascii_lowercase().starts_with("ldaps://") {
        return Err(
            "LDAP must use ldaps:// (LDAP over TLS, port 636). Plaintext ldap:// is refused \
             because it would expose the domain password on the network."
                .to_owned(),
        );
    }
    if !cfg.tls_verify {
        log::warn!(
            "Nemo LDAP: TLS certificate verification is DISABLED for {}. An on-path attacker \
             could impersonate the directory and authenticate as any user. Enable verification \
             once the DC's CA is trusted.",
            url
        );
    }

    // Build the TLS connector (pinned-cert / verification posture is shared with
    // the directory-search path).
    let connector = build_ldap_connector(cfg)?;
    let make_settings = || LdapConnSettings::new().set_connector(connector.clone());

    let mut dn = String::new();
    let mut attrs: HashMap<String, Vec<String>> = HashMap::new();
    let attr_list = vec![
        "distinguishedName",
        "sAMAccountName",
        "userPrincipalName",
        "displayName",
        "mail",
    ];

    if !cfg.bind_dn.trim().is_empty() {
        // Service-account bind, then search for the user, then bind as the user.
        let (conn, mut ldap) =
            LdapConnAsync::with_settings(make_settings(), cfg.server_url.trim())
                .await
                .map_err(|e| format!("connect failed: {}", e))?;
        ldap3::drive!(conn);
        ldap.simple_bind(cfg.bind_dn.trim(), &cfg.bind_password)
            .await
            .map_err(|e| format!("service bind failed: {}", e))?
            .success()
            .map_err(|e| format!("service bind rejected: {}", e))?;

        let filter = build_search_filter(&cfg.user_search_filter, username, &cfg.windows_domain);
        let base = cfg.base_dn.trim();
        if base.is_empty() {
            let _ = ldap.unbind().await;
            return Err("base DN is not configured".to_owned());
        }
        let (entries, _res) = ldap
            .search(base, Scope::Subtree, &filter, attr_list.clone())
            .await
            .map_err(|e| format!("user search failed: {}", e))?
            .success()
            .map_err(|e| format!("user search rejected: {}", e))?;
        let _ = ldap.unbind().await;

        let entry = entries.into_iter().next().ok_or_else(|| {
            // L-fix (user enumeration): an unknown username must be indistinguishable
            // from a wrong password in the client-visible error. Detail stays in the
            // server log for the operator.
            log::warn!("LDAP login: user '{}' not found in directory", username);
            "invalid username or password".to_owned()
        })?;
        let se = SearchEntry::construct(entry);
        dn = se.dn.clone();
        attrs = se.attrs;
        if dn.is_empty() {
            return Err("user record has no distinguished name".to_owned());
        }

        // Verify the password by binding as the discovered DN.
        let (uconn, mut uldap) =
            LdapConnAsync::with_settings(make_settings(), cfg.server_url.trim())
                .await
                .map_err(|e| format!("connect failed: {}", e))?;
        ldap3::drive!(uconn);
        uldap
            .simple_bind(&dn, password)
            .await
            .map_err(|e| format!("authentication failed: {}", e))?
            .success()
            .map_err(|_| "invalid username or password".to_owned())?;
        let _ = uldap.unbind().await;
    } else {
        // Direct principal bind (no service account).
        let principal = auth_principal(username, &cfg.windows_domain);
        let (conn, mut ldap) =
            LdapConnAsync::with_settings(make_settings(), cfg.server_url.trim())
                .await
                .map_err(|e| format!("connect failed: {}", e))?;
        ldap3::drive!(conn);
        ldap.simple_bind(&principal, password)
            .await
            .map_err(|e| format!("authentication failed: {}", e))?
            .success()
            .map_err(|_| "invalid username or password".to_owned())?;

        // Best-effort self-search for profile attributes.
        let base = cfg.base_dn.trim();
        if !base.is_empty() {
            let filter =
                build_search_filter(&cfg.user_search_filter, username, &cfg.windows_domain);
            if let Ok(sr) = ldap
                .search(base, Scope::Subtree, &filter, attr_list.clone())
                .await
            {
                if let Ok((entries, _)) = sr.success() {
                    if let Some(entry) = entries.into_iter().next() {
                        let se = SearchEntry::construct(entry);
                        dn = se.dn.clone();
                        attrs = se.attrs;
                    }
                }
            }
        }
        let _ = ldap.unbind().await;
    }

    let canonical = canonical_username(&attrs, username);
    if canonical.is_empty() {
        return Err("could not determine canonical username".to_owned());
    }
    Ok(LdapUser {
        username: canonical,
        display_name: first_attr(&attrs, "displayName"),
        email: first_attr(&attrs, "mail"),
        dn,
    })
}

/// Stub used when the `nemo-ldap` feature is disabled at build time, so the rest
/// of the server compiles without the `ldap3` dependency.
#[cfg(not(feature = "nemo-ldap"))]
pub async fn authenticate_ldap(
    _cfg: &LdapConfig,
    _username: &str,
    _password: &str,
) -> Result<LdapUser, String> {
    Err("LDAP support was not compiled in (build with --features nemo-ldap)".to_owned())
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Named-policy resolution: an assigned named policy wins over a user's inline
    // policy and provides the device policy; a dangling name falls back to inline.
    // Mutates the process-global CONFIG directly (no disk write) with unique keys
    // and cleans them up, so it does not disturb other tests.
    #[test]
    fn named_policy_wins_for_user_and_device() {
        {
            let mut cfg = CONFIG.lock().unwrap();
            let mut opts = HashMap::new();
            opts.insert("view_only".to_owned(), "Y".to_owned());
            opts.insert("one-way-file-transfer".to_owned(), "Y".to_owned());
            cfg.policies.insert(
                "__test_pol".to_owned(),
                UserManagedPolicy { allow_user_override: false, options: opts },
            );
            let mut up = UserPermission::default();
            up.policy_name = Some("__test_pol".to_owned());
            // Inline differs, to prove the named policy is the one resolved.
            up.policy.options.insert("view_only".to_owned(), "N".to_owned());
            cfg.permissions.insert("__testuser".to_owned(), up);
            cfg.device_policies.insert("__testpeer".to_owned(), "__test_pol".to_owned());
        }
        // User: named policy wins over inline.
        let up = user_policy("__testuser");
        assert_eq!(up.options.get("view_only").map(String::as_str), Some("Y"));
        assert_eq!(up.options.get("one-way-file-transfer").map(String::as_str), Some("Y"));
        // Device: resolves the assigned named policy.
        let dp = device_policy("__testpeer").expect("device policy resolved");
        assert_eq!(dp.options.get("one-way-file-transfer").map(String::as_str), Some("Y"));
        // Dangling name falls back to the inline policy.
        CONFIG.lock().unwrap().policies.remove("__test_pol");
        let up2 = user_policy("__testuser");
        assert_eq!(up2.options.get("view_only").map(String::as_str), Some("N"));
        assert!(device_policy("__testpeer").is_none());
        // Cleanup.
        let mut cfg = CONFIG.lock().unwrap();
        cfg.permissions.remove("__testuser");
        cfg.device_policies.remove("__testpeer");
    }

    // An admin gets the admin policy as DEFAULTS ONLY: allow_user_override is
    // forced true on delivery so the admin can flip any setting locally on the
    // client, even when the stored admin policy is flagged non-overridable.
    #[test]
    fn admin_policy_is_delivered_user_overridable() {
        {
            let mut cfg = CONFIG.lock().unwrap();
            assert!(!cfg.admin_policy.allow_user_override, "precondition: stored admin policy is non-overridable");
            let mut up = UserPermission::default();
            up.is_admin = true;
            cfg.permissions.insert("__testadmin".to_owned(), up);
        }
        let ap = user_policy("__testadmin");
        assert!(ap.allow_user_override, "admin policy must be delivered with allow_user_override=true");
        // The stored config itself must stay untouched.
        let mut cfg = CONFIG.lock().unwrap();
        assert!(!cfg.admin_policy.allow_user_override);
        cfg.permissions.remove("__testadmin");
    }

    // L-fix: two different keys sharing a 16-char alphanumeric prefix must get
    // DISTINCT ids (the old scheme silently replaced the first pinned key).
    #[test]
    fn device_key_id_extends_prefix_on_collision() {
        let shared = "AAAABBBBCCCCDDDD"; // 16 alnum chars
        let key_a = format!("{}EEEE+rest/of/keyA==", shared);
        let key_b = format!("{}FFFF+rest/of/keyB==", shared);
        let id_a = device_key_id_for(&key_a, &[]);
        assert_eq!(id_a, shared);
        let existing = vec![DeviceKey {
            id: id_a.clone(),
            label: String::new(),
            public_key: key_a.clone(),
            created_at: String::new(),
            peer_id: String::new(),
        }];
        let id_b = device_key_id_for(&key_b, &existing);
        assert_ne!(id_b, id_a, "colliding prefix must not reuse the id");
        assert!(id_b.starts_with(shared));
        // Re-deriving for the SAME key keeps its id stable.
        assert_eq!(device_key_id_for(&key_a, &existing), id_a);
    }

    // S-C: tls_verify=false is refused unless the loud override flag is set.
    #[test]
    fn ldap_tls_verify_off_requires_explicit_override() {
        assert_eq!(ldap_tls_verify_effective(true, false), Ok(true));
        assert_eq!(ldap_tls_verify_effective(true, true), Ok(true));
        assert_eq!(ldap_tls_verify_effective(false, true), Ok(false));
        assert!(ldap_tls_verify_effective(false, false).is_err());
    }

    #[test]
    fn raw_username_strips_domain_decorations() {
        assert_eq!(raw_username("EXAMPLE\\jdoe"), "jdoe");
        assert_eq!(raw_username("jdoe@example.local"), "jdoe");
        assert_eq!(raw_username("  jdoe  "), "jdoe");
        assert_eq!(raw_username("jdoe"), "jdoe");
    }

    #[test]
    fn normalize_lookup_username_is_case_folded_and_bare() {
        assert_eq!(normalize_lookup_username("EXAMPLE\\JDoe"), "jdoe");
        assert_eq!(normalize_lookup_username("JDoe@Example.Local"), "jdoe");
    }

    #[test]
    fn auth_principal_builds_upn_when_bare() {
        assert_eq!(auth_principal("jdoe", "example.local"), "jdoe@example.local");
        // Already-qualified inputs are left untouched.
        assert_eq!(auth_principal("jdoe@example.local", "x"), "jdoe@example.local");
        assert_eq!(auth_principal("EXAMPLE\\jdoe", "x"), "EXAMPLE\\jdoe");
        // No domain configured => raw username.
        assert_eq!(auth_principal("jdoe", ""), "jdoe");
    }

    #[cfg(feature = "nemo-ldap")]
    #[test]
    fn directory_search_filter_categories_wildcards_and_baseline() {
        // Empty query = baseline only (normal, enabled users), no match clause.
        let all = directory_search_filter("");
        assert!(all.contains("(!(userAccountControl:1.2.840.113556.1.4.803:=2))")); // not disabled
        assert!(all.contains("(!(sAMAccountName=*$))")); // not machine/trust
        assert!(all.contains("(!(isCriticalSystemObject=TRUE))")); // not system
        assert!(!all.contains("(|")); // no per-term OR group when listing all

        // A role term also matches the AD "category" attributes + groups.
        let tech = directory_search_filter("techniker");
        assert!(tech.contains(DIRECTORY_BASELINE));
        assert!(tech.contains("(department=*techniker*)"));
        assert!(tech.contains("(title=*techniker*)"));
        assert!(tech.contains("(memberOf=*techniker*)"));

        // Whitespace-separated terms are AND-ed (each its own OR group).
        let two = directory_search_filter("tech wien");
        assert_eq!(two.matches("(|").count(), 2);

        // A user-typed wildcard is preserved verbatim (not re-wrapped).
        let star = directory_search_filter("tech*");
        assert!(star.contains("(title=tech*)"));
        assert!(!star.contains("*tech*"));

        // Injection can't break out: parens are escaped, not literal.
        let inj = directory_search_filter("a)(uid=x");
        assert!(!inj.contains("(uid=x)"));
        assert!(inj.contains("\\29\\28")); // ")(" → escaped
    }

    #[test]
    fn build_search_filter_substitutes_and_escapes() {
        let f = build_search_filter(DEFAULT_USER_SEARCH_FILTER, "jdoe", "example.local");
        assert!(f.contains("(sAMAccountName=jdoe)"));
        assert!(f.contains("(userPrincipalName=jdoe)")); // raw_username
        assert!(f.contains("(userPrincipalName=jdoe@example.local)")); // upn
    }

    #[test]
    fn build_search_filter_escapes_injection() {
        // A malicious username must not break out of the filter grouping.
        let f = build_search_filter("(sAMAccountName={username})", "a*)(uid=*", "d");
        assert!(!f.contains("*)("));
        assert!(f.contains("\\2a")); // escaped star
        assert!(f.contains("\\28")); // escaped open paren
        assert!(f.contains("\\29")); // escaped close paren
    }

    #[test]
    fn canonical_username_prefers_sam_then_upn() {
        let mut attrs = HashMap::new();
        attrs.insert("sAMAccountName".to_owned(), vec!["JDoe".to_owned()]);
        attrs.insert(
            "userPrincipalName".to_owned(),
            vec!["jdoe@example.local".to_owned()],
        );
        assert_eq!(canonical_username(&attrs, "whatever"), "jdoe");

        let mut upn_only = HashMap::new();
        upn_only.insert(
            "userPrincipalName".to_owned(),
            vec!["Jane@Example.Local".to_owned()],
        );
        assert_eq!(canonical_username(&upn_only, "x"), "jane");

        // No attributes => fall back to the raw input (canonicalised).
        assert_eq!(canonical_username(&HashMap::new(), "EXAMPLE\\Bob"), "bob");
    }

    #[test]
    fn user_allowed_target_respects_admin_and_wildcard() {
        assert!(user_allowed_target(true, &[], "any"));
        assert!(user_allowed_target(false, &["*".to_owned()], "any"));
        assert!(user_allowed_target(
            false,
            &["123".to_owned(), "456".to_owned()],
            "456"
        ));
        assert!(!user_allowed_target(false, &["123".to_owned()], "456"));
        assert!(!user_allowed_target(false, &[], "456"));
    }

    #[test]
    fn normalize_targets_trims_and_dedupes() {
        let out = normalize_targets(vec![
            " 1 ".to_owned(),
            "1".to_owned(),
            "".to_owned(),
            "2".to_owned(),
        ]);
        assert_eq!(out, vec!["1".to_owned(), "2".to_owned()]);
    }

    #[test]
    fn login_backoff_grows_and_caps() {
        assert_eq!(login_backoff_ms(0), 0);
        assert_eq!(login_backoff_ms(1), 250);
        assert_eq!(login_backoff_ms(2), 500);
        assert_eq!(login_backoff_ms(3), 1000);
        // Escalates but never exceeds the 30s cap, and never overflows.
        assert_eq!(login_backoff_ms(100), 30_000);
        assert!(login_backoff_ms(7) <= 30_000);
    }

    #[test]
    fn ldap_config_view_masks_password() {
        let cfg = LdapConfig {
            bind_password: "secret".to_owned(),
            ..LdapConfig::default()
        };
        let view = LdapConfigView::from(&cfg);
        assert!(view.bind_password_set);
        // The view has no field that could carry the plaintext.
        let json = serde_json::to_string(&view).unwrap();
        assert!(!json.contains("secret"));
    }
}
