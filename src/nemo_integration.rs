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
use std::collections::{HashMap, HashSet};
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

fn default_permissions_version() -> u64 {
    1
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
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
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
    /// Version number for concurrency control (H11/H20/H22).
    /// Incremented on every permissions update. Clients can use this to detect
    /// stale tabs and prevent overwriting concurrent changes.
    #[serde(default = "default_permissions_version")]
    pub permissions_version: u64,
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
    /// Layer 1: when true, a poll, address-book or login request that is not signed
    /// with a PINNED device key is refused; a client with just the server's public
    /// key is not a member of the fleet. ON by default — the device key is mandatory.
    /// `default_true` (not the type default) so a config file that OMITS the field is
    /// treated like a fresh install, while a file that stores an explicit `false`
    /// keeps it (Rollout: the operator's stored choice is the guard; an upgrade never
    /// flips it).
    #[serde(default = "default_true")]
    pub require_device_key: bool,
    /// H4 / Layer 1: when true, secret policy values (managed password etc.) are
    /// STRIPPED from any policy response that cannot be sealed to a verified device
    /// key, instead of being sent in plaintext authenticated only by id+uuid. ON by
    /// default for the same reason as `require_device_key`, with the same upgrade
    /// rule: an explicit stored `false` survives, an omitted field becomes `true`.
    #[serde(default = "default_true")]
    pub strip_unsealed_secrets: bool,
    /// S-B / N12: when true, an /api/login request that carries no sealed credential
    /// is rejected instead of being accepted with a readable password. ON by default
    /// (a config file without the field gets it on too); current clients have no
    /// plaintext path at all. An existing file that says false keeps false -- flip it
    /// in the dashboard once the fleet is updated.
    #[serde(default = "default_true")]
    pub require_sealed_login: bool,
    /// S-B: when true, the policy poll and the address-book request must arrive as a
    /// sealed request envelope; a plaintext body is rejected. Off by default for the
    /// same reason — an un-updated client is only locked out when the operator flips this.
    #[serde(default)]
    pub require_sealed_request: bool,
    /// M1-CLAIM: when true, a pinned key with NO peer-id binding may *request* a
    /// binding. The first client that PROVES the key (a valid signature over the id it
    /// claims) does not get in: it files a **pending claim** that the operator confirms
    /// or denies in the dashboard. Only that confirmation writes the binding, and from
    /// then on the key authenticates that id and nothing else.
    ///
    /// This is what makes provisioning workable at all: a client shows no TBFDesk id
    /// until it is past the provisioning gate, and it cannot pass the gate without a
    /// key, so the operator cannot know the id at the moment they generate the key.
    /// The pending claim closes that loop — the client reports the id, the operator
    /// approves it — without ever letting the client decide its own trust.
    ///
    /// ON by default. With it off, the old fail-closed rule stands (an unbound key
    /// authenticates nothing, and no claim is even filed) and every key has to be
    /// bound by hand.
    #[serde(default = "default_true")]
    pub claim_unbound_device_keys: bool,
    /// M1-CLAIM: binding requests awaiting the operator's confirmation. Persisted, so
    /// a request filed overnight is still on the dashboard in the morning and a
    /// restart does not forget a denial.
    #[serde(default)]
    pub pending_device_key_claims: Vec<PendingDeviceKeyClaim>,
}

/// M1-CLAIM: a client has proved a pinned-but-unbound key and asks for it to become
/// *its* key. It is NOT authenticated while this row exists — the row is the request,
/// not the grant.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct PendingDeviceKeyClaim {
    /// `DeviceKey::id`, so the dashboard can join the request to the key.
    pub key_id: String,
    pub public_key: String,
    /// The id the client claims. Proved, in the sense that the signature covers it —
    /// but a machine-derived id is self-reported, which is exactly why a human confirms.
    pub peer_id: String,
    pub first_seen: String,
    pub last_seen: String,
    /// How many times this client has asked (it re-asks on every poll while pending),
    /// so a silent flap is visible.
    pub attempts: u32,
    /// Which endpoint it came in on ("settings poll", "rendezvous handshake").
    pub via: String,
    /// Denied by the operator: kept so the next poll does not re-raise it 30 s later.
    /// The operator can forget the row to let the client ask again.
    #[serde(default)]
    pub denied: bool,
}

/// A provisioned client device key (public half pinned server-side).
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct DeviceKey {
    pub id: String,
    pub label: String,
    pub public_key: String, // base64 Ed25519 public key
    pub created_at: String,
    /// M1: the peer id this key is bound to. Empty = not bound yet.
    /// A bound key only authenticates polls for exactly this peer id, so one leaked
    /// key no longer satisfies require_device_key for the whole fleet.
    ///
    /// Empty is not "any id": with `claim_unbound_device_keys` on (the default) the
    /// key is a one-shot provisioning token that the first client to prove it claims
    /// (see `claim_device_key_in`); with it off, an empty binding authenticates
    /// nothing at all.
    #[serde(default)]
    pub peer_id: String,
    /// M1-CLAIM: when the binding above was taken by first use, as an ISO timestamp.
    /// Empty means the operator bound it by hand (or it is still unclaimed), so the
    /// dashboard can tell "I typed this id" apart from "a client took this key".
    #[serde(default)]
    pub claimed_at: String,
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
            permissions_version: 1,
            permissions: HashMap::new(),
            default_targets: Vec::new(),
            require_login: false,
            policies: HashMap::new(),
            device_policies: HashMap::new(),
            default_policy_name: None,
            admin_policy: default_admin_policy(),
            device_keys: Vec::new(),
            // Layer 1 / Rollout step 3: a fresh install is fail-closed. An upgraded
            // server keeps whatever its nemo_integration.json stores (field docs above).
            require_device_key: true,
            strip_unsealed_secrets: true,
            require_sealed_login: true,
            require_sealed_request: false,
            claim_unbound_device_keys: true,
            pending_device_key_claims: Vec::new(),
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
                // Crash-safety review finding: silently falling back to
                // IntegrationConfig::default() here -- empty allowlist, no device
                // keys, require_login off -- used to be invisible, AND the very next
                // persist() (record_login writes on every successful login) wrote
                // those defaults straight over the damaged file, destroying whatever
                // of it could have been recovered by hand. Move the bad file aside
                // first, so it survives for inspection/recovery, and say so loudly
                // (not just at error level -- this is a fleet-wide lockout under
                // require_device_key/require_login).
                let corrupt = path.with_extension(format!("corrupt-{}", now_iso8601()));
                match std::fs::rename(&path, &corrupt) {
                    Ok(()) => log::error!(
                        "Nemo integration config at {} is invalid ({}); moved it to {}                          and starting from EMPTY defaults -- every user/device key is                          gone until it is restored or reconfigured",
                        path.display(), err, corrupt.display()
                    ),
                    Err(rename_err) => log::error!(
                        "Nemo integration config at {} is invalid ({}); could not move                          it aside ({}), starting from EMPTY defaults -- the NEXT save                          will overwrite it",
                        path.display(), err, rename_err
                    ),
                }
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

/// Crash-safety review finding: a plain `fs::write` truncates the file first and
/// rewrites it in place, so a crash or a full disk mid-write left a truncated,
/// unparseable file -- and record_login persists on every login, so this was not
/// a rare window. Write to a sibling temp file, fsync it, then rename over the
/// target: on the same filesystem (always true here; the temp file sits next to
/// it) POSIX rename is atomic, so readers only ever see the old complete file or
/// the new complete file, never a partial one. Returns the path actually
/// written, for the caller to restrict permissions on.
fn atomic_write(path: &std::path::Path, text: &str) -> std::io::Result<()> {
    let tmp = path.with_extension(format!(
        "{}.tmp-{}",
        path.extension().and_then(|e| e.to_str()).unwrap_or("json"),
        std::process::id()
    ));
    {
        let mut f = std::fs::File::create(&tmp)?;
        use std::io::Write;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

fn persist(cfg: &IntegrationConfig) {
    // A unit test must never write the operator's config. Several tests enter through
    // an enforcement point (verify_device_signature, the rendezvous handshake), which
    // reaches the locking wrappers and so this function -- and that once left a real
    // nemo_integration.json, full of test keys, in the repo checkout. The pure `*_in`
    // halves keep the rules testable; this closes the hole for every present and future
    // test in one place, including the ones that cannot avoid the wrapper.
    #[cfg(test)]
    {
        let _ = cfg;
        return;
    }
    #[cfg(not(test))]
    persist_to_disk(cfg)
}

#[cfg(not(test))]
fn persist_to_disk(cfg: &IntegrationConfig) {
    let path = config_path();
    match serde_json::to_string_pretty(cfg) {
        Ok(text) => {
            if let Err(err) = atomic_write(&path, &text) {
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
/// is optional so the UI can leave it blank to keep the stored value; because of
/// that, a blank field can never *remove* a stored password, so
/// `clear_bind_password` exists to say so explicitly (same two-state pattern the
/// pinned CA certificate uses).
#[derive(Clone, Debug, Deserialize)]
pub struct LdapConfigUpdate {
    pub enabled: Option<bool>,
    pub server_url: Option<String>,
    pub windows_domain: Option<String>,
    pub base_dn: Option<String>,
    pub bind_dn: Option<String>,
    pub bind_password: Option<String>,
    /// `true` wipes the stored service-account password. Without this there was no
    /// way to remove a credential once saved, short of editing nemo_integration.json
    /// on the server and restarting it.
    pub clear_bind_password: Option<bool>,
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
    // An explicit clear wins over everything: it is the only way to remove a stored
    // credential, and it must not be defeated by a blank field arriving beside it.
    if update.clear_bind_password.unwrap_or(false) {
        ldap.bind_password.clear();
    } else if let Some(v) = update.bind_password {
        // Otherwise only overwrite when a non-empty value is supplied, so the UI can
        // leave the field blank to keep what is stored.
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

/// H11/H20/H22: Get the current permissions version for concurrency control
pub fn permissions_version() -> u64 {
    CONFIG.lock().unwrap().permissions_version
}

pub fn default_targets() -> Vec<String> {
    CONFIG.lock().unwrap().default_targets.clone()
}

#[derive(Clone, Debug, Deserialize)]
pub struct PermissionsUpdate {
    /// H11/H20/H22: Version number for concurrency control. If the client's version
    /// doesn't match the server's current version, the update is rejected to prevent
    /// stale tabs from overwriting concurrent changes.
    #[serde(default)]
    pub version: Option<u64>,
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

/// H11/H20/H22: a save carrying a version must carry the current one, so a tab
/// loaded before someone else's save cannot silently overwrite it.
fn check_permissions_version(client: Option<u64>, server: u64) -> Result<(), String> {
    match client {
        Some(v) if v != server => Err(format!(
            "version mismatch: client has version {}, server has version {}",
            v, server
        )),
        _ => Ok(()),
    }
}

/// Replace the RBAC map (and optionally the default targets / require-login),
/// persist, return it with the new `permissions_version`. A `version` that is
/// present and stale is refused; an absent one is accepted (scripts), which is
/// why the admin UI always sends it.
pub fn update_permissions(
    update: PermissionsUpdate,
) -> Result<(HashMap<String, UserPermission>, u64, Vec<String>), String> {
    let mut cfg = CONFIG.lock().unwrap();
    check_permissions_version(update.version, cfg.permissions_version)?;

    // H23/M13: Capture existing permissions before update to detect changes
    let old_permissions = cfg.permissions.clone();
    
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
    // H11/H20/H22: Increment permissions version to detect concurrent modifications
    cfg.permissions_version = cfg.permissions_version.saturating_add(1);
    let snapshot = cfg.permissions.clone();
    let version = cfg.permissions_version;
    persist(&cfg);
    drop(cfg);
    bump_ab_version(); // signal logged-in clients to re-fetch their address book
    
    // H23/M13: Evict live sessions whose permissions have changed
    // so they must re-authenticate with the new policy
    let evicted_keys = evict_sessions_with_changed_permissions(&old_permissions, &snapshot);

    Ok((snapshot, version, evicted_keys))
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

/// H23/M13: Evict live sessions whose permissions have changed.
/// When permissions are updated, existing sessions are invalidated so users
/// must re-authenticate with the new policy. This ensures permission changes
/// take effect immediately rather than lingering until token expiry.
fn evict_sessions_with_changed_permissions(
    old_perms: &HashMap<String, UserPermission>,
    new_perms: &HashMap<String, UserPermission>,
) -> Vec<String> {
    let mut sessions = SESSIONS.lock().unwrap();
    
    // Collect tokens to evict
    let to_evict: Vec<String> = sessions
        .iter()
        .filter(|(_, s)| {
            let key = normalize_lookup_username(&s.username);
            // Evict if user was removed from permissions
            if !new_perms.contains_key(&key) {
                return true;
            }
            // Evict if user was disabled (enabled: true -> false)
            let old_enabled = old_perms.get(&key).map(|p| p.enabled);
            let new_enabled = new_perms.get(&key).map(|p| p.enabled);
            if old_enabled == Some(true) && new_enabled == Some(false) {
                return true;
            }
            // Evict if allowed_targets changed (user can no longer reach some targets)
            let old_targets = old_perms.get(&key).map(|p| &p.allowed_targets);
            let new_targets = new_perms.get(&key).map(|p| &p.allowed_targets);
            if old_targets != new_targets {
                return true;
            }
            // Evict if is_admin flag changed (admin changes affect live sessions)
            let old_admin = old_perms.get(&key).map(|p| p.is_admin);
            let new_admin = new_perms.get(&key).map(|p| p.is_admin);
            if old_admin != new_admin {
                return true;
            }
            // Evict if policy changed
            let old_policy = old_perms.get(&key).map(|p| (&p.policy, p.policy_name.as_deref()));
            let new_policy = new_perms.get(&key).map(|p| (&p.policy, p.policy_name.as_deref()));
            if old_policy != new_policy {
                return true;
            }
            false
        })
        .map(|(t, _)| t.clone())
        .collect();
    
    let evicted_count = to_evict.len();
    let mut evicted_keys = Vec::new();
    for token in to_evict {
        if let Some(s) = sessions.remove(&token) {
            if !s.device_key_pub.is_empty() && !evicted_keys.contains(&s.device_key_pub) {
                evicted_keys.push(s.device_key_pub);
            }
        }
    }
    
    // Persist only when something was evicted.
    if evicted_count > 0 {
        if sessions.is_empty() {
            let _ = std::fs::remove_file(sessions_path());
        } else {
            persist_sessions(&sessions);
        }
    }
    evicted_keys
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
            // Pairs with the "login failed"/"login refused" warnings in
            // nemo_management; the account name only, no display name or email.
            log::info!("Nemo login recorded: {}", key);
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
) -> (String, UserPermission, u64, Vec<String>) {
    let key = normalize_lookup_username(username);
    let mut cfg = CONFIG.lock().unwrap();
    let old_permissions = cfg.permissions.clone();
    let defaults = cfg.default_targets.clone();
    let entry = cfg
        .permissions
        .entry(key.clone())
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
    // The allowlist changed, so an ACL tab loaded before this must not save over it.
    cfg.permissions_version = cfg.permissions_version.saturating_add(1);
    let version = cfg.permissions_version;
    let snapshot = cfg.permissions.clone();
    persist(&cfg);
    drop(cfg);
    let evicted_keys = evict_sessions_with_changed_permissions(&old_permissions, &snapshot);
    (key, result, version, evicted_keys)
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
        // Operator-typed, like the editable field: accept the grouped form the client
        // displays. The approve path deliberately does NOT normalize — the id there is
        // the one the client reported, and it has to match the pending row byte-exact.
        peer_id: normalize_peer_id(&peer_id),
        claimed_at: String::new(),
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
/// Remove a device key; returns the removed key (if any) and drops every login
/// session that key proved, so its tokens die with it (M69).
pub fn remove_device_key(id: &str) -> Option<DeviceKey> {
    let mut cfg = CONFIG.lock().unwrap();
    let pos = cfg.device_keys.iter().position(|k| k.id == id)?;
    let removed = cfg.device_keys.remove(pos);
    // M1-CLAIM: a request against a key that no longer exists can neither be approved
    // nor mean anything, so it goes with the key instead of haunting the dashboard.
    cfg.pending_device_key_claims
        .retain(|c| c.public_key != removed.public_key);
    persist(&cfg);
    drop(cfg);
    let mut sessions = SESSIONS.lock().unwrap();
    let before = sessions.len();
    sessions.retain(|_, s| s.device_key_pub != removed.public_key);
    if sessions.len() != before {
        persist_sessions(&sessions);
    }
    Some(removed)
}

/// The peer id each given device key is bound to (unbound or unknown keys are
/// skipped): the controller machines whose live sessions a revocation must end.
pub fn peer_ids_for_device_keys(keys: &[String]) -> Vec<String> {
    let cfg = CONFIG.lock().unwrap();
    let mut out = Vec::new();
    for k in &cfg.device_keys {
        if !k.peer_id.is_empty() && keys.contains(&k.public_key) && !out.contains(&k.peer_id) {
            out.push(k.peer_id.clone());
        }
    }
    out
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
/// TASK #14 escape hatch, read like insecure_ldap_allowed (CLI/.env only).
pub(crate) fn allow_unbound_device_keys() -> bool {
    crate::nemo_management::is_truthy(&get_arg("allow-unbound-device-keys"))
}

/// M1-CLAIM: what the binding rule says about a key whose signature has not been
/// checked yet. `Proven` and `Refused` are final; `ClaimOnProof` means "let the
/// signature decide" — the caller verifies it and only then calls `claim_device_key`.
///
/// The order matters and is the whole security argument for first-use binding: the
/// claim is written AFTER the signature verifies, so claiming a key requires holding
/// its private half. Naming someone else's unbound key cannot take it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BindingDecision {
    /// The binding is already satisfied (bound to this id, or the CLI escape hatch).
    Proven,
    /// Pinned but unbound, and claiming is on: bind it to `claimed` once the
    /// signature verifies.
    ClaimOnProof,
    Refused(String),
}

/// TASK #14 + M1-CLAIM: the one binding rule both enforcement points apply
/// (`nemo_client_auth_open`, `verify_device_signature`), now with the claim arm.
///
/// Precedence is deliberate, so no existing deployment changes behaviour silently:
/// 1. a bound key authenticates exactly its peer, nothing else — unchanged;
/// 2. `--allow-unbound-device-keys Y` still means "unbound authenticates anything",
///    and does NOT claim: an operator who asked for the loose rule keeps it, including
///    the (bad) one-key-many-machines workflow it enables;
/// 3. otherwise an unbound key is claimable, if claiming is on;
/// 4. otherwise it authenticates nothing — the original fail-closed rule.
pub(crate) fn device_key_binding_decision(
    bound: &str,
    claimed: &str,
    allow_unbound: bool,
    claim_enabled: bool,
) -> BindingDecision {
    if !bound.is_empty() {
        return if bound == claimed {
            BindingDecision::Proven
        } else {
            BindingDecision::Refused(format!(
                "device key is bound to peer {} but the client claims {}",
                bound, claimed
            ))
        };
    }
    if allow_unbound {
        return BindingDecision::Proven;
    }
    if claim_enabled {
        if claimed.trim().is_empty() {
            return BindingDecision::Refused(
                "device key has no peer-id binding and the client claims no id".to_owned(),
            );
        }
        return BindingDecision::ClaimOnProof;
    }
    BindingDecision::Refused(format!(
        "device key has no peer-id binding (client claims {}); bind it, enable first-use \
         claiming, or pass --allow-unbound-device-keys Y",
        claimed
    ))
}

/// M1-CLAIM: take an unbound key for `peer_id`. Pure over the key list so the rule is
/// testable without writing the on-disk config. `Ok(true)` = the binding was just
/// written (the caller persists and audits it), `Ok(false)` = already bound to this
/// same peer (a re-poll, or two of its own requests racing), `Err` = refuse.
///
/// Re-checking the binding HERE, under the same lock that writes it, is what makes two
/// different ids racing for one token safe: whichever gets the lock first binds it, the
/// other is refused by the `bound != peer_id` arm rather than overwriting the winner.
fn claim_device_key_in(
    keys: &mut [DeviceKey],
    public_key: &str,
    peer_id: &str,
    claimed_at: &str,
) -> Result<bool, String> {
    let pk = public_key.trim();
    let peer_id = peer_id.trim();
    if peer_id.is_empty() {
        return Err("cannot claim a device key for an empty peer id".to_owned());
    }
    let Some(key) = keys.iter_mut().find(|k| k.public_key == pk) else {
        // Deleted between the decision and the claim: fail closed.
        return Err("device key is no longer pinned on this server".to_owned());
    };
    if key.peer_id == peer_id {
        return Ok(false);
    }
    if !key.peer_id.is_empty() {
        return Err(format!(
            "device key was claimed by peer {} first; {} is refused",
            key.peer_id, peer_id
        ));
    }
    key.peer_id = peer_id.to_owned();
    key.claimed_at = claimed_at.to_owned();
    Ok(true)
}

/// Operator-typed peer ids: strip ALL whitespace, not just the ends.
///
/// The client shows its id grouped in threes ("456 456 456"), so that is what an
/// operator reading it off a screen types or pastes — and `456 456 456` must mean the
/// same thing as `456456456` rather than being refused as malformed, which is a
/// guaranteed support call otherwise. `is_whitespace` (not `== ' '`) so a non-breaking
/// space pasted out of a GUI is handled too.
///
/// Only for ids a human enters. A client reports its own id programmatically and must
/// keep matching byte-for-byte, so nothing on the request path normalizes — that is why
/// `valid_peer_id` still refuses an id with spaces in it rather than accepting one.
pub fn normalize_peer_id(raw: &str) -> String {
    raw.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Peer ids are the client's own machine-derived id, and they end up in log lines,
/// JSON and the dashboard, so keep them to the shape hbbs already accepts
/// (`register_pk_core` refuses anything under 6 characters).
pub fn valid_peer_id(id: &str) -> bool {
    let id = id.trim();
    id.len() >= 6
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Set (or clear) a key's binding by hand. Pure half, for the same reason as
/// `claim_device_key_in`.
fn set_device_key_peer_id_in(
    keys: &mut [DeviceKey],
    id: &str,
    peer_id: &str,
) -> Result<DeviceKey, String> {
    // Typed by a human, so accept the grouped form the client displays.
    let peer_id = normalize_peer_id(peer_id);
    let peer_id = peer_id.as_str();
    if !peer_id.is_empty() && !valid_peer_id(peer_id) {
        return Err(
            "not a TBFDesk id: use 6-64 characters, letters, digits, '-' or '_' (empty clears \
             the binding)"
                .to_owned(),
        );
    }
    let Some(key) = keys.iter_mut().find(|k| k.id == id) else {
        return Err("no such device key".to_owned());
    };
    key.peer_id = peer_id.to_owned();
    // An operator typing the id is not a first-use claim: clearing this is what keeps
    // the dashboard's "claimed by the client" badge honest, and clearing the binding
    // re-arms the key as a fresh provisioning token.
    key.claimed_at = String::new();
    Ok(key.clone())
}

/// Bind a key to a peer id after the fact (the GUI's editable "Bound to ID" field), or
/// clear it to re-arm the key as a claimable provisioning token.
pub fn set_device_key_peer_id(id: &str, peer_id: &str) -> Result<DeviceKey, String> {
    let mut cfg = CONFIG.lock().unwrap();
    let updated = set_device_key_peer_id_in(&mut cfg.device_keys, id, peer_id)?;
    // M1-CLAIM: the operator has just answered the question the pending rows ask, one
    // way or the other. Binding by hand settles it; CLEARING the binding re-arms the key
    // as a fresh provisioning token, and a stale denial must not then refuse the first
    // client that proves it.
    cfg.pending_device_key_claims
        .retain(|c| c.public_key != updated.public_key);
    persist(&cfg);
    Ok(updated)
}

/// The key provisioned for a peer, if any: what the dashboard needs to tell a
/// provisioned machine from one that is merely registered at the rendezvous server
/// and still unverified. Unlike the poll-derived auth mode this survives a restart,
/// because it is read from the pinned registry rather than from runtime state.
pub fn device_key_for_peer(peer_id: &str) -> Option<DeviceKey> {
    let peer_id = peer_id.trim();
    if peer_id.is_empty() {
        return None;
    }
    CONFIG
        .lock()
        .unwrap()
        .device_keys
        .iter()
        .find(|k| k.peer_id == peer_id)
        .cloned()
}

pub fn claim_unbound_device_keys() -> bool {
    CONFIG.lock().unwrap().claim_unbound_device_keys
}
pub fn set_claim_unbound_device_keys(v: bool) {
    let mut cfg = CONFIG.lock().unwrap();
    cfg.claim_unbound_device_keys = v;
    persist(&cfg);
}
/// Keys still waiting for a first use, for the dashboard's provisioning view.
pub fn unclaimed_device_key_count() -> usize {
    CONFIG
        .lock()
        .unwrap()
        .device_keys
        .iter()
        .filter(|k| k.peer_id.is_empty())
        .count()
}
// --- M1-CLAIM: pending binding requests ------------------------------------
//
// A pending claim is a REQUEST, never a grant: while the row exists the client is
// still refused (it sits in its provisioning gate), and only the operator's
// confirmation writes the binding. Because the row is only ever filed AFTER a
// signature over the claimed id verifies, filing one requires holding the key's
// private half -- naming someone else's unclaimed key cannot even raise a request
// against it.

/// How many different ids one key may have waiting at once, and how many requests the
/// whole table holds. A claim needs a valid signature over a pinned key, so this is not
/// an open flood -- but one key must not be able to fill a PERSISTED table with ids.
pub const MAX_PENDING_PER_KEY: usize = 5;
pub const MAX_PENDING_CLAIMS: usize = 200;

/// What `register_pending_claim` did with a request. Every variant means "refused for
/// now" to the caller -- it only decides what to tell the operator and the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingOutcome {
    /// Filed now: the operator has something new to confirm.
    New,
    /// Already filed and still waiting; `attempts`/`last_seen` were bumped.
    Repeat,
    /// The operator denied this pairing. Deliberately NOT re-raised, or the denial
    /// would reappear on the next poll 30 s later; the operator can forget the row to
    /// let the client ask again.
    Denied,
    /// This key already has `MAX_PENDING_PER_KEY` ids waiting, or the table is full of
    /// denied rows. Dropped.
    Full,
    /// The key was deleted between the decision and the claim, or the id is not a
    /// TBFDesk id. Nothing is filed -- a junk id must not reach the persisted table.
    Rejected,
}

fn register_pending_claim_in(
    claims: &mut Vec<PendingDeviceKeyClaim>,
    key_id: &str,
    public_key: &str,
    peer_id: &str,
    via: &str,
    now: &str,
) -> PendingOutcome {
    let pk = public_key.trim();
    let peer_id = peer_id.trim();
    if !valid_peer_id(peer_id) {
        return PendingOutcome::Rejected;
    }
    if let Some(existing) = claims
        .iter_mut()
        .find(|c| c.public_key == pk && c.peer_id == peer_id)
    {
        existing.last_seen = now.to_owned();
        existing.attempts = existing.attempts.saturating_add(1);
        existing.via = via.to_owned();
        // The key id is derived from the public key's prefix and can be re-derived on a
        // re-pin, so keep the dashboard's join column current.
        existing.key_id = key_id.to_owned();
        return if existing.denied {
            PendingOutcome::Denied
        } else {
            PendingOutcome::Repeat
        };
    }
    if claims.iter().filter(|c| c.public_key == pk).count() >= MAX_PENDING_PER_KEY {
        return PendingOutcome::Full;
    }
    // Global cap: make room by dropping the oldest row that is still merely waiting,
    // rather than refusing a real provisioning request because a stale one was never
    // cleared. A DENIED row is never evicted -- dropping it would let the denied client
    // re-raise its request on the next poll, which is exactly what `denied` prevents.
    while claims.len() >= MAX_PENDING_CLAIMS {
        let Some(oldest) = claims
            .iter()
            .enumerate()
            .filter(|(_, c)| !c.denied)
            .min_by(|(ai, a), (bi, b)| a.first_seen.cmp(&b.first_seen).then(ai.cmp(bi)))
            .map(|(i, _)| i)
        else {
            return PendingOutcome::Full;
        };
        claims.remove(oldest);
    }
    claims.push(PendingDeviceKeyClaim {
        key_id: key_id.to_owned(),
        public_key: pk.to_owned(),
        peer_id: peer_id.to_owned(),
        first_seen: now.to_owned(),
        last_seen: now.to_owned(),
        attempts: 1,
        via: via.to_owned(),
        denied: false,
    });
    PendingOutcome::New
}

/// File (or refresh) a binding request against the live config. `now` is passed in for
/// the same reason as `add_device_key`'s `created_at`: this module keeps no clock.
///
/// The caller MUST refuse the request regardless of the outcome.
pub fn register_pending_claim(
    public_key: &str,
    peer_id: &str,
    via: &str,
    now: String,
) -> PendingOutcome {
    let mut cfg = CONFIG.lock().unwrap();
    let pk = public_key.trim().to_owned();
    let Some(key_id) = cfg
        .device_keys
        .iter()
        .find(|k| k.public_key == pk)
        .map(|k| k.id.clone())
    else {
        return PendingOutcome::Rejected;
    };
    let outcome = register_pending_claim_in(
        &mut cfg.pending_device_key_claims,
        &key_id,
        &pk,
        peer_id,
        via,
        &now,
    );
    // Only a change is worth a write: a client re-polling every 30 s while it waits
    // must not rewrite the config file every 30 s. `Repeat` bumps counters in memory;
    // losing them to a restart costs nothing, the request itself is already on disk.
    if matches!(outcome, PendingOutcome::New) {
        persist(&cfg);
    }
    outcome
}

pub fn pending_device_key_claims() -> Vec<PendingDeviceKeyClaim> {
    CONFIG.lock().unwrap().pending_device_key_claims.clone()
}

/// The request this peer is waiting on, if any: what the peers panel needs to show an
/// "unverified -- key claim pending" badge on a machine that is registered but refused.
pub fn pending_claim_for_peer(peer_id: &str) -> Option<PendingDeviceKeyClaim> {
    let peer_id = peer_id.trim();
    if peer_id.is_empty() {
        return None;
    }
    let cfg = CONFIG.lock().unwrap();
    cfg.pending_device_key_claims
        .iter()
        .find(|c| c.peer_id == peer_id && !c.denied)
        .or_else(|| {
            cfg.pending_device_key_claims
                .iter()
                .find(|c| c.peer_id == peer_id)
        })
        .cloned()
}

/// The operator confirms a pairing: this is the ONLY path that writes a binding the
/// operator did not type. The key's other pending rows go with it -- one token, one
/// machine -- including denied ones, which have nothing left to deny.
pub fn approve_device_key_claim(
    key_id: &str,
    peer_id: &str,
    claimed_at: String,
) -> Result<DeviceKey, String> {
    let mut cfg = CONFIG.lock().unwrap();
    let Some(public_key) = cfg
        .pending_device_key_claims
        .iter()
        .find(|c| c.key_id == key_id && c.peer_id == peer_id)
        .map(|c| c.public_key.clone())
    else {
        return Err("no such pending device-key claim".to_owned());
    };
    // Re-checks the binding under the lock that writes it, so two approvals racing (two
    // browser tabs) cannot both bind.
    claim_device_key_in(&mut cfg.device_keys, &public_key, peer_id, &claimed_at)?;
    cfg.pending_device_key_claims
        .retain(|c| c.public_key != public_key);
    let Some(key) = cfg
        .device_keys
        .iter()
        .find(|k| k.public_key == public_key)
        .cloned()
    else {
        return Err("device key is no longer pinned on this server".to_owned());
    };
    persist(&cfg);
    Ok(key)
}

/// The operator refuses a pairing. The row stays, marked, so the next poll does not
/// re-raise it 30 s later and so the refusal survives a restart.
pub fn deny_device_key_claim(key_id: &str, peer_id: &str) -> Result<PendingDeviceKeyClaim, String> {
    let mut cfg = CONFIG.lock().unwrap();
    let Some(claim) = cfg
        .pending_device_key_claims
        .iter_mut()
        .find(|c| c.key_id == key_id && c.peer_id == peer_id)
    else {
        return Err("no such pending device-key claim".to_owned());
    };
    claim.denied = true;
    let out = claim.clone();
    persist(&cfg);
    Ok(out)
}

/// Drop a row, denied or not: a denied client may ask again, and a request filed by a
/// machine that no longer exists should not sit on the dashboard forever.
pub fn forget_device_key_claim(key_id: &str, peer_id: &str) -> Result<bool, String> {
    let mut cfg = CONFIG.lock().unwrap();
    let before = cfg.pending_device_key_claims.len();
    cfg.pending_device_key_claims
        .retain(|c| !(c.key_id == key_id && c.peer_id == peer_id));
    let removed = cfg.pending_device_key_claims.len() != before;
    if removed {
        persist(&cfg);
    } else {
        return Err("no such pending device-key claim".to_owned());
    }
    Ok(removed)
}

/// Requests waiting for a decision, for the dashboard badge and the boot warning.
pub fn pending_device_key_claim_count() -> usize {
    CONFIG
        .lock()
        .unwrap()
        .pending_device_key_claims
        .iter()
        .filter(|c| !c.denied)
        .count()
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

/// S-B: fail closed on a login that was not sealed to the management key — an
/// attacker on the wire never sees a readable password, but only once the whole
/// fleet seals. False = today's behaviour (a plaintext login is still accepted).
pub fn require_sealed_login() -> bool {
    CONFIG.lock().unwrap().require_sealed_login
}
pub fn set_require_sealed_login(v: bool) {
    let mut cfg = CONFIG.lock().unwrap();
    cfg.require_sealed_login = v;
    persist(&cfg);
}
/// S-B: fail closed on a poll / address-book request that arrived unsealed.
/// False = today's behaviour (a plaintext request body is still accepted).
pub fn require_sealed_request() -> bool {
    CONFIG.lock().unwrap().require_sealed_request
}
pub fn set_require_sealed_request(v: bool) {
    let mut cfg = CONFIG.lock().unwrap();
    cfg.require_sealed_request = v;
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
    /// TASK #19: base64 of the pinned Ed25519 device key that proved the login this
    /// token was issued for; the punch/relay user gate refuses the token from any
    /// connection that did not prove exactly this key. Empty only when the login
    /// carried no valid proof (possible solely while require_device_key is off).
    /// Deliberately NO serde default: a sessions file from before this field fails
    /// to parse and is dropped whole (everyone signs in again) instead of loading
    /// its tokens as unbound.
    pub device_key_pub: String,
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
        if let Err(err) = atomic_write(&path, &text) {
            log::error!("failed to persist Nemo sessions to {}: {}", path.display(), err);
        } else {
            // M3: live bearer tokens — keep them readable only by the service account.
            restrict_file(&path);
        }
    }
}

pub fn create_session(
    username: String,
    display_name: String,
    email: String,
    device_key_pub: String,
) -> String {
    let token = uuid::Uuid::new_v4().simple().to_string();
    let session = Session {
        username,
        display_name,
        email,
        device_key_pub,
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
    // C4: count the moment an account's backoff first reaches the 30s cap (the
    // transition, not every subsequent capped failure), so the security panel can
    // surface "an account is being hammered hard" as a discrete anomaly.
    if entry.0 >= 1
        && login_backoff_ms(entry.0) >= LOGIN_BACKOFF_MAX_MS
        && login_backoff_ms(entry.0.saturating_sub(1)) < LOGIN_BACKOFF_MAX_MS
    {
        SEC_BACKOFF_CAP_HITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    entry.0
}

/// Clear the failure counter for `username` after a successful login.
pub fn clear_login_failures(username: &str) {
    LOGIN_FAILURES
        .lock()
        .unwrap()
        .remove(&normalize_lookup_username(username));
}

/// The ceiling `login_backoff_ms` saturates at, exposed so callers can detect the
/// moment an account's backoff first reaches the cap (a loggable anomaly).
pub fn login_backoff_max_ms() -> u64 {
    LOGIN_BACKOFF_MAX_MS
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
// SEC-10: pre-bind spray / AD-lockout protection
// --------------------------------------------------------------------------
//
// The per-username backoff above runs *after* the directory bind and is keyed on
// the username, so it does nothing against password *spraying* -- one password
// tried against many different accounts. Every attempt still reaches the DC, and
// enough of them lock real users out of Windows. That is the damage worth
// preventing here: not the attacker guessing a password, but the attacker denying
// the whole site its accounts.
//
// What separates spraying from typos is the number of DISTINCT usernames that fail
// from one source in a short window: a fat-fingered user fails the same name over
// and over, a sprayer walks the directory. So count distinct failed usernames per
// source, and fleet-wide for a sprayer that rotates its source, and refuse BEFORE
// the bind once either trips. Refusal is immediate -- no tarpit, which would only
// be a self-DoS -- and logged once per trip.
//
// Sizing note: every workstation behind one NAT presents the SAME source IP to this
// server, so the per-IP threshold has to sit above what a whole site can plausibly
// fail by accident. Ten different people failing inside five minutes is not that.

const SPRAY_IP_WINDOW_SECS: u64 = 300;
const SPRAY_IP_MAX_USERS: usize = 10;
const SPRAY_IP_COOLDOWN_SECS: u64 = 60;
const SPRAY_GLOBAL_WINDOW_SECS: u64 = 60;
const SPRAY_GLOBAL_MAX_USERS: usize = 30;
const SPRAY_GLOBAL_COOLDOWN_SECS: u64 = 120;
/// Bound on the per-IP table so a spoofed-source flood cannot grow it without limit.
const SPRAY_MAX_TRACKED_IPS: usize = 4096;

#[derive(Default)]
struct SprayWindow {
    users: HashSet<String>,
    started: u64,
    blocked_until: u64,
}

impl SprayWindow {
    /// Start a fresh counting window once the current one has aged out. A cooldown
    /// keeps its own deadline and is not affected by this.
    fn roll(&mut self, now: u64, window: u64) {
        if now.saturating_sub(self.started) >= window {
            self.users.clear();
            self.started = now;
        }
    }

    fn trip(&mut self, now: u64, cooldown: u64) -> bool {
        if now < self.blocked_until {
            return false;
        }
        self.blocked_until = now.saturating_add(cooldown);
        self.users.clear();
        self.started = now;
        true
    }
}

static SPRAY_BY_IP: Lazy<Mutex<HashMap<String, SprayWindow>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static SPRAY_GLOBAL: Lazy<Mutex<SprayWindow>> = Lazy::new(|| Mutex::new(SprayWindow::default()));

/// Checked BEFORE the directory bind. `Some(reason)` means refuse the login
/// without ever contacting the DC -- which is what stops a spray from locking AD
/// accounts out. The reason is deliberately vague (it is shown to whoever is
/// calling, attacker included) and says nothing about whether the account exists.
pub fn login_spray_block(source_ip: Option<&str>) -> Option<&'static str> {
    let now = now_secs();
    {
        let mut global = SPRAY_GLOBAL.lock().unwrap();
        if now < global.blocked_until {
            SEC_PRE_BIND_REFUSALS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Some("too many failed sign-ins on this server right now; try again shortly");
        }
        global.roll(now, SPRAY_GLOBAL_WINDOW_SECS);
    }
    let ip = source_ip?;
    let mut map = SPRAY_BY_IP.lock().unwrap();
    let entry = map.get_mut(ip)?;
    if now < entry.blocked_until {
        SEC_PRE_BIND_REFUSALS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return Some("too many failed sign-ins from your network; try again shortly");
    }
    None
}

/// Record a failed login against its source. Call this only for failures -- a
/// success is never counted, so a legitimate user is never penalised for someone
/// else's typo. Returns true when this failure tripped a cooldown.
pub fn note_login_spray(source_ip: Option<&str>, username: &str) -> bool {
    let now = now_secs();
    let user = normalize_lookup_username(username);
    if user.is_empty() {
        return false;
    }
    let mut tripped = false;
    {
        let mut global = SPRAY_GLOBAL.lock().unwrap();
        global.roll(now, SPRAY_GLOBAL_WINDOW_SECS);
        global.users.insert(user.clone());
        if global.users.len() > SPRAY_GLOBAL_MAX_USERS
            && global.trip(now, SPRAY_GLOBAL_COOLDOWN_SECS)
        {
            tripped = true;
            SEC_GLOBAL_SPRAY_TRIPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            log::error!(
                "Nemo login: more than {} distinct usernames failed within {}s across all \
                 sources - refusing directory binds for {}s (password spraying)",
                SPRAY_GLOBAL_MAX_USERS,
                SPRAY_GLOBAL_WINDOW_SECS,
                SPRAY_GLOBAL_COOLDOWN_SECS,
            );
        }
    }
    let Some(ip) = source_ip else {
        return tripped;
    };
    let mut map = SPRAY_BY_IP.lock().unwrap();
    map.retain(|_, w| now < w.blocked_until || now.saturating_sub(w.started) < SPRAY_IP_WINDOW_SECS);
    if map.len() >= SPRAY_MAX_TRACKED_IPS && !map.contains_key(ip) {
        // Table is full of live windows: fall back to the global tripwire rather than
        // letting a source-spoofing flood grow it without bound.
        return tripped;
    }
    let entry = map.entry(ip.to_owned()).or_insert_with(|| SprayWindow {
        started: now,
        ..Default::default()
    });
    entry.roll(now, SPRAY_IP_WINDOW_SECS);
    entry.users.insert(user);
    if entry.users.len() > SPRAY_IP_MAX_USERS && entry.trip(now, SPRAY_IP_COOLDOWN_SECS) {
        log::warn!(
            "Nemo login: more than {} distinct usernames failed within {}s from {} - refusing \
             directory binds from it for {}s (password spraying)",
            SPRAY_IP_MAX_USERS,
            SPRAY_IP_WINDOW_SECS,
            ip,
            SPRAY_IP_COOLDOWN_SECS,
        );
        SEC_IP_SPRAY_TRIPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        tripped = true;
    }
    tripped
}

// --------------------------------------------------------------------------
// C1 (pentest 08-IMPROVEMENTS): pre-gate volumetric rate limit for the
// UNAUTHENTICATED mgmt-API routes (/api/login, /api/login-key,
// /api/tls-cert-info). The credential defences above (per-username backoff and
// the spray tripwires) only engage AFTER a sealedbox open and a valid username,
// so none of them blunt a raw flood of TLS handshakes + unseal attempts. This
// per-source token bucket sheds such a flood BEFORE the sealedbox open, with a
// budget set well above any human-paced sign-in so a legitimate client -- even
// many behind one NAT -- is never throttled. It is a backstop for when no edge
// proxy/WAF fronts the API; see 07-HARDENING R1.
const UNAUTH_BUCKET_CAPACITY: f64 = 40.0; // burst
const UNAUTH_REFILL_PER_SEC: f64 = 2.0; // sustained ~20 / 10 s
const UNAUTH_MAX_TRACKED_IPS: usize = 8192;

struct TokenBucket {
    tokens: f64,
    last_ms: u64,
}

static UNAUTH_RATE: Lazy<Mutex<HashMap<String, TokenBucket>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// `true` means SHED this request (respond 429) before any sealedbox open.
/// Consumes one token per call. A missing source IP is allowed -- it cannot be
/// keyed, and this is a volumetric backstop, not the primary control (the
/// device-key gate still runs behind it).
pub fn unauth_rate_block(source_ip: Option<&str>) -> bool {
    let Some(ip) = source_ip else {
        return false;
    };
    let now = now_ms();
    let mut map = UNAUTH_RATE.lock().unwrap();
    // Bound the table: when full and this is a new IP, drop buckets that have
    // refilled to full (idle) so churn cannot grow it without limit. A TCP+TLS
    // flood cannot spoof its source, so distinct IPs are real reachable hosts.
    if map.len() >= UNAUTH_MAX_TRACKED_IPS && !map.contains_key(ip) {
        map.retain(|_, b| {
            let elapsed = now.saturating_sub(b.last_ms) as f64 / 1000.0;
            (b.tokens + elapsed * UNAUTH_REFILL_PER_SEC) < UNAUTH_BUCKET_CAPACITY
        });
        if map.len() >= UNAUTH_MAX_TRACKED_IPS {
            // Still full of actively-limited sources: don't start tracking a new
            // one (and don't block it) -- the ones in the table are the ones
            // being throttled, and the global/credential controls still apply.
            return false;
        }
    }
    let b = map.entry(ip.to_owned()).or_insert(TokenBucket {
        tokens: UNAUTH_BUCKET_CAPACITY,
        last_ms: now,
    });
    let elapsed = now.saturating_sub(b.last_ms) as f64 / 1000.0;
    b.tokens = (b.tokens + elapsed * UNAUTH_REFILL_PER_SEC).min(UNAUTH_BUCKET_CAPACITY);
    b.last_ms = now;
    if b.tokens >= 1.0 {
        b.tokens -= 1.0;
        false
    } else {
        SEC_UNAUTH_SHED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        true
    }
}

// --------------------------------------------------------------------------
// C4 (pentest 08-IMPROVEMENTS): security observability + operator controls
// --------------------------------------------------------------------------
//
// The limiters above only `log::warn!/error!` when they trip, so a live spray or
// flood is invisible to an operator and there is no way to lift an auto-block short
// of waiting out the cooldown. These two things fix that:
//   * monotonic counters incremented at each trip point (metrics for the panel), and
//   * a read-only snapshot of the *current* defensive state (who is blocked, for how
//     long, which accounts are under backoff, which IPs are being throttled), plus
//   * explicit clear_* controls so an admin can re-enable a source that was blocked
//     by mistake (e.g. a shared NAT egress that legitimately tripped the per-IP gate).
// None of this weakens a control: clearing is an authenticated, audited admin action,
// and the counters/snapshot expose no secret.

static SEC_UNAUTH_SHED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static SEC_IP_SPRAY_TRIPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static SEC_GLOBAL_SPRAY_TRIPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static SEC_BACKOFF_CAP_HITS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static SEC_PRE_BIND_REFUSALS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Monotonic since-boot counters for the security dashboard. Cheap to read.
#[derive(Clone, Default, Serialize)]
pub struct SecurityCounters {
    /// Unauthenticated requests shed with 429 by the pre-gate token bucket (C1).
    pub unauth_shed: u64,
    /// Times a single source IP tripped the per-IP spray cooldown.
    pub ip_spray_trips: u64,
    /// Times the fleet-wide spray tripwire fired (refuse-all cooldown).
    pub global_spray_trips: u64,
    /// Times an account's login backoff first reached the 30s cap.
    pub backoff_cap_hits: u64,
    /// Logins refused before the directory bind by an active spray block.
    pub pre_bind_refusals: u64,
}

fn load_counter(c: &std::sync::atomic::AtomicU64) -> u64 {
    c.load(std::sync::atomic::Ordering::Relaxed)
}

/// The thresholds behind the limiters, so the panel can show "10 users / 300s"
/// beside each block rather than hard-coding them in the HTML.
#[derive(Clone, Serialize)]
pub struct SecurityConfig {
    pub spray_ip_window_secs: u64,
    pub spray_ip_max_users: usize,
    pub spray_ip_cooldown_secs: u64,
    pub spray_global_window_secs: u64,
    pub spray_global_max_users: usize,
    pub spray_global_cooldown_secs: u64,
    pub backoff_max_ms: u64,
    pub unauth_bucket_capacity: f64,
    pub unauth_refill_per_sec: f64,
}

/// An IP currently inside a per-IP spray cooldown (a directory-bind block).
#[derive(Clone, Serialize)]
pub struct IpSprayBlock {
    pub ip: String,
    pub remaining_secs: u64,
    pub distinct_users: usize,
}

/// The fleet-wide tripwire state.
#[derive(Clone, Serialize)]
pub struct GlobalTripwire {
    pub active: bool,
    pub remaining_secs: u64,
    pub distinct_users_window: usize,
}

/// An account currently under login backoff (consecutive failures in the window).
#[derive(Clone, Serialize)]
pub struct BackoffAccount {
    pub username: String,
    pub failures: u32,
    pub backoff_ms: u64,
    pub at_cap: bool,
    pub last_failure_secs_ago: u64,
}

/// An IP whose unauth token bucket is depleted below full (under rate pressure).
#[derive(Clone, Serialize)]
pub struct ThrottledIp {
    pub ip: String,
    pub tokens: f64,
    pub shedding: bool,
}

/// Everything the Security panel renders, captured under the relevant locks.
#[derive(Clone, Serialize)]
pub struct SecuritySnapshot {
    pub now_secs: u64,
    pub counters: SecurityCounters,
    pub config: SecurityConfig,
    pub global_tripwire: GlobalTripwire,
    pub ip_blocks: Vec<IpSprayBlock>,
    pub backoff_accounts: Vec<BackoffAccount>,
    pub throttled_ips: Vec<ThrottledIp>,
}

/// Read the current counters.
pub fn security_counters() -> SecurityCounters {
    SecurityCounters {
        unauth_shed: load_counter(&SEC_UNAUTH_SHED),
        ip_spray_trips: load_counter(&SEC_IP_SPRAY_TRIPS),
        global_spray_trips: load_counter(&SEC_GLOBAL_SPRAY_TRIPS),
        backoff_cap_hits: load_counter(&SEC_BACKOFF_CAP_HITS),
        pre_bind_refusals: load_counter(&SEC_PRE_BIND_REFUSALS),
    }
}

/// Snapshot the live defensive state for the admin dashboard. Read-only: it never
/// writes back a refilled bucket or rolls a window, so observing never alters the
/// controls.
pub fn security_snapshot() -> SecuritySnapshot {
    let now = now_secs();
    let now_ms_v = now_ms();

    let global_tripwire = {
        let g = SPRAY_GLOBAL.lock().unwrap();
        GlobalTripwire {
            active: now < g.blocked_until,
            remaining_secs: g.blocked_until.saturating_sub(now),
            distinct_users_window: g.users.len(),
        }
    };

    let ip_blocks = {
        let map = SPRAY_BY_IP.lock().unwrap();
        let mut v: Vec<IpSprayBlock> = map
            .iter()
            .filter(|(_, w)| now < w.blocked_until)
            .map(|(ip, w)| IpSprayBlock {
                ip: ip.clone(),
                remaining_secs: w.blocked_until.saturating_sub(now),
                distinct_users: w.users.len(),
            })
            .collect();
        v.sort_by(|a, b| b.remaining_secs.cmp(&a.remaining_secs));
        v
    };

    let backoff_accounts = {
        let map = LOGIN_FAILURES.lock().unwrap();
        let mut v: Vec<BackoffAccount> = map
            .iter()
            .filter(|(_, (fails, last))| {
                *fails > 0 && now.saturating_sub(*last) < LOGIN_FAILURE_WINDOW_SECS
            })
            .map(|(user, (fails, last))| {
                let ms = login_backoff_ms(*fails);
                BackoffAccount {
                    username: user.clone(),
                    failures: *fails,
                    backoff_ms: ms,
                    at_cap: ms >= LOGIN_BACKOFF_MAX_MS,
                    last_failure_secs_ago: now.saturating_sub(*last),
                }
            })
            .collect();
        v.sort_by(|a, b| b.failures.cmp(&a.failures));
        v
    };

    let throttled_ips = {
        let map = UNAUTH_RATE.lock().unwrap();
        let mut v: Vec<ThrottledIp> = map
            .iter()
            .filter_map(|(ip, b)| {
                let elapsed = now_ms_v.saturating_sub(b.last_ms) as f64 / 1000.0;
                let tokens =
                    (b.tokens + elapsed * UNAUTH_REFILL_PER_SEC).min(UNAUTH_BUCKET_CAPACITY);
                // Only surface IPs still below full budget -- a bucket at capacity is
                // an idle, unremarkable source.
                if tokens < UNAUTH_BUCKET_CAPACITY - 0.5 {
                    Some(ThrottledIp {
                        ip: ip.clone(),
                        tokens: (tokens * 10.0).round() / 10.0,
                        shedding: tokens < 1.0,
                    })
                } else {
                    None
                }
            })
            .collect();
        v.sort_by(|a, b| a.tokens.partial_cmp(&b.tokens).unwrap_or(std::cmp::Ordering::Equal));
        v
    };

    SecuritySnapshot {
        now_secs: now,
        counters: security_counters(),
        config: SecurityConfig {
            spray_ip_window_secs: SPRAY_IP_WINDOW_SECS,
            spray_ip_max_users: SPRAY_IP_MAX_USERS,
            spray_ip_cooldown_secs: SPRAY_IP_COOLDOWN_SECS,
            spray_global_window_secs: SPRAY_GLOBAL_WINDOW_SECS,
            spray_global_max_users: SPRAY_GLOBAL_MAX_USERS,
            spray_global_cooldown_secs: SPRAY_GLOBAL_COOLDOWN_SECS,
            backoff_max_ms: LOGIN_BACKOFF_MAX_MS,
            unauth_bucket_capacity: UNAUTH_BUCKET_CAPACITY,
            unauth_refill_per_sec: UNAUTH_REFILL_PER_SEC,
        },
        global_tripwire,
        ip_blocks,
        backoff_accounts,
        throttled_ips,
    }
}

/// Operator control: lift the per-IP spray cooldown for `ip`. Returns true if an
/// entry existed (removing it clears both the counting window and the cooldown, so
/// the source starts clean). Use when a shared/NAT egress tripped the gate.
pub fn clear_ip_spray_block(ip: &str) -> bool {
    SPRAY_BY_IP.lock().unwrap().remove(ip).is_some()
}

/// Operator control: lift the fleet-wide spray tripwire immediately.
pub fn clear_global_tripwire() {
    *SPRAY_GLOBAL.lock().unwrap() = SprayWindow::default();
}

/// Operator control: reset an account's login-failure backoff. Returns true if the
/// account had a live failure counter.
pub fn clear_backoff(username: &str) -> bool {
    LOGIN_FAILURES
        .lock()
        .unwrap()
        .remove(&normalize_lookup_username(username))
        .is_some()
}

/// Operator control: refill an IP's unauth token bucket (drop its entry so its next
/// request starts at full budget). Returns true if the IP was being tracked.
pub fn clear_unauth_throttle(ip: &str) -> bool {
    UNAUTH_RATE.lock().unwrap().remove(ip).is_some()
}

/// Test hook: forget all spray + rate-limit state. Not used at runtime.
#[cfg(test)]
fn reset_spray_state() {
    SPRAY_BY_IP.lock().unwrap().clear();
    *SPRAY_GLOBAL.lock().unwrap() = SprayWindow::default();
    UNAUTH_RATE.lock().unwrap().clear();
    LOGIN_FAILURES.lock().unwrap().clear();
    SEC_UNAUTH_SHED.store(0, std::sync::atomic::Ordering::Relaxed);
    SEC_IP_SPRAY_TRIPS.store(0, std::sync::atomic::Ordering::Relaxed);
    SEC_GLOBAL_SPRAY_TRIPS.store(0, std::sync::atomic::Ordering::Relaxed);
    SEC_BACKOFF_CAP_HITS.store(0, std::sync::atomic::Ordering::Relaxed);
    SEC_PRE_BIND_REFUSALS.store(0, std::sync::atomic::Ordering::Relaxed);
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

/// The identity an LDAP server reports for the current connection (RFC 4532
/// "Who am I?"). `dn:` carries a distinguished name, `u:` a directory-specific
/// user string -- Active Directory answers `u:DOMAIN\\sAMAccountName`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthzId {
    Dn(String),
    User(String),
}

/// Parse an authzid. Anything that is neither form is not an identity we are
/// willing to act on, so it comes back as None and the caller falls back to the
/// (tightened) search path rather than guessing.
pub fn parse_authzid(authzid: &str) -> Option<AuthzId> {
    let s = authzid.trim();
    if let Some(dn) = s.strip_prefix("dn:") {
        let dn = dn.trim();
        if !dn.is_empty() {
            return Some(AuthzId::Dn(dn.to_owned()));
        }
        return None;
    }
    if let Some(u) = s.strip_prefix("u:") {
        let u = u.trim();
        if !u.is_empty() {
            return Some(AuthzId::User(u.to_owned()));
        }
        return None;
    }
    None
}

/// Prefer sAMAccountName, then userPrincipalName, then the raw input, for the
/// canonical username used everywhere else.
pub fn canonical_username(attrs: &HashMap<String, Vec<String>>, raw_input: &str) -> String {
    let sam = first_attr(attrs, "sAMAccountName");
    let upn = first_attr(attrs, "userPrincipalName");
    // `uid` is the standard account-name attribute outside Active Directory
    // (inetOrgPerson/posixAccount). It is directory-supplied like the other two, so
    // consulting it costs nothing on AD -- where sAMAccountName wins anyway -- and is
    // what lets a non-AD directory produce a canonical name at all now that the raw
    // input is no longer an acceptable fallback (SEC-8).
    let uid = first_attr(attrs, "uid");
    let chosen = if !sam.is_empty() {
        sam
    } else if !upn.is_empty() {
        upn
    } else if !uid.is_empty() {
        uid
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

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
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
        "uid",
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
    "uid",
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

/// RFC 4532 "Who am I?": ask the directory which identity this connection is bound
/// as. `None` means the server did not answer usefully -- the caller must then fall
/// back to a search and treat the result with suspicion, never assume success.
///
/// The response value is read by hand rather than through `Exop::parse`, which
/// panics on an absent or non-UTF-8 value; a hostile or merely odd directory must
/// not be able to take the server down.
#[cfg(feature = "nemo-ldap")]
async fn ldap_whoami(ldap: &mut ldap3::Ldap) -> Option<AuthzId> {
    use ldap3::exop::WhoAmI;
    let (exop, _res) = match ldap.extended(WhoAmI).await {
        Ok(r) => match r.success() {
            Ok(v) => v,
            Err(err) => {
                log::debug!("LDAP Who-am-I refused: {}", err);
                return None;
            }
        },
        Err(err) => {
            log::debug!("LDAP Who-am-I failed: {}", err);
            return None;
        }
    };
    let raw = exop.val?;
    let authzid = String::from_utf8(raw).ok()?;
    let parsed = parse_authzid(&authzid);
    if parsed.is_none() && !authzid.trim().is_empty() {
        log::warn!("LDAP Who-am-I returned an unrecognised authzid: {:?}", authzid);
    }
    parsed
}

/// Search that insists on exactly one entry. Zero matches and several matches are
/// both "could not identify", which is the only safe reading when the answer picks
/// which account a caller becomes.
#[cfg(feature = "nemo-ldap")]
async fn search_one(
    ldap: &mut ldap3::Ldap,
    base: &str,
    scope: ldap3::Scope,
    filter: &str,
    attr_list: &[&str],
) -> Option<ldap3::SearchEntry> {
    let sr = match ldap.search(base, scope, filter, attr_list.to_vec()).await {
        Ok(sr) => sr,
        Err(err) => {
            log::debug!("LDAP search under {} failed: {}", base, err);
            return None;
        }
    };
    let (entries, _res) = match sr.success() {
        Ok(v) => v,
        Err(err) => {
            log::debug!("LDAP search under {} rejected: {}", base, err);
            return None;
        }
    };
    if entries.len() != 1 {
        if entries.len() > 1 {
            log::warn!(
                "LDAP search under {} matched {} entries where exactly one was required",
                base,
                entries.len()
            );
        }
        return None;
    }
    entries
        .into_iter()
        .next()
        .map(ldap3::SearchEntry::construct)
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
    // SEC-8: the directory-confirmed identity, used as the canonical-name fallback
    // in place of the raw input. Stays empty unless RFC 4532 supplied it.
    let mut identity = String::new();
    let attr_list = vec![
        "distinguishedName",
        "sAMAccountName",
        "userPrincipalName",
        "uid",
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

        // SEC-8: exactly one, not the first of several. A filter that matches two
        // accounts is an ambiguity, and picking one of them is how you bind as the
        // wrong user. L-fix (user enumeration): an unknown username must still be
        // indistinguishable from a wrong password in the client-visible error, so the
        // detail stays in the server log.
        if entries.len() != 1 {
            log::warn!(
                "LDAP login: filter for user '{}' matched {} directory entries; refusing \
                 (exactly one is required)",
                username,
                entries.len(),
            );
            return Err("invalid username or password".to_owned());
        }
        let entry = entries.into_iter().next().ok_or_else(|| {
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

        // SEC-8: the bind proved the PASSWORD. It did NOT prove which account the
        // typed name belongs to. The old follow-up search was filtered by that same
        // typed string, so an unusual user_search_filter could resolve it to a
        // different entry than the one that actually bound -- and when the search was
        // skipped (no base DN) or simply failed, canonical_username fell all the way
        // back to the raw input. The allowlist was then matched against a name the
        // user chose rather than one the directory confirmed.
        //
        // So ask the directory who it thinks we are (RFC 4532, which Active Directory
        // has answered since 2003) and act only on that. AD replies
        // `u:DOMAIN\sAMAccountName`, which normalises to exactly the account name the
        // allowlist is keyed on -- no search needed at all in the common case.
        let confirmed = ldap_whoami(&mut ldap).await;
        let base = cfg.base_dn.trim();
        match &confirmed {
            Some(AuthzId::Dn(bound_dn)) => {
                // Authoritative DN: read the account's own attributes from it, not from
                // whatever a filter on the typed name happens to match.
                dn = bound_dn.clone();
                if let Some(se) = search_one(&mut ldap, bound_dn, Scope::Base, "(objectClass=*)", &attr_list).await {
                    attrs = se.attrs;
                }
                if attrs.is_empty() {
                    let _ = ldap.unbind().await;
                    log::warn!(
                        "LDAP login: the directory reported the bound DN as '{}' but its \
                         attributes could not be read, so the account's real login name is \
                         unknown. Refusing rather than trusting the typed name.",
                        bound_dn
                    );
                    return Err("invalid username or password".to_owned());
                }
            }
            Some(AuthzId::User(reported)) => {
                // Authoritative name. Enrich with profile attributes if we can, but
                // filter by the CONFIRMED name, and drop the entry if it disagrees.
                identity = normalize_lookup_username(reported);
                if !base.is_empty() {
                    let filter =
                        build_search_filter(&cfg.user_search_filter, reported, &cfg.windows_domain);
                    if let Some(se) =
                        search_one(&mut ldap, base, Scope::Subtree, &filter, &attr_list).await
                    {
                        if canonical_username(&se.attrs, &identity) == identity {
                            dn = se.dn.clone();
                            attrs = se.attrs;
                        } else {
                            log::warn!(
                                "LDAP login: the directory confirmed '{}' but the profile search \
                                 matched a different entry ('{}'); using the confirmed identity \
                                 and dropping the profile attributes",
                                identity,
                                se.dn,
                            );
                        }
                    }
                }
            }
            None => {
                // The directory does not answer RFC 4532. Fall back to the search, but
                // tightened: exactly one entry, and its canonical name must be the
                // account that actually bound. Ambiguity is refused, never resolved.
                if base.is_empty() {
                    let _ = ldap.unbind().await;
                    log::warn!(
                        "LDAP login: {} answered no RFC 4532 Who-am-I and no base DN is \
                         configured, so a bound account cannot be identified at all. Set the \
                         base DN (or a service bind DN) to enable login.",
                        url
                    );
                    return Err(
                        "this server cannot confirm your account; ask your administrator to \
                         finish the directory configuration"
                            .to_owned(),
                    );
                }
                let filter =
                    build_search_filter(&cfg.user_search_filter, username, &cfg.windows_domain);
                let expected = normalize_lookup_username(&principal);
                match search_one(&mut ldap, base, Scope::Subtree, &filter, &attr_list).await {
                    Some(se) => {
                        let found = canonical_username(&se.attrs, "");
                        if found.is_empty() || found != expected {
                            let _ = ldap.unbind().await;
                            log::warn!(
                                "LDAP login: the entry matched for '{}' resolves to '{}', which is \
                                 not the account that bound ('{}'). Refusing.",
                                username,
                                found,
                                expected,
                            );
                            return Err("invalid username or password".to_owned());
                        }
                        dn = se.dn.clone();
                        attrs = se.attrs;
                    }
                    None => {
                        let _ = ldap.unbind().await;
                        log::warn!(
                            "LDAP login: '{}' bound successfully but could not be uniquely \
                             identified in the directory (no match, or more than one). Refusing.",
                            username
                        );
                        return Err("invalid username or password".to_owned());
                    }
                }
            }
        }
        let _ = ldap.unbind().await;
    }

    // SEC-8: the fallback is the identity the DIRECTORY confirmed, never the raw
    // input. It is empty on every path where `attrs` is authoritative, so an entry
    // with no sAMAccountName/userPrincipalName fails closed below instead of
    // silently adopting whatever was typed.
    let canonical = canonical_username(&attrs, &identity);
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

    /// The spray / rate-limit / backoff limiters all key off process-global statics,
    /// so the tests that drive them (and call `reset_spray_state`) must not run at the
    /// same time or one will clear or trip state out from under another. Every such
    /// test takes this lock first to serialise them. `parking_lot`-free: a poisoned
    /// std Mutex from a panicking test is fine here -- we only need mutual exclusion.
    static SPRAY_TEST_GUARD: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

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
            claimed_at: String::new(),
        }];
        let id_b = device_key_id_for(&key_b, &existing);
        assert_ne!(id_b, id_a, "colliding prefix must not reuse the id");
        assert!(id_b.starts_with(shared));
        // Re-deriving for the SAME key keeps its id stable.
        assert_eq!(device_key_id_for(&key_a, &existing), id_a);
    }

    // TASK #14 + M1-CLAIM: a bound key opens for exactly its peer; an UNBOUND key for
    // nobody -- it may at most ASK, and only when claiming is on. The rule both
    // enforcement points share, in its precedence order.
    #[test]
    fn device_key_binding_decision_covers_the_four_arms_in_order() {
        use BindingDecision::*;
        // 1. A bound key authenticates exactly its peer, whatever the two switches say.
        for allow in [false, true] {
            for claim in [false, true] {
                assert_eq!(device_key_binding_decision("peer-a", "peer-a", allow, claim), Proven);
                assert!(matches!(
                    device_key_binding_decision("peer-a", "peer-b", allow, claim),
                    Refused(_)
                ));
            }
        }
        // 2. The CLI escape hatch still means "unbound authenticates anything", and
        //    files no claim -- an operator who asked for the loose rule keeps it.
        assert_eq!(device_key_binding_decision("", "peer-a", true, true), Proven);
        assert_eq!(device_key_binding_decision("", "peer-a", true, false), Proven);
        // 3. Otherwise an unbound key may only ASK (the caller verifies the signature
        //    and then files a pending claim; it is still refused meanwhile).
        assert_eq!(device_key_binding_decision("", "peer-a", false, true), ClaimOnProof);
        // ... and cannot ask on behalf of no id at all.
        assert!(matches!(
            device_key_binding_decision("", "", false, true),
            Refused(_)
        ));
        // 4. With claiming off, TASK #14 exactly as it was: an unbound key
        //    authenticates NOTHING, because "blank = any id" was a fleet-wide
        //    skeleton key.
        let err = match device_key_binding_decision("", "peer-a", false, false) {
            Refused(e) => e,
            other => panic!("an unbound key must authenticate nothing: {:?}", other),
        };
        assert!(err.contains("no peer-id binding"), "{}", err);
        let err = match device_key_binding_decision("peer-a", "peer-b", false, false) {
            Refused(e) => e,
            other => panic!("a bound key must not authenticate another peer: {:?}", other),
        };
        assert!(err.contains("bound to peer"), "{}", err);
    }

    #[test]
    fn ldap_tls_verify_off_requires_explicit_override() {
        assert_eq!(ldap_tls_verify_effective(true, false), Ok(true));
        assert_eq!(ldap_tls_verify_effective(true, true), Ok(true));
        assert_eq!(ldap_tls_verify_effective(false, true), Ok(false));
        assert!(ldap_tls_verify_effective(false, false).is_err());
    }

    // Layer 1 / Rollout: the device key is mandatory, so a FRESH config (no file, or
    // a file that omits the field) is fail-closed, while a deployed file that stores
    // an explicit choice keeps it on upgrade — the stored value is the rollout guard.
    #[test]
    fn device_key_switches_default_true_and_keep_stored_false() {
        let fresh = IntegrationConfig::default();
        assert!(fresh.require_device_key);
        assert!(fresh.strip_unsealed_secrets);
        // Field omitted (file last written by a build that predates it) == fresh.
        let omitted: IntegrationConfig = serde_json::from_str("{}").unwrap();
        assert!(omitted.require_device_key);
        assert!(omitted.strip_unsealed_secrets);
        // An explicit stored `false` survives the upgrade untouched.
        let stored: IntegrationConfig = serde_json::from_str(
            r#"{"require_device_key": false, "strip_unsealed_secrets": false}"#,
        )
        .unwrap();
        assert!(!stored.require_device_key);
        assert!(!stored.strip_unsealed_secrets);
        // persist() serializes every field, so a file written by this build always
        // carries both keys explicitly; the omitted-field rule cannot apply to it.
        let text = serde_json::to_string(&fresh).unwrap();
        assert!(text.contains("\"require_device_key\":true"));
        assert!(text.contains("\"strip_unsealed_secrets\":true"));
    }


    // ---- M1-CLAIM: first-use binding, with operator confirmation -------------
    //
    // These tests run against the live CONFIG (pin_device_key_for_test), which is safe
    // only because persist() is a no-op under cfg(test) -- a test that reached the real
    // one once wrote a nemo_integration.json full of test keys into the repo checkout.
    // Each test uses its own public key, since the global config is shared.

    fn test_key(tag: &str) -> String {
        // Shaped like a real base64 Ed25519 key, but only ever compared as a string
        // here: these tests exercise the claim bookkeeping, not the signature check
        // (that one lives in nemo_management, through verify_device_signature).
        format!("{:A<44}", tag)
    }

    fn pin_claimable(tag: &str) -> String {
        let public_key = test_key(tag);
        pin_device_key_for_test(DeviceKey {
            id: tag.to_owned(),
            label: tag.to_owned(),
            public_key: public_key.clone(),
            created_at: String::new(),
            peer_id: String::new(),
            claimed_at: String::new(),
        });
        public_key
    }

    fn drop_claimable(public_key: &str) {
        unpin_device_key_for_test(public_key);
        let mut cfg = CONFIG.lock().unwrap();
        cfg.pending_device_key_claims
            .retain(|c| c.public_key != public_key);
    }

    // The core of the design: proving an unbound key does NOT authenticate, it files a
    // request. Nothing is bound until the operator confirms, and the confirmation binds
    // the key to exactly that one id.
    #[test]
    fn first_use_files_a_claim_and_only_approval_binds() {
        let pk = pin_claimable("claim1");
        assert_eq!(
            register_pending_claim(&pk, "111111111", "settings poll", "t0".to_owned()),
            PendingOutcome::New
        );
        // Still unbound: a pending claim grants nothing.
        assert_eq!(device_key_binding(&pk).as_deref(), Some(""));
        assert_eq!(
            device_key_binding_decision("", "111111111", false, true),
            BindingDecision::ClaimOnProof,
            "the client must keep being refused (and keep asking) while it waits"
        );
        // Re-polling every 30s is one request, not a new one each time.
        assert_eq!(
            register_pending_claim(&pk, "111111111", "settings poll", "t1".to_owned()),
            PendingOutcome::Repeat
        );
        let claim = pending_claim_for_peer("111111111").expect("the request must be visible");
        assert_eq!(claim.key_id, "claim1");
        assert_eq!(claim.attempts, 2);
        assert_eq!(claim.first_seen, "t0");
        assert_eq!(claim.last_seen, "t1");

        // The operator confirms: NOW it binds, and the request is gone.
        let key = approve_device_key_claim("claim1", "111111111", "t2".to_owned())
            .expect("approval must bind");
        assert_eq!(key.peer_id, "111111111");
        assert_eq!(key.claimed_at, "t2", "a first-use binding is marked as claimed");
        assert!(pending_claim_for_peer("111111111").is_none());
        assert_eq!(device_key_binding(&pk).as_deref(), Some("111111111"));

        // And from here it is an ordinary bound key: it authenticates that id and
        // nothing else, which is the whole point of binding on first use.
        assert_eq!(
            device_key_binding_decision("111111111", "222222222", false, true),
            BindingDecision::Refused(
                "device key is bound to peer 111111111 but the client claims 222222222".to_owned()
            )
        );
        drop_claimable(&pk);
    }

    // Two machines with the same token: both may ask, only one can be approved, and the
    // loser is refused rather than overwriting the winner.
    #[test]
    fn one_token_binds_one_machine_even_with_two_claims() {
        let pk = pin_claimable("claim2");
        assert_eq!(
            register_pending_claim(&pk, "111111111", "rendezvous handshake", "t0".to_owned()),
            PendingOutcome::New
        );
        assert_eq!(
            register_pending_claim(&pk, "222222222", "rendezvous handshake", "t0".to_owned()),
            PendingOutcome::New
        );
        approve_device_key_claim("claim2", "111111111", "t1".to_owned()).expect("first wins");
        // Approving the other one is impossible: its row went with the key's binding,
        // and the binding re-check under the write lock refuses it anyway.
        assert!(approve_device_key_claim("claim2", "222222222", "t2".to_owned()).is_err());
        assert_eq!(device_key_binding(&pk).as_deref(), Some("111111111"));
        // The race the lock actually settles, at the layer that writes it.
        let mut keys = vec![DeviceKey {
            id: "r".to_owned(),
            label: String::new(),
            public_key: "race".to_owned(),
            created_at: String::new(),
            peer_id: String::new(),
            claimed_at: String::new(),
        }];
        assert_eq!(claim_device_key_in(&mut keys, "race", "111111111", "t"), Ok(true));
        assert!(claim_device_key_in(&mut keys, "race", "222222222", "t").is_err());
        // The winner re-polling is not a second claim.
        assert_eq!(claim_device_key_in(&mut keys, "race", "111111111", "t"), Ok(false));
        drop_claimable(&pk);
    }

    // A denial has to STICK: the client re-polls every 30s, so a forgotten denial would
    // put the row back on the dashboard half a minute after it was dismissed. And it is
    // persisted (here: survives in the config the same way), so a restart does not
    // silently re-open the question.
    #[test]
    fn a_denied_claim_is_not_re_raised_until_it_is_forgotten() {
        let pk = pin_claimable("claim3");
        register_pending_claim(&pk, "333333333", "settings poll", "t0".to_owned());
        deny_device_key_claim("claim3", "333333333").expect("deny must find the row");
        assert_eq!(
            register_pending_claim(&pk, "333333333", "settings poll", "t1".to_owned()),
            PendingOutcome::Denied
        );
        assert!(pending_claim_for_peer("333333333").unwrap().denied);
        // A denied row cannot be approved by accident -- it is still a row, so this is
        // the operator changing their mind, which is allowed and explicit.
        assert!(approve_device_key_claim("claim3", "333333333", "t2".to_owned()).is_ok());
        assert_eq!(device_key_binding(&pk).as_deref(), Some("333333333"));
        drop_claimable(&pk);

        // Forgetting it lets the client ask again.
        let pk = pin_claimable("claim4");
        register_pending_claim(&pk, "444444444", "settings poll", "t0".to_owned());
        deny_device_key_claim("claim4", "444444444").unwrap();
        forget_device_key_claim("claim4", "444444444").expect("forget must find the row");
        assert!(forget_device_key_claim("claim4", "444444444").is_err());
        assert_eq!(
            register_pending_claim(&pk, "444444444", "settings poll", "t1".to_owned()),
            PendingOutcome::New
        );
        drop_claimable(&pk);
    }

    // The table is persisted, so one key must not be able to fill it with ids. A claim
    // costs a valid signature over a pinned key, so this is not an open flood -- it is
    // the bound on a client (or a leaked key) that cycles its id.
    #[test]
    fn pending_claims_are_capped_per_key() {
        let pk = pin_claimable("claim5");
        for i in 0..MAX_PENDING_PER_KEY {
            assert_eq!(
                register_pending_claim(&pk, &format!("peer-{:04}", i), "poll", "t".to_owned()),
                PendingOutcome::New
            );
        }
        assert_eq!(
            register_pending_claim(&pk, "peer-9999", "poll", "t".to_owned()),
            PendingOutcome::Full
        );
        // An id already in the list still gets through: a waiting client must not be
        // starved by its own neighbours.
        assert_eq!(
            register_pending_claim(&pk, "peer-0000", "poll", "t2".to_owned()),
            PendingOutcome::Repeat
        );
        drop_claimable(&pk);
    }

    // The global cap is the second half of that bound. It makes room by dropping the
    // OLDEST row that is merely waiting, and never a denied one: evicting a denial would
    // let that client re-raise its request on the next poll, which is the one thing
    // `denied` exists to prevent. Pure, so it does not touch the shared live table.
    #[test]
    fn the_global_pending_cap_evicts_the_oldest_waiting_row_not_a_denial() {
        let mut claims: Vec<PendingDeviceKeyClaim> = Vec::new();
        for i in 0..MAX_PENDING_CLAIMS {
            claims.push(PendingDeviceKeyClaim {
                key_id: format!("k{}", i),
                public_key: format!("pk{}", i),
                peer_id: format!("peer-{:04}", i),
                // Oldest first, and the oldest of all is a DENIED row.
                first_seen: format!("t{:04}", i),
                last_seen: format!("t{:04}", i),
                attempts: 1,
                via: "poll".to_owned(),
                denied: i == 0,
            });
        }
        assert_eq!(
            register_pending_claim_in(
                &mut claims, "knew", "pknew", "999999999", "poll", "t9999"
            ),
            PendingOutcome::New
        );
        assert_eq!(claims.len(), MAX_PENDING_CLAIMS);
        assert!(
            claims.iter().any(|c| c.peer_id == "peer-0000" && c.denied),
            "the denial must survive the eviction"
        );
        assert!(
            !claims.iter().any(|c| c.peer_id == "peer-0001"),
            "the oldest WAITING row is the one that goes"
        );
        assert!(claims.iter().any(|c| c.peer_id == "999999999"));

        // A table that is full of denials refuses rather than forgetting one.
        claims.iter_mut().for_each(|c| c.denied = true);
        assert_eq!(
            register_pending_claim_in(
                &mut claims, "kfull", "pkfull", "888888888", "poll", "t9999"
            ),
            PendingOutcome::Full
        );
    }

    // The operator types the id the client SHOWS, and the client shows it grouped in
    // threes. Refusing that as malformed would be a support call every time, so the
    // operator-typed paths normalize first — while the request path keeps comparing
    // ids byte-for-byte.
    #[test]
    fn a_grouped_peer_id_is_the_same_id() {
        assert_eq!(normalize_peer_id("456 456 456"), "456456456");
        assert_eq!(normalize_peer_id("  456456456  "), "456456456");
        assert_eq!(normalize_peer_id("456\t456\n456"), "456456456");
        // Non-breaking space, as pasted out of a GUI.
        assert_eq!(normalize_peer_id("456\u{a0}456\u{a0}456"), "456456456");
        assert!(valid_peer_id(&normalize_peer_id("456 456 456")));
        // Normalising must not invent a valid id out of junk.
        assert!(!valid_peer_id(&normalize_peer_id("12 34")));
        assert!(!valid_peer_id(&normalize_peer_id("456 456 45!")));
        assert!(!valid_peer_id(&normalize_peer_id("   ")));

        // The editable "Bound to ID" field takes the grouped form and stores it compact.
        let mut keys = vec![DeviceKey {
            id: "k1".to_owned(),
            label: "Reception".to_owned(),
            public_key: "pk1".to_owned(),
            created_at: String::new(),
            peer_id: String::new(),
            claimed_at: "2026-10-16T00:00:00Z".to_owned(),
        }];
        let updated = set_device_key_peer_id_in(&mut keys, "k1", "456 456 456").unwrap();
        assert_eq!(updated.peer_id, "456456456");
        // An operator typing the id is not a first-use claim, so the stamp is cleared.
        assert_eq!(updated.claimed_at, "");
        // Junk is still refused, and leaves the stored binding alone.
        let err = set_device_key_peer_id_in(&mut keys, "k1", "12 34").unwrap_err();
        assert!(err.contains("not a TBFDesk id"), "{}", err);
        assert_eq!(keys[0].peer_id, "456456456");
        // Whitespace-only clears the binding rather than becoming a junk id.
        assert_eq!(
            set_device_key_peer_id_in(&mut keys, "k1", " \u{a0} ")
                .unwrap()
                .peer_id,
            ""
        );
    }

    // A junk id must never reach the persisted table (it ends up in the dashboard, the
    // log and an API response), and a key deleted between the decision and the claim
    // fails closed.
    #[test]
    fn a_claim_needs_a_real_peer_id_and_a_pinned_key() {
        assert!(valid_peer_id("111111111"));
        assert!(valid_peer_id("desk-01_a"));
        assert!(!valid_peer_id("short"));
        assert!(!valid_peer_id(""));
        // Still refused HERE: a client's own reported id must match byte-for-byte, so
        // only the operator-typed paths normalize (see the test below).
        assert!(!valid_peer_id("has spaces"));
        assert!(!valid_peer_id("semi;colon"));
        assert!(!valid_peer_id(&"x".repeat(65)));

        let pk = pin_claimable("claim6");
        assert_eq!(
            register_pending_claim(&pk, "bad id", "poll", "t".to_owned()),
            PendingOutcome::Rejected
        );
        assert_eq!(
            register_pending_claim("not-pinned-at-all", "555555555", "poll", "t".to_owned()),
            PendingOutcome::Rejected
        );
        drop_claimable(&pk);
    }

    // Binding by hand answers the pending question; CLEARING the binding re-arms the key
    // as a fresh token, and a stale denial must not then refuse the first client that
    // proves it.
    #[test]
    fn editing_the_binding_clears_the_keys_pending_rows() {
        let pk = pin_claimable("claim7");
        register_pending_claim(&pk, "666666666", "poll", "t0".to_owned());
        deny_device_key_claim("claim7", "666666666").unwrap();
        let key = set_device_key_peer_id("claim7", "777777777").expect("bind by hand");
        assert_eq!(key.peer_id, "777777777");
        assert_eq!(key.claimed_at, "", "the operator typed this one, it is not a claim");
        assert!(pending_claim_for_peer("666666666").is_none());
        // Cleared: claimable again, with no memory of the old denial.
        set_device_key_peer_id("claim7", "").expect("clear the binding");
        assert_eq!(
            register_pending_claim(&pk, "666666666", "poll", "t1".to_owned()),
            PendingOutcome::New
        );
        assert!(set_device_key_peer_id("claim7", "no").is_err(), "junk id refused");
        drop_claimable(&pk);
    }

    #[test]
    fn raw_username_strips_domain_decorations() {
        assert_eq!(raw_username("EXAMPLE\\jdoe"), "jdoe");
        assert_eq!(raw_username("jdoe@example.local"), "jdoe");
        assert_eq!(raw_username("  jdoe  "), "jdoe");
        assert_eq!(raw_username("jdoe"), "jdoe");
    }

    // SEC-8. The allowlist is keyed on the normalised bare account name, so what
    // matters is that an AD-shaped authzid lands on exactly that -- and that anything
    // we do not recognise is None rather than a guess.
    #[test]
    fn authzid_is_parsed_only_in_its_two_defined_forms() {
        // Active Directory's answer.
        assert_eq!(
            parse_authzid("u:CORP\\jdoe"),
            Some(AuthzId::User("CORP\\jdoe".to_owned()))
        );
        match parse_authzid("u:CORP\\jdoe").unwrap() {
            AuthzId::User(u) => assert_eq!(normalize_lookup_username(&u), "jdoe"),
            other => panic!("{:?}", other),
        }
        // OpenLDAP's answer.
        assert_eq!(
            parse_authzid("dn:uid=jdoe,ou=people,dc=corp,dc=local"),
            Some(AuthzId::Dn("uid=jdoe,ou=people,dc=corp,dc=local".to_owned()))
        );
        assert_eq!(parse_authzid("  dn:cn=x,dc=y  "), Some(AuthzId::Dn("cn=x,dc=y".to_owned())));
        // An anonymous bind reports an empty authzid: not an identity.
        assert_eq!(parse_authzid(""), None);
        assert_eq!(parse_authzid("dn:"), None);
        assert_eq!(parse_authzid("u:"), None);
        assert_eq!(parse_authzid("u: "), None);
        // Neither defined form -- must not be treated as a name.
        assert_eq!(parse_authzid("jdoe"), None);
        assert_eq!(parse_authzid("dn=cn=x"), None);
        assert_eq!(parse_authzid("U:jdoe"), None);
    }

    // SEC-8: with no directory-confirmed identity the fallback is empty, so an entry
    // carrying neither sAMAccountName nor userPrincipalName yields an empty canonical
    // name -- which authenticate_ldap refuses, instead of adopting the typed string.
    #[test]
    fn canonical_username_fails_closed_without_a_confirmed_identity() {
        assert_eq!(canonical_username(&HashMap::new(), ""), "");
        let mut attrs = HashMap::new();
        attrs.insert("displayName".to_owned(), vec!["John Doe".to_owned()]);
        assert_eq!(canonical_username(&attrs, ""), "");
        // A confirmed identity IS used when attributes are missing.
        assert_eq!(canonical_username(&attrs, "jdoe"), "jdoe");
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
    fn permissions_version_check_refuses_only_a_stale_version() {
        assert!(check_permissions_version(Some(3), 3).is_ok());
        assert!(check_permissions_version(None, 3).is_ok());
        let err = check_permissions_version(Some(2), 3).unwrap_err();
        assert!(err.contains("version mismatch"), "{}", err);
        assert!(check_permissions_version(Some(4), 3).is_err());
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

    // SEC-10. The limiter state is process-global; this test and
    // `security_snapshot_reflects_...` both drive it, so both hold SPRAY_TEST_GUARD to
    // run serially (otherwise one's reset/trip races the other under the parallel runner).
    #[test]
    fn spray_limiter_counts_distinct_usernames_and_trips_before_the_bind() {
        let _guard = SPRAY_TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        reset_spray_state();

        // A user fat-fingering the SAME account never trips it, however often.
        for _ in 0..50 {
            note_login_spray(Some("10.0.0.5"), "alice");
        }
        assert_eq!(login_spray_block(Some("10.0.0.5")), None);

        // Walking distinct accounts from one source does, on the 11th.
        for n in 0..SPRAY_IP_MAX_USERS {
            assert!(!note_login_spray(Some("10.0.0.9"), &format!("user{}", n)));
        }
        assert_eq!(login_spray_block(Some("10.0.0.9")), None);
        assert!(note_login_spray(Some("10.0.0.9"), "user-over"));
        assert!(login_spray_block(Some("10.0.0.9")).is_some());
        // Scoped to that source only; the rest of the fleet keeps signing in.
        assert_eq!(login_spray_block(Some("10.0.0.5")), None);
        assert_eq!(login_spray_block(None), None);

        // Username forms that normalise to the same account count once, so a
        // sprayer cannot pad the window with decorations of one name.
        reset_spray_state();
        for form in ["bob", "CORP\\bob", "bob@corp.local", "BOB"] {
            note_login_spray(Some("10.0.0.7"), form);
        }
        assert_eq!(
            SPRAY_BY_IP.lock().unwrap().get("10.0.0.7").unwrap().users.len(),
            1
        );

        // The global tripwire catches a sprayer that rotates its source address,
        // where no single per-IP window would ever fill.
        reset_spray_state();
        for n in 0..SPRAY_GLOBAL_MAX_USERS {
            assert!(!note_login_spray(Some(&format!("10.1.0.{}", n)), &format!("g{}", n)));
        }
        assert_eq!(login_spray_block(Some("10.1.0.200")), None);
        assert!(note_login_spray(Some("10.1.0.200"), "g-over"));
        // Now every source is refused, including ones that never failed.
        assert!(login_spray_block(Some("10.9.9.9")).is_some());
        assert!(login_spray_block(None).is_some());

        reset_spray_state();
        assert_eq!(login_spray_block(None), None);

        // C1: the pre-gate per-source token bucket. Shares this one test because its
        // table is process-global too (reset_spray_state clears it).
        reset_spray_state();
        // No source IP: never shed (cannot be keyed) -- the device-key gate still runs.
        for _ in 0..100 {
            assert!(!unauth_rate_block(None));
        }
        // A rapid burst from one source: the first ~CAPACITY pass, then it sheds.
        let cap = UNAUTH_BUCKET_CAPACITY as usize;
        let mut passed = 0usize;
        for _ in 0..(cap + 20) {
            if !unauth_rate_block(Some("203.0.113.7")) {
                passed += 1;
            }
        }
        assert!(passed <= cap + 2, "burst not capped: {passed} passed");
        assert!(passed >= cap - 2, "a legitimate burst was wrongly shed: {passed}");
        assert!(
            unauth_rate_block(Some("203.0.113.7")),
            "a sustained flood from one source should stay shed"
        );
        // A different source has its own full bucket -- one flooder cannot starve others.
        assert!(!unauth_rate_block(Some("203.0.113.8")));
        reset_spray_state();
    }

    #[test]
    fn security_snapshot_reflects_blocks_and_controls_clear_them() {
        let _guard = SPRAY_TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        reset_spray_state();

        // Trip the per-IP spray gate: >SPRAY_IP_MAX_USERS distinct names from one IP.
        for n in 0..=SPRAY_IP_MAX_USERS {
            note_login_spray(Some("198.51.100.5"), &format!("victim{n}"));
        }
        // Drive one IP's unauth bucket to shedding so it shows as throttled.
        for _ in 0..(UNAUTH_BUCKET_CAPACITY as usize + 5) {
            unauth_rate_block(Some("198.51.100.9"));
        }
        // An account under backoff.
        for _ in 0..3 {
            note_login_failure("bob");
        }

        let snap = security_snapshot();
        // The spray trip is both counted and visible as a live block.
        assert_eq!(snap.counters.ip_spray_trips, 1, "one per-IP trip counted");
        assert!(
            snap.ip_blocks.iter().any(|b| b.ip == "198.51.100.5" && b.remaining_secs > 0),
            "the blocked IP must appear with time remaining"
        );
        // The flooded IP is shedding and surfaced as throttled; the shed counter moved.
        assert!(snap.counters.unauth_shed >= 1, "shed requests counted");
        assert!(
            snap.throttled_ips.iter().any(|t| t.ip == "198.51.100.9" && t.shedding),
            "the flooded IP must appear as shedding"
        );
        // The failing account is listed under backoff.
        assert!(
            snap.backoff_accounts.iter().any(|a| a.username == "bob" && a.failures == 3),
            "the backed-off account must be listed"
        );
        // Config is surfaced for the panel.
        assert_eq!(snap.config.spray_ip_max_users, SPRAY_IP_MAX_USERS);

        // Operator controls lift each block, and a snapshot taken after is clean.
        assert!(clear_ip_spray_block("198.51.100.5"));
        assert!(!clear_ip_spray_block("198.51.100.5"), "second clear is a no-op");
        assert!(clear_unauth_throttle("198.51.100.9"));
        assert!(clear_backoff("bob"));
        assert!(!clear_backoff("bob"), "second clear is a no-op");

        let after = security_snapshot();
        assert!(after.ip_blocks.is_empty(), "block lifted");
        assert!(after.backoff_accounts.is_empty(), "backoff cleared");
        assert!(
            after.throttled_ips.iter().all(|t| t.ip != "198.51.100.9"),
            "throttle reset -> bucket refills to full, no longer listed"
        );
        // Clearing a source does NOT rewrite the monotonic counters (they are an
        // audit trail of what has happened, not the current block set).
        assert_eq!(after.counters.ip_spray_trips, 1);

        // Global tripwire can be tripped and then lifted by the operator.
        for n in 0..=SPRAY_GLOBAL_MAX_USERS {
            note_login_spray(Some(&format!("10.9.9.{n}")), &format!("g{n}"));
        }
        assert!(security_snapshot().global_tripwire.active, "global tripwire active");
        clear_global_tripwire();
        assert!(!security_snapshot().global_tripwire.active, "global tripwire lifted");
        reset_spray_state();
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
