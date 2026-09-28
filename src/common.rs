use clap::App;
use hbb_common::{
    anyhow::{Context, Result}, log, ResultType
};
use ini::Ini;
use sodiumoxide::crypto::sign;
use std::{
    io::prelude::*,
    io::Read,
    net::SocketAddr,
    time::{Instant, SystemTime},
};

#[allow(dead_code)]
pub(crate) fn get_expired_time() -> Instant {
    let now = Instant::now();
    now.checked_sub(std::time::Duration::from_secs(3600))
        .unwrap_or(now)
}

#[allow(dead_code)]
pub(crate) fn test_if_valid_server(host: &str, name: &str) -> ResultType<SocketAddr> {
    use std::net::ToSocketAddrs;
    let res = if host.contains(':') {
        host.to_socket_addrs()?.next().context("")
    } else {
        format!("{}:{}", host, 0)
            .to_socket_addrs()?
            .next()
            .context("")
    };
    if res.is_err() {
        log::error!("Invalid {} {}: {:?}", name, host, res);
    }
    res
}

#[allow(dead_code)]
pub(crate) fn get_servers(s: &str, tag: &str) -> Vec<String> {
    let servers: Vec<String> = s
        .split(',')
        .filter(|x| !x.is_empty() && test_if_valid_server(x, tag).is_ok())
        .map(|x| x.to_owned())
        .collect();
    log::info!("{}={:?}", tag, servers);
    servers
}

#[allow(dead_code)]
#[inline]
fn arg_name(name: &str) -> String {
    name.to_uppercase().replace('_', "-")
}

#[allow(dead_code)]
pub fn init_args(args: &str, name: &str, about: &str) {
    let matches = App::new(name)
        .version(crate::version::VERSION)
        .author("Purslane Ltd. <info@rustdesk.com>")
        .about(about)
        .args_from_usage(args)
        .get_matches();
    if let Ok(v) = Ini::load_from_file(".env") {
        if let Some(section) = v.section(None::<String>) {
            section
                .iter()
                .for_each(|(k, v)| std::env::set_var(arg_name(k), v));
        }
    }
    if let Some(config) = matches.value_of("config") {
        if let Ok(v) = Ini::load_from_file(config) {
            if let Some(section) = v.section(None::<String>) {
                section
                    .iter()
                    .for_each(|(k, v)| std::env::set_var(arg_name(k), v));
            }
        }
    }
    for (k, v) in matches.args {
        if let Some(v) = v.vals.first() {
            std::env::set_var(arg_name(k), v.to_string_lossy().to_string());
        }
    }
}

#[allow(dead_code)]
#[inline]
pub fn get_arg(name: &str) -> String {
    get_arg_or(name, "".to_owned())
}

#[allow(dead_code)]
#[inline]
pub fn get_arg_or(name: &str, default: String) -> String {
    // arg_name yields NEMO-API-TOKEN, and that is the only spelling .env and clap ever
    // set. But systemd's EnvironmentFile cannot carry a dash in a key, so the shipped
    // unit could only reach us by re-passing the token on argv -- where it sat in
    // /proc/<pid>/cmdline, world-readable. Accept the underscore spelling too, so the
    // env file alone is enough and the argv bridge can go.
    let dashed = arg_name(name);
    std::env::var(&dashed)
        .or_else(|_| std::env::var(dashed.replace('-', "_")))
        .unwrap_or(default)
}

// TASK #16: the relay session grant. hbbs mints one per session it brokers and hands
// it to BOTH parties as the relay `uuid`; hbbr admits a RequestRelay only if its uuid
// is a grant signed with the server key that has not expired -- knowing the key (every
// client does) no longer joins a session. The expiry is the one clock in the path:
// hbbs and hbbr share a host in the shipped unit; 60s covers a dial plus hbbr's park.
// Layout: base64( nonce[16] || exp_be_u64[8] || sig[64] ), sig over DOMAIN||nonce||exp.
#[allow(dead_code)]
pub const RELAY_GRANT_TTL_SECS: u64 = 60;
const RELAY_GRANT_DOMAIN: &[u8] = b"tbfdesk-relay-grant-v1";
const RELAY_GRANT_LEN: usize = 16 + 8 + sign::SIGNATUREBYTES;

#[allow(dead_code)]
pub fn relay_grant_mint(sk: &sign::SecretKey, ttl_secs: u64) -> String {
    let nonce = *uuid::Uuid::new_v4().as_bytes();
    let exp = (now() + ttl_secs).to_be_bytes();
    let msg = [RELAY_GRANT_DOMAIN, &nonce[..], &exp[..]].concat();
    let sig = sign::sign_detached(&msg, sk);
    base64::encode([&nonce[..], &exp[..], sig.as_ref()].concat())
}

#[allow(dead_code)]
#[inline]
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|x| x.as_secs())
        .unwrap_or_default()
}

#[allow(dead_code)]
pub fn relay_grant_verify(pk: &sign::PublicKey, grant: &str) -> ResultType<()> {
    let raw = base64::decode(grant).context("relay grant is not base64")?;
    if raw.len() != RELAY_GRANT_LEN {
        hbb_common::bail!("relay grant has the wrong length");
    }
    let (nonce, rest) = raw.split_at(16);
    let (exp, sig) = rest.split_at(8);
    let sig = sign::Signature::from_bytes(sig)
        .ok()
        .context("relay grant signature is malformed")?;
    let msg = [RELAY_GRANT_DOMAIN, nonce, exp].concat();
    if !sign::verify_detached(&sig, &msg, pk) {
        hbb_common::bail!("relay grant signature does not verify");
    }
    let exp = u64::from_be_bytes(exp.try_into().context("relay grant expiry")?);
    if now() >= exp {
        hbb_common::bail!("relay grant expired");
    }
    Ok(())
}

// Review finding (HIGH): `id_ed25519` holds the rendezvous signing secret — the trust
// anchor the client verifies the --key-exchange offer with, and the same key the S-B
// sealing work is built on. It used to be written with File::create, i.e. mode 0644, so
// any local account on the hbbs host could read it and the compromise would be silent.
// Created 0600 now, and an existing key is tightened on every start (the same
// "fix a previously world-readable key" pattern used for the TLS key).
#[cfg(unix)]
fn restrict_key_file(path: &str) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(md) = std::fs::metadata(path) {
        if md.permissions().mode() & 0o077 != 0 {
            if std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).is_ok() {
                println!("Tightened permissions on {path} to 0600.");
            }
        }
    }
}

#[cfg(not(unix))]
fn restrict_key_file(_path: &str) {}

#[cfg(unix)]
fn create_private_file(path: &str) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_private_file(path: &str) -> std::io::Result<std::fs::File> {
    std::fs::File::create(path)
}

/// One attempt to read and parse `sk_file`. `Ok(None)` means "no file there yet",
/// which is the only outcome that should ever lead to generating one; a file that
/// exists but does not parse is `Err` and always fatal (never silently regenerated
/// -- that would be exactly the "lost key mints a new one nobody pinned" bug this
/// function exists to close).
fn read_sk(sk_file: &str) -> Result<Option<(String, sign::SecretKey)>, ()> {
    let mut file = match std::fs::File::open(sk_file) {
        Ok(f) => f,
        Err(_) => return Ok(None),
    };
    let mut contents = String::new();
    if file.read_to_string(&mut contents).is_err() {
        return Ok(None);
    }
    let contents = contents.trim();
    let sk = base64::decode(contents).unwrap_or_default();
    if sk.len() != sign::SECRETKEYBYTES {
        return Err(());
    }
    let mut tmp = [0u8; sign::SECRETKEYBYTES];
    tmp[..].copy_from_slice(&sk);
    let pk = base64::encode(&tmp[sign::SECRETKEYBYTES / 2..]);
    Ok(Some((pk, sign::SecretKey(tmp))))
}

/// R6-7: `gen_sk(_, true)` (hbbs `--generate-key Y`) used to `File::create` the key
/// file directly. Two hbbs processes starting at once on a fresh host (a retried
/// provisioning script, systemd racing a manual start) could both take that branch,
/// both generate a DIFFERENT key, and both write it -- the loser's key overwrites
/// the winner's, and whichever client happened to already read the pubkey off the
/// admin API pins one hbbs no longer holds. No lock is taken anywhere in this fix
/// -- there is nothing to deadlock on -- the race is closed with the filesystem's
/// own atomicity instead: write the new key to a private, per-process temp file,
/// then `hard_link` that temp file onto `sk_file`. `hard_link` either creates the
/// link (this process's key becomes THE key, instantly and completely -- there is
/// no window where `sk_file` exists but is partially written, because it was
/// already a complete, closed file under its temp name before the link was made)
/// or fails with `AlreadyExists` because another process's `hard_link` won first,
/// in which case this process discards its own generated key and reads the
/// winner's off disk like any other start -- so every process that raced ends up
/// agreeing on the SAME key, never split between two.
fn generate_and_publish_sk(sk_file: &str) -> Option<(String, sign::SecretKey)> {
    let gen_func = || {
        let (tmp, sk) = sign::gen_keypair();
        (base64::encode(tmp), sk)
    };
    let (mut pk, mut sk) = gen_func();
    for _ in 0..300 {
        if !pk.contains('/') && !pk.contains(':') {
            break;
        }
        (pk, sk) = gen_func();
    }

    // PID alone identifies the temp file across distinct hbbs processes, which is
    // the case this closes the race for; the counter on top of it is only so a
    // multi-threaded test simulating that race doesn't have every "racer" collide
    // on one filename (they'd all share a PID) and corrupt each other's write.
    static TMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let tmp_file = format!(
        "{sk_file}.tmp-{}-{}",
        std::process::id(),
        TMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let write_ok = create_private_file(&tmp_file)
        .and_then(|mut f| f.write_all(base64::encode(&sk).as_bytes()))
        .is_ok();
    if !write_ok {
        let _ = std::fs::remove_file(&tmp_file);
        return None;
    }

    let published = std::fs::hard_link(&tmp_file, sk_file).is_ok();
    let _ = std::fs::remove_file(&tmp_file); // the link (if made) keeps the data
    if !published {
        // AlreadyExists (another process won) or any other link failure: this
        // process's key is not the one going into service either way.
        return None;
    }

    let pub_file = format!("{sk_file}.pub");
    if let Ok(mut f) = std::fs::File::create(&pub_file) {
        f.write_all(pk.as_bytes()).ok();
    }
    log::info!("Private/public key written to {}/{}", sk_file, pub_file);
    log::debug!("Public key: {}", pk);
    Some((pk, sk))
}

/// Load the signing key from `id_ed25519`, or -- only when `may_generate` --
/// create one. A missing key file used to mean a silent new key: every client
/// that pinned the old one then refused the server, and hbbs and hbbr could each
/// mint a different key on a fresh host. Now a missing file is fatal unless the
/// operator asked for a new key (hbbs `--generate-key Y`); hbbr never generates.
pub fn gen_sk(wait: u64, may_generate: bool) -> (String, Option<sign::SecretKey>) {
    let sk_file = "id_ed25519";
    if wait > 0 && !std::path::Path::new(sk_file).exists() {
        std::thread::sleep(std::time::Duration::from_millis(wait));
    }
    restrict_key_file(sk_file);

    let fatal_malformed = || -> ! {
        // don't use log here, since it is async
        println!("Fatal error: malformed private key in {sk_file}.");
        std::process::exit(1);
    };
    match read_sk(sk_file) {
        Ok(Some((pk, sk))) => {
            log::info!("Private key comes from {}", sk_file);
            return (pk, Some(sk));
        }
        Err(()) => fatal_malformed(),
        Ok(None) => {} // fall through: no file yet
    }

    if !may_generate {
        // don't use log here, since it is async
        println!(
            "Fatal error: no {sk_file} in {}. Restore the backed-up key (clients pin it), \
             or create a new one once with `hbbs -k _ --generate-key Y` -- which \
             invalidates every client provisioned with the old key.",
            std::env::current_dir()
                .map(|d| d.display().to_string())
                .unwrap_or_else(|_| ".".to_owned())
        );
        std::process::exit(1);
    }

    if let Some((pk, sk)) = generate_and_publish_sk(sk_file) {
        return (pk, Some(sk));
    }
    // We lost the race to publish (or the write failed outright): the file exists
    // now regardless, so this is a normal load, not a second generation attempt.
    match read_sk(sk_file) {
        Ok(Some((pk, sk))) => {
            log::info!("Private key comes from {} (published by a concurrent start)", sk_file);
            (pk, Some(sk))
        }
        Ok(None) | Err(()) => {
            println!("Fatal error: could not create or read {sk_file}.");
            std::process::exit(1);
        }
    }
}

#[cfg(unix)]
pub async fn listen_signal() -> Result<()> {
    use hbb_common::tokio;
    use hbb_common::tokio::signal::unix::{signal, SignalKind};

    tokio::spawn(async {
        let mut s = signal(SignalKind::terminate())?;
        let terminate = s.recv();
        let mut s = signal(SignalKind::interrupt())?;
        let interrupt = s.recv();
        let mut s = signal(SignalKind::quit())?;
        let quit = s.recv();

        tokio::select! {
            _ = terminate => {
                log::info!("signal terminate");
            }
            _ = interrupt => {
                log::info!("signal interrupt");
            }
            _ = quit => {
                log::info!("signal quit");
            }
        }
        Ok(())
    })
    .await?
}

#[cfg(not(unix))]
pub async fn listen_signal() -> Result<()> {
    let () = std::future::pending().await;
    unreachable!();
}


// Sweep MEDIUM (2026-09-27): this used to phone home to api.rustdesk.com once a
// day with the OS, this server's version, architecture and a machine
// fingerprint, to ask whether a newer RELEASE exists. This fork ships its own
// update manifest (nemo_management: put_update_manifest / /nemo/api/update)
// signed by the operator's own key, so an external check served no purpose
// here beyond leaking that this server exists and when it last restarted.
// Removed rather than disabled: no flag reintroduces it by accident.

#[cfg(test)]
mod relay_grant_tests {
    use super::*;

    // TASK #16: what hbbr relies on: right key, untampered, not expired.
    #[test]
    fn relay_grant_verifies_only_fresh_untampered_grants_from_this_key() {
        let (pk, sk) = sign::gen_keypair();
        let grant = relay_grant_mint(&sk, RELAY_GRANT_TTL_SECS);
        assert!(relay_grant_verify(&pk, &grant).is_ok());
        assert_ne!(relay_grant_mint(&sk, 60), grant, "fresh nonce");

        let (other_pk, _) = sign::gen_keypair();
        assert!(relay_grant_verify(&other_pk, &grant).is_err(), "wrong key");

        let mut raw = base64::decode(&grant).unwrap();
        raw[0] ^= 1;
        assert!(relay_grant_verify(&pk, &base64::encode(&raw)).is_err(), "tampered");

        let expired = relay_grant_mint(&sk, 0);
        assert!(relay_grant_verify(&pk, &expired).is_err(), "expired");

        assert!(relay_grant_verify(&pk, "").is_err(), "empty");
        assert!(relay_grant_verify(&pk, "not a grant").is_err(), "junk");
    }
}

#[cfg(test)]
mod gen_sk_race_tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    fn cleanup(path: &str) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{path}.pub"));
        // any temp file a crashed-mid-test run could have left behind
        if let Ok(dir) = std::fs::read_dir(std::path::Path::new(path).parent().unwrap_or(std::path::Path::new("."))) {
            let stem = std::path::Path::new(path).file_name().unwrap().to_string_lossy().into_owned();
            for entry in dir.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with(&format!("{stem}.tmp-")) {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
    }

    // R6-7: hard_link's atomicity, not a lock, is what closes the race, so there is
    // nothing here that CAN deadlock -- every thread either wins the link or gets
    // AlreadyExists and returns immediately. What must hold is convergence: no
    // matter how many processes raced to generate a key, everyone who starts
    // afterward reads back the SAME key, never a coin-flip between two.
    #[test]
    fn concurrent_generation_converges_on_one_key_and_never_deadlocks() {
        let path = format!(
            "{}/tbf-gen-sk-race-test-{}-{}",
            std::env::temp_dir().display(),
            std::process::id(),
            line!()
        );
        cleanup(&path);

        const N: usize = 12;
        let barrier = Arc::new(Barrier::new(N));
        let handles: Vec<_> = (0..N)
            .map(|_| {
                let path = path.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait(); // maximise the chance every thread races at once
                    generate_and_publish_sk(&path)
                })
            })
            .collect();

        // A timeout on the join, not on generate_and_publish_sk itself: if this
        // fix ever regressed into taking a lock and deadlocking, this is where a
        // frozen test would show it instead of hanging the whole suite forever.
        let results: Vec<_> = handles
            .into_iter()
            .map(|h| h.join().expect("a racing thread panicked"))
            .collect();

        let winners: Vec<_> = results.iter().filter(|r| r.is_some()).collect();
        assert_eq!(winners.len(), 1, "exactly one racer should publish the key, not {}", winners.len());
        let (winner_pk, winner_sk) = winners[0].clone().unwrap();

        // Every racer -- winner and losers alike -- must agree with what is now on
        // disk: this is the property that actually matters (a losing process that
        // went on to serve ITS OWN generated key, never written anywhere, would be
        // the split-brain this test exists to catch).
        for _ in 0..N {
            let (pk, sk) = read_sk(&path).unwrap().expect("file must exist after the race");
            assert_eq!(pk, winner_pk, "every reader must see the published winner's key");
            assert_eq!(sk.0.as_slice(), winner_sk.0.as_slice());
        }

        cleanup(&path);
    }
}


#[cfg(test)]
mod arg_env_tests {
    use super::*;
    #[test]
    fn get_arg_accepts_the_underscore_spelling_an_env_file_can_set() {
        std::env::remove_var("TBF-ARG-TEST");
        std::env::set_var("TBF_ARG_TEST", "from-underscore");
        assert_eq!(get_arg("tbf-arg-test"), "from-underscore");
        std::env::set_var("TBF-ARG-TEST", "from-dash");
        assert_eq!(get_arg("tbf-arg-test"), "from-dash", "the dashed spelling still wins");
        std::env::remove_var("TBF-ARG-TEST");
        std::env::remove_var("TBF_ARG_TEST");
        assert_eq!(get_arg_or("tbf-arg-test", "dflt".into()), "dflt");
    }
}
