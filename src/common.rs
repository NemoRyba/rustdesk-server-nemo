use clap::App;
use hbb_common::{
    allow_err, anyhow::{Context, Result}, get_version_number, log, tokio, ResultType
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

pub fn gen_sk(wait: u64) -> (String, Option<sign::SecretKey>) {
    let sk_file = "id_ed25519";
    if wait > 0 && !std::path::Path::new(sk_file).exists() {
        std::thread::sleep(std::time::Duration::from_millis(wait));
    }
    restrict_key_file(sk_file);
    if let Ok(mut file) = std::fs::File::open(sk_file) {
        let mut contents = String::new();
        if file.read_to_string(&mut contents).is_ok() {
            let contents = contents.trim();
            let sk = base64::decode(contents).unwrap_or_default();
            if sk.len() == sign::SECRETKEYBYTES {
                let mut tmp = [0u8; sign::SECRETKEYBYTES];
                tmp[..].copy_from_slice(&sk);
                let pk = base64::encode(&tmp[sign::SECRETKEYBYTES / 2..]);
                log::info!("Private key comes from {}", sk_file);
                return (pk, Some(sign::SecretKey(tmp)));
            } else {
                // don't use log here, since it is async
                println!("Fatal error: malformed private key in {sk_file}.");
                std::process::exit(1);
            }
        }
    } else {
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
        let pub_file = format!("{sk_file}.pub");
        if let Ok(mut f) = std::fs::File::create(&pub_file) {
            f.write_all(pk.as_bytes()).ok();
            if let Ok(mut f) = create_private_file(sk_file) {
                let s = base64::encode(&sk);
                if f.write_all(s.as_bytes()).is_ok() {
                    log::info!("Private/public key written to {}/{}", sk_file, pub_file);
                    log::debug!("Public key: {}", pk);
                    return (pk, Some(sk));
                }
            }
        }
    }
    ("".to_owned(), None)
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


pub fn check_software_update() {
    const ONE_DAY_IN_SECONDS: u64 = 60 * 60 * 24;
    std::thread::spawn(move || loop {
        std::thread::spawn(move || allow_err!(check_software_update_()));
        std::thread::sleep(std::time::Duration::from_secs(ONE_DAY_IN_SECONDS));
    });
}

#[tokio::main(flavor = "current_thread")]
async fn check_software_update_() -> hbb_common::ResultType<()> {
    let (request, url) = hbb_common::version_check_request(hbb_common::VER_TYPE_RUSTDESK_SERVER.to_string());
    let latest_release_response = reqwest::Client::builder().build()?
        .post(url)
        .json(&request)
        .send()
        .await?;

    let bytes = latest_release_response.bytes().await?;
    let resp: hbb_common::VersionCheckResponse = serde_json::from_slice(&bytes)?;
    let response_url = resp.url;
    let latest_release_version = response_url.rsplit('/').next().unwrap_or_default();
    if get_version_number(&latest_release_version) > get_version_number(crate::version::VERSION) {
       log::info!("new version is available: {}", latest_release_version);
    }
    Ok(())
}

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
