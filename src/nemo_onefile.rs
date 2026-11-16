//! Build the dashboard's "one-file installer".
//!
//! A one-file installer is a single artifact that carries BOTH a real TBFDesk installer
//! and a per-device setup string (server settings + the generated device key), so a
//! technician runs one file instead of unpacking an installer, a `.tbfsetup` and a
//! script into a folder. It is an ADDITION: the separate installer + `.tbfsetup` +
//! `install.cmd`/`install.sh` workflow is unchanged and still offered.
//!
//! - **Windows** (`build_windows`): the committed SFX stub (`assets/sfx/`) with the
//!   installer, the setup bytes, the setup name and a 28-byte trailer appended as a PE
//!   overlay. The stub (requireAdministrator) carves the two out to a temp dir and runs
//!   `installer --silent-install --import-setup <file>`.
//! - **Linux** (`build_linux`): a POSIX-sh self-extracting `.run` — a header that carves
//!   the appended installer + setup out by byte offset, installs the package and runs
//!   `rustdesk --import-setup <file>` (the installed Linux binary name).
//!
//! The setup is always handed over as a FILE, never on a command line (a setup string
//! carries the device key, and argv is world-readable — H26). This module is pure byte
//! wrangling; the HTTP handler and all server state live in `nemo_management.rs`.

/// The committed Windows SFX stub (`assets/sfx/tbfdesk-sfx-stub.exe`). Rebuild it with
/// `assets/sfx/build-stub.sh` after changing the C source and commit the new binary — the
/// server embeds exactly these bytes and never cross-compiles at build time, so the
/// shipped stub does not depend on the build host.
pub const WINDOWS_STUB: &[u8] = include_bytes!("../assets/sfx/tbfdesk-sfx-stub.exe");

/// The 8-byte trailer magic, shared with the C stub (`tbfdesk-sfx-stub.c`).
const TRAILER_MAGIC: &[u8; 8] = b"TBFSFX01";
/// magic(8) + installer_len(u64) + setup_len(u64) + name_len(u32).
const TRAILER_LEN: usize = 8 + 8 + 8 + 4;

/// `stub || installer || setup || setup_name || trailer`. The trailer is the last 28
/// bytes; the stub reads it to find the two blobs. A PE ignores trailing overlay bytes,
/// so the stub still launches.
pub fn build_windows(installer: &[u8], setup_string: &str, setup_name: &str) -> Vec<u8> {
    let name = setup_name.as_bytes();
    let mut out = Vec::with_capacity(
        WINDOWS_STUB.len() + installer.len() + setup_string.len() + name.len() + TRAILER_LEN,
    );
    out.extend_from_slice(WINDOWS_STUB);
    out.extend_from_slice(installer);
    out.extend_from_slice(setup_string.as_bytes());
    out.extend_from_slice(name);
    out.extend_from_slice(TRAILER_MAGIC);
    out.extend_from_slice(&(installer.len() as u64).to_le_bytes());
    out.extend_from_slice(&(setup_string.len() as u64).to_le_bytes());
    out.extend_from_slice(&(name.len() as u32).to_le_bytes());
    out
}

/// Parse a file built by [`build_windows`] back into `(installer, setup, setup_name)` —
/// the exact mirror of the C stub's reader, used by the round-trip unit test. `None` if
/// the magic is absent or the lengths do not fit the file.
pub fn parse_windows(file: &[u8]) -> Option<(&[u8], &[u8], String)> {
    if file.len() < TRAILER_LEN {
        return None;
    }
    let tr = &file[file.len() - TRAILER_LEN..];
    if &tr[0..8] != TRAILER_MAGIC {
        return None;
    }
    let inst_len = u64::from_le_bytes(tr[8..16].try_into().ok()?) as usize;
    let setup_len = u64::from_le_bytes(tr[16..24].try_into().ok()?) as usize;
    let name_len = u32::from_le_bytes(tr[24..28].try_into().ok()?) as usize;
    let end = file.len() - TRAILER_LEN;
    let name_off = end.checked_sub(name_len)?;
    let setup_off = name_off.checked_sub(setup_len)?;
    let inst_off = setup_off.checked_sub(inst_len)?;
    let installer = file.get(inst_off..setup_off)?;
    let setup = file.get(setup_off..name_off)?;
    let name = String::from_utf8(file.get(name_off..end)?.to_vec()).ok()?;
    Some((installer, setup, name))
}

/// Which Linux package manager the bundled installer needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinuxPkg {
    Deb,
    Rpm,
    Arch,
}

/// The marker line after which the appended `installer || setup` payload begins. Chosen
/// to never occur in the header above it; the script finds it with a whole-line match.
const LINUX_MARKER: &str = "__TBFDESK_PAYLOAD_BELOW__";

/// A POSIX-sh self-extracting `.run`: a text header (which carves the payload out by byte
/// offset, installs the package and runs `rustdesk --import-setup`), the marker line, then
/// `installer || setup` appended verbatim.
pub fn build_linux(
    installer: &[u8],
    installer_name: &str,
    pkg: LinuxPkg,
    setup_string: &str,
    setup_name: &str,
) -> Vec<u8> {
    let install_cmd = match pkg {
        LinuxPkg::Deb => "if command -v apt-get >/dev/null 2>&1; then \
             apt-get install -y \"$TMP/$INST_NAME\"; else dpkg -i \"$TMP/$INST_NAME\"; fi",
        LinuxPkg::Rpm => "if command -v dnf >/dev/null 2>&1; then \
             dnf install -y \"$TMP/$INST_NAME\"; else rpm -i --force \"$TMP/$INST_NAME\"; fi",
        LinuxPkg::Arch => "pacman -U --noconfirm \"$TMP/$INST_NAME\"",
    };
    let inst_name = sanitize_name(installer_name);
    let setup_nm = sanitize_name(setup_name);

    // NB: this whole string is sh. `{{`/`}}` are escaped braces for format!.
    let header = format!(
        "#!/bin/sh\n\
# TBFDesk one-file installer (self-extracting): installs the bundled package and\n\
# provisions this computer with its device key + server settings in one run.\n\
# Run as root:  sudo sh <this-file>\n\
set -e\n\
INST_NAME='{inst_name}'\n\
INST_LEN={inst_len}\n\
SETUP_NAME='{setup_nm}'\n\
SETUP_LEN={setup_len}\n\
\n\
if [ \"$(id -u)\" -ne 0 ]; then\n\
  echo \"This installer needs root. Re-run with:  sudo sh \\\"$0\\\"\" >&2\n\
  exit 1\n\
fi\n\
umask 077\n\
TMP=$(mktemp -d) || {{ echo \"cannot create a temp dir\" >&2; exit 1; }}\n\
trap 'rm -rf \"$TMP\"' EXIT INT TERM\n\
\n\
# Byte offset just past the marker line below (unique, whole-line matched).\n\
LINE=$(grep -an '^{marker}$' \"$0\" | head -1 | cut -d: -f1)\n\
[ -n \"$LINE\" ] || {{ echo \"corrupt one-file installer (no payload marker)\" >&2; exit 1; }}\n\
SKIP=$(head -n \"$LINE\" \"$0\" | wc -c)\n\
tail -c +$((SKIP + 1)) \"$0\" | head -c \"$INST_LEN\" > \"$TMP/$INST_NAME\"\n\
tail -c +$((SKIP + 1 + INST_LEN)) \"$0\" | head -c \"$SETUP_LEN\" > \"$TMP/$SETUP_NAME\"\n\
\n\
echo \"Installing TBFDesk...\"\n\
{install_cmd}\n\
echo \"Provisioning this computer...\"\n\
# The installed binary is 'rustdesk' on Linux (the fork keeps the upstream binary/.desktop\n\
# names); prefer 'tbfdesk' in case a future package renames it.\n\
BIN=$(command -v tbfdesk 2>/dev/null || command -v rustdesk 2>/dev/null || true)\n\
[ -n \"$BIN\" ] || {{ echo \"TBFDesk binary not found after install\" >&2; exit 1; }}\n\
# The setup is passed as a FILE: it carries the device key, and argv is world-readable.\n\
\"$BIN\" --import-setup \"$TMP/$SETUP_NAME\"\n\
echo \"Done. This computer is now installed and provisioned for TBFDesk.\"\n\
exit 0\n\
{marker}\n",
        inst_name = inst_name,
        inst_len = installer.len(),
        setup_nm = setup_nm,
        setup_len = setup_string.len(),
        marker = LINUX_MARKER,
        install_cmd = install_cmd,
    );

    let mut out = Vec::with_capacity(header.len() + installer.len() + setup_string.len());
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(installer);
    out.extend_from_slice(setup_string.as_bytes());
    out
}

/// Keep a name a bare, shell- and path-safe file name.
pub fn sanitize_name(n: &str) -> String {
    let s: String = n
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let s = s.trim_matches(|c| matches!(c, '.' | '_' | '-')).to_owned();
    if s.is_empty() {
        "client.tbfsetup".to_owned()
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_trailer_round_trips() {
        let installer = b"MZ\x90\x00 pretend installer bytes \x00\x01\x02".as_slice();
        let setup = "tbfdesk-setup-v1:eyJ2IjoxfQ";
        let name = "tbfdesk-acme-setup-lan-with-key.tbfsetup";
        let blob = build_windows(installer, setup, name);

        // The stub must still be at the front (overlay comes after the PE).
        assert!(blob.starts_with(WINDOWS_STUB));
        assert!(blob.len() > WINDOWS_STUB.len() + installer.len());

        let (gi, gs, gn) = parse_windows(&blob).expect("parses back");
        assert_eq!(gi, installer);
        assert_eq!(gs, setup.as_bytes());
        assert_eq!(gn, name);
    }

    #[test]
    fn windows_rejects_garbage_and_truncation() {
        // No trailer magic at all.
        assert!(parse_windows(b"not an sfx").is_none());
        // Magic intact but a length field blown up so a blob overflows the file: the
        // most-significant byte of name_len (the last u32) → an enormous name offset.
        let mut blob = build_windows(b"installer", "tbfdesk-setup-v1:x", "a.tbfsetup");
        let l = blob.len();
        blob[l - 1] = 0xFF; // name_len becomes >= 0xFF000000
        assert!(parse_windows(&blob).is_none());
    }

    #[test]
    fn linux_header_is_shell_with_payload_after_marker() {
        let installer = b"!<arch>\ndebian-binary pretend deb";
        let setup = "tbfdesk-setup-v1:eyJ2IjoxfQ";
        let blob = build_linux(installer, "tbfdesk-1.4.21-amd64.deb", LinuxPkg::Deb, setup, "x.tbfsetup");
        let text = String::from_utf8_lossy(&blob);
        assert!(text.starts_with("#!/bin/sh"));
        assert!(text.contains("--import-setup"));
        assert!(text.contains("command -v rustdesk"));
        assert!(text.contains("apt-get install -y"));

        // Payload begins right after the marker line's newline, installer first.
        let marker_line = format!("{}\n", LINUX_MARKER);
        let idx = text.find(&marker_line).expect("marker present");
        let payload_start = idx + marker_line.len();
        assert_eq!(&blob[payload_start..payload_start + installer.len()], installer);
        assert_eq!(
            &blob[payload_start + installer.len()..],
            setup.as_bytes()
        );
    }

    #[test]
    fn sanitize_name_is_safe() {
        assert_eq!(sanitize_name("a b/c:..\\d"), "a_b_c_.._d");
        assert_eq!(sanitize_name("../../etc/passwd"), "etc_passwd");
        assert_eq!(sanitize_name(""), "client.tbfsetup");
        assert_eq!(sanitize_name("ok-name_1.2.tbfsetup"), "ok-name_1.2.tbfsetup");
    }
}
