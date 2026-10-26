# TBFDesk selective uninstaller

A GUI uninstaller that lets an operator remove a TBFDesk install and **tick exactly
what to wipe** — settings, the device ID + encryption keypair, the device key / cached
secrets, logs, and (for the server) the signing keys, database and policy state — so the
next install comes up completely fresh. Covers the **client** and the **server** on
**Linux** and **Windows**.

## Files
| File | Platform | Covers |
|------|----------|--------|
| `tbfdesk-uninstall.sh`  | Linux   | client + server (`client` is the default mode) |
| `tbfdesk-uninstall.ps1` | Windows | client + server (`-Mode client` default) |
| `tbfdesk-uninstaller.desktop` | Linux | app-menu launcher |

The same two scripts ship in the server repo under `scripts/uninstall/`.

## What each component removes
**Client** — config dir `~/.config/tbfdesk` (Linux) / `%APPDATA%\TBFDesk` (Windows):
- **Application** — binary, service, desktop entry / Start-Menu & Desktop shortcuts, the
  Add/Remove-Programs registry entry (Windows), `/etc/rustdesk` + PAM (Linux).
- **Settings** — `TBFDesk_local.toml`, peer/address-book cache.
- **Device ID & keypair** — `TBFDesk.toml` (removing it means a **new ID** next launch).
- **Device key & cached secrets** — `TBFDesk2.toml` (the provisioning device key + the
  cached management policy, which holds the knock keys).
- **Logs**.
- Ticking all of the above wipes the whole config dir in one step.

**Server** — data dir (auto-detected from the hbbs systemd unit's `WorkingDirectory`, or
pass `DATA_DIR=`):
- **Services** — stop/disable/remove `rustdesk-hbbs-nemo` / `rustdesk-hbbr-nemo`.
- **Binaries** — `hbbs`, `hbbr`.
- **Signing keys** — `id_ed25519` (+`.pub`). Removing them gives the server a **brand-new
  identity**; every provisioned client must then be re-provisioned (this is the "fresh
  keys" reset).
- **Database** — `db_v2.sqlite3*` (registered peers).
- **TLS** — `nemo-api-cert.pem` / `nemo-api-key.pem`.
- **Policy / integration / session state** — `nemo_*.json`, `token`.
- **Update packages** — `nemo_updates`.

## Usage
Linux:
```
tbfdesk-uninstall.sh            # GUI mode picker, then component checklist
tbfdesk-uninstall.sh server
DRY_RUN=1 tbfdesk-uninstall.sh client     # preview only, deletes nothing
DATA_DIR=/var/lib/rustdesk-server tbfdesk-uninstall.sh server
```
Uses `zenity` (GTK) or `kdialog` (Qt); falls back to a text checklist over SSH.

Windows (self-elevates):
```
powershell -ExecutionPolicy Bypass -File tbfdesk-uninstall.ps1
powershell -ExecutionPolicy Bypass -File tbfdesk-uninstall.ps1 -Mode server
powershell -ExecutionPolicy Bypass -File tbfdesk-uninstall.ps1 -DryRun
```

Nothing is deleted until you confirm; a confirmation dialog lists the exact targets first.

### Headless / scripted (no GUI)
For mass deployment or automation, both scripts run without any dialog:
```
# Linux: COMPONENTS = "all" or a comma list; ASSUME_YES=1 skips the confirmation
COMPONENTS=all ASSUME_YES=1 tbfdesk-uninstall.sh client
COMPONENTS=keys,db,tls,policy,updates ASSUME_YES=1 DATA_DIR=/var/lib/rustdesk-server tbfdesk-uninstall.sh server

# Windows: -NoGui with -Components ("all" or a comma list)
powershell -File tbfdesk-uninstall.ps1 -Mode client -NoGui -Components all
powershell -File tbfdesk-uninstall.ps1 -Mode server -NoGui -Components keys,db,tls,policy,updates -DataDir C:\ProgramData\rustdesk-server
```

### Verified end-to-end (2026-10-26)
- **Windows client** on the lab VM: app, service, Add/Remove-Programs entry, Start-Menu/Desktop
  shortcuts and the whole config (settings, ID, keypair, device key, logs) all removed and
  confirmed gone.
- **Linux server** on the lab: the full data dir (`id_ed25519`, `db_v2.sqlite3*`, TLS,
  `nemo_*.json`, `token`, `nemo_updates`) wiped, then a fresh server came up with a **new**
  signing key and correctly refused the previously-provisioned clients.

## Shipping with the installers
- **Linux package**: install `tbfdesk-uninstall.sh` to `/usr/bin/tbfdesk-uninstall` and
  `tbfdesk-uninstaller.desktop` to `/usr/share/applications/`.
- **Windows installer**: drop `tbfdesk-uninstall.ps1` into the install dir and point the
  Add/Remove-Programs `UninstallString` at it, e.g.
  `powershell -ExecutionPolicy Bypass -File "%ProgramFiles%\TBFDesk\tbfdesk-uninstall.ps1"`,
  so "Uninstall" from Apps & Features shows the component picker.
