#!/usr/bin/env bash
# TBFDesk server installer (Linux). Installs hbbs/hbbr + systemd units.
#
# Upgrade-safe by design: the unit's ExecStart binary path is ALWAYS kept in sync with
# where this script installs the binaries ($PREFIX), so re-running it to upgrade never
# leaves the service pointing at a stale binary and you never have to re-point the units
# by hand. All runtime config (token/relay/mask) lives in /etc/tbfdesk/hbbs.env and is
# left untouched on upgrade.
#
#   ./install.sh                 # install/upgrade with the defaults below
#   PREFIX=/usr/local/bin ./install.sh    # install the binaries elsewhere (unit follows)
#   RESTART=1 ./install.sh       # also restart the services if they are already running
set -euo pipefail

PREFIX="${PREFIX:-/usr/bin}"                 # where hbbs/hbbr go; the unit ExecStart tracks this
DATADIR="${DATADIR:-/var/lib/rustdesk-server}"
LOGDIR="${LOGDIR:-/var/log/rustdesk-server}"
UNITDIR="${UNITDIR:-/etc/systemd/system}"
ENVDIR="${ENVDIR:-/etc/tbfdesk}"
ENVFILE="$ENVDIR/hbbs.env"
SVCUSER="${SVCUSER:-rustdesk}"
cd "$(dirname "$0")"

# 1. binaries ------------------------------------------------------------------
sudo install -m755 bin/hbbs bin/hbbr "$PREFIX"/

# 2. service user + state/log dirs (idempotent; created only if missing) -------
if ! id -u "$SVCUSER" >/dev/null 2>&1; then
  sudo useradd --system --home "$DATADIR" --shell /usr/sbin/nologin "$SVCUSER"
fi
sudo install -d -o "$SVCUSER" -g "$SVCUSER" -m 0750 "$DATADIR" "$LOGDIR"

# 3. config env file (created as a template on first install, never overwritten) -
if [ ! -e "$ENVFILE" ]; then
  sudo install -d -m 0755 "$ENVDIR"
  sudo tee "$ENVFILE" >/dev/null <<'ENV'
# TBFDesk hbbs/hbbr configuration, read by systemd (EnvironmentFile).
# Fill these in, then: sudo systemctl enable --now rustdesk-hbbr-nemo rustdesk-hbbs-nemo
# NEVER put the token on the ExecStart command line -- argv is world-readable via /proc.
NEMO_API_TOKEN=
TBFDESK_RELAY=CHANGE_ME_PUBLIC_IP:21117
TBFDESK_MASK=192.168.0.0/16
# Split ports: a SECOND listener serving only what clients need (policy poll, login,
# address book, audit, update manifest), so the admin dashboard on 21120 can stay
# firewalled to the operator. Clients provisioned "from the internet" use this port.
# Same TLS certificate as 21120, so pinned clients keep working. Remove the line to
# serve everything on 21120.
NEMO_CLIENT_API_BIND=0.0.0.0:21121
ENV
  sudo chmod 0600 "$ENVFILE"            # read by systemd as root before dropping privs
  echo "Created template $ENVFILE -- set NEMO_API_TOKEN / TBFDESK_RELAY / TBFDESK_MASK."
fi

# 4. systemd units -------------------------------------------------------------
# Rewrite only the ExecStart binary path to $PREFIX so it can never drift from where
# the binaries actually are. On an existing install we edit the installed unit in place
# (preserving any operator customisation); on a fresh install we lay down the template.
sync_execstart() {    # <src-or-dst-unit-file>
  sudo sed -Ei "s#^(ExecStart=)[^[:space:]]*/(hbbs|hbbr)#\1$PREFIX/\2#" "$1"
}
for src in systemd/rustdesk-hbbs-nemo.service systemd/rustdesk-hbbr-nemo.service; do
  name="$(basename "$src")"
  dst="$UNITDIR/$name"
  if [ -e "$dst" ]; then
    sync_execstart "$dst"
    echo "Updated ExecStart path in existing $name -> $PREFIX"
  else
    sudo cp "$src" "$dst"
    sync_execstart "$dst"
    echo "Installed $name (ExecStart -> $PREFIX)"
  fi
done
sudo systemctl daemon-reload

# 5. apply / next steps --------------------------------------------------------
if systemctl is-enabled --quiet rustdesk-hbbs-nemo 2>/dev/null; then
  if [ "${RESTART:-0}" = 1 ]; then
    sudo systemctl restart rustdesk-hbbr-nemo rustdesk-hbbs-nemo
    echo "Upgraded and restarted. Verify: sudo sha256sum /proc/\$(pgrep -x hbbs)/exe"
  else
    echo "Upgrade staged. Apply it with:"
    echo "  sudo systemctl restart rustdesk-hbbr-nemo rustdesk-hbbs-nemo"
    echo "(or re-run as: RESTART=1 ./install.sh)"
  fi
else
  echo "First install. Set $ENVFILE, then:"
  echo "  sudo systemctl enable --now rustdesk-hbbr-nemo rustdesk-hbbs-nemo"
  echo "First hbbs start with no id_ed25519 and '-k _ --generate-key Y' mints a fresh signing key."
fi
echo "Binaries -> $PREFIX ; units -> $UNITDIR ; data dir $DATADIR ; config $ENVFILE"
echo "Uninstall (wipe keys/db/config for a clean reset): ./uninstall/tbfdesk-uninstall.sh server"
