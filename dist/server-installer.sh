#!/usr/bin/env bash
# TBFDesk server @VER@ -- installer and updater (Linux, systemd). One self-contained file:
# this script with the release tarball appended (dist/pkg-server.sh builds it).
#
#   sudo ./tbfdesk-server-@VER@-install.run            dialog (GUI on a desktop, text UI over SSH)
#   sudo ./tbfdesk-server-@VER@-install.run --text     force the text menu in THIS terminal (no GUI dialog)
#   sudo ./tbfdesk-server-@VER@-install.run --update   unattended update, configuration KEPT
#   sudo ./tbfdesk-server-@VER@-install.run --fresh    unattended clean install (new machine)
#   sudo ./tbfdesk-server-@VER@-install.run --extract DIR   only unpack the release
#
# UPDATE (the default, preselected) keeps EVERYTHING the server is: /etc/tbfdesk (token,
# relay, ports), the data directory (signing keys = server identity, database of devices,
# TLS certificate, policies, published client updates) and any change made to the systemd
# units. Before it touches anything it writes a full backup to /var/backups/tbfdesk/, and
# afterwards it checks that the server identity, the configuration and the database are
# unchanged and that both services are running the new version; if the services do not
# come up, the previous binaries are put back.
# A clean reinstall (new identity -- every client must be provisioned again) is offered
# separately and needs an explicit confirmation; it also makes the backup first.
set -uo pipefail
VER="@VER@"
APP="TBFDesk server"
BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/tbfdesk}"
UNITS="rustdesk-hbbs-nemo rustdesk-hbbr-nemo"
# Progress shown in the terminal (on stderr) so a command-line run is never a blank screen.
# Harmless when the installer is launched from a GUI with no terminal attached.
say() { printf '  -> %s\n' "$*" >&2; }
MODE=""
for a in "$@"; do
  case "$a" in
    --update) MODE=update ;;
    --fresh) MODE=fresh ;;
    --extract) MODE=extract ;;
    --text) FORCE_TEXT=1 ;;
    -h|--help) sed -n '2,19p' "$0"; exit 0 ;;
  esac
done

# ---- root -------------------------------------------------------------------------
if [ "$(id -u)" != 0 ] && [ "$MODE" != extract ]; then
  if command -v pkexec >/dev/null 2>&1 && [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ] && [ -z "${SSH_TTY:-}" ]; then
    printf '%s\n' \
      "$APP $VER installer: asking for administrator rights." \
      "A password dialog should open now -- it may be behind this window or on another monitor." \
      "Approve it to continue.  No dialog? Press Ctrl+C and run:  sudo \"$0\"" >&2
    exec pkexec env DISPLAY="${DISPLAY:-}" WAYLAND_DISPLAY="${WAYLAND_DISPLAY:-}" XAUTHORITY="${XAUTHORITY:-}" bash "$(readlink -f "$0")" "$@"
  fi
  printf '%s\n' "$APP $VER installer: administrator rights are required -- enter your password below." >&2
  exec sudo -E bash "$(readlink -f "$0")" "$@"
fi
[ "$MODE" = extract ] || say "$APP $VER installer -- preparing (running as $(id -un))."

# ---- unpack -----------------------------------------------------------------------
WORK="$(mktemp -d /tmp/tbfdesk-server-install.XXXXXX)"; trap 'rm -rf "$WORK"' EXIT
LINE=$(awk '/^__TBFDESK_PAYLOAD_BELOW__$/ { print NR + 1; exit 0; }' "$0")
[ "$MODE" = extract ] || say "Unpacking the release..."
tail -n +"$LINE" "$0" | tar xz -C "$WORK" || { echo "$APP $VER: the installer is damaged (payload)" >&2; exit 1; }
REL="$(ls -d "$WORK"/tbfdesk-server-* | head -1)"
if [ "$MODE" = extract ]; then
  D="${2:-./tbfdesk-server-$VER}"; mkdir -p "$D"; cp -a "$REL"/. "$D"/; echo "unpacked to $D"; exit 0
fi

# ---- dialogs: zenity / kdialog on a desktop, whiptail on a terminal, plain text last -
GUI=text
if [ -z "${FORCE_TEXT:-}" ]; then
  if [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ] && command -v zenity >/dev/null 2>&1; then GUI=zenity
  elif [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ] && command -v kdialog >/dev/null 2>&1; then GUI=kdialog
  elif [ -t 0 ] && command -v whiptail >/dev/null 2>&1; then GUI=whiptail; fi
fi
[ -n "$MODE" ] && GUI=none
TITLE="$APP $VER"
msg() {   # info box
  case "$GUI" in
    zenity) zenity --info --title "$TITLE" --width=640 --text "$1" 2>/dev/null ;;
    kdialog) kdialog --title "$TITLE" --msgbox "$1" 2>/dev/null ;;
    whiptail) whiptail --title "$TITLE" --msgbox "$1" 22 78 ;;
    *) printf '\n%s\n' "$1" ;;
  esac
}
ask() {   # yes/no, default NO
  case "$GUI" in
    zenity) zenity --question --title "$TITLE" --width=640 --default-cancel --text "$1" 2>/dev/null ;;
    kdialog) kdialog --title "$TITLE" --warningyesno "$1" 2>/dev/null ;;
    whiptail) whiptail --title "$TITLE" --defaultno --yesno "$1" 20 78 ;;
    none) return 0 ;;
    *) printf '%s [y/N] ' "$1"; read -r r; [ "$r" = y ] || [ "$r" = Y ] ;;
  esac
}
choose() {  # $1 text, then tag|label pairs; the FIRST is preselected
  local text="$1"; shift; local a
  case "$GUI" in
    zenity)
      local args=(); local first=TRUE
      for a in "$@"; do args+=("$first" "${a%%|*}" "${a#*|}"); first=FALSE; done
      zenity --list --radiolist --title "$TITLE" --width=760 --height=330 --text "$text" \
        --column "" --column "id" --column "What to do" --hide-column 2 --print-column 2 "${args[@]}" 2>/dev/null ;;
    kdialog)
      local args=(); local first=on
      for a in "$@"; do args+=("${a%%|*}" "${a#*|}" "$first"); first=off; done
      kdialog --title "$TITLE" --radiolist "$text" "${args[@]}" 2>/dev/null ;;
    whiptail)
      local args=(); local first=ON
      for a in "$@"; do args+=("${a%%|*}" "${a#*|}" "$first"); first=OFF; done
      whiptail --title "$TITLE" --radiolist "$text" 22 100 6 "${args[@]}" 3>&1 1>&2 2>&3 ;;
    *)
      printf '\n%s\n' "$text" >&2; local i=1
      for a in "$@"; do printf '  %d) %s%s\n' "$i" "${a#*|}" "$([ $i = 1 ] && echo '   [default]')" >&2; i=$((i + 1)); done
      printf 'Choice [1]: ' >&2; read -r r; r=${r:-1}; i=1
      for a in "$@"; do [ "$i" = "$r" ] && { echo "${a%%|*}"; return; }; i=$((i + 1)); done ;;
  esac
}

# ---- what is installed ----------------------------------------------------------------
unit_val() { systemctl show -p "$2" --value "$1" 2>/dev/null; }
DATADIR="$(unit_val rustdesk-hbbs-nemo WorkingDirectory)"; DATADIR="${DATADIR:-/var/lib/rustdesk-server}"
HBBS_BIN="$(unit_val rustdesk-hbbs-nemo ExecStart | sed -n 's/.*path=\([^ ;]*\).*/\1/p')"
HBBS_BIN="${HBBS_BIN:-/usr/bin/hbbs}"
PREFIX="$(dirname "$HBBS_BIN")"
ENVFILE=/etc/tbfdesk/hbbs.env
installed=0
{ [ -e /etc/systemd/system/rustdesk-hbbs-nemo.service ] || [ -x "$HBBS_BIN" ] || [ -f "$DATADIR/id_ed25519" ]; } && installed=1
OLDVER="$( [ -x "$HBBS_BIN" ] && "$HBBS_BIN" --version 2>/dev/null | awk '{print $2}')"

fp() { [ -f "$1" ] && sha256sum "$1" | cut -c1-16 || echo "-"; }
peers() { [ -f "$DATADIR/db_v2.sqlite3" ] && command -v sqlite3 >/dev/null 2>&1 \
  && sqlite3 -readonly "$DATADIR/db_v2.sqlite3" 'select count(*) from peer;' 2>/dev/null || echo "?"; }
snapshot() {  # what must not change across an update
  echo "identity=$(fp "$DATADIR/id_ed25519.pub") config=$(fp "$ENVFILE") tls=$(fp "$DATADIR/nemo-api-cert.pem") peers=$(peers)"
}

backup() {
  install -d -m 0700 "$BACKUP_ROOT"
  local ts f; ts=$(date +%Y%m%d-%H%M%S); f="$BACKUP_ROOT/server-$ts-before-$VER.tar.gz"
  local items=()
  for p in /etc/tbfdesk "$DATADIR" /etc/systemd/system/rustdesk-hbbs-nemo.service /etc/systemd/system/rustdesk-hbbr-nemo.service \
           /etc/systemd/system/rustdesk-hbbs-nemo.service.d /etc/systemd/system/rustdesk-hbbr-nemo.service.d "$PREFIX/hbbs" "$PREFIX/hbbr"; do
    [ -e "$p" ] && items+=("$p")
  done
  # the database is copied consistently while hbbs keeps running (WAL mode)
  if [ -f "$DATADIR/db_v2.sqlite3" ] && command -v sqlite3 >/dev/null 2>&1; then
    sqlite3 "$DATADIR/db_v2.sqlite3" ".backup '$WORK/db_v2.sqlite3.consistent'" 2>/dev/null && items+=("$WORK/db_v2.sqlite3.consistent")
  fi
  tar --absolute-names -czf "$f" "${items[@]}" 2>/dev/null || { echo "backup FAILED -- nothing was changed" >&2; return 1; }
  chmod 0600 "$f"; echo "$f"
}

services_ok() {
  # both units active with the SAME main process for 6 s in a row: a crashing binary under
  # Restart=always is "active" for a moment between restarts, which proves nothing
  local i u pids last="" stable=0
  for i in $(seq 45); do
    pids=""
    for u in $UNITS; do
      systemctl is-active --quiet "$u" || { pids="down"; break; }
      pids="$pids $(systemctl show -p MainPID --value "$u")"
    done
    if [ "$pids" != down ] && [ "$pids" = "$last" ]; then stable=$((stable + 1)); else stable=0; fi
    last="$pids"
    [ $stable -ge 6 ] && return 0
    sleep 1
  done
  return 1
}

# a `sudo` for install.sh that works for root on systems without sudo
SHIM="$WORK/shim"; mkdir -p "$SHIM"; printf '#!/bin/sh\nexec "$@"\n' > "$SHIM/sudo"; chmod +x "$SHIM/sudo"

do_update() {
  local before after bk report
  before="$(snapshot)"
  say "Backing up the current server (configuration, keys, database) to $BACKUP_ROOT ..."
  bk="$(backup)" || { msg "Backup failed -- nothing was changed."; exit 1; }
  local was_enabled=0; systemctl is-enabled --quiet rustdesk-hbbs-nemo 2>/dev/null && was_enabled=1
  local t0; t0=$(date +%s)
  say "Installing $APP $VER (keeping configuration) ..."
  ( cd "$REL" && PATH="$SHIM:$PATH" PREFIX="$PREFIX" DATADIR="$DATADIR" RESTART=1 ./install.sh ) > "$WORK/install.log" 2>&1
  local rc=$?
  say "Verifying both services start and stay up (up to ~45s) ..."
  if [ $was_enabled = 1 ] && ! services_ok; then
    # roll back the binaries; configuration and data were never touched
    tar --absolute-names -xzf "$bk" "$PREFIX/hbbs" "$PREFIX/hbbr" 2>/dev/null
    systemctl restart $UNITS 2>/dev/null
    msg "The new version did not start -- the previous binaries ($OLDVER) were put back.
Configuration and data were not changed.

Backup: $bk
Installer log: $(cat "$WORK/install.log" | tail -5)
Service log: journalctl -u rustdesk-hbbs-nemo -n 50"
    exit 1
  fi
  after="$(snapshot)"
  local pid; pid=$(pgrep -x hbbs | head -1)
  local running; running="$(sha256sum /proc/$pid/exe 2>/dev/null | cut -c1-16)"
  local shipped; shipped="$(sha256sum "$REL/bin/hbbs" | cut -c1-16)"
  if [ -z "$running" ] && [ -n "$pid" ]; then
    # /proc/<pid>/exe not readable (hardened /proc, containers): the installed binary is
    # the shipped one AND the running process was started after this update began
    local started; started=$(date -d "$(ps -o lstart= -p "$pid")" +%s 2>/dev/null || echo 0)
    [ "$(sha256sum "$PREFIX/hbbs" | cut -c1-16)" = "$shipped" ] && [ "$started" -ge "$t0" ] && running="$shipped"
  fi
  local same="YES"; [ "$before" = "$after" ] || same="NO -- compare: before [$before] after [$after]"
  local live="not running (was not enabled)"; [ $was_enabled = 1 ] && { [ "$running" = "$shipped" ] && live="yes, the new hbbs is running" || live="NO (running $running, shipped $shipped)"; }
  report="Updated $APP ${OLDVER:-?} -> $VER.

Configuration, server identity, TLS certificate and device database unchanged: $same
  ($after)
New version live: $live

Backup of everything before the update:
  $bk
(restore: sudo tar --absolute-names -xzf <backup> && sudo systemctl restart rustdesk-hbbr-nemo rustdesk-hbbs-nemo)"
  [ $rc = 0 ] || report="$report

install.sh reported an error (exit $rc):
$(tail -5 "$WORK/install.log")"
  [ $rc = 0 ] && say "Update finished: $APP ${OLDVER:-?} -> $VER." || say "Update finished with errors (see the summary / install log)."
  msg "$report"
  echo "$report" > "$BACKUP_ROOT/last-update-$VER.txt"
}

do_fresh() {
  if [ $installed = 1 ]; then
    ask "RESET the server?

This DELETES the signing keys (the server's identity), the device database, the TLS
certificate, policies and published updates. Every client then has to be provisioned
again. A backup is written first.

Continue with the reset?" || { msg "Cancelled -- nothing was changed."; exit 0; }
    say "Backing up, then resetting the previous server ..."
    local bk; bk="$(backup)" || { msg "Backup failed -- nothing was changed."; exit 1; }
    COMPONENTS=svc,bins,keys,db,tls,policy,updates ASSUME_YES=1 DATA_DIR="$DATADIR" NONINTERACTIVE=1 \
      "$REL/uninstall/tbfdesk-uninstall.sh" server > "$WORK/uninstall.log" 2>&1
  fi
  say "Installing $APP $VER ..."
  ( cd "$REL" && PATH="$SHIM:$PATH" PREFIX="$PREFIX" DATADIR="$DATADIR" ./install.sh ) > "$WORK/install.log" 2>&1
  say "Installation finished."
  msg "$APP $VER installed.

$(tail -6 "$WORK/install.log")
${bk:+
Backup of the previous server: $bk}"
}

# ---- main -------------------------------------------------------------------------------
if [ -z "$MODE" ]; then
  if [ $installed = 1 ]; then
    MODE=$(choose "Installed: $APP ${OLDVER:-(unknown version)} in $PREFIX, data $DATADIR.
This installer: $VER.

Update keeps the configuration, the server identity (signing keys), the device database,
TLS certificate, policies and published client updates. A backup is made first." \
      "update|Update to $VER -- KEEP configuration, keys and database (recommended)" \
      "fresh|Reset and reinstall -- DELETES keys, database and configuration" \
      "cancel|Cancel")
  else
    MODE=$(choose "No $APP found on this machine. This installer: $VER." \
      "fresh|Install $APP $VER" "cancel|Cancel")
  fi
fi
case "$MODE" in
  update) [ $installed = 1 ] || { msg "Nothing to update: no $APP installed."; exit 1; }; do_update ;;
  fresh) do_fresh ;;
  *) echo "Cancelled -- nothing was changed."; exit 0 ;;
esac
exit 0
__TBFDESK_PAYLOAD_BELOW__
