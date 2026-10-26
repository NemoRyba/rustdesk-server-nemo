#!/usr/bin/env bash
# TBFDesk uninstaller (Linux) — GUI component picker for the client and the server.
#
# Lets an operator cleanly remove a TBFDesk install and selectively wipe settings,
# the device ID + encryption keypair, the device key / cached secrets, logs, and (for
# the server) the signing keys, database and policy state — so the next install comes
# up fresh. Presents a zenity (GTK) or kdialog (Qt) checklist; falls back to a text
# prompt when no display is available.
#
# Usage:
#   tbfdesk-uninstall.sh [client|server]      # mode picker shown if omitted
#   DRY_RUN=1 tbfdesk-uninstall.sh ...         # print what would be removed, delete nothing
#   DATA_DIR=/path tbfdesk-uninstall.sh server # override the server data dir
#
# Nothing is deleted until you confirm, and a confirmation dialog lists the exact
# paths first.
set -uo pipefail

APP_NAME="TBFDesk"
PKG="rustdesk"                                  # Linux package/service/bin name
CONFIG_DIR="${HOME}/.config/tbfdesk"            # client config (per the app's ProjectDirs)
DRY_RUN="${DRY_RUN:-0}"
# Non-interactive mode for scripting/automation: set COMPONENTS to "all" or a comma list
# (e.g. "svc,keys,db"). ASSUME_YES=1 skips the confirmation. No dialog is shown.
COMPONENTS="${COMPONENTS:-}"
ASSUME_YES="${ASSUME_YES:-0}"
NONINT=0; [ -n "$COMPONENTS" ] && NONINT=1

have(){ command -v "$1" >/dev/null 2>&1; }
GUI=""
if [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]; then
  if have zenity; then GUI=zenity; elif have kdialog; then GUI=kdialog; fi
fi

# ---- dialog helpers (zenity | kdialog | text) ---------------------------------
pick_mode(){ # -> prints "client" or "server"
  case "$GUI" in
    zenity) zenity --list --radiolist --title "$APP_NAME Uninstaller" \
              --text "What do you want to uninstall?" --column "" --column "Target" \
              TRUE "client" FALSE "server" 2>/dev/null ;;
    kdialog) kdialog --title "$APP_NAME Uninstaller" --radiolist "What do you want to uninstall?" \
              client "TBFDesk client" on server "TBFDesk server" off 2>/dev/null ;;
    *) read -rp "Uninstall [client/server]: " m; echo "$m" ;;
  esac
}

# checklist: args are triples "key|Label|default(on/off)"; prints chosen keys newline-separated
checklist(){
  local title="$1"; shift
  if [ "$NONINT" = 1 ]; then
    if [ "$COMPONENTS" = all ]; then
      local t k l d; for t in "$@"; do IFS='|' read -r k l d <<<"$t"; echo "$k"; done
    else
      echo "$COMPONENTS" | tr ',' '\n' | tr -d ' '
    fi
    return
  fi
  if [ "$GUI" = zenity ]; then
    local args=(); for t in "$@"; do IFS='|' read -r k l d <<<"$t"; args+=("$([ "$d" = on ] && echo TRUE || echo FALSE)" "$k" "$l"); done
    zenity --list --checklist --title "$APP_NAME Uninstaller" --text "$title\nUntick anything you want to KEEP." \
      --column "Remove" --column "key" --column "Component" --hide-column=2 --print-column=2 \
      --separator=$'\n' --width=640 --height=420 "${args[@]}" 2>/dev/null
  elif [ "$GUI" = kdialog ]; then
    local args=(); for t in "$@"; do IFS='|' read -r k l d <<<"$t"; args+=("$k" "$l" "$([ "$d" = on ] && echo on || echo off)"); done
    kdialog --title "$APP_NAME Uninstaller" --checklist "$title" "${args[@]}" 2>/dev/null | tr ' ' '\n' | tr -d '"'
  else
    echo "$title" >&2; local out=""
    for t in "$@"; do IFS='|' read -r k l d <<<"$t"; read -rp "Remove '$l'? [$([ "$d" = on ] && echo Y/n || echo y/N)] " a
      a="${a:-$([ "$d" = on ] && echo y || echo n)}"; [[ "$a" =~ ^[Yy] ]] && out+="$k"$'\n'; done
    printf '%s' "$out"
  fi
}

confirm(){ # $1 = message with the list; returns 0 if user confirms
  if [ "$NONINT" = 1 ]; then printf '%b\n' "$1" >&2; [ "$ASSUME_YES" = 1 ]; return; fi
  case "$GUI" in
    zenity) zenity --question --title "$APP_NAME Uninstaller" --width=640 \
              --ok-label="Delete" --cancel-label="Cancel" --text "$1" 2>/dev/null ;;
    kdialog) kdialog --title "$APP_NAME Uninstaller" --warningyesno "$1" 2>/dev/null ;;
    *) printf '%s\n' "$1" >&2; read -rp "Proceed? [y/N] " a; [[ "$a" =~ ^[Yy] ]] ;;
  esac
}

info(){ case "$GUI" in
    zenity) zenity --info --title "$APP_NAME Uninstaller" --width=640 --text "$1" 2>/dev/null ;;
    kdialog) kdialog --title "$APP_NAME Uninstaller" --msgbox "$1" 2>/dev/null ;;
    *) printf '%b\n' "$1" ;; esac; }

# ---- removal engine -----------------------------------------------------------
declare -a PLAN_DESC PLAN_CMD
plan(){ PLAN_DESC+=("$1"); PLAN_CMD+=("$2"); }     # human line, shell command
sudo_if_needed(){ if [ "$(id -u)" -ne 0 ]; then echo "sudo $*"; else echo "$*"; fi; }

run_plan(){
  local out="" i
  for i in "${!PLAN_CMD[@]}"; do
    if [ "$DRY_RUN" = 1 ]; then out+="[dry-run] ${PLAN_DESC[$i]}"$'\n'
    else if eval "${PLAN_CMD[$i]}" >/dev/null 2>&1; then out+="✓ ${PLAN_DESC[$i]}"$'\n'
         else out+="✗ (failed/absent) ${PLAN_DESC[$i]}"$'\n'; fi; fi
  done
  printf '%s' "$out"
}

# ---- CLIENT -------------------------------------------------------------------
do_client(){
  local sel; sel="$(checklist "Select what to remove from the TBFDesk CLIENT:" \
    "app|Application, service & system files (needs sudo)|on" \
    "settings|Settings & preferences|on" \
    "identity|Device ID & encryption keypair (→ new ID next install)|on" \
    "devkey|Device key & cached management secrets|on" \
    "logs|Logs|on")"
  [ -z "$sel" ] && { info "Nothing selected — cancelled."; exit 0; }

  local wipe_all=1
  for k in settings identity devkey logs; do grep -qx "$k" <<<"$sel" || wipe_all=0; done

  if grep -qx app <<<"$sel"; then
    plan "Stop & disable the $PKG service"            "$(sudo_if_needed systemctl disable --now $PKG); $(sudo_if_needed systemctl disable --now ${PKG}.service); pkill -f '$PKG --tray' ; pkill -x $PKG ; true"
    plan "Remove the $PKG binary (/usr/bin/$PKG)"      "$(sudo_if_needed rm -f /usr/bin/$PKG /usr/lib/$PKG/$PKG)"
    plan "Remove desktop entry & icon"                 "$(sudo_if_needed rm -f /usr/share/applications/$PKG.desktop /usr/share/icons/hicolor/*/apps/$PKG.png)"
    plan "Remove system config (/etc/$PKG, pam)"       "$(sudo_if_needed rm -rf /etc/$PKG /etc/pam.d/$PKG)"
    plan "Remove systemd unit file"                    "$(sudo_if_needed rm -f /etc/systemd/system/$PKG.service /usr/lib/systemd/system/$PKG.service); $(sudo_if_needed systemctl daemon-reload); true"
  fi

  if [ "$wipe_all" = 1 ] && [ -d "$CONFIG_DIR" ]; then
    plan "Wipe entire config dir ($CONFIG_DIR): settings, ID, keypair, device key, logs" "rm -rf '$CONFIG_DIR'"
  else
    grep -qx identity <<<"$sel" && plan "Remove device ID & keypair ($CONFIG_DIR/$APP_NAME.toml)"        "rm -f '$CONFIG_DIR/$APP_NAME.toml'"
    grep -qx devkey   <<<"$sel" && plan "Remove device key & policy cache ($CONFIG_DIR/${APP_NAME}2.toml)" "rm -f '$CONFIG_DIR/${APP_NAME}2.toml'"
    grep -qx settings <<<"$sel" && plan "Remove local settings & peer cache"                              "rm -f '$CONFIG_DIR/${APP_NAME}_local.toml' '$CONFIG_DIR'/peers.toml ; rm -rf '$CONFIG_DIR'/peers '$CONFIG_DIR'/ab"
    grep -qx logs     <<<"$sel" && plan "Remove logs"                                                     "rm -rf '$CONFIG_DIR'/log '$CONFIG_DIR'/*.log"
  fi
}

# ---- SERVER -------------------------------------------------------------------
detect_server_datadir(){
  [ -n "${DATA_DIR:-}" ] && { echo "$DATA_DIR"; return; }
  local unit wd
  for unit in rustdesk-hbbs-nemo rustdesk-hbbs; do
    wd=$(systemctl show -p WorkingDirectory --value "$unit" 2>/dev/null)
    [ -n "$wd" ] && [ -d "$wd" ] && { echo "$wd"; return; }
  done
  for d in /var/lib/rustdesk-server /var/lib/rustdesk /opt/rustdesk-server; do
    [ -f "$d/id_ed25519" ] && { echo "$d"; return; }
  done
  echo ""
}

do_server(){
  # NOT local: the plan command strings reference $dd and are eval'd later (in run_plan's
  # subshell, after this function returns), so $dd must be a global that survives.
  dd="$(detect_server_datadir)"
  if [ -z "$dd" ] && [ "$GUI" = zenity ]; then
    dd=$(zenity --entry --title "$APP_NAME Uninstaller" --text "Server data directory (holds id_ed25519, db_v2.sqlite3):" --entry-text "/var/lib/rustdesk-server" 2>/dev/null)
  fi
  [ -z "$dd" ] && dd="/var/lib/rustdesk-server"

  local sel; sel="$(checklist "Select what to remove from the TBFDesk SERVER (data dir: $dd):" \
    "svc|Stop, disable & remove hbbs/hbbr services (needs sudo)|on" \
    "bins|Remove hbbs/hbbr binaries|on" \
    "keys|Signing keys id_ed25519(.pub) (→ NEW server identity; all clients must re-provision)|on" \
    "db|Database (db_v2.sqlite3 — registered peers)|on" \
    "tls|Management TLS cert & key (nemo-api-cert/key.pem)|on" \
    "policy|Policy, integration & session state (nemo_*.json, token)|on" \
    "updates|Published client-update packages (nemo_updates)|on")"
  [ -z "$sel" ] && { info "Nothing selected — cancelled."; exit 0; }

  if grep -qx svc <<<"$sel"; then
    plan "Stop & disable hbbs/hbbr services" "$(sudo_if_needed systemctl disable --now rustdesk-hbbs-nemo rustdesk-hbbr-nemo rustdesk-hbbs rustdesk-hbbr); true"
    plan "Remove hbbs/hbbr systemd units"    "$(sudo_if_needed rm -f /etc/systemd/system/rustdesk-hbb*-nemo.service /etc/systemd/system/rustdesk-hbb*.service /usr/lib/systemd/system/rustdesk-hbb*.service); $(sudo_if_needed systemctl daemon-reload); true"
  fi
  grep -qx bins    <<<"$sel" && plan "Remove hbbs/hbbr binaries"               "$(sudo_if_needed rm -f /usr/bin/hbbs /usr/bin/hbbr /usr/local/bin/hbbs /usr/local/bin/hbbr)"
  grep -qx keys    <<<"$sel" && plan "Remove signing keys ($dd/id_ed25519*)"   "$(sudo_if_needed rm -f '$dd/id_ed25519' '$dd/id_ed25519.pub')"
  grep -qx db      <<<"$sel" && plan "Remove database ($dd/db_v2.sqlite3*)"      "$(sudo_if_needed rm -f '$dd/db_v2.sqlite3' '$dd/db_v2.sqlite3-shm' '$dd/db_v2.sqlite3-wal')"
  grep -qx tls     <<<"$sel" && plan "Remove management TLS cert & key"          "$(sudo_if_needed rm -f '$dd/nemo-api-cert.pem' '$dd/nemo-api-key.pem')"
  grep -qx policy  <<<"$sel" && plan "Remove policy/integration/session state"   "$(sudo_if_needed rm -f '$dd'/nemo_*.json '$dd'/nemo_*.json.* '$dd/token')"
  grep -qx updates <<<"$sel" && plan "Remove published update packages"          "$(sudo_if_needed rm -rf '$dd/nemo_updates')"
}

# ---- main ---------------------------------------------------------------------
MODE="${1:-}"; [ -z "$MODE" ] && MODE="$(pick_mode)"
case "$MODE" in client) do_client ;; server) do_server ;; *) info "Cancelled."; exit 0 ;; esac
[ "${#PLAN_CMD[@]}" -eq 0 ] && { info "Nothing to do."; exit 0; }

summary="$APP_NAME uninstaller — the following will be removed:\n\n"
for d in "${PLAN_DESC[@]}"; do summary+="  • $d\n"; done
summary+="\n"; [ "$DRY_RUN" = 1 ] && summary+="(DRY RUN — nothing will actually be deleted)\n"
summary+="This cannot be undone."
if confirm "$summary"; then
  result="$(run_plan)"
  info "Done.\n\n$result"
  echo "$result"
else
  info "Cancelled — nothing was removed."
fi
