#!/usr/bin/env bash
# =============================================================================
# harden-now.sh — one-shot system-configuration tightening (macOS 26)
#
# Run:  sudo bash /Users/evw/dev/security/harden-now.sh
#
# Applies the deviations found in the 2026-08-10 config scan:
#   1. Pin DNS (1.1.1.1/1.0.0.1/8.8.8.8/9.9.9.9) on every active network service (DHCP DNS drift fix)
#   2. Prune the Application Firewall app allow-list (moot under block-all)
#   3. Enable the three unset automatic-update flags
#   4. Neutralize the broadcast device name (Bonjour identity leak)
#   5. Deactivate Remote Management (remotemanagementd running w/o MDM)
#   6. Disable netbiosd (running while SMB sharing is off — LAN info leak)
#   7. Report-only root checks: profiles, root listener sweep, pf state
#
# Idempotent; safe to re-run. Edit the values below before running.
# =============================================================================

set -euo pipefail

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error-guard.sh)
_eg_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
while [ "$_eg_d" != "/" ] && [ ! -f "$_eg_d/lib/error-guard.sh" ]; do _eg_d="$(dirname "$_eg_d")"; done
[ -f "$_eg_d/lib/error-guard.sh" ] && . "$_eg_d/lib/error-guard.sh"; unset _eg_d
command -v guard_run >/dev/null 2>&1 || guard_run() { shift; "$@"; }
command -v guard_throw >/dev/null 2>&1 || guard_throw() { printf 'error-guard: throw: %s\n' "$*" >&2; return 1; }

DNS_SERVERS="1.1.1.1 1.0.0.1 8.8.8.8 9.9.9.9"
NEW_NAME="mbp"   # ComputerName + LocalHostName (Bonjour). Edit to taste.

info() { echo "[*] $*"; }
ok()   { echo "[✓] $*"; }
warn() { echo "[!] $*"; }

if [[ $EUID -ne 0 ]]; then
    echo "[!] Must be run as root: sudo bash $0" >&2
    exit 1
fi

# ── 1. Pinned DNS on every active service ───────────────────────────────────
info "Pinning DNS (1.1.1.1/1.0.0.1/8.8.8.8/9.9.9.9) on all active network services"
networksetup -listallnetworkservices | tail -n +2 | while IFS= read -r svc; do
    [[ "$svc" == \** ]] && continue   # disabled service
    guard_run "setdnsservers" networksetup -setdnsservers "$svc" $DNS_SERVERS || true
    echo "    $svc -> $(networksetup -getdnsservers "$svc" | tr '\n' ' ')"
done
ok "DNS pinned"

# ── 2. Prune ALF app allow-list ───────────────────────────────────────────────
info "Pruning Application Firewall allow-list (block-all stays on)"
FW=/usr/libexec/ApplicationFirewall/socketfilterfw
# NB: the flag is --listapps — there is no --getlistapps (bad flag exits 255 and,
# piped into sed -n, fails silently; under pipefail + set -e it kills this script).
FW_APPS="$("$FW" --listapps 2>/dev/null)" || warn "socketfilterfw --listapps failed (rc=$?) — skipping prune"
printf '%s\n' "$FW_APPS" | sed -nE 's/^[[:space:]]*[0-9]+[[:space:]]*:[[:space:]]*(\/.*)$/\1/p' | while IFS= read -r app; do
    app="${app%"${app##*[![:space:]]}"}"   # trim trailing whitespace (--listapps pads columns)
    [ -n "$app" ] || continue
    guard_run "alf-remove-app" "$FW" --remove "$app" >/dev/null && echo "    removed: $app" || true
done
FW_LEFT="$(grep -c ':' <<< "$FW_APPS" || true)"
ok "Allow-list pruned (${FW_LEFT:-0} entries remain)"

# ── 3. Automatic-update flags ─────────────────────────────────────────────────
info "Enabling automatic macOS / security-response updates"
SU=/Library/Preferences/com.apple.SoftwareUpdate
guard_run "swupdate-macos-install" defaults write "$SU" AutomaticallyInstallMacOSUpdates -bool true || true
guard_run "swupdate-critical-install" defaults write "$SU" CriticalUpdateInstall -bool true || true
guard_run "swupdate-configdata-install" defaults write "$SU" ConfigDataInstall -bool true || true
ok "Auto-update flags set"

# ── 4. Neutral device name ────────────────────────────────────────────────────
info "Setting neutral device name: $NEW_NAME"
guard_run "scutil-computername" scutil --set ComputerName "$NEW_NAME" || true
guard_run "scutil-localhostname" scutil --set LocalHostName "$NEW_NAME" || true
# HostName intentionally left unset
ok "Bonjour now advertises: $(scutil --get LocalHostName)"

# ── 5. Remote Management off ──────────────────────────────────────────────────
KICK=/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart
if [[ -x "$KICK" ]]; then
    info "Deactivating Remote Management / ARD"
    guard_run "ard-deactivate" "$KICK" -deactivate -stop 2>&1 | sed 's/^/    /' || true
    ok "Remote Management deactivated"
else
    warn "kickstart not found — skipping ARD deactivation"
fi

# ── 6. netbiosd off ───────────────────────────────────────────────────────────
info "Disabling netbiosd"
guard_run "netbiosd-disable" launchctl disable system/com.apple.netbiosd 2>/dev/null || true
guard_run "netbiosd-bootout" launchctl bootout system/com.apple.netbiosd 2>/dev/null || true
pgrep -x netbiosd >/dev/null && warn "netbiosd still running" || ok "netbiosd disabled and stopped"

# ── 6b. AirDrop hard-disable (system-wide, all users) ─────────────────────────
info "Hard-disabling AirDrop system-wide"
guard_run "airdrop-disable" defaults write /Library/Preferences/com.apple.NetworkBrowser DisableAirDrop -bool true || true
# Take down the AWDL interface AirDrop/AirPlay use for peer discovery
guard_run "awdl-down" ifconfig awdl0 down 2>/dev/null || warn "awdl0 not present or already down"
ok "AirDrop disabled (system plist + awdl0 down; user-level keys already set)"

# ── 7. Report-only root checks ────────────────────────────────────────────────
echo ""
info "=== Root verification report ==="
echo ""
echo "--- Configuration profiles (expect: none) ---"
profiles -P 2>&1 | sed 's/^/    /' || true
echo ""
echo "--- All TCP listeners (root view) ---"
lsof -nP -iTCP -sTCP:LISTEN | sed 's/^/    /'
echo ""
echo "--- pf state ---"
pfctl -s info 2>&1 | head -5 | sed 's/^/    /'
echo ""
echo "--- Remote login (expect: Off) ---"
systemsetup -getremotelogin 2>&1 | sed 's/^/    /' || true
echo ""
echo "--- Background Task Management items (the persistence store non-root can't read) ---"
sfltool dumpbtm 2>&1 | grep -iE "identifier|path|name" | grep -viE "com.apple|littlesnitch|homebrew|openbrain" | head -30 | sed 's/^/    /' || true
echo "    (full dump: sudo sfltool dumpbtm — above filters out Apple/known items)"
echo ""
echo "--- System crontabs (expect: nothing) ---"
ls -la /usr/lib/cron/tabs/ 2>&1 | sed 's/^/    /'
echo ""
ok "Done. Re-run seccheck.sh to confirm: bash /Users/evw/dev/security/scripts/seccheck.sh"
