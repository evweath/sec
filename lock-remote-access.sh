#!/usr/bin/env bash
# lock-remote-access.sh
# Audits and disables every macOS remote-access / sharing technology I know of.
# Safe to run repeatedly (idempotent). Each step uses `try` so a missing
# service / SIP-protected unit won't halt the script.
#
# Covers:
#   • SSH Remote Login                  (com.openssh.sshd / systemsetup)
#   • Apple Remote Desktop (ARD)        (kickstart -deactivate)
#   • Screen Sharing (VNC)              (com.apple.screensharing + helpers)
#   • SMB File Sharing                  (com.apple.smbd)
#   • AFP File Sharing                  (com.apple.AppleFileServer)
#   • NetBIOS (legacy SMB advertising)  (com.apple.netbiosd)
#   • Printer Sharing                   (cups)
#   • Internet Sharing                  (NAT defaults)
#   • Remote Apple Events               (com.apple.AEServer)
#   • Apple Classroom (managed-edu)     (com.apple.studentd / classroomd / teacherd)
#   • Content Caching                   (com.apple.AssetCache.builtin & locator)
#   • Media (iTunes/Music) Sharing      (com.apple.amp.mediasharingd)
#   • Bluetooth Sharing (OBEX)          (per-host pref)
#   • AirDrop                           (sharingd: best-effort kill, see notes)
#
# Run:   /Users/evw/dev/security/lock-remote-access.sh
# Log:   ~/lock-remote-access-YYYYMMDD-HHMMSS.log

set -uo pipefail

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error-guard.sh)
_eg_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
while [ "$_eg_d" != "/" ] && [ ! -f "$_eg_d/lib/error-guard.sh" ]; do _eg_d="$(dirname "$_eg_d")"; done
[ -f "$_eg_d/lib/error-guard.sh" ] && . "$_eg_d/lib/error-guard.sh"; unset _eg_d
command -v guard_run >/dev/null 2>&1 || guard_run() { shift; "$@"; }
command -v guard_throw >/dev/null 2>&1 || guard_throw() { printf 'error-guard: throw: %s\n' "$*" >&2; return 1; }

LOG="$HOME/lock-remote-access-$(date +%Y%m%d-%H%M%S).log"
touch "$LOG"; chmod 600 "$LOG"
exec > >(tee -a "$LOG") 2>&1

RED=$'\033[0;31m'; GRN=$'\033[0;32m'; YLW=$'\033[0;33m'; BLU=$'\033[0;34m'; NC=$'\033[0m'
log()     { printf "%s[*]%s %s\n" "$BLU" "$NC" "$*"; }
ok()      { printf "%s[+]%s %s\n" "$GRN" "$NC" "$*"; }
warn()    { printf "%s[!]%s %s\n" "$YLW" "$NC" "$*"; }
err()     { printf "%s[x]%s %s\n" "$RED" "$NC" "$*"; }
section() { printf "\n%s═══ %s ═══%s\n" "$BLU" "$*" "$NC"; }
try()     { local _c="$1"; [ "$_c" = "sudo" ] && _c="${2:-sudo}"; guard_run "try:${_c##*/}" "$@" || warn "command exited non-zero (continuing): $*"; }
# Expected-failure tolerances (keep the guard's failure counter honest):
#   lsof rc 1        = no matching lines — the lockdown goal state, not an error
#   bootout rc 150   = SIP-protected unit refusing bootout — expected, see NOTES
lsof_listen()   { sudo lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null; [ $? -le 1 ]; }
bootout_label() { sudo launchctl bootout "system/$1" 2>/dev/null; local rc=$?; [ $rc -eq 0 ] || [ $rc -eq 150 ]; }

[[ "$(uname)" == "Darwin" ]] || { err "macOS only"; exit 1; }
[[ "$EUID" -ne 0 ]] || { err "Do NOT run as root — script will sudo where needed"; exit 1; }

log "Priming sudo (you'll be prompted once)…"
sudo -v || { err "sudo required"; exit 1; }
( while true; do sudo -n true; sleep 50; kill -0 "$$" 2>/dev/null || exit; done ) 2>/dev/null &
SUDO_KEEPALIVE=$!
trap 'kill $SUDO_KEEPALIVE 2>/dev/null || true' EXIT

# Labels we want disabled in the system domain. Some won't exist on this
# machine — that's fine; launchctl disable still records the disabled flag.
SYSTEM_LABELS=(
    com.openssh.sshd
    com.apple.screensharing
    com.apple.screensharing.agent
    com.apple.screensharing.MessagesAgent
    com.apple.screensharing.menuextra
    com.apple.RemoteDesktop.agent
    com.apple.smbd
    com.apple.AppleFileServer
    com.apple.netbiosd
    com.apple.AEServer
    com.apple.studentd
    com.apple.classroomd
    com.apple.teacherd
    com.apple.amp.mediasharingd
    com.apple.AssetCache.builtin
    com.apple.AssetCacheLocatorService
    com.apple.AssetCacheManagerService
    com.apple.AssetCacheTetheratorService
)

# These plists, if present, can be unloaded too (belt + suspenders).
SYSTEM_PLISTS=(
    /System/Library/LaunchDaemons/com.apple.screensharing.plist
    /System/Library/LaunchDaemons/com.apple.smbd.plist
    /System/Library/LaunchDaemons/com.apple.AppleFileServer.plist
    /System/Library/LaunchDaemons/com.apple.netbiosd.plist
    /System/Library/LaunchDaemons/com.apple.AEServer.plist
    /System/Library/LaunchDaemons/com.apple.studentd.plist
    /System/Library/LaunchDaemons/com.apple.classroomd.plist
    /System/Library/LaunchDaemons/com.apple.teacherd.plist
    /System/Library/LaunchDaemons/com.apple.amp.mediasharingd.plist
    /System/Library/LaunchDaemons/com.apple.AssetCache.builtin.plist
    /System/Library/LaunchDaemons/com.apple.AssetCacheLocatorService.plist
    /System/Library/LaunchDaemons/com.apple.AssetCacheManagerService.plist
    /System/Library/LaunchDaemons/com.apple.AssetCacheTetheratorService.plist
)

audit_label() {
    local label="$1"
    local enabled disabled loaded
    # Disabled flag (true means we've disabled it)
    if sudo launchctl print-disabled system 2>/dev/null | grep -q "\"$label\" => disabled"; then
        disabled="DISABLED"
    elif sudo launchctl print-disabled system 2>/dev/null | grep -q "\"$label\""; then
        disabled="enabled"
    else
        disabled="unknown"
    fi
    # Currently loaded?
    if sudo launchctl print "system/$label" >/dev/null 2>&1; then
        loaded="loaded"
    else
        loaded="not-loaded"
    fi
    printf "  %-50s [%s, %s]\n" "$label" "$disabled" "$loaded"
}

# ────────────────────────────────────────────────────────────────────────────
section "AUDIT (before)"
# ────────────────────────────────────────────────────────────────────────────
log "SSH (Remote Login):"
try sudo systemsetup -getremotelogin

log "Apple Remote Desktop (ARD) status:"
try sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status 2>/dev/null

log "Printer Sharing:"
try cupsctl | grep -i share

log "Internet Sharing (NAT) state:"
try sudo defaults read /Library/Preferences/SystemConfiguration/com.apple.nat NAT 2>/dev/null

log "LaunchD labels (before):"
for L in "${SYSTEM_LABELS[@]}"; do guard_run "audit-label" audit_label "$L"; done

# ────────────────────────────────────────────────────────────────────────────
section "DISABLE: SSH (Remote Login)"
# ────────────────────────────────────────────────────────────────────────────
try sudo systemsetup -f -setremotelogin off     # -f skips the y/n prompt

# ────────────────────────────────────────────────────────────────────────────
section "DISABLE: Apple Remote Desktop (ARD)"
# ────────────────────────────────────────────────────────────────────────────
try sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart \
    -deactivate -stop -uninstall

# ────────────────────────────────────────────────────────────────────────────
section "DISABLE: launchd units (screen sharing, file sharing, classroom, etc.)"
# ────────────────────────────────────────────────────────────────────────────
for L in "${SYSTEM_LABELS[@]}"; do
    log "disable system/$L"
    try sudo launchctl disable "system/$L"
    # Try to bootout if currently loaded (modern equivalent of unload -w)
    sudo launchctl print "system/$L" >/dev/null 2>&1 && try bootout_label "$L"
done

# Best-effort unload of known plists (will fail under SIP — that's OK, the
# launchctl disable above already prevents future starts)
for P in "${SYSTEM_PLISTS[@]}"; do
    [[ -f "$P" ]] || continue
    try sudo launchctl unload -w "$P"
done

# ────────────────────────────────────────────────────────────────────────────
section "DISABLE: Printer Sharing"
# ────────────────────────────────────────────────────────────────────────────
try cupsctl --no-share-printers
try cupsctl --no-remote-admin
try cupsctl --no-remote-any

# ────────────────────────────────────────────────────────────────────────────
section "DISABLE: Internet Sharing"
# ────────────────────────────────────────────────────────────────────────────
try sudo defaults write /Library/Preferences/SystemConfiguration/com.apple.nat NAT -dict Enabled -int 0
try sudo launchctl disable system/com.apple.InternetSharing 2>/dev/null

# ────────────────────────────────────────────────────────────────────────────
section "DISABLE: Bluetooth Sharing (OBEX)"
# ────────────────────────────────────────────────────────────────────────────
try defaults -currentHost write com.apple.Bluetooth PrefKeyServicesEnabled -bool false
# Per-folder OBEX exchange defaults
try defaults write com.apple.bluetooth PrefKeyFTPServerEnabled -bool false
try defaults write com.apple.bluetooth PrefKeyOBEXServerEnabled -bool false

# ────────────────────────────────────────────────────────────────────────────
section "DISABLE: AirDrop / sharingd-mediated proximity sharing"
# ────────────────────────────────────────────────────────────────────────────
# sharingd is core to AirDrop, Handoff, Continuity, Universal Clipboard, etc.
# It runs as a LaunchAgent in the user's gui domain.
USER_UID=$(id -u)
try launchctl disable "gui/$USER_UID/com.apple.sharingd"
# AirDrop discoverability for the current user
try defaults write com.apple.NetworkBrowser DisableAirDrop -bool true
# Handoff / Continuity off
try defaults -currentHost write com.apple.coreservices.useractivityd ActivityAdvertisingAllowed -bool false
try defaults -currentHost write com.apple.coreservices.useractivityd ActivityReceivingAllowed -bool false

# ────────────────────────────────────────────────────────────────────────────
section "VERIFY (after)"
# ────────────────────────────────────────────────────────────────────────────
log "SSH (should be Off):"
try sudo systemsetup -getremotelogin

log "ARD status (should be 'is not running' / similar):"
try sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status 2>/dev/null

log "Printer Sharing (should show _share_printers=0):"
try cupsctl | grep -i share

log "Internet Sharing NAT (should be Enabled=0):"
try sudo defaults read /Library/Preferences/SystemConfiguration/com.apple.nat NAT 2>/dev/null

log "LaunchD labels (after):"
for L in "${SYSTEM_LABELS[@]}"; do guard_run "audit-label" audit_label "$L"; done

log "Open listening TCP ports (should be empty if you don't run servers):"
try lsof_listen

ok "Remote-access lockdown complete. Log: $LOG"
warn ""
warn "NOTES:"
warn "  • sharingd disabling will weaken AirDrop, Handoff, Universal Clipboard, AirPlay-to-Mac."
warn "    That's intentional for high-threat models. To re-enable later:"
warn "       launchctl enable gui/\$(id -u)/com.apple.sharingd"
warn "  • SIP protects /System/Library/LaunchDaemons/* — 'launchctl unload' may print errors."
warn "    That's expected. The 'launchctl disable' above is what actually prevents future starts."
warn "  • Some services will only appear in the audit if they were ever launched on this Mac."
warn "    'unknown' for a label simply means launchd has no record of it — effectively off."
warn "  • Reboot once after running this to ensure all disabled units stay down across launchd restarts."
