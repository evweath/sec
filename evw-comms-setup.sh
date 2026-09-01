#!/bin/bash
# evw-comms-setup.sh — one-time setup: disable all non-WiFi communication channels.
#
# What this does:
#   1. Disables user-level (gui/501) communication services in disabled.501.plist
#   2. Disables system-level communication daemons
#   3. Turns off Bluetooth hardware
#   4. Kills all currently running target processes
#   5. Installs evw-comms-guard.sh to /usr/local/bin/
#   6. Installs and loads com.evw.comms-guard LaunchDaemon (root, 25s interval)
#
# Must run as root: sudo bash ~/dev/security/evw-comms-setup.sh
#
# WiFi is NOT affected: airportd and mDNSResponder are preserved.

set -uo pipefail

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error-guard.sh)
_eg_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
# As root, only trust a root-owned lib: a user-writable ancestor dir (e.g.
# Intel Homebrew's /usr/local) could plant one and have it sourced as root.
_eg_ok() { [ -f "$1" ] && { [ "$EUID" -ne 0 ] || [ "$(stat -f %u "$1" 2>/dev/null)" = "0" ]; }; }
while [ "$_eg_d" != "/" ] && ! _eg_ok "$_eg_d/lib/error-guard.sh"; do _eg_d="$(dirname "$_eg_d")"; done
_eg_ok "$_eg_d/lib/error-guard.sh" && . "$_eg_d/lib/error-guard.sh"; unset _eg_d; unset -f _eg_ok
command -v guard_run >/dev/null 2>&1 || guard_run() { shift; "$@"; }
command -v guard_throw >/dev/null 2>&1 || guard_throw() { printf 'error-guard: throw: %s\n' "$*" >&2; return 1; }

GUARD_SRC="$(dirname "$0")/evw-comms-guard.sh"
GUARD_DST="/usr/local/bin/evw-comms-guard.sh"
DAEMON_PLIST="/Library/LaunchDaemons/com.evw.comms-guard.plist"
PLIST_501="/var/db/com.apple.xpc.launchd/disabled.501.plist"

log() { printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"; }

if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: must run as root (sudo bash $0)"
    exit 1
fi

# ── DISABLED 2026-09-01 ─────────────────────────────────────────────────────
# The comms guard this script installs CAUSED recurring ~100-second internet
# outages (killing bluetoothd flaps the shared Wi-Fi/BT radio). Evidence:
#   /Users/evw/dev/fix/netdiag/STATE.md
if [[ "${COMMS_GUARD_ENABLED:-0}" != "1" ]]; then
    echo "evw-comms-setup: DISABLED 2026-09-01 — the comms guard caused recurring Wi-Fi outages."
    echo "Do not install it. Override (not recommended): COMMS_GUARD_ENABLED=1"
    exit 1
fi

if [[ ! -f "$GUARD_SRC" ]]; then
    echo "ERROR: guard script not found at $GUARD_SRC"
    exit 1
fi

echo "================================================================"
echo "evw-comms-setup.sh — disable all non-WiFi communication channels"
echo "$(date)"
echo "================================================================"
echo ""

# ── 1. User-level service disables (disabled.501.plist) ─────────────
log "[1/6] Disabling user-level services (gui/501)..."
guard_run "chflags-unlock" chflags noschg "$PLIST_501"

GUI_SVCS=(
    com.apple.AirPlayReceiver
    com.apple.AirPlayUIAgent
    com.apple.universalcontrol
    com.apple.PersonalHotspotAgent
    com.apple.rapportd-user
    com.apple.screensharingd
    com.apple.ARDAgent
    com.apple.mediaremoteagent
    com.apple.nearbyd
    com.apple.avconferenced
    com.apple.sharingd
    com.apple.identityservicesd
    com.apple.replicatord
    com.apple.studentd
    com.apple.replayd
    com.apple.replaykit.sharingsession
    com.apple.remotemanagementd
    com.apple.RemoteManagementAgent
    com.apple.privatecloudcomputed
)
for svc in "${GUI_SVCS[@]}"; do
    launchctl disable "gui/501/$svc" 2>/dev/null \
        && log "  disabled gui/501/$svc" \
        || log "  (not found) gui/501/$svc"
done

guard_run "chflags-relock" chflags schg "$PLIST_501"
# Verify the relock actually took — never log success unverified.
if ls -lO "$PLIST_501" | grep -qw schg; then
    log "  schg re-applied to $PLIST_501"
else
    echo "ERROR: schg NOT set on $PLIST_501 — file left unlocked, aborting" >&2
    exit 1
fi
echo ""

# ── 2. System-level service disables ────────────────────────────────
log "[2/6] Disabling system-level services..."
SYS_SVCS=(
    com.apple.bluetoothd
    com.apple.bluetooth.BTLEServer
    com.apple.rapportd
    com.apple.AirPlayReceiver
    com.apple.AirPlayXPCHelper
    com.apple.screensharingd
    com.apple.ARDAgent
    com.apple.mediaremoted
    com.apple.nearbyd
    com.apple.avconferenced
    com.apple.sharingd
    com.apple.identityservicesd
    com.apple.replicatord
    com.apple.studentd
    com.apple.replayd
    com.apple.remotemanagementd
    com.apple.privatecloudcomputed
)
for svc in "${SYS_SVCS[@]}"; do
    launchctl disable "system/$svc" 2>/dev/null \
        && log "  disabled system/$svc" \
        || log "  (not found) system/$svc"
    launchctl stop "system/$svc" 2>/dev/null || true
done
echo ""

# ── 3. Bluetooth hardware off ────────────────────────────────────────
log "[3/6] Turning off Bluetooth hardware..."
guard_run "defaults-bluetooth" defaults write /Library/Preferences/com.apple.Bluetooth ControllerPowerState -int 0
guard_run "defaults-bluetooth" defaults write /Library/Preferences/com.apple.Bluetooth BluetoothAutoSeekKeyboard -bool false
guard_run "defaults-bluetooth" defaults write /Library/Preferences/com.apple.Bluetooth BluetoothAutoSeekPointingDevice -bool false
log "  Bluetooth pref set to off"
echo ""

# ── 4. Kill all running instances now ───────────────────────────────
log "[4/6] Killing running instances..."
KILL_NOW=(
    bluetoothd bluetoothaudiod BTLEServer BTAvrcp
    AirPlayReceiver AirPlayUIAgent AirPlayXPCHelper
    universalcontrol rapportd PersonalHotspotAgent
    screensharingd ARDAgent mediaremoted nearbyd
    replayd studentd remotemanagementd RemoteManagementAgent
    sharingd identityservicesd replicatord privatecloudcomputed
)
for proc in "${KILL_NOW[@]}"; do
    pids=$(pgrep -x "$proc" 2>/dev/null) || true
    if [[ -n "$pids" ]]; then
        pkill -SIGKILL -x "$proc" 2>/dev/null && log "  killed $proc (PID $pids)" || true
    fi
done
echo ""

# ── 5. Install guard script ──────────────────────────────────────────
log "[5/6] Installing guard script..."
guard_run "install-bindir" install -d -m 755 -o root -g wheel /usr/local/bin
guard_run "install-guard" install -m 755 -o root -g wheel "$GUARD_SRC" "$GUARD_DST"
log "  installed $GUARD_DST"

guard_run "write-plist" cat > "$DAEMON_PLIST" << 'PLIST_EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.evw.comms-guard</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>/usr/local/bin/evw-comms-guard.sh</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>UserName</key>
    <string>root</string>
    <key>StandardErrorPath</key>
    <string>/private/var/log/evw-comms-guard-err.log</string>
</dict>
</plist>
PLIST_EOF

guard_run "chown-plist" chown root:wheel "$DAEMON_PLIST"
guard_run "chmod-plist" chmod 644 "$DAEMON_PLIST"
log "  installed $DAEMON_PLIST"
echo ""

# ── 6. Load daemon ───────────────────────────────────────────────────
log "[6/6] Loading LaunchDaemon..."
launchctl unload "$DAEMON_PLIST" 2>/dev/null || true
guard_run "launchctl-load" launchctl load -w "$DAEMON_PLIST"
log "  loaded com.evw.comms-guard"
echo ""

echo "================================================================"
echo "Setup complete."
echo ""
echo "Verify:"
echo "  sudo launchctl print system/com.evw.comms-guard"
echo "  sudo tail -30 /private/var/log/evw-comms-guard.log"
echo ""
echo "The guard will kill all target processes every 25 seconds."
echo "WiFi (airportd, mDNSResponder) is unaffected."
echo "================================================================"
