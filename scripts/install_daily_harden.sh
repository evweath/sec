#!/usr/bin/env bash
# =============================================================================
# install_daily_harden.sh
# One-time installer: registers mac_harden_rescan.sh as a daily launchd job.
# Run once with sudo (installs a root LaunchDaemon — the rescan requires root).
# =============================================================================

set -euo pipefail

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error-guard.sh)
_eg_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
while [ "$_eg_d" != "/" ] && [ ! -f "$_eg_d/lib/error-guard.sh" ]; do _eg_d="$(dirname "$_eg_d")"; done
[ -f "$_eg_d/lib/error-guard.sh" ] && . "$_eg_d/lib/error-guard.sh"; unset _eg_d
command -v guard_run >/dev/null 2>&1 || guard_run() { shift; "$@"; }
command -v guard_throw >/dev/null 2>&1 || guard_throw() { printf 'error-guard: throw: %s\n' "$*" >&2; return 1; }

if [[ $EUID -ne 0 ]]; then
    echo "[!] Must be run as root: sudo bash $0" >&2
    exit 1
fi

REAL_USER="${SUDO_USER:-$(logname 2>/dev/null || echo evw)}"
REAL_HOME="/Users/${REAL_USER}"

SCRIPT_SRC="$(cd "$(dirname "$0")" && pwd)/mac_harden_rescan.sh"
SCRIPT_DEST="/usr/local/bin/mac_harden_rescan.sh"
PLIST_DEST="/Library/LaunchDaemons/local.security.harden.plist"
LOG_DIR="$REAL_HOME/Library/Logs/SecurityAudit"
LABEL="local.security.harden"

echo ""
echo "=== Daily Hardening Script Installer (root LaunchDaemon) ==="
echo ""

# ── 1. Install the hardening script to a root-owned location ─────────────────
install -d -m 755 -o root -g wheel /usr/local/bin
if [ -f "$SCRIPT_SRC" ]; then
    guard_run "install-rescan-script" install -m 755 -o root -g wheel "$SCRIPT_SRC" "$SCRIPT_DEST" || true
    echo "[+] Installed mac_harden_rescan.sh → $SCRIPT_DEST (root:wheel)"
else
    echo "[!] mac_harden_rescan.sh not found next to this installer."
    echo "    Place mac_harden_rescan.sh in the same directory and re-run."
    exit 1
fi

# ── 2. Create log directory ──────────────────────────────────────────────────
# Keep the directory root:wheel — the root daemon's StandardOutPath lives
# inside it. A user-owned dir would let the user replace the log with a
# symlink, turning root's append-write into an arbitrary-file write. The log
# files themselves are made world-readable so the user can still read them.
mkdir -p "$LOG_DIR"
chown root:wheel "$LOG_DIR"
# Remove any pre-existing symlinks from the old user-owned layout so the
# touch/chmod below cannot be redirected to a file outside the log dir.
if [[ -L "$LOG_DIR/daily_harden.log" ]]; then rm -f "$LOG_DIR/daily_harden.log"; fi
if [[ -L "$LOG_DIR/daily_harden_err.log" ]]; then rm -f "$LOG_DIR/daily_harden_err.log"; fi
touch "$LOG_DIR/daily_harden.log" "$LOG_DIR/daily_harden_err.log"
chmod 644 "$LOG_DIR/daily_harden.log" "$LOG_DIR/daily_harden_err.log"
echo "[+] Log directory: $LOG_DIR (root:wheel; logs 644 for user read access)"

# ── 3. Write the plist ────────────────────────────────────────────────────────
guard_run "plist-write" cat > "$PLIST_DEST" << PLIST_EOF || true
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>local.security.harden</string>

    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>${SCRIPT_DEST}</string>
    </array>

    <!-- Daily at 09:00 AM local time -->
    <key>StartCalendarInterval</key>
    <dict>
        <key>Hour</key>
        <integer>9</integer>
        <key>Minute</key>
        <integer>0</integer>
    </dict>

    <!-- Do NOT run immediately on load -->
    <key>RunAtLoad</key>
    <false/>

    <key>StandardOutPath</key>
    <string>${LOG_DIR}/daily_harden.log</string>

    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/daily_harden_err.log</string>

    <key>KeepAlive</key>
    <false/>
</dict>
</plist>
PLIST_EOF

guard_run "plist-chmod" chmod 644 "$PLIST_DEST" || true
guard_run "plist-chown" chown root:wheel "$PLIST_DEST" || true
echo "[+] Plist written → $PLIST_DEST (root:wheel 644)"

# ── 4. (Re)load the job ───────────────────────────────────────────────────────
# Remove the old user LaunchAgent version if it exists
OLD_AGENT="$REAL_HOME/Library/LaunchAgents/local.security.harden.plist"
if [ -f "$OLD_AGENT" ]; then
    launchctl bootout "gui/$(id -u "$REAL_USER")" "$OLD_AGENT" 2>/dev/null || \
        sudo -u "$REAL_USER" launchctl unload "$OLD_AGENT" 2>/dev/null || true
    rm -f "$OLD_AGENT"
    echo "[i] Removed old user LaunchAgent version: $OLD_AGENT"
fi

launchctl bootout system "$PLIST_DEST" 2>/dev/null || true
guard_run "launchd-bootstrap" launchctl bootstrap system "$PLIST_DEST" || true
echo "[+] Job loaded into launchd (system domain)."

# ── 5. Verify ────────────────────────────────────────────────────────────────
echo ""
echo "=== Verification ==="
if launchctl print "system/$LABEL" &>/dev/null; then
    echo "[✓] Job '$LABEL' is registered and active."
else
    echo "[✗] Job did not register. Check plist syntax with:"
    echo "    plutil -lint $PLIST_DEST"
    exit 1
fi

echo ""
echo "=== Installation Complete ==="
echo ""
echo "  Schedule  : Daily at 09:00 AM"
echo "  Script    : $SCRIPT_DEST (runs as root)"
echo "  Plist     : $PLIST_DEST"
echo "  Logs      : $LOG_DIR/"
echo ""
echo "  To run manually right now:"
echo "    sudo $SCRIPT_DEST"
echo ""
echo "  To trigger the launchd job immediately (for testing):"
echo "    sudo launchctl kickstart system/$LABEL"
echo ""
echo "  To uninstall:"
echo "    sudo launchctl bootout system $PLIST_DEST && sudo rm $PLIST_DEST"
echo ""
