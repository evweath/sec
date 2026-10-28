#!/bin/bash
# evw-security-audit-setup.sh — one-time install of the unattended audit:
#
#   /usr/local/bin/evw-security-audit.sh              (root-owned audit script)
#   /usr/local/bin/{scan-hashes.sh,evw-log-doctor.py,ls-*.py,tcc-audit.sh}
#                                                     (root-owned helper copies)
#   com.evw.security-audit        LaunchDaemon, root  → full audit at every BOOT
#   com.evw.security-audit-login  LaunchAgent,  evw   → user audit at every LOGIN
#
# (boot + login within 10 min is debounced inside the audit script, so the
#  pair never double-reports.)
#
# Must run as root: sudo bash ~/dev/security/evw-security-audit-setup.sh
# Uninstall:        sudo bash ~/dev/security/evw-security-audit-setup.sh --uninstall

set -euo pipefail

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error-guard.sh)
_eg_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
_eg_ok() { [ -f "$1" ] && { [ "$EUID" -ne 0 ] || [ "$(stat -f %u "$1" 2>/dev/null)" = "0" ]; }; }
while [ "$_eg_d" != "/" ] && ! _eg_ok "$_eg_d/lib/error-guard.sh"; do _eg_d="$(dirname "$_eg_d")"; done
_eg_ok "$_eg_d/lib/error-guard.sh" && . "$_eg_d/lib/error-guard.sh"; unset _eg_d; unset -f _eg_ok
command -v guard_run >/dev/null 2>&1 || guard_run() { shift; "$@"; }
command -v guard_throw >/dev/null 2>&1 || guard_throw() { printf 'error-guard: throw: %s\n' "$*" >&2; return 1; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AUDIT_SRC="$SCRIPT_DIR/evw-security-audit.sh"
AUDIT_DST="/usr/local/bin/evw-security-audit.sh"
DAEMON_PLIST="/Library/LaunchDaemons/com.evw.security-audit.plist"
DAEMON_LABEL="com.evw.security-audit"
AGENT_PLIST="/Users/evw/Library/LaunchAgents/com.evw.security-audit-login.plist"
AGENT_LABEL="com.evw.security-audit-login"

[[ $EUID -ne 0 ]] && { echo "ERROR: must run as root: sudo bash $0"; exit 1; }

if [[ "${1:-}" == "--uninstall" ]]; then
    echo "=== evw-security-audit uninstall ==="
    launchctl bootout "system/$DAEMON_LABEL" 2>/dev/null || launchctl unload "$DAEMON_PLIST" 2>/dev/null || true
    launchctl bootout "gui/501/$AGENT_LABEL" 2>/dev/null || true
    rm -f "$DAEMON_PLIST" "$AGENT_PLIST" "$AUDIT_DST"
    echo "removed: $AUDIT_DST"
    echo "removed: $DAEMON_PLIST"
    echo "removed: $AGENT_PLIST"
    echo "=== Done ==="
    exit 0
fi

echo "=== evw-security-audit setup ==="
echo ""

echo "[1/5] Installing audit script and root-owned helpers..."
guard_run "install-script" install -m 755 -o root -g wheel "$AUDIT_SRC" "$AUDIT_DST"
echo "      $AUDIT_DST"
HELPERS=(
    scan-hashes.sh
    evw-log-doctor.py
    ls-full-analysis.py
    ls-domain-audit.py
    ls-permissive-analysis.py
    tcc-audit.sh
)
for tool in "${HELPERS[@]}"; do
    [[ -f "$SCRIPT_DIR/$tool" ]] || { echo "ERROR: missing $SCRIPT_DIR/$tool" >&2; exit 1; }
    guard_run "install-$tool" install -m 755 -o root -g wheel "$SCRIPT_DIR/$tool" "/usr/local/bin/$tool"
    echo "      /usr/local/bin/$tool"
done
[[ -f "$SCRIPT_DIR/scan-2026-08-10/ls-rules-deep-audit.py" ]] || {
    echo "ERROR: missing $SCRIPT_DIR/scan-2026-08-10/ls-rules-deep-audit.py" >&2; exit 1;
}
guard_run "install-deep-audit" install -m 755 -o root -g wheel \
    "$SCRIPT_DIR/scan-2026-08-10/ls-rules-deep-audit.py" /usr/local/bin/ls-rules-deep-audit.py
echo "      /usr/local/bin/ls-rules-deep-audit.py"

if [[ -d /opt/homebrew/opt/lynis ]]; then
    LYNIS_SRC=$(cd /opt/homebrew/opt/lynis && pwd -P)
    install -d -m 755 -o root -g wheel /usr/local/opt
    guard_run "install-lynis-tree" ditto "$LYNIS_SRC" /usr/local/opt/lynis
    guard_run "perms-lynis-tree" bash -c "chown -R root:wheel /usr/local/opt/lynis && chmod -R u=rwX,go=rX /usr/local/opt/lynis"
    echo "      /usr/local/opt/lynis"
else
    echo "      WARNING: Homebrew Lynis not found; root audit will report it missing"
fi
if [[ -d /Applications/KnockKnock.app ]]; then
    install -d -m 755 -o root -g wheel /usr/local/libexec
    guard_run "install-knockknock" ditto /Applications/KnockKnock.app /usr/local/libexec/KnockKnock.app
    guard_run "perms-knockknock" bash -c "chown -R root:wheel /usr/local/libexec/KnockKnock.app && chmod -R u=rwX,go=rX /usr/local/libexec/KnockKnock.app"
    echo "      /usr/local/libexec/KnockKnock.app"
else
    echo "      WARNING: KnockKnock not found; root audit will report it missing"
fi

echo "[2/5] Writing boot LaunchDaemon..."
guard_run "write-daemon-plist" cat > "$DAEMON_PLIST" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.evw.security-audit</string>

    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>/usr/local/bin/evw-security-audit.sh</string>
        <string>--auto</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>UserName</key>
    <string>root</string>

    <key>StandardOutPath</key>
    <string>/private/var/log/evw-security-audit.log</string>

    <key>StandardErrorPath</key>
    <string>/private/var/log/evw-security-audit-err.log</string>
</dict>
</plist>
PLIST
guard_run "perms-daemon-plist" bash -c "chmod 644 '$DAEMON_PLIST' && chown root:wheel '$DAEMON_PLIST'"
echo "      $DAEMON_PLIST"

echo "[3/5] Writing login LaunchAgent (evw)..."
guard_run "write-agent-plist" cat > "$AGENT_PLIST" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.evw.security-audit-login</string>

    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>/usr/local/bin/evw-security-audit.sh</string>
        <string>--auto</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>StandardOutPath</key>
    <string>/Users/evw/dev/security/logs/security-audit-login.log</string>

    <key>StandardErrorPath</key>
    <string>/Users/evw/dev/security/logs/security-audit-login-err.log</string>
</dict>
</plist>
PLIST
guard_run "perms-agent-plist" bash -c "chmod 644 '$AGENT_PLIST' && chown evw:staff '$AGENT_PLIST'"
echo "      $AGENT_PLIST (auto-registers at every login)"

echo "[4/5] Loading daemon + agent..."
launchctl unload "$DAEMON_PLIST" 2>/dev/null || true
guard_run "load-daemon" launchctl load -w "$DAEMON_PLIST"
# agent: activate now if the gui domain is up; otherwise it self-registers at next login
launchctl bootout "gui/501/$AGENT_LABEL" 2>/dev/null || true
launchctl bootstrap "gui/501" "$AGENT_PLIST" 2>/dev/null \
    && echo "      agent bootstrapped into gui/501" \
    || echo "      agent will auto-register at next login"

echo "[5/5] Verifying (daemon's RunAtLoad fires a full root audit now)..."
sleep 25
launchctl print "system/$DAEMON_LABEL" 2>/dev/null | grep -E '^\s+(state|pid|last exit code)' | head -4 || {
    echo "ERROR: $DAEMON_LABEL not registered after load" >&2
    exit 1
}
tail -3 /Users/evw/dev/security/logs/boot-audit.log 2>/dev/null || true

echo ""
echo "=== Done ==="
echo "Boot  (root, full audit incl. LS export + TCC): $DAEMON_LABEL"
echo "Login (evw,  user subset)                    : $AGENT_LABEL"
echo "Status lines  : /Users/evw/dev/security/logs/boot-audit.log"
echo "Daemon stdout : /private/var/log/evw-security-audit.log"
echo "Uninstall     : sudo bash $0 --uninstall"
