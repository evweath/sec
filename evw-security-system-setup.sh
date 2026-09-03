#!/bin/bash
# evw-security-system-setup.sh — one-time install of the self-healing
# security system (2026-09-03):
#
#   /usr/local/bin/evw-security-system.py   (root-owned orchestrator daemon)
#   /usr/local/bin/evw-alert-center.py      (root-owned; runs as the evw GUI agent)
#   /usr/local/bin/ls-screenshare-deny.py   (root-owned LS both-ways deny tool)
#   /usr/local/bin/ls-hole-audit.py         (root-owned LS hole audit; used by
#                                            the ls-change-watch job)
#   com.evw.security-system   LaunchDaemon, root      (KeepAlive)
#   com.evw.alert-center      LaunchAgent,  evw / gui (KeepAlive, Aqua session)
#   /var/db/evw-security-system/   state dir (alerts/ 755, ack/ 1777, config)
#
# Must run as root: sudo bash ~/dev/security/evw-security-system-setup.sh
# Config refresh:   sudo bash ~/dev/security/evw-security-system-setup.sh --config-update
# Uninstall:        sudo bash ~/dev/security/evw-security-system-setup.sh --uninstall

set -euo pipefail

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error-guard.sh)
_eg_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
_eg_ok() { [ -f "$1" ] && { [ "$EUID" -ne 0 ] || [ "$(stat -f %u "$1" 2>/dev/null)" = "0" ]; }; }
while [ "$_eg_d" != "/" ] && ! _eg_ok "$_eg_d/lib/error-guard.sh"; do _eg_d="$(dirname "$_eg_d")"; done
_eg_ok "$_eg_d/lib/error-guard.sh" && . "$_eg_d/lib/error-guard.sh"; unset _eg_d; unset -f _eg_ok
command -v guard_run >/dev/null 2>&1 || guard_run() { shift; "$@"; }
command -v guard_throw >/dev/null 2>&1 || guard_throw() { printf 'error-guard: throw: %s\n' "$*" >&2; return 1; }

SEC="$(cd "$(dirname "$0")" && pwd)"
STATE_DIR="/var/db/evw-security-system"
DAEMON_PLIST="/Library/LaunchDaemons/com.evw.security-system.plist"
DAEMON_LABEL="com.evw.security-system"
AGENT_PLIST="/Users/evw/Library/LaunchAgents/com.evw.alert-center.plist"
AGENT_LABEL="com.evw.alert-center"
LSCLI="/Applications/Little Snitch.app/Contents/Components/littlesnitch"
TS="$(date +%Y%m%d-%H%M%S)"

CONFIG_UPDATE=0
for arg in "$@"; do
    [[ "$arg" == "--config-update" ]] && CONFIG_UPDATE=1
done

[[ $EUID -ne 0 ]] && { echo "ERROR: must run as root: sudo bash $0"; exit 1; }

if [[ " $* " == *" --uninstall "* ]]; then
    echo "=== evw-security-system uninstall ==="
    launchctl bootout "system/$DAEMON_LABEL" 2>/dev/null || launchctl unload "$DAEMON_PLIST" 2>/dev/null || true
    launchctl bootout "gui/501/$AGENT_LABEL" 2>/dev/null || true
    rm -f "$DAEMON_PLIST" "$AGENT_PLIST" \
        /usr/local/bin/evw-security-system.py \
        /usr/local/bin/evw-alert-center.py \
        /usr/local/bin/ls-screenshare-deny.py \
        /usr/local/bin/ls-hole-audit.py
    echo "removed: $DAEMON_PLIST"
    echo "removed: $AGENT_PLIST"
    echo "removed: /usr/local/bin/{evw-security-system,evw-alert-center,ls-screenshare-deny,ls-hole-audit}.py"
    echo "kept (records): $STATE_DIR, /var/log/evw-security-system*.log,"
    echo "                /Users/evw/Library/Logs/evw-alert-center*.log"
    echo "=== Done ==="
    exit 0
fi

echo "=== evw-security-system setup ==="
echo ""

for f in evw-security-system.py evw-alert-center.py ls-screenshare-deny.py ls-hole-audit.py security-system.json; do
    [[ -f "$SEC/$f" ]] || { echo "ERROR: missing $SEC/$f" >&2; exit 1; }
done

echo "[1/8] Creating state dir $STATE_DIR ..."
guard_run "mkdir-state" mkdir -p "$STATE_DIR" "$STATE_DIR/alerts" "$STATE_DIR/ack"
guard_run "perms-state" bash -c \
    "chown root:wheel '$STATE_DIR' '$STATE_DIR/alerts' '$STATE_DIR/ack' && \
     chmod 755 '$STATE_DIR' '$STATE_DIR/alerts' && chmod 1777 '$STATE_DIR/ack'"
echo "      alerts/ 755 root:wheel, ack/ 1777 (user droppable)"

echo "[2/8] Installing root-owned copies in /usr/local/bin ..."
for tool in evw-security-system.py evw-alert-center.py ls-screenshare-deny.py ls-hole-audit.py; do
    guard_run "install-$tool" install -m 755 -o root -g wheel "$SEC/$tool" "/usr/local/bin/$tool"
    echo "      /usr/local/bin/$tool"
done

echo "[3/8] Installing config ..."
if [[ ! -f "$STATE_DIR/security-system.json" || "$CONFIG_UPDATE" -eq 1 ]]; then
    guard_run "install-config" cp "$SEC/security-system.json" "$STATE_DIR/security-system.json"
    guard_run "perms-config" bash -c \
        "chown root:wheel '$STATE_DIR/security-system.json' && chmod 644 '$STATE_DIR/security-system.json'"
    echo "      $STATE_DIR/security-system.json"
elif cmp -s "$SEC/security-system.json" "$STATE_DIR/security-system.json"; then
    echo "      unchanged (use --config-update to force)"
else
    echo "      WARNING: repo config differs from installed config — keeping installed copy"
    echo "      (re-run with --config-update to replace it)"
fi

echo "[4/8] Writing LaunchDaemon $DAEMON_LABEL (root, KeepAlive) ..."
guard_run "write-daemon-plist" cat > "$DAEMON_PLIST" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.evw.security-system</string>

    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>/usr/local/bin/evw-security-system.py</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <true/>

    <key>UserName</key>
    <string>root</string>

    <key>StandardOutPath</key>
    <string>/var/log/evw-security-system.log</string>

    <key>StandardErrorPath</key>
    <string>/var/log/evw-security-system-err.log</string>
</dict>
</plist>
PLIST
guard_run "perms-daemon-plist" bash -c "chmod 644 '$DAEMON_PLIST' && chown root:wheel '$DAEMON_PLIST'"
launchctl bootout "system/$DAEMON_LABEL" 2>/dev/null || launchctl unload "$DAEMON_PLIST" 2>/dev/null || true
guard_run "load-daemon" launchctl load -w "$DAEMON_PLIST"
echo "      $DAEMON_PLIST loaded"

echo "[5/8] Writing LaunchAgent $AGENT_LABEL (evw GUI, KeepAlive) ..."
guard_run "mkdir-user-dirs" bash -c \
    "mkdir -p /Users/evw/Library/LaunchAgents /Users/evw/Library/Logs"
guard_run "write-agent-plist" cat > "$AGENT_PLIST" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.evw.alert-center</string>

    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>/usr/local/bin/evw-alert-center.py</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <true/>

    <key>LimitLoadToSessionType</key>
    <string>Aqua</string>

    <key>StandardOutPath</key>
    <string>/Users/evw/Library/Logs/evw-alert-center.log</string>

    <key>StandardErrorPath</key>
    <string>/Users/evw/Library/Logs/evw-alert-center-err.log</string>
</dict>
</plist>
PLIST
guard_run "perms-agent-plist" bash -c "chmod 644 '$AGENT_PLIST' && chown evw:staff '$AGENT_PLIST'"
launchctl bootout "gui/501/$AGENT_LABEL" 2>/dev/null || true
launchctl bootstrap "gui/501" "$AGENT_PLIST" 2>/dev/null \
    && echo "      agent bootstrapped into gui/501" \
    || echo "      cannot bootstrap now — agent will auto-register at next login"

echo "[6/8] Planting initial both-ways Little Snitch denies ..."
guard_run "mkdir-reports" mkdir -p "$SEC/security-system/reports"
chown evw:staff "$SEC/security-system" "$SEC/security-system/reports" 2>/dev/null || true
if [[ -x "$LSCLI" ]]; then
    WORK="$(mktemp -d /tmp/ls-screenshare-initial.XXXXXXXX)"
    if guard_run "ls-export-model" "$LSCLI" export-model "$WORK/model.json"; then
        if guard_run "ls-screenshare-deny" /usr/bin/python3 \
            /usr/local/bin/ls-screenshare-deny.py "$WORK/model.json" --apply \
            --report "$SEC/security-system/reports/screenshare-deny-initial-$TS.md" \
            --undo "$STATE_DIR/screenshare-undo-initial-$TS.json"; then
            if guard_run "ls-restore-model" "$LSCLI" restore-model "$WORK/model.json"; then
                echo "      restore-model OK"
            else
                echo "      WARNING: restore-model FAILED — live LS model may be unchanged" >&2
            fi
        else
            echo "      WARNING: ls-screenshare-deny failed — live LS model NOT touched" >&2
        fi
        chown evw:staff "$SEC/security-system/reports/screenshare-deny-initial-$TS.md" 2>/dev/null || true
    else
        echo "      WARNING: export-model failed (LS CLI access disabled?) — skipping" >&2
    fi
    rm -rf "$WORK"
else
    echo "      WARNING: Little Snitch CLI not found at $LSCLI — skipping initial denies" >&2
    echo "      plant later: export-model + sudo /usr/bin/python3 /usr/local/bin/ls-screenshare-deny.py MODEL.json --apply"
fi

echo "[7/8] One-shot: full copy of /var/log/evw-audit-alerts.log ..."
guard_run "mkdir-digests" mkdir -p "$SEC/logs/digests"
if [[ -f /var/log/evw-audit-alerts.log ]]; then
    guard_run "copy-audit-alerts" cp /var/log/evw-audit-alerts.log \
        "$SEC/logs/digests/evw-audit-alerts-full.txt"
    guard_run "perms-digests" bash -c \
        "chown evw:staff '$SEC/logs/digests' '$SEC/logs/digests/evw-audit-alerts-full.txt' && \
         chmod 644 '$SEC/logs/digests/evw-audit-alerts-full.txt'"
    echo "      $SEC/logs/digests/evw-audit-alerts-full.txt"
else
    echo "      /var/log/evw-audit-alerts.log not present — skipped"
fi

echo "[8/8] Verifying ..."
sleep 3
launchctl print "system/$DAEMON_LABEL" 2>/dev/null | grep -E 'state|pid' | head -4 || {
    echo "ERROR: $DAEMON_LABEL not registered after load" >&2
    exit 1
}
tail -3 /var/log/evw-security-system.log 2>/dev/null || true

echo ""
echo "=== Done ==="
echo "Daemon (root, orchestrator) : $DAEMON_LABEL  ->  /var/log/evw-security-system.log"
echo "Agent  (evw GUI, alerts)    : $AGENT_LABEL  ->  /Users/evw/Library/Logs/evw-alert-center.log"
echo "State dir                   : $STATE_DIR (alerts/ ack/ security-system.json)"
echo "LS deny reports / undo      : $SEC/security-system/reports/  +  $STATE_DIR/"
echo "Audit-alerts full digest    : $SEC/logs/digests/evw-audit-alerts-full.txt"
echo "--uninstall removes everything (also bootout gui agent)"
