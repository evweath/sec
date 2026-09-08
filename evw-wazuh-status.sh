#!/bin/bash
# evw-wazuh-status.sh — read-only Wazuh agent status for the evw toolkit.
# Works unprivileged (reduced detail); root sees ossec.conf + ossec.log too.
#
#   bash /Users/evw/dev/security/evw-wazuh-status.sh

set -uo pipefail

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error-guard.sh)
_eg_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
while [ "$_eg_d" != "/" ] && [ ! -f "$_eg_d/lib/error-guard.sh" ]; do _eg_d="$(dirname "$_eg_d")"; done
[ -f "$_eg_d/lib/error-guard.sh" ] && . "$_eg_d/lib/error-guard.sh"; unset _eg_d
command -v guard_run >/dev/null 2>&1 || guard_run() { shift; "$@"; }

OSSEC_DIR="/Library/Ossec"
CONF="$OSSEC_DIR/etc/ossec.conf"
OSSEC_LOG="$OSSEC_DIR/logs/ossec.log"

yn() { [ "$1" -eq 0 ] && echo "yes" || echo "NO"; }

echo "=== Wazuh agent status — $(date '+%Y-%m-%d %H:%M:%S %Z') ==="
echo ""

echo "── install ──"
if pkgutil --pkg-info com.wazuh.pkg.wazuh-agent >/dev/null 2>&1; then
    echo "pkg:      $(pkgutil --pkg-info com.wazuh.pkg.wazuh-agent | awk '/^version:/{print "wazuh-agent", $2}')"
else
    echo "pkg:      NOT INSTALLED"
fi
if [ -x "$OSSEC_DIR/bin/wazuh-control" ] || [ -x "$OSSEC_DIR/bin/ossec-control" ]; then
    echo "wazuh-control present: yes"
elif pkgutil --pkg-info com.wazuh.pkg.wazuh-agent >/dev/null 2>&1; then
    echo "wazuh-control present: yes (root-only dir — verified via pkg receipt)"
else
    echo "wazuh-control present: NO"
fi
[ -f /Library/LaunchDaemons/com.wazuh.agent.plist ] \
    && echo "launchd:  com.wazuh.agent.plist installed" \
    || echo "launchd:  com.wazuh.agent.plist MISSING"

echo ""
echo "── processes ──"
for d in wazuh-agentd wazuh-logcollector wazuh-syscheckd wazuh-execd wazuh-modulesd; do
    if pgrep -f "$d" >/dev/null 2>&1; then
        echo "  $d: running (pid $(pgrep -f "$d" | head -1))"
    else
        echo "  $d: NOT RUNNING"
    fi
done

echo ""
echo "── manager ──"
MGR=""
if [ -r "$CONF" ]; then
    MGR=$(sed -n 's:.*<address>\(.*\)</address>.*:\1:p' "$CONF" | head -1)
    echo "configured address: ${MGR:-<none found>}  (from ossec.conf)"
else
    echo "ossec.conf: not readable (needs root) — trying guard state + defaults"
fi
MGR="${MGR:-10.0.0.2}"
for port in 1515 1514; do
    nc -z -G 3 "$MGR" "$port" >/dev/null 2>&1 \
        && echo "  tcp/$port ($MGR): reachable" \
        || echo "  tcp/$port ($MGR): UNREACHABLE"
done
[ -f /var/tmp/evw-wazuh-guard.state ] \
    && echo "guard-observed state: $(cat /var/tmp/evw-wazuh-guard.state 2>/dev/null)"

if [ -r "$OSSEC_LOG" ]; then
    echo "ossec.log last connect lines:"
    grep -E "Connected to server|Unable to connect|Could not resolve|Connection refused" "$OSSEC_LOG" 2>/dev/null \
        | tail -3 | sed 's/^/  /'
else
    echo "ossec.log: not readable (needs root)"
fi

echo ""
echo "── evw guard ──"
if pgrep -f evw-wazuh-guard.sh >/dev/null 2>&1; then
    echo "evw-wazuh-guard: running (pid $(pgrep -f evw-wazuh-guard.sh | head -1))"
else
    echo "evw-wazuh-guard: NOT RUNNING  — install: sudo bash /Users/evw/dev/security/evw-wazuh-setup.sh"
fi
for f in /private/var/log/evw-wazuh-guard.log "$HOME/Library/Logs/evw-wazuh-guard.log"; do
    if [ -r "$f" ]; then
        echo "guard log tail ($f):"
        tail -5 "$f" | sed 's/^/  /'
        break
    fi
done
echo ""
