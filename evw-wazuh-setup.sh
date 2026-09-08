#!/usr/bin/env bash
# =============================================================================
# evw-wazuh-setup.sh — finish the Wazuh agent install on this Mac and wire it
# into the evw security toolkit.
#
# Run:  sudo bash /Users/evw/dev/security/evw-wazuh-setup.sh [MANAGER_IP]
#
#   MANAGER_IP defaults to 10.0.0.2 (the value used at pkg install time).
#   Unreachable manager is a WARNING, not a failure — the agent retries
#   forever and connects when the manager appears.
#
# Idempotent. Steps:
#   1. verify the wazuh-agent pkg + binaries are present
#   2. set the manager address in /Library/Ossec/etc/ossec.conf (backup first)
#   3. enable + load the stock com.wazuh.agent LaunchDaemon, start the agent
#   4. install evw-wazuh-guard.sh (keep-alive) as root LaunchDaemon
#      com.evw.wazuh-guard  —  the stock plist has no KeepAlive
#   5. verify processes + launchd registration, report manager state
# =============================================================================

set -uo pipefail

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error-guard.sh)
_eg_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
while [ "$_eg_d" != "/" ] && [ ! -f "$_eg_d/lib/error-guard.sh" ]; do _eg_d="$(dirname "$_eg_d")"; done
[ -f "$_eg_d/lib/error-guard.sh" ] && . "$_eg_d/lib/error-guard.sh"; unset _eg_d
command -v guard_run >/dev/null 2>&1 || guard_run() { shift; "$@"; }
command -v guard_throw >/dev/null 2>&1 || guard_throw() { printf 'error-guard: throw: %s\n' "$*" >&2; return 1; }

SEC_DIR="/Users/evw/dev/security"
BIN="/usr/local/bin"
LD_DIR="/Library/LaunchDaemons"
OSSEC_DIR="/Library/Ossec"
# Wazuh ≥4.8 renamed ossec-* binaries to wazuh-* — prefer new, fall back to old
OSSEC_CTL="$OSSEC_DIR/bin/wazuh-control"
[ -x "$OSSEC_CTL" ] || OSSEC_CTL="$OSSEC_DIR/bin/ossec-control"
CONF="$OSSEC_DIR/etc/ossec.conf"
WAZUH_PLIST="$LD_DIR/com.wazuh.agent.plist"
GUARD_LABEL="com.evw.wazuh-guard"
MONITOR_LABEL="com.evw.wazuh-monitor"
MANAGER_IP="${1:-${WAZUH_MANAGER:-10.0.0.2}}"

RED='\033[1;31m'; GRN='\033[1;32m'; YLW='\033[1;33m'; BLU='\033[1;34m'; NC='\033[0m'
info() { echo -e "${BLU}[*]${NC} $*"; }
ok()   { echo -e "${GRN}[✓]${NC} $*"; }
warn() { echo -e "${YLW}[!]${NC} $*"; }
fail() { echo -e "${RED}[✗]${NC} $*" >&2; }

if [[ $EUID -ne 0 ]]; then
    fail "Must be run as root: sudo bash $0 [MANAGER_IP]"
    exit 1
fi

# ── 1. pkg + binaries present ────────────────────────────────────────────────
info "[1/5] Checking wazuh-agent installation ..."
if ! pkgutil --pkg-info com.wazuh.pkg.wazuh-agent >/dev/null 2>&1; then
    fail "wazuh-agent pkg not installed. Install first (harden.sh §10 does this):"
    fail "  sudo bash $SEC_DIR/harden.sh   — or download from packages.wazuh.com"
    exit 1
fi
WAZ_VER=$(pkgutil --pkg-info com.wazuh.pkg.wazuh-agent | awk '/^version:/{print $2}')
[[ -x "$OSSEC_CTL" ]] || { fail "$OSSEC_CTL missing — pkg install looks broken"; exit 1; }
ok "wazuh-agent $WAZ_VER installed"

# ── 2. manager address in ossec.conf ─────────────────────────────────────────
info "[2/5] Configuring manager address ($MANAGER_IP) in ossec.conf ..."
[[ -f "$CONF" ]] || { fail "$CONF missing"; exit 1; }
CURRENT=$(sed -n 's:.*<address>\(.*\)</address>.*:\1:p' "$CONF" | head -1)
if [[ "$CURRENT" == "$MANAGER_IP" ]]; then
    ok "manager address already set to $MANAGER_IP"
else
    BAK="$CONF.evw-bak-$(date +%Y%m%d-%H%M%S)"
    guard_run "conf-backup" cp -a "$CONF" "$BAK" || true
    if [[ -n "$CURRENT" ]]; then
        # replace first <address> only
        guard_run "conf-replace" awk -v ip="$MANAGER_IP" '
            !done && /<address>.*<\/address>/ { sub(/<address>[^<]*<\/address>/, "<address>" ip "</address>"); done=1 }
            { print }' "$CONF" > "$CONF.evw-new" || true
    else
        # no address element: insert one right after the first <server> line
        guard_run "conf-insert" awk -v ip="$MANAGER_IP" '
            { print }
            !done && /<server>/ { print "    <address>" ip "</address>"; done=1 }' \
            "$CONF" > "$CONF.evw-new" || true
    fi
    if [[ -s "$CONF.evw-new" ]] && grep -q "<address>$MANAGER_IP</address>" "$CONF.evw-new"; then
        PERMS=$(stat -f '%Lp %u %g' "$CONF")
        install -m "${PERMS%% *}" -o "$(echo $PERMS | awk '{print $2}')" -g "$(echo $PERMS | awk '{print $3}')" \
            "$CONF.evw-new" "$CONF" && rm -f "$CONF.evw-new"
        ok "manager address: ${CURRENT:-<none>} -> $MANAGER_IP (backup: $BAK)"
    else
        rm -f "$CONF.evw-new"
        fail "ossec.conf edit produced no valid result — left untouched (backup: $BAK)"
        exit 1
    fi
fi

# connectivity precheck — advisory only
for port in 1515 1514; do
    if nc -z -G 3 "$MANAGER_IP" "$port" 2>/dev/null; then
        ok "manager reachable on tcp/$port"
    else
        warn "manager $MANAGER_IP tcp/$port unreachable — agent will retry until the manager is up"
    fi
done

# ── 3. enable + load agent, start ────────────────────────────────────────────
info "[3/5] Enabling and starting the wazuh agent ..."
if [[ -f "$WAZUH_PLIST" ]]; then
    launchctl enable system/com.wazuh.agent 2>/dev/null || true
    launchctl bootout system "$WAZUH_PLIST" 2>/dev/null || true
    guard_run "bootstrap-wazuh" launchctl bootstrap system "$WAZUH_PLIST" || true
else
    warn "$WAZUH_PLIST missing — falling back to ossec-control only"
fi
guard_run "ossec-start" "$OSSEC_CTL" start || true
sleep 3
CORE_OK=1
for d in wazuh-agentd wazuh-logcollector wazuh-syscheckd; do
    pgrep -f "$d" >/dev/null 2>&1 || { CORE_OK=0; warn "$d not running"; }
done
[[ $CORE_OK -eq 1 ]] && ok "core agent daemons running" || warn "some core daemons down — guard will keep retrying"

# ── 4. keep-alive guard + log monitor daemons ────────────────────────────────
info "[4/5] Installing keep-alive guard ($GUARD_LABEL) + log monitor ($MONITOR_LABEL) ..."
guard_run "install-guard-script" install -m 755 -o root -g wheel \
    "$SEC_DIR/evw-wazuh-guard.sh" "$BIN/evw-wazuh-guard.sh" || true
guard_run "install-guard-plist" install -m 644 -o root -g wheel \
    "$SEC_DIR/com.evw.wazuh-guard.plist" "$LD_DIR/com.evw.wazuh-guard.plist" || true
launchctl bootout system "$LD_DIR/com.evw.wazuh-guard.plist" 2>/dev/null || true
guard_run "bootstrap-guard" launchctl bootstrap system "$LD_DIR/com.evw.wazuh-guard.plist" || true

guard_run "install-monitor-script" install -m 755 -o root -g wheel \
    "$SEC_DIR/evw-wazuh-monitor.py" "$BIN/evw-wazuh-monitor.py" || true
guard_run "install-monitor-plist" install -m 644 -o root -g wheel \
    "$SEC_DIR/com.evw.wazuh-monitor.plist" "$LD_DIR/com.evw.wazuh-monitor.plist" || true
launchctl bootout system "$LD_DIR/com.evw.wazuh-monitor.plist" 2>/dev/null || true
guard_run "bootstrap-monitor" launchctl bootstrap system "$LD_DIR/com.evw.wazuh-monitor.plist" || true

# ── 5. verify ────────────────────────────────────────────────────────────────
info "[5/5] Verification ..."
rc=0
launchctl print system/com.wazuh.agent  >/dev/null 2>&1 && ok "com.wazuh.agent registered"  || { fail "com.wazuh.agent NOT registered"; rc=1; }
launchctl print "system/$GUARD_LABEL"   >/dev/null 2>&1 && ok "$GUARD_LABEL registered"     || { fail "$GUARD_LABEL NOT registered"; rc=1; }
launchctl print "system/$MONITOR_LABEL" >/dev/null 2>&1 && ok "$MONITOR_LABEL registered"   || { fail "$MONITOR_LABEL NOT registered"; rc=1; }
"$OSSEC_CTL" status 2>/dev/null | sed 's/^/      /'
echo ""
if [[ $rc -eq 0 ]]; then
    ok "Wazuh agent installed, started, and guarded."
else
    warn "Installed with errors — see above."
fi
echo "Manager:  $MANAGER_IP (edit $CONF to change, then: $OSSEC_CTL restart)"
echo "Status:   bash $SEC_DIR/evw-wazuh-status.sh"
echo "Logs:     /Library/Ossec/logs/ossec.log, /private/var/log/evw-wazuh-guard.log"
echo "Note:     first connection enrolls the agent with the manager (tcp/1515)."
echo "          If it never connects, check manager-side registration + that"
echo "          $MANAGER_IP is the right address (this Mac's LAN is not 10.0.0.0/24)."
exit $rc
