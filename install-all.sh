#!/usr/bin/env bash
# =============================================================================
# install-all.sh — one-pass reviewed installer for the evw security toolkit
#
# Run:  sudo bash /Users/evw/dev/security/install-all.sh          (asks to confirm)
#       sudo bash /Users/evw/dev/security/install-all.sh --yes    (no prompt)
#
# What it does:
#   1. Installs guard/monitor scripts to root-owned /usr/local/bin
#   2. Installs their plists to /Library/LaunchDaemons (root:wheel 644)
#   3. Loads each daemon via launchctl bootstrap (idempotent: bootout first)
#   4. Delegates to the per-tool setup scripts for dns-guard / ls-watchdog /
#      comms-guard, and to setup-pf.sh for the dev-ports PF anchor
#   5. Verifies every enabled job is registered afterwards
#
# Toggle the feature flags below before running. Nothing is installed that
# is flagged 0.
# =============================================================================

set -euo pipefail

# ── Feature flags (1 = install, 0 = skip) ────────────────────────────────────
INSTALL_PLIST_MONITOR=1    # fs_usage watcher on /var/db/.../disabled.501.plist
INSTALL_REPLAYD_GUARD=1    # kills replayd on sight, logs forensics first
INSTALL_AUDIT_MONITOR=1    # BSM auditpipe exec-args monitor (python variant)
INSTALL_FILE_SENTINEL=1    # kqueue file-change daemon (credentials, ssh, configs)
INSTALL_BINDING_MONITOR=1  # logs/notifies on processes bound to 0.0.0.0
INSTALL_DNS_GUARD=1        # re-pins Quad9 DNS whenever it drifts
INSTALL_LS_WATCHDOG=1      # prunes forged/permissive Little Snitch rules every 10 min
INSTALL_COMMS_GUARD=0      # OFF by default: SIGKILLs Bluetooth/AirPlay/Handoff/etc every 25s
INSTALL_PF_DEVPORTS=1      # PF anchor blocking inbound connections to dev ports
INSTALL_DAILY_HARDEN=1     # daily 09:00 root security rescan (mac_harden_rescan.sh)

SEC_DIR="/Users/evw/dev/security"
LEG_DIR="/Users/evw/dev/scripts"
BIN="/usr/local/bin"
LD="/Library/LaunchDaemons"

RED='\033[1;31m'; GRN='\033[1;32m'; YLW='\033[1;33m'; BLU='\033[1;34m'; NC='\033[0m'
info() { echo -e "${BLU}[*]${NC} $*"; }
ok()   { echo -e "${GRN}[✓]${NC} $*"; }
warn() { echo -e "${YLW}[!]${NC} $*"; }
fail() { echo -e "${RED}[✗]${NC} $*" >&2; }

# ── Root check ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    fail "Must be run as root: sudo bash $0"
    exit 1
fi

# ── Plan + confirmation ───────────────────────────────────────────────────────
echo ""
echo "=== evw security toolkit installer ==="
echo ""
for entry in \
    "plist-monitor :$INSTALL_PLIST_MONITOR" "replayd-guard :$INSTALL_REPLAYD_GUARD" \
    "audit-monitor :$INSTALL_AUDIT_MONITOR" "file-sentinel :$INSTALL_FILE_SENTINEL" \
    "binding-monitor:$INSTALL_BINDING_MONITOR" "dns-guard    :$INSTALL_DNS_GUARD" \
    "ls-watchdog   :$INSTALL_LS_WATCHDOG" "comms-guard   :$INSTALL_COMMS_GUARD" \
    "pf-devports   :$INSTALL_PF_DEVPORTS" "daily-harden  :$INSTALL_DAILY_HARDEN"; do
    name="${entry%%:*}"; flag="${entry##*:}"
    if [[ "$flag" == "1" ]]; then echo -e "  ${GRN}install${NC}  ${name// /}"; else echo -e "  ${YLW}skip   ${NC}  ${name// /}"; fi
done
echo ""

if [[ "${1:-}" != "--yes" ]]; then
    read -r -p "Type INSTALL to proceed: " reply
    if [[ "$reply" != "INSTALL" ]]; then
        echo "Aborted."
        exit 0
    fi
fi

install -d -m 755 -o root -g wheel "$BIN"

# ── Helper: install one daemon (script → /usr/local/bin, plist → LaunchDaemons)
# usage: install_daemon <script_src> <bin_name> <plist_src> <label> [patch_arg1]
#   patch_arg1: if set, rewrite ProgramArguments[1] of the installed plist to
#               the /usr/local/bin path (for legacy plists pointing at ~/dev)
install_daemon() {
    local src="$1" bin_name="$2" plist_src="$3" label="$4" patch="${5:-}"
    local plist_dest="$LD/$(basename "$plist_src")"

    info "Installing $label"
    install -m 755 -o root -g wheel "$src" "$BIN/$bin_name"
    install -m 644 -o root -g wheel "$plist_src" "$plist_dest"

    if [[ -n "$patch" ]]; then
        /usr/libexec/PlistBuddy -c "Set :ProgramArguments:1 $BIN/$bin_name" "$plist_dest"
    fi

    launchctl bootout system "$plist_dest" 2>/dev/null || true
    launchctl bootstrap system "$plist_dest"
    ok "$label loaded"
}

# ── 1. evw.* daemons (plists already point at /usr/local/bin) ────────────────
[[ $INSTALL_PLIST_MONITOR -eq 1 ]] && \
    install_daemon "$SEC_DIR/evw-plist-monitor.sh" evw-plist-monitor.sh \
                   "$SEC_DIR/com.evw.plist-monitor.plist" com.evw.plist-monitor

[[ $INSTALL_REPLAYD_GUARD -eq 1 ]] && \
    install_daemon "$SEC_DIR/evw-replayd-guard.sh" evw-replayd-guard.sh \
                   "$SEC_DIR/com.evw.replayd-guard.plist" com.evw.replayd-guard

[[ $INSTALL_AUDIT_MONITOR -eq 1 ]] && \
    install_daemon "$SEC_DIR/evw-audit-monitor.py" evw-audit-monitor.py \
                   "$SEC_DIR/com.evw.audit-monitor.plist" com.evw.audit-monitor

# ── 2. Legacy sentinels (plists point at ~/dev — patched to /usr/local/bin) ──
[[ $INSTALL_FILE_SENTINEL -eq 1 ]] && \
    install_daemon "$LEG_DIR/file-sentinel.py" file-sentinel.py \
                   "$LEG_DIR/com.ew.file-sentinel.plist" com.ew.file-sentinel patch

[[ $INSTALL_BINDING_MONITOR -eq 1 ]] && \
    install_daemon "$LEG_DIR/binding-monitor.sh" binding-monitor.sh \
                   "$LEG_DIR/com.ew.binding-monitor.plist" com.ew.binding-monitor patch

# ── 3. Tools with their own setup scripts ─────────────────────────────────────
if [[ $INSTALL_DNS_GUARD -eq 1 ]]; then
    info "Running evw-dns-guard-setup.sh"
    bash "$SEC_DIR/evw-dns-guard-setup.sh"
fi

if [[ $INSTALL_LS_WATCHDOG -eq 1 ]]; then
    info "Running evw-ls-watchdog-setup.sh"
    bash "$SEC_DIR/evw-ls-watchdog-setup.sh"
fi

if [[ $INSTALL_COMMS_GUARD -eq 1 ]]; then
    info "Running evw-comms-setup.sh"
    bash "$SEC_DIR/evw-comms-setup.sh"
fi

# ── 4. PF dev-ports anchor ────────────────────────────────────────────────────
if [[ $INSTALL_PF_DEVPORTS -eq 1 ]]; then
    info "Running setup-pf.sh (loads rules now)"
    bash "$LEG_DIR/setup-pf.sh"
    # Install the boot daemon so the anchor survives reboot
    install_daemon "$LEG_DIR/setup-pf.sh" setup-pf.sh \
                   "$LEG_DIR/com.ew.pf-devports.plist" com.ew.pf-devports patch
fi

# ── 5. Daily hardening rescan ─────────────────────────────────────────────────
if [[ $INSTALL_DAILY_HARDEN -eq 1 ]]; then
    info "Running install_daily_harden.sh"
    bash "$LEG_DIR/install_daily_harden.sh"
fi

# ── 6. Verification ───────────────────────────────────────────────────────────
echo ""
info "=== Verification ==="
rc=0
for entry in \
    "$INSTALL_PLIST_MONITOR:com.evw.plist-monitor" \
    "$INSTALL_REPLAYD_GUARD:com.evw.replayd-guard" \
    "$INSTALL_AUDIT_MONITOR:com.evw.audit-monitor" \
    "$INSTALL_FILE_SENTINEL:com.ew.file-sentinel" \
    "$INSTALL_BINDING_MONITOR:com.ew.binding-monitor" \
    "$INSTALL_DNS_GUARD:com.evw.dns-guard" \
    "$INSTALL_LS_WATCHDOG:com.evw.ls-watchdog" \
    "$INSTALL_LS_WATCHDOG:com.evw.ls-watchdog-monitor" \
    "$INSTALL_COMMS_GUARD:com.evw.comms-guard" \
    "$INSTALL_PF_DEVPORTS:com.ew.pf-devports" \
    "$INSTALL_DAILY_HARDEN:local.security.harden"; do
    flag="${entry%%:*}"; label="${entry##*:}"
    [[ "$flag" != "1" ]] && continue
    if launchctl print "system/$label" &>/dev/null; then
        ok "$label registered"
    else
        fail "$label NOT registered"
        rc=1
    fi
done

if [[ $INSTALL_PF_DEVPORTS -eq 1 ]]; then
    if pfctl -a com.ew.devports -s rules 2>/dev/null | grep -q block; then
        ok "PF anchor com.ew.devports has block rules loaded"
    else
        fail "PF anchor com.ew.devports has no rules"
        rc=1
    fi
fi

echo ""
if [[ $rc -eq 0 ]]; then
    ok "All enabled components installed and verified."
else
    fail "Some components failed — see above."
fi
echo ""
echo "Logs:    /private/var/log/evw-*.log, /var/log/file-sentinel.log, /var/log/binding-monitor.log"
echo "Remove:  sudo launchctl bootout system /Library/LaunchDaemons/<plist> && sudo rm /Library/LaunchDaemons/<plist>"
exit $rc
