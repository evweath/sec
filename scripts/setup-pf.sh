#!/bin/bash
# setup-pf.sh — Install and activate PF dev-port lockdown rules.
#
# This script is idempotent — safe to run on every boot via LaunchDaemon.
# On first run (or if /etc/pf.conf is missing our anchor), it patches the
# file and enables PF. On subsequent boots it just reloads the anchor.
#
# Requires root. Run once manually to install:
#   sudo ./setup-pf.sh
# Then install the LaunchDaemon so it runs at every boot:
#   sudo cp /Users/evw/dev/security/scripts/com.ew.pf-devports.plist /Library/LaunchDaemons/
#   sudo launchctl load -w /Library/LaunchDaemons/com.ew.pf-devports.plist

set -euo pipefail

[[ $EUID -ne 0 ]] && { echo "Must run as root: sudo $0"; exit 1; }

SRC_ANCHOR=/Users/evw/dev/security/scripts/pf-devports.conf
ANCHOR_FILE=/etc/pf.anchors/com.ew.devports
PF_CONF=/etc/pf.conf
ANCHOR_NAME="com.ew.devports"
LOG=/var/log/pf-devports.log

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

log "=== PF dev-port lockdown ==="

# ── 1. Install anchor file ────────────────────────────────────────────────────
if [[ ! -f "$SRC_ANCHOR" ]]; then
    log "ERROR: $SRC_ANCHOR not found"
    exit 1
fi
log "Copying $SRC_ANCHOR → $ANCHOR_FILE"
cp "$SRC_ANCHOR" "$ANCHOR_FILE"
chmod 644 "$ANCHOR_FILE"
chown root:wheel "$ANCHOR_FILE"

# ── 2. Patch /etc/pf.conf to include our anchor (once) ───────────────────────
ANCHOR_STANZA="anchor \"${ANCHOR_NAME}\""
LOAD_STANZA="load anchor \"${ANCHOR_NAME}\" from \"${ANCHOR_FILE}\""

if ! grep -qF "$ANCHOR_STANZA" "$PF_CONF" 2>/dev/null; then
    log "Patching $PF_CONF to include $ANCHOR_NAME anchor..."
    cp "$PF_CONF" "${PF_CONF}.bak.$(date +%Y%m%d_%H%M%S)"
    # Insert before the final load anchor line (last non-empty line)
    printf '\n# ── ew dev-port lockdown ─────────────────────────────────────────────\n' >> "$PF_CONF"
    printf '%s\n' "$ANCHOR_STANZA"  >> "$PF_CONF"
    printf '%s\n' "$LOAD_STANZA"    >> "$PF_CONF"
    log "Patched."
else
    log "$PF_CONF already contains anchor — skipping patch"
fi

# ── 3. Enable PF if not already running ──────────────────────────────────────
if ! pfctl -s info 2>/dev/null | grep -q "^Status.*Enabled"; then
    log "Enabling PF..."
    pfctl -e 2>/dev/null || true
fi

# ── 4. Load main ruleset (harmless if already loaded) ────────────────────────
log "Loading /etc/pf.conf..."
pfctl -f "$PF_CONF" 2>&1 | tee -a "$LOG" || true

# ── 5. Reload just our anchor (fast path on subsequent boots) ─────────────────
log "Reloading anchor $ANCHOR_NAME..."
pfctl -a "$ANCHOR_NAME" -f "$ANCHOR_FILE" 2>&1 | tee -a "$LOG"

# ── 6. Verify ────────────────────────────────────────────────────────────────
log "Current anchor rules:"
pfctl -a "$ANCHOR_NAME" -s rules 2>&1 | tee -a "$LOG"

RULE_COUNT=$(pfctl -a "$ANCHOR_NAME" -s rules 2>/dev/null | wc -l | tr -d ' ')
if [[ "$RULE_COUNT" -gt 2 ]]; then
    log "OK — $RULE_COUNT rules active in $ANCHOR_NAME"
else
    log "WARN — only $RULE_COUNT rules loaded; check $ANCHOR_FILE"
fi

log "Done. External connections to dev ports are now blocked at the network layer."
