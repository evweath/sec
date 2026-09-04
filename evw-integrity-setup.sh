#!/usr/bin/env bash
# =============================================================================
# evw-integrity-setup.sh — install the file-integrity & rollback system (root)
#
# Run:  sudo bash /Users/evw/dev/security/evw-integrity-setup.sh
#
#   1. /var/db/evw-integrity store (root:wheel 700) + git init + Tier A seed
#   2. evw-integrity.py + evw-rollback.py -> /usr/local/bin (root:wheel 755)
#   3. Three LaunchDaemons:
#        com.evw.integrity-pulse  (120 s)  sweep --tiers A --heal
#        com.evw.integrity-sweep  (900 s)  sweep --tiers B,C
#        com.evw.integrity-full   (daily 03:47)  full --tiers A,B,C,D + verify
#   4. Verify registration + print canary test instructions
#
# Idempotent (bootout before bootstrap). A deploy.marker is held for the whole
# setup so the seed itself is never mistaken for an intrusion.
# =============================================================================

set -euo pipefail

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error-guard.sh)
_eg_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
while [ "$_eg_d" != "/" ] && [ ! -f "$_eg_d/lib/error-guard.sh" ]; do _eg_d="$(dirname "$_eg_d")"; done
[ -f "$_eg_d/lib/error-guard.sh" ] && . "$_eg_d/lib/error-guard.sh"; unset _eg_d
command -v guard_run >/dev/null 2>&1 || guard_run() { shift; "$@"; }

SEC_DIR="/Users/evw/dev/security"
STORE="/var/db/evw-integrity"
BIN="/usr/local/bin"
LD="/Library/LaunchDaemons"

if [[ $EUID -ne 0 ]]; then
    echo "[!] Must be run as root: sudo bash $0" >&2
    exit 1
fi

info() { echo "[*] $*"; }
ok()   { echo "[✓] $*"; }
warn() { echo "[!] $*"; }

mkdir -p "$STORE/logs"
date +%s > "$STORE/deploy.marker"          # held until setup completes
trap 'rm -f "$STORE/deploy.marker"' EXIT

info "installing executables"
install -d -m 755 -o root -g wheel "$BIN" /usr/local/lib
guard_run "inst-integrity" install -m 755 -o root -g wheel "$SEC_DIR/evw-integrity.py" "$BIN/evw-integrity.py"
guard_run "inst-rollback"  install -m 755 -o root -g wheel "$SEC_DIR/evw-rollback.py"  "$BIN/evw-rollback.py"
[[ -f /usr/local/lib/error_guard.py ]] || \
    guard_run "inst-eg-py" install -m 644 -o root -g wheel "$SEC_DIR/lib/error_guard.py" /usr/local/lib/error_guard.py
ok "executables in $BIN"

info "initializing store at $STORE"
install -d -m 700 -o root -g wheel "$STORE"
guard_run "store-init" "$BIN/evw-integrity.py" init --store "$STORE"
ok "store initialized"

write_daemon() { # label interval-or-calendar program-args...
    local label="$1"; shift
    local plist="$LD/$label.plist"
    cat > "$plist" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>$label</string>
    <key>ProgramArguments</key><array>$@</array>
    $SCHEDULE
    <key>RunAtLoad</key><false/>
    <key>Nice</key><integer>10</integer>
    <key>StandardOutPath</key><string>/var/log/evw-integrity.log</string>
    <key>StandardErrorPath</key><string>/var/log/evw-integrity-err.log</string>
</dict>
</plist>
PLIST
    chmod 644 "$plist"; chown root:wheel "$plist"
    launchctl bootout system "$plist" 2>/dev/null || true
    guard_run "bootstrap-$label" launchctl bootstrap system "$plist"
    ok "$label loaded"
}

info "installing daemons"
SCHEDULE="<key>StartInterval</key><integer>120</integer>" \
    write_daemon com.evw.integrity-pulse \
    "<string>/usr/local/bin/evw-integrity.py</string><string>sweep</string><string>--tiers</string><string>A</string><string>--heal</string>"
SCHEDULE="<key>StartInterval</key><integer>900</integer>" \
    write_daemon com.evw.integrity-sweep \
    "<string>/usr/local/bin/evw-integrity.py</string><string>sweep</string><string>--tiers</string><string>B,C</string>"
SCHEDULE="<key>StartCalendarInterval</key><dict><key>Hour</key><integer>3</integer><key>Minute</key><integer>47</integer></dict>" \
    write_daemon com.evw.integrity-full \
    "<string>/usr/local/bin/evw-integrity.py</string><string>full</string><string>--tiers</string><string>A,B,C,D</string>"
SCHEDULE="<key>StartCalendarInterval</key><dict><key>Weekday</key><integer>0</integer><key>Hour</key><integer>4</integer><key>Minute</key><integer>12</integer></dict>" \
    write_daemon com.evw.integrity-verify \
    "<string>/usr/local/bin/evw-integrity.py</string><string>verify</string><string>--sample</string><string>5000</string>"

info "seeding baseline (first Tier A sweep — this is the known-good state)"
guard_run "seed-sweep" "$BIN/evw-integrity.py" sweep --tiers A --heal --store "$STORE" || \
    warn "seed sweep had errors — check /var/log/evw-integrity-err.log"

echo ""
info "verification"
fails=0
for label in com.evw.integrity-pulse com.evw.integrity-sweep com.evw.integrity-full com.evw.integrity-verify; do
    if launchctl print "system/$label" >/dev/null 2>&1; then
        ok "$label registered"
    else
        warn "$label NOT registered"; fails=$((fails+1))
    fi
done

cat << EOF

[✓] evw-integrity installed.

  store:     $STORE (root-only; tree/ + index.db + quarantine/ + reports/)
  daemons:   pulse 120s (Tier A + auto-heal) · sweep 900s (Tier B,C) ·
             full daily 03:47 (A–D) · verify weekly Sun 04:12
  reports:   $STORE/reports/ and ~/dev/security/scan-<date>/
  events:    $STORE/logs/events.log

  Canary round-trip (proves detect→heal works):
    sudo /usr/local/bin/evw-integrity.py canary
    echo TAMPER | sudo tee /usr/local/bin/evw-canary
    # wait <=120s, then: cat /usr/local/bin/evw-canary   (must show canary-…)

  Rollback:
    sudo /usr/local/bin/evw-rollback.py list
    sudo /usr/local/bin/evw-rollback.py restore --all --dry-run
    sudo /usr/local/bin/evw-rollback.py restore --paths /etc/hosts --apply
EOF
[[ $fails -eq 0 ]] || exit 1
