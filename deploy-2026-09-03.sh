#!/bin/bash
# deploy-2026-09-03.sh — one-shot privileged deploy for the 2026-09-02 panic
# post-mortem + sentinel-deny batch. Review, then run:
#
#     sudo bash /Users/evw/dev/security/deploy-2026-09-03.sh
#
# Steps:
#   1. deploy fixed guard scripts (fs_usage memory cap, replayd log throttle,
#      file-sentinel O_EVTONLY fix, systemsetup -f prompt-flood fix)
#   2. restart the affected daemons
#   3. truncate the 172 MB replayd-guard log
#   4. run the daily harden rescan missed this morning
#   5. apply sentinel-deny Little Snitch rules (44 denies from the alert feed;
#      pre-patch backup + undo JSON in /var/log/mac-sentinel/)
#   6. kill warned processes so existing flows drop (rules block reconnects)
#   7. install the boot/login unattended audit pair (fires a full root audit,
#      incl. LS model export + 4 analyses + TCC audit)
#   8. diff the resulting LS model against the 2026-09-02 known-good model
#
set -euo pipefail
SEC=/Users/evw/dev/security
SCAN="$SEC/scan-2026-09-03"
LSCLI="/Applications/Little Snitch.app/Contents/Components/littlesnitch"
TS=$(date +%Y%m%d-%H%M%S)
MARKER=$(mktemp /var/tmp/deploy-marker.XXXXXX)

[[ $EUID -ne 0 ]] && { echo "run with sudo"; exit 1; }
mkdir -p "$SCAN" /var/log/mac-sentinel

echo "== [1/8] deploy fixed scripts =="
install -o root -g wheel -m 755 "$SEC/evw-plist-monitor.sh"      /usr/local/bin/
install -o root -g wheel -m 755 "$SEC/evw-replayd-guard.sh"      /usr/local/bin/
install -o root -g wheel -m 755 "$SEC/scripts/file-sentinel.py"  /usr/local/bin/
install -o root -g wheel -m 755 "$SEC/scripts/mac_harden_rescan.sh" /usr/local/bin/

echo "== [2/8] restart daemons =="
launchctl kickstart -k system/com.evw.plist-monitor
launchctl kickstart -k system/com.evw.replayd-guard
launchctl kickstart -k system/com.ew.file-sentinel
sleep 3
launchctl print system/com.ew.file-sentinel 2>/dev/null | grep -E 'state|pid' | head -2 || true

echo "== [3/8] truncate replayd-guard log =="
: > /var/log/evw-replayd-guard.log

echo "== [4/8] missed daily harden rescan =="
launchctl kickstart system/local.security.harden || true

echo "== [5/8] sentinel-deny LS rules =="
WORK=/var/tmp/ls-model-sentinel-$TS.json
"$LSCLI" export-model "$WORK"
cp "$WORK" "/var/log/mac-sentinel/ls-model-pre-sentinel-$TS.json"
python3 "$SEC/ls-sentinel-deny.py" "$WORK" --apply \
    --report "$SCAN/ls-sentinel-deny-report.md" \
    --undo  "/var/log/mac-sentinel/ls-sentinel-undo-$TS.json"
"$LSCLI" restore-model "$WORK"
rm -f "$WORK"
echo "    pre-patch backup: /var/log/mac-sentinel/ls-model-pre-sentinel-$TS.json"
echo "    report:           $SCAN/ls-sentinel-deny-report.md"

echo "== [6/8] kill warned processes (LS denies block reconnects) =="
pkill -9 -f "com.apple.WebKit.Networking" 2>/dev/null && echo "    killed WebKit.Networking" || echo "    WebKit.Networking not running"
for d in remoted mediaremoted AirPlayXPCHelper rapportd; do
    pkill -9 -x "$d" 2>/dev/null && echo "    killed $d" || true
done
# excluded from kills: Little Snitch extension (firewall itself), mDNSResponder
# + timed (DNS/NTP infra), networkserviceproxy (optional group), kimi (this
# session), ssh (git remote), node (warned pid long gone; rule covers its IP)

echo "== [7/8] install boot/login audit pair (fires full root audit) =="
rm -f /var/tmp/evw-security-audit.last   # clear debounce so the boot audit runs
bash "$SEC/evw-security-audit-setup.sh"

echo "== [8/8] wait for root audit, then diff LS model vs 2026-09-02 =="
for i in $(seq 1 36); do
    [ "$SCAN/ls-model.json" -nt "$MARKER" ] 2>/dev/null && break
    sleep 5
done
if [ -f "$SCAN/ls-model.json" ]; then
    python3 "$SEC/ls-model-diff.py" "$SEC/scan-2026-09-02/ls-model.json" "$SCAN/ls-model.json" \
        | tee "$SCAN/ls-model-diff-vs-2026-09-02.txt"
else
    echo "WARN: root audit did not produce $SCAN/ls-model.json within 3 min —"
    echo "      check /private/var/log/evw-security-audit.log and run:"
    echo "      sudo bash /usr/local/bin/evw-security-audit.sh"
fi
rm -f "$MARKER"
chown -R evw:staff "$SCAN" "$SEC/logs/boot-audit.log" 2>/dev/null || true
echo "== done =="
