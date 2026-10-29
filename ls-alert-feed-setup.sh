#!/usr/bin/env bash
# =============================================================================
# ls-alert-feed-setup.sh — install the Little Snitch alert feed daemon (root)
#
# Run:  sudo bash /Users/evw/dev/security/ls-alert-feed-setup.sh
#
#   1. /usr/local/bin/ls-alert-feed.py (root:wheel 755)
#   2. /var/db/evw-ls-alerts/ store — ls-alerts.jsonl world-readable (644):
#      root daemon appends, you read without sudo
#   3. LaunchDaemon com.evw.ls-alert-feed (RunAtLoad + KeepAlive, throttle 10s)
#
# The daemon wraps `littlesnitch log -s -j -a` — every connection LS asks about
# (the pop-up queries) is appended to the JSONL. Rotates at 50 MB, keeps 10
# archives. Idempotent: re-run to reinstall after edits.
# =============================================================================
set -euo pipefail

SEC_DIR="/Users/evw/dev/security"
BIN="/usr/local/bin"
STORE="/var/db/evw-ls-alerts"
LD="/Library/LaunchDaemons"
LABEL="com.evw.ls-alert-feed"

if [[ $EUID -ne 0 ]]; then
    echo "[!] Must be run as root: sudo bash $0" >&2
    exit 1
fi

info() { echo "[*] $*"; }
ok()   { echo "[✓] $*"; }

info "installing executable"
install -m 755 -o root -g wheel "$SEC_DIR/ls-alert-feed.py" "$BIN/ls-alert-feed.py"
ok "$BIN/ls-alert-feed.py"

info "creating store at $STORE"
install -d -m 755 -o root -g wheel "$STORE"
touch "$STORE/ls-alerts.jsonl"
chmod 644 "$STORE/ls-alerts.jsonl"   # readable without sudo
ok "$STORE/ls-alerts.jsonl"

info "writing LaunchDaemon $LABEL"
cat > "$LD/$LABEL.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array>
    <string>$BIN/ls-alert-feed.py</string>
    <string>--out</string>
    <string>$STORE/ls-alerts.jsonl</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>StandardOutPath</key><string>/var/log/ls-alert-feed.log</string>
  <key>StandardErrorPath</key><string>/var/log/ls-alert-feed-err.log</string>
</dict></plist>
PLIST
chmod 644 "$LD/$LABEL.plist"
ok "$LD/$LABEL.plist"

info "(re)starting daemon"
launchctl bootout "system/$LABEL" 2>/dev/null || true
launchctl bootstrap system "$LD/$LABEL.plist"
sleep 3
if launchctl print "system/$LABEL" >/dev/null 2>&1; then
    ok "$LABEL registered and running"
else
    echo "[!] $LABEL failed to register — check /var/log/ls-alert-feed-err.log" >&2
    exit 1
fi

cat <<EOF

[✓] ls-alert-feed installed.

  data:      $STORE/ls-alerts.jsonl   (readable without sudo)
  live view: tail -f /var/log/ls-alert-feed.log
  replay:    sudo $BIN/ls-alert-feed.py --last 2h
  remove:    sudo launchctl bootout system/$LABEL &&
             sudo rm $LD/$LABEL.plist $BIN/ls-alert-feed.py

EOF
