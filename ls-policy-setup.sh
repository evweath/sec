#!/usr/bin/env bash
# =============================================================================
# ls-policy-setup.sh — schedule the LS policy/enrichment/leak-scan pipeline
#
# Run:  bash ls-policy-setup.sh          (user-level parts)
#       sudo bash ls-policy-setup.sh     (also installs the root traffic export)
#
#   1. com.evw.ls-enrich      LaunchAgent  (user,  every 15 min) — PTR/RDAP cache
#   2. com.evw.ls-leak-scan   LaunchDaemon (root,  hourly)       — traffic export
#                             + leak report into ~/dev/security/scan-<date>/
#
# The policy reconciler (ls-policy-apply.py) stays manual: review its dry run,
# then `sudo python3 ls-policy-apply.py --apply` when you like what it shows.
# Prerequisite: ls-alert-feed-setup.sh installed (the feed this reads from).
# =============================================================================
set -euo pipefail

SEC_DIR="/Users/evw/dev/security"
STORE="/var/db/evw-ls-alerts"
LD="/Library/LaunchDaemons"
ENRICH_LABEL="com.evw.ls-enrich"
SCAN_LABEL="com.evw.ls-leak-scan"

# The user-agent parts must land on the real console user even under sudo
# (sudo makes HOME=/var/root and id -u=0, and gui/0 does not exist).
REAL_USER="${SUDO_USER:-$(stat -f %Su /dev/console)}"
REAL_UID="$(id -u "$REAL_USER")"
REAL_HOME="$(eval echo "~$REAL_USER")"
LA_USER="$REAL_HOME/Library/LaunchAgents"
LOG_DIR="$REAL_HOME/Library/Logs"

info() { echo "[*] $*"; }
ok()   { echo "[✓] $*"; }

# ── user agent: enricher every 15 min ─────────────────────────────────────────
info "installing $ENRICH_LABEL (user agent for $REAL_USER, 15 min)"
mkdir -p "$LA_USER" "$LOG_DIR"
rm -f /var/root/Library/LaunchAgents/$ENRICH_LABEL.plist 2>/dev/null || true  # stray from earlier sudo run
cat > "$LA_USER/$ENRICH_LABEL.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$ENRICH_LABEL</string>
  <key>ProgramArguments</key><array>
    <string>/usr/bin/python3</string>
    <string>$SEC_DIR/ls-enrich.py</string>
  </array>
  <key>StartInterval</key><integer>900</integer>
  <key>StandardOutPath</key><string>$LOG_DIR/ls-enrich.log</string>
  <key>StandardErrorPath</key><string>$LOG_DIR/ls-enrich-err.log</string>
</dict></plist>
PLIST
chown "$REAL_USER" "$LA_USER/$ENRICH_LABEL.plist"
launchctl bootout "gui/$REAL_UID/$ENRICH_LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$REAL_UID" "$LA_USER/$ENRICH_LABEL.plist"
ok "$ENRICH_LABEL scheduled"

# ── root daemon: traffic export + leak scan, hourly ───────────────────────────
if [[ $EUID -eq 0 ]]; then
  info "installing $SCAN_LABEL (root daemon, hourly)"
  cat > "$LD/$SCAN_LABEL.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$SCAN_LABEL</string>
  <key>ProgramArguments</key><array>
    <string>/bin/bash</string>
    <string>-c</string>
    <string>/usr/bin/python3 $SEC_DIR/ls-leak-scan.py --export-traffic 1h >> $LOG_DIR/ls-leak-scan.log 2>&amp;1</string>
  </array>
  <key>StartInterval</key><integer>3600</integer>
  <key>StandardOutPath</key><string>$LOG_DIR/ls-leak-scan-daemon.log</string>
  <key>StandardErrorPath</key><string>$LOG_DIR/ls-leak-scan-daemon-err.log</string>
</dict></plist>
PLIST
  chmod 644 "$LD/$SCAN_LABEL.plist"
  launchctl bootout "system/$SCAN_LABEL" 2>/dev/null || true
  launchctl bootstrap system "$LD/$SCAN_LABEL.plist"
  ok "$SCAN_LABEL scheduled"
else
  echo "[i] not root — skipping the hourly traffic-export daemon."
  echo "    re-run with sudo to install it:  sudo bash $0"
fi

cat <<EOF

[✓] LS policy pipeline scheduled.

  feed:      $STORE/ls-alerts.jsonl   (install ls-alert-feed-setup.sh first)
  enrich:    15-min user agent  → ls-enrich.db + ls-enrich.jsonl
  leak scan: hourly root daemon → scan-<date>/ls-leak-scan-*.md
  policy:    manual — python3 ls-policy-apply.py <model.json>   (dry run)
                     sudo python3 ls-policy-apply.py --apply    (live)

EOF
