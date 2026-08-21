#!/usr/bin/env bash
# restore-hardening-2026-06-12.sh
# Re-applies the launchd hardening that was wiped when the macOS 26.5.1
# update (Jun 11) replaced disabled.501.plist (dropping schg) and the
# boot-time managed-services reset removed the 11 entries.
# Procedure replicated from MASTER-SECURITY-LOG.md (scans 12-15).
# Also exports the current Little Snitch model for rule review.
# Run: sudo bash ~/dev/security/restore-hardening-2026-06-12.sh
set -uo pipefail

PLIST=/var/db/com.apple.xpc.launchd/disabled.501.plist
LSCLI="/Applications/Little Snitch.app/Contents/Components/littlesnitch"
LSOUT=/tmp/ls-model-2026-06-12.json

[ "$(id -u)" -eq 0 ] || { echo "must run with sudo"; exit 1; }

echo "── 1. Current plist state ──"
ls -lO "$PLIST"
plutil -p "$PLIST"

echo ""
echo "── 2. Remove schg if present (so we can write) ──"
chflags noschg "$PLIST" 2>/dev/null || true

echo ""
echo "── 3. Re-apply the 11 disables ──"
SERVICES=(
  com.apple.RemoteManagementAgent
  com.apple.remotemanagementd
  com.apple.sharingd
  com.apple.identityservicesd
  com.apple.replicatord
  com.apple.studentd
  com.apple.privatecloudcomputed
  com.apple.aps.remotemanagementd.http.apns-dev
  com.apple.aps.remotemanagementd.http.apns-prod
  com.apple.replayd
  com.apple.replaykit.sharingsession
)
for s in "${SERVICES[@]}"; do
  launchctl disable "gui/501/$s" && echo "disabled $s" || echo "FAILED launchctl disable $s"
done

# Belt-and-suspenders: ensure every entry exists as true in the plist
for s in "${SERVICES[@]}"; do
  if ! plutil -p "$PLIST" | grep -qF "\"$s\" => true"; then
    /usr/libexec/PlistBuddy -c "Add :$s bool true" "$PLIST" 2>/dev/null \
      || /usr/libexec/PlistBuddy -c "Set :$s true" "$PLIST"
    echo "PlistBuddy ensured $s"
  fi
done

echo ""
echo "── 4. Verify all 11 entries present ──"
COUNT=0
for s in "${SERVICES[@]}"; do
  if plutil -p "$PLIST" | grep -qF "\"$s\" => true"; then
    COUNT=$((COUNT+1))
  else
    echo "MISSING: $s"
  fi
done
echo "$COUNT/11 entries confirmed"

echo ""
echo "── 5. Re-apply schg (kernel immutable) ──"
chflags schg "$PLIST"
ls -lO "$PLIST"

echo ""
echo "── 6. Kill currently-running disabled services ──"
for p in studentd sharingd replicatord privatecloudcomputed RemoteManagementAgent; do
  pkill -x "$p" 2>/dev/null && echo "killed $p" || true
done
killall identityservicesd 2>/dev/null && echo "killed identityservicesd" || true

echo ""
echo "── 7. Export Little Snitch model for rule review ──"
"$LSCLI" export-model "$LSOUT" && chown eric "$LSOUT" && chmod 600 "$LSOUT" \
  && echo "exported $(wc -c < "$LSOUT") bytes → $LSOUT" \
  || echo "LS export FAILED"

echo ""
echo "Done."
