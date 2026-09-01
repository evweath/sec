#!/usr/bin/env bash
# restore-hardening-2026-06-12.sh
# Re-applies the launchd hardening that was wiped when the macOS 26.5.1
# update (Jun 11) replaced disabled.501.plist (dropping schg) and the
# boot-time managed-services reset removed the 11 entries.
# Procedure replicated from MASTER-SECURITY-LOG.md (scans 12-15).
# Also exports the current Little Snitch model for rule review.
# Run: sudo bash ~/dev/security/restore-hardening-2026-06-12.sh
set -uo pipefail

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error-guard.sh)
_eg_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
while [ "$_eg_d" != "/" ] && [ ! -f "$_eg_d/lib/error-guard.sh" ]; do _eg_d="$(dirname "$_eg_d")"; done
[ -f "$_eg_d/lib/error-guard.sh" ] && . "$_eg_d/lib/error-guard.sh"; unset _eg_d
command -v guard_run >/dev/null 2>&1 || guard_run() { shift; "$@"; }
command -v guard_throw >/dev/null 2>&1 || guard_throw() { printf 'error-guard: throw: %s\n' "$*" >&2; return 1; }

PLIST=/var/db/com.apple.xpc.launchd/disabled.501.plist
LSCLI="/Applications/Little Snitch.app/Contents/Components/littlesnitch"
# mktemp: file is created root-owned 0600 and, in sticky /tmp, unlinkable by
# others — so the chown below can't be tricked into following a planted symlink.
# (X's must be trailing on macOS mktemp; a .json suffix after them is NOT randomized.)
LSOUT="$(mktemp /tmp/ls-model-2026-06-12.XXXXXXXX)"

[ "$(id -u)" -eq 0 ] || { echo "must run with sudo"; exit 1; }

echo "── 1. Current plist state ──"
ls -lO "$PLIST"
plutil -p "$PLIST"

echo ""
echo "── 2. Remove schg if present (so we can write) ──"
guard_run "chflags-noschg" chflags noschg "$PLIST" 2>/dev/null || true

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
  guard_run "launchctl-disable" launchctl disable "gui/501/$s" && echo "disabled $s" || echo "FAILED launchctl disable $s"
done

# Belt-and-suspenders: ensure every entry exists as true in the plist
for s in "${SERVICES[@]}"; do
  if ! plutil -p "$PLIST" | grep -qF "\"$s\" => true"; then
    guard_run "plistbuddy-add" /usr/libexec/PlistBuddy -c "Add :$s bool true" "$PLIST" 2>/dev/null \
      || guard_run "plistbuddy-set" /usr/libexec/PlistBuddy -c "Set :$s true" "$PLIST"
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
guard_run "chflags-schg" chflags schg "$PLIST"
ls -lO "$PLIST"

echo ""
echo "── 6. Kill currently-running disabled services ──"
for p in studentd sharingd replicatord privatecloudcomputed RemoteManagementAgent; do
  pkill -x "$p" 2>/dev/null && echo "killed $p" || true
done
killall identityservicesd 2>/dev/null && echo "killed identityservicesd" || true

echo ""
echo "── 7. Export Little Snitch model for rule review ──"
guard_run "ls-export" "$LSCLI" export-model "$LSOUT" && chown evw "$LSOUT" && chmod 600 "$LSOUT" \
  && echo "exported $(wc -c < "$LSOUT") bytes → $LSOUT" \
  || echo "LS export FAILED"

echo ""
echo "Done."
