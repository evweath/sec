#!/bin/bash
# netdiag/remediate.sh — stop the daemon that flaps the Wi-Fi radio every ~100s.
#
# ROOT CAUSE (see /Users/evw/dev/fix/netdiag/STATE.md): com.evw.comms-guard
# SIGKILLs bluetoothd/rapportd/sharingd/nearbyd every 25s; killing bluetoothd
# drops the shared Wi-Fi/BT radio on this Mac → ~100s internet outages.
#
# SAFE & REVERSIBLE: the plist is QUARANTINED (moved to
# /Library/LaunchDaemons.disabled/), scripts in /usr/local/bin are untouched.
# Undo:  sudo mv /Library/LaunchDaemons.disabled/com.evw.comms-guard.plist \
#          /Library/LaunchDaemons/ && sudo launchctl bootstrap system \
#          /Library/LaunchDaemons/com.evw.comms-guard.plist
#
# RUN:  sudo bash /Users/evw/dev/fix/netdiag/remediate.sh
set -uo pipefail
LOG=/Users/evw/dev/fix/netdiag/logs/remediate.log
mkdir -p "$(dirname "$LOG")"
exec > >(tee -a "$LOG") 2>&1

echo "=== remediate.sh started $(date) ==="
if [ "$(id -u)" -ne 0 ]; then echo "ERROR: run with sudo"; exit 1; fi

Q=/Library/LaunchDaemons.disabled
mkdir -p "$Q"

stop_daemon() {
  label="$1"; plist="/Library/LaunchDaemons/$label.plist"
  echo "--- $label"
  if launchctl print "system/$label" >/dev/null 2>&1; then
    launchctl bootout "system/$label" && echo "  stopped (bootout ok)" || echo "  bootout FAILED"
  else
    echo "  not loaded (already stopped?)"
  fi
  if [ -f "$plist" ]; then
    mv "$plist" "$Q/" && echo "  plist quarantined -> $Q/" || echo "  quarantine mv FAILED"
  else
    echo "  plist already absent from /Library/LaunchDaemons"
  fi
}

# The outage culprit. Everything else stays running until the fix is verified.
stop_daemon com.evw.comms-guard

echo
echo "=== self-verification (waiting 30s) ==="
sleep 30
echo "comms-guard processes (expect none):"
pgrep -fl evw-comms-guard || echo "  none — good"
echo "daemon ages (bluetoothd should now be OLDER than 30s and keep climbing):"
ps -eo etime,comm | grep -E "bluetoothd$|rapportd$|sharingd$|nearbyd$" | grep -v grep
echo
echo "=== remediate.sh done $(date) ==="
echo "Next: watch  tail -f /Users/evw/dev/fix/netdiag/logs/monitor.log  for 10 min."
echo "Expect NO new 'wifi=inactive' or 'gwip=none' lines (baseline: ~1 per 100s)."
