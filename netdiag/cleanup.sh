#!/bin/bash
# netdiag/cleanup.sh — remove the two harmful/useless members of the evw guard stack.
#
#   com.evw.ls-watchdog(+ -monitor): auto-DELETES Little Snitch rules every 600s,
#     including rules the user approved via LS alert dialogs (origin=alert/monitor).
#     Currently inert only because the LS CLI is unauthorized; a loaded gun.
#   local.awdl-down: runs `ifconfig awdl0 down` every 60s; awdl0 does not exist on
#     this Mac — 1,440 error lines/day for zero function.
#
# Everything else (mac-sentinel, replayd-guard, plist-monitor, audit-monitor,
# dns-guard, binding-monitor, file-sentinel, lockdown, pf-devports, harden,
# config-sentinel) measured cheap (<= ~1m CPU/18h) and is LEFT RUNNING.
#
# SAFE & REVERSIBLE: plists moved to /Library/LaunchDaemons.disabled/, nothing deleted.
# RUN:  sudo bash /Users/evw/dev/fix/netdiag/cleanup.sh
set -uo pipefail
LOG=/Users/evw/dev/fix/netdiag/logs/cleanup.log
mkdir -p "$(dirname "$LOG")"
exec > >(tee -a "$LOG") 2>&1

echo "=== cleanup.sh started $(date) ==="
if [ "$(id -u)" -ne 0 ]; then echo "ERROR: run with sudo"; exit 1; fi

Q=/Library/LaunchDaemons.disabled
mkdir -p "$Q"

stop_daemon() {
  label="$1"; plist="/Library/LaunchDaemons/$label.plist"
  echo "--- $label"
  if launchctl print "system/$label" >/dev/null 2>&1; then
    launchctl bootout "system/$label" && echo "  stopped (bootout ok)" || echo "  bootout FAILED"
  else
    echo "  not loaded"
  fi
  if [ -f "$plist" ]; then
    mv "$plist" "$Q/" && echo "  plist quarantined -> $Q/" || echo "  quarantine mv FAILED"
  else
    echo "  plist already absent"
  fi
}

stop_daemon com.evw.ls-watchdog
stop_daemon com.evw.ls-watchdog-monitor
stop_daemon local.awdl-down

echo
echo "=== verification ==="
pgrep -fl "ls-watchdog" || echo "  ls-watchdog: none running — good"
ls /Library/LaunchDaemons.disabled/
echo "=== cleanup.sh done $(date) ==="
