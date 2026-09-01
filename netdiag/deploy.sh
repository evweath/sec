#!/bin/bash
# netdiag/deploy.sh — root step: apply guard-stack cleanup + install patched copies.
#
#   1. cleanup.sh: removes com.evw.ls-watchdog(+ -monitor) and local.awdl-down
#      (plists quarantined, reversible — see cleanup.sh header).
#   2. Installs the NEUTERED evw-comms-guard.sh over /usr/local/bin/ so even a
#      direct/manual invocation exits harmlessly (gate: COMMS_GUARD_ENABLED=0).
#   3. Installs the patched mac-sentinel.py (alerts to ONE tty instead of all)
#      and restarts the daemon; its self-integrity hash re-baselines at startup.
#
# RUN:  sudo bash /Users/evw/dev/fix/netdiag/deploy.sh
set -uo pipefail
exec > >(tee -a /Users/evw/dev/fix/netdiag/logs/deploy.log) 2>&1
echo "=== deploy.sh started $(date) ==="
[ "$(id -u)" -ne 0 ] && { echo "ERROR: must run as root"; exit 1; }

bash /Users/evw/dev/fix/netdiag/cleanup.sh

install -m 755 -o root -g wheel \
  /Users/evw/dev/security/evw-comms-guard.sh /usr/local/bin/evw-comms-guard.sh \
  && echo "installed neutered /usr/local/bin/evw-comms-guard.sh"

install -m 755 -o root -g wheel \
  /Users/evw/dev/security/scripts/mac-sentinel.py /usr/local/lib/mac-sentinel/mac-sentinel.py \
  && echo "installed patched /usr/local/lib/mac-sentinel/mac-sentinel.py"
launchctl kickstart -k system/com.evw.mac-sentinel \
  && echo "mac-sentinel restarted (single-tty alerts now active)"
sleep 3
pgrep -f "mac-sentinel/mac-sentinel.py" >/dev/null \
  && echo "mac-sentinel: running with patched code" \
  || echo "WARN: mac-sentinel not running after restart"

echo "=== deploy.sh done $(date) ==="
