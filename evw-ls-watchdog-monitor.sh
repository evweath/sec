#!/bin/bash
# evw-ls-watchdog-monitor.sh
#
# Runs every 5 minutes. Checks that evw-ls-watchdog wrote a heartbeat
# within the last 15 minutes. If not, fires a macOS notification and
# logs to syslog.
#
# Deployed to: /usr/local/bin/evw-ls-watchdog-monitor.sh
# LaunchDaemon: com.evw.ls-watchdog-monitor (root, StartInterval=300)

set -uo pipefail

HEARTBEAT="/private/var/run/evw-ls-watchdog-heartbeat.ts"
MAX_AGE=900   # 15 minutes — watchdog runs every 10 min so 15 min = 1 missed run
LOG="/private/var/log/evw-ls-watchdog.log"

log() { printf '[%s] monitor: %s\n' "$(date -Iseconds)" "$*" >> "$LOG"; }

if [[ ! -f "$HEARTBEAT" ]]; then
    age=99999
else
    last_ts=$(cat "$HEARTBEAT" 2>/dev/null || echo 0)
    now_ts=$(date +%s)
    age=$(( now_ts - last_ts ))
fi

if (( age > MAX_AGE )); then
    mins=$(( age / 60 ))
    msg="LS watchdog has not run in ${mins} min — Little Snitch rules may be unprotected"
    log "ALERT: $msg"
    logger -t evw-ls-watchdog-monitor "ALERT: $msg"

    # Deliver notification to the console user's session
    CONSOLE_USER=$(stat -f '%Su' /dev/console 2>/dev/null || echo "")
    if [[ -n "$CONSOLE_USER" ]]; then
        CONSOLE_UID=$(id -u "$CONSOLE_USER" 2>/dev/null || echo "")
        if [[ -n "$CONSOLE_UID" ]]; then
            launchctl asuser "$CONSOLE_UID" /usr/bin/osascript \
                -e 'display notification "'"$msg"'" with title "SECURITY ALERT" subtitle "LS Watchdog Dead" sound name "Basso"' \
                2>/dev/null || true
        fi
    fi
else
    log "OK heartbeat age=${age}s"
fi
