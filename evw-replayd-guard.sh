#!/bin/bash
# Persistent guard: kills replayd if it appears, logs the triggering context.
# Runs as root LaunchDaemon. Complements the LS deny rule by preventing
# replayd from running at all (not just blocking its network).

LOG="/private/var/log/evw-replayd-guard.log"

log() { printf '%s %s\n' "$(date -Iseconds)" "$*" >> "$LOG"; }

log "=== evw-replayd-guard started (PID=$$) ==="

while true; do
    PID=$(pgrep -x replayd 2>/dev/null)
    if [ -n "$PID" ]; then
        log "ALERT: replayd running PID=$PID — capturing context before kill"

        # Log parent chain
        PPID=$(ps -p "$PID" -o ppid= 2>/dev/null | tr -d ' ')
        log "  ppid=$PPID parent_cmd=$(ps -p "$PPID" -o comm= 2>/dev/null)"

        # Log open files (video/surface evidence)
        lsof -p "$PID" 2>/dev/null | grep -iE "\.mov|\.mp4|\.m4v|IOSurface|screen|video|capture" \
            | while IFS= read -r line; do log "  lsof: $line"; done

        # Log network connections
        lsof -i -n -P -p "$PID" 2>/dev/null \
            | while IFS= read -r line; do log "  net: $line"; done

        # Log TCC-relevant processes that have screen capture grant
        sqlite3 "/Library/Application Support/com.apple.TCC/TCC.db" \
            "SELECT client, auth_value FROM access WHERE service='kTCCServiceScreenCapture' AND auth_value=2;" \
            2>/dev/null | while IFS= read -r line; do log "  tcc-grant: $line"; done

        kill -9 "$PID" 2>/dev/null && log "  killed PID=$PID" || log "  kill failed PID=$PID"
    fi
    sleep 30
done
