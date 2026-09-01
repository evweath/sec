#!/bin/bash
# Persistent guard: kills replayd if it appears, logs the triggering context.
# Runs as root LaunchDaemon. Complements the LS deny rule by preventing
# replayd from running at all (not just blocking its network).

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error-guard.sh)
_eg_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
# As root, only trust a root-owned lib: a user-writable ancestor dir (e.g.
# Intel Homebrew's /usr/local) could plant one and have it sourced as root.
_eg_ok() { [ -f "$1" ] && { [ "$EUID" -ne 0 ] || [ "$(stat -f %u "$1" 2>/dev/null)" = "0" ]; }; }
while [ "$_eg_d" != "/" ] && ! _eg_ok "$_eg_d/lib/error-guard.sh"; do _eg_d="$(dirname "$_eg_d")"; done
_eg_ok "$_eg_d/lib/error-guard.sh" && . "$_eg_d/lib/error-guard.sh"; unset _eg_d; unset -f _eg_ok
command -v guard_run >/dev/null 2>&1 || guard_run() { shift; "$@"; }
command -v guard_throw >/dev/null 2>&1 || guard_throw() { printf 'error-guard: throw: %s\n' "$*" >&2; return 1; }
EVW_GUARD_POLICY=continue   # daemon: a tripped breaker logs + skips, never exits

umask 077   # root logs in /private/var/log must not be world-readable

LOG="/private/var/log/evw-replayd-guard.log"
# Not root (e.g. manual run as user)? Fall back to a user-writable log
# instead of spamming "Permission denied" on every log line.
if ! touch "$LOG" 2>/dev/null; then LOG="$HOME/Library/Logs/$(basename "$LOG")"; fi
mkdir -p "$(dirname "$LOG")" 2>/dev/null || true

log() { printf '%s %s\n' "$(date -Iseconds)" "$*" >> "$LOG"; }

# probe wrapper: for pgrep/lsof rc 1 (no match / nothing found) is a normal
# result, not a probe failure — only rc > 1 means the probe itself broke.
probe() { "$@" 2>/dev/null; [ $? -le 1 ]; }

log "=== evw-replayd-guard started (PID=$$) ==="

while true; do
    PID=$(guard_run "probe-replayd" probe pgrep -x replayd || true)
    if [ -n "$PID" ]; then
        log "ALERT: replayd running PID=$PID — capturing context before kill"

        # Log parent chain and immediate spawn reason (identifies which Mach port triggered)
        PARENT_PID=$(ps -p "$PID" -o ppid= 2>/dev/null | tr -d ' ')
        log "  ppid=$PARENT_PID parent_cmd=$(ps -p "$PARENT_PID" -o comm= 2>/dev/null)"
        REASON=$(launchctl print gui/501/com.apple.replayd 2>/dev/null | grep "immediate reason" | tr -d '\t')
        log "  spawn_reason: ${REASON:-unknown}"

        # Log open files (video/surface evidence)
        guard_run "lsof-files" lsof -p "$PID" 2>/dev/null | grep -iE "\.mov|\.mp4|\.m4v|IOSurface|screen|video|capture" \
            | while IFS= read -r line; do log "  lsof: $line"; done

        # Log network connections
        guard_run "lsof-net" probe lsof -i -n -P -p "$PID" \
            | while IFS= read -r line; do log "  net: $line"; done

        # Log TCC-relevant processes that have screen capture grant
        guard_run "tcc-db" sqlite3 "/Library/Application Support/com.apple.TCC/TCC.db" \
            "SELECT client, auth_value FROM access WHERE service='kTCCServiceScreenCapture' AND auth_value=2;" \
            2>/dev/null | while IFS= read -r line; do log "  tcc-grant: $line"; done

        guard_run "kill-replayd" kill -9 "$PID" 2>/dev/null && log "  killed PID=$PID" || log "  kill failed PID=$PID"
    fi
    sleep 5
done
