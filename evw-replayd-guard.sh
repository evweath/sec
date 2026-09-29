#!/bin/bash
# Persistent guard: caps every replayd instance at GRACE seconds, logs kills.
# Runs as root LaunchDaemon. Complements the LS deny rule by preventing
# replayd from running LONG (not just blocking its network).
#
# Threat model (incident #14, 2026-06-02): a rogue client recorded the screen
# for 8.5h via replayd's TCC-bypass entitlement. The original guard killed
# every replayd on sight — which also broke the built-in Screenshot tool
# (screencapture/Screenshot.app need replayd for ~1-2s per shot; confirmed
# broken 2026-09-28: "could not create image from display").
# Grace-window design: any replayd instance may live GRACE seconds — enough
# for interactive screenshots, far too short for useful surveillance — then
# it is killed and the kill + context are logged.

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

# Full forensic context (lsof/TCC/parent) is expensive — dumping it per kill
# produced a 171 MB log in <2 days. Capture full context at most once per
# SNAP_INTERVAL; plain kill lines otherwise.
SNAP_INTERVAL=600
LAST_SNAP=0
# seconds a single replayd instance may live before it is killed.
# Screenshots need ~1-2s; the rogue recording ran 8.5h. 20s caps any capture
# session at a useless-to-an-attacker length while keeping Screenshot.app and
# /usr/sbin/screencapture functional.
GRACE=20

# seconds a process has been alive. macOS ps has etime ([[dd-]hh:]mm:ss),
# NOT etimes (2026-09-28: using etimes made ps dump its keyword list, the -ge
# test failed silently, and replayd ran uncapped for ~21h).
pid_age_s() {
    local et d=0 h=0 m=0 s=0
    et=$(ps -p "$1" -o etime= 2>/dev/null | tr -d ' ')
    [ -n "$et" ] || return 1
    case "$et" in *-*) d=${et%%-*}; et=${et#*-} ;; esac
    case "$et" in
        *:*:*) IFS=: read -r h m s <<< "$et" ;;
        *:*)   IFS=: read -r m s <<< "$et" ;;
        *)     s=$et ;;
    esac
    echo $(( 10#$d * 86400 + 10#${h:-0} * 3600 + 10#${m:-0} * 60 + 10#${s:-0} ))
}

while true; do
    PID=$(guard_run "probe-replayd" probe pgrep -x replayd || true)
    if [ -n "$PID" ]; then
        AGE=$(pid_age_s "$PID")
        # within the grace window (or age unknown) — leave it alone this tick
        if [ -n "$AGE" ] && [ "$AGE" -ge "$GRACE" ]; then
            now=$(date +%s)
            if [ $((now - LAST_SNAP)) -ge $SNAP_INTERVAL ]; then
                LAST_SNAP=$now
                log "ALERT: replayd PID=$PID age=${AGE}s (>=${GRACE}s grace) — capturing context before kill"

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
            else
                guard_run "kill-replayd" kill -9 "$PID" 2>/dev/null \
                    && log "killed replayd PID=$PID age=${AGE}s" || log "kill failed PID=$PID"
            fi
        fi
    fi
    sleep 5
done
