#!/bin/bash
# evw-ls-resource-guard.sh — stop the Little Snitch UI CPU/memory spiral
# before it can lock up the Mac again.
#
# Background (2026-09-03 incidents):
#   - 09:44 kernel panic: watchdogd starved under 63 swapfiles / 100% compressor
#     segments; Little Snitch Network Monitor had burned ~11,000s CPU and the
#     config app ~7,000s in one boot.
#   - 18:07 forced restart: LS config app spinning in KVO cascades (cpu_resource
#     diag 15:49) — Mac beachballed until the user restarted.
# The filter itself lives in the root-owned network extension + daemon; the
# user-owned UI apps (config app, Network Monitor, Agent) are what spiral.
# Killing a UI app never weakens filtering — rules keep being enforced.
#
# Each run (every 5 min via LaunchAgent com.evw.ls-resource-guard):
#   1. Compute true average CPU since last run (delta cumulative CPU time /
#      delta wall clock) for each LS UI process, plus RSS.
#   2. Breach = CPU > MAX_CPU_FRAC of one core sustained, or RSS > MAX_RSS_MB.
#   3. Two consecutive breaches -> kill -TERM the app, log, notify.
#   4. Swapfile count > MAX_SWAPFILES -> notify once per 24h (panic precursor).
#
# Runs as the user (no root): can only kill user-owned UI apps, by design.

set -uo pipefail

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error-guard.sh)
_eg_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
while [ "$_eg_d" != "/" ] && [ ! -f "$_eg_d/lib/error-guard.sh" ]; do _eg_d="$(dirname "$_eg_d")"; done
[ -f "$_eg_d/lib/error-guard.sh" ] && . "$_eg_d/lib/error-guard.sh"; unset _eg_d
command -v guard_run >/dev/null 2>&1 || guard_run() { shift; "$@"; }

LOG_DIR="$HOME/dev/security/logs"
LOG="$LOG_DIR/ls-resource-guard.log"
STATE_DIR="$HOME/Library/Caches/evw-ls-resource-guard"
MAX_CPU_FRAC="0.20"     # >20% of one core sustained over the check window
MAX_RSS_MB=1024         # config app was 324MB and NM 694MB at the panic — 1GB is far past healthy
MAX_SWAPFILES=24        # 63 swapfiles preceded the 09:44 watchdog panic
BREACHES_NEEDED=2

mkdir -p "$STATE_DIR" "$LOG_DIR"

log() { printf '[%s] %s\n' "$(date -Iseconds)" "$*" >> "$LOG"; }

# Log rotation: keep last 1 MB
if [[ -f "$LOG" ]] && (( $(wc -c < "$LOG") > 1048576 )); then
    guard_run "log-rotate" mv "$LOG" "${LOG}.1"
fi

notify() {
    /usr/bin/osascript -e 'display notification "'"$1"'" with title "LS RESOURCE GUARD" sound name "Basso"' \
        >/dev/null 2>&1 || true
}

# cpu_seconds <pid> — cumulative CPU time in seconds
cpu_seconds() {
    ps -o time= -p "$1" 2>/dev/null | awk -F'[:-]' '
        NF==4 {print ($1*86400)+($2*3600)+($3*60)+$4}
        NF==3 {print ($1*3600)+($2*60)+$3}
        NF==2 {print ($1*60)+$2}'
}

now=$(date +%s)
report=""

# name|pgrep-pattern|max_rss_mb
TARGETS=(
    "LS config app|/Applications/Little Snitch.app/Contents/MacOS/Little Snitch|$MAX_RSS_MB"
    "LS Network Monitor|Little Snitch Network Monitor.app/Contents/MacOS|$MAX_RSS_MB"
    "LS Agent|Little Snitch Agent.app/Contents/MacOS|512"
)

for entry in "${TARGETS[@]}"; do
    IFS='|' read -r name pattern max_rss <<< "$entry"
    pid=$(pgrep -f "$pattern" | head -1)
    [[ -z "$pid" ]] && continue

    cpu_now=$(cpu_seconds "$pid")
    rss_kb=$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ')
    rss_mb=$(( ${rss_kb:-0} / 1024 ))
    state="$STATE_DIR/$(echo "$name" | tr ' ' '-').state"
    last_cpu=0; last_ts=$now; breaches=0
    [[ -f "$state" ]] && read -r last_cpu last_ts breaches < "$state"

    wall=$(( now - last_ts ))
    (( wall < 60 )) && wall=60   # first run: assume 60s floor to avoid div spikes
    frac=$(awk -v cn="${cpu_now:-0}" -v lc="${last_cpu:-0}" -v w="$wall" 'BEGIN{printf "%.3f", (cn-lc)/w}')

    breach=0; why=""
    if awk -v f="$frac" -v m="$MAX_CPU_FRAC" 'BEGIN{exit !(f>m)}'; then
        breach=1; why="cpu=${frac}/core"
    fi
    if (( rss_mb > max_rss )); then
        breach=1; why="${why:+$why,}rss=${rss_mb}MB"
    fi

    if (( breach )); then
        breaches=$(( breaches + 1 ))
        log "breach $breaches/$BREACHES_NEEDED: $name (pid $pid) $why"
    else
        breaches=0
    fi
    printf '%s %s %s\n' "${cpu_now:-0}" "$now" "$breaches" > "$state"
    report="$report $name:cpu=$frac,rss=${rss_mb}MB;"

    if (( breaches >= BREACHES_NEEDED )); then
        if kill -TERM "$pid" 2>/dev/null; then
            log "KILLED $name (pid $pid) after $breaches consecutive breaches ($why) — filtering unaffected (daemon+networkext untouched)"
            notify "$name was hogging resources ($why) and was quit. Little Snitch filtering is unaffected."
        else
            log "KILL FAILED for $name (pid $pid)"
        fi
        printf '%s %s %s\n' 0 "$now" 0 > "$state"
    fi
done

[[ -n "$report" ]] && log "ok:${report}"

# Swap early warning (the panic precursor) — notify at most once per 24h
swapfiles=$(ls /private/var/vm/swapfile* 2>/dev/null | wc -l | tr -d ' ')
swap_stamp="$STATE_DIR/swap-notified.ts"
last_note=0
[[ -f "$swap_stamp" ]] && last_note=$(cat "$swap_stamp")
if (( ${swapfiles:-0} > MAX_SWAPFILES )) && (( now - last_note > 86400 )); then
    used=$(sysctl -n vm.swapusage 2>/dev/null | awk -F'used = ' '{print $2}' | cut -d, -f1)
    log "ALERT: ${swapfiles} swapfiles (>${MAX_SWAPFILES}, used ${used:-?}) — memory-pressure spiral that preceded the 09:44 panic"
    notify "WARNING: ${swapfiles} swapfiles — memory pressure is building toward the state that panicked the Mac. Consider restarting soon."
    echo "$now" > "$swap_stamp"
fi

exit 0
