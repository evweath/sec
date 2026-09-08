#!/bin/bash
# Persistent guard: keeps the Wazuh agent daemons alive and logs manager
# connection-state transitions. Runs as root LaunchDaemon (com.evw.wazuh-guard).
# Companion to evw-wazuh-setup.sh — the stock com.wazuh.agent plist has no
# KeepAlive, so without this guard a crashed/exited agent stays down.

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

LOG="/private/var/log/evw-wazuh-guard.log"
# Not root (e.g. manual run as user)? Fall back to a user-writable log
# instead of spamming "Permission denied" on every log line.
if ! touch "$LOG" 2>/dev/null; then LOG="$HOME/Library/Logs/$(basename "$LOG")"; fi
mkdir -p "$(dirname "$LOG")" 2>/dev/null || true

log() { printf '%s %s\n' "$(date -Iseconds)" "$*" >> "$LOG"; }

# probe wrapper: for pgrep/grep rc 1 (no match) is a normal result, not a
# probe failure — only rc > 1 means the probe itself broke.
probe() { "$@" 2>/dev/null; [ $? -le 1 ]; }

OSSEC_DIR="/Library/Ossec"
# Wazuh ≥4.8 renamed ossec-* binaries to wazuh-* — prefer new, fall back to old
OSSEC_CTL="$OSSEC_DIR/bin/wazuh-control"
[ -x "$OSSEC_CTL" ] || OSSEC_CTL="$OSSEC_DIR/bin/ossec-control"
OSSEC_LOG="$OSSEC_DIR/logs/ossec.log"
STATE="/var/tmp/evw-wazuh-guard.state"

# Core daemons that must be alive. wazuh-execd/wazuh-modulesd are checked
# too but only logged — a missing module daemon is not worth a full restart.
CORE="wazuh-agentd wazuh-logcollector wazuh-syscheckd"
EXTRA="wazuh-execd wazuh-modulesd"

CHECK_INTERVAL=30
RESTART_MIN_INTERVAL=300   # never restart the agent more than once per 5 min
LAST_RESTART=0

log "=== evw-wazuh-guard started (PID=$$) ==="

manager_state() {
    # connected | disconnected | unknown — from the most recent relevant
    # ossec.log line. Reads as root; returns 'unknown' when unreadable.
    [ -r "$OSSEC_LOG" ] || { echo unknown; return; }
    local last
    last=$(grep -E "Connected to server|Unable to connect|Could not resolve|Connection refused|ERROR.*connect" \
            "$OSSEC_LOG" 2>/dev/null | tail -1)
    case "$last" in
        *"Connected to server"*) echo connected ;;
        *"Unable to connect"*|*"Could not resolve"*|*"Connection refused"*|*"ERROR"*connect*) echo disconnected ;;
        *) echo unknown ;;
    esac
}

while true; do
    if [ ! -x "$OSSEC_CTL" ]; then
        # Agent not installed (or removed) — nothing to guard. Quiet hourly note.
        log "note: $OSSEC_CTL not present — wazuh agent uninstalled? sleeping 1h"
        sleep 3600
        continue
    fi

    # ── 1. keep core daemons alive ───────────────────────────────────────────
    MISSING=""
    for d in $CORE; do
        guard_run "pgrep-$d" probe pgrep -f "$d" || true
        pgrep -f "$d" >/dev/null 2>&1 || MISSING="$MISSING $d"
    done
    for d in $EXTRA; do
        pgrep -f "$d" >/dev/null 2>&1 || log "note: optional daemon $d not running"
    done

    if [ -n "$MISSING" ]; then
        now=$(date +%s)
        if [ $((now - LAST_RESTART)) -ge $RESTART_MIN_INTERVAL ]; then
            LAST_RESTART=$now
            log "ALERT: wazuh daemons missing:$MISSING — restarting agent"
            OUT=$(guard_run "ossec-restart" "$OSSEC_CTL" restart 2>&1 || true)
            printf '%s\n' "$OUT" | while IFS= read -r line; do log "  restart: $line"; done
            sleep 5
            STILL=""
            for d in $CORE; do
                pgrep -f "$d" >/dev/null 2>&1 || STILL="$STILL $d"
            done
            if [ -n "$STILL" ]; then
                log "ALERT: still missing after restart:$STILL"
            else
                log "ok: all core daemons running after restart"
            fi
        fi
    fi

    # ── 2. manager connection-state transitions ──────────────────────────────
    CUR=$(manager_state)
    PREV=$(cat "$STATE" 2>/dev/null || echo unknown)
    if [ "$CUR" != "$PREV" ]; then
        log "manager state: $PREV -> $CUR"
        echo "$CUR" > "$STATE" 2>/dev/null || true
    fi

    sleep $CHECK_INTERVAL
done
