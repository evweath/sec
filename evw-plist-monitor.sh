#!/bin/bash
# Boot-time monitor for writes to disabled.501.plist.
# Runs as a LaunchDaemon (root). Logs process name, PID, and call type for
# every fs event touching the target file. Survives across reboots.

set -uo pipefail

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

TARGET="disabled.501.plist"
LOG="/private/var/log/evw-plist-monitor.log"
# Not root (e.g. manual run as user)? Fall back to a user-writable log
# instead of spamming "Permission denied" on every log line.
if ! touch "$LOG" 2>/dev/null; then LOG="$HOME/Library/Logs/$(basename "$LOG")"; fi
mkdir -p "$(dirname "$LOG")" 2>/dev/null || true

log() { printf '%s %s\n' "$(date -Iseconds)" "$*" >> "$LOG"; }

log "=== evw-plist-monitor started (PID=$$) ==="
log "Target: /var/db/com.apple.xpc.launchd/$TARGET"

# fs_usage buffers the whole-system fs trace in userspace and grows without
# bound (117 GB RSS on 2026-09-02 — primary driver of the watchdog-timeout
# kernel panic that night). Cap it: once fs_usage exceeds MAX_RSS_KB, kill it
# and exit; launchd KeepAlive restarts the pipeline within seconds.
MAX_RSS_KB=2097152   # 2 GB
(
    while sleep 60; do
        rss=0
        for p in $(pgrep -x fs_usage 2>/dev/null); do
            r=$(ps -o rss= -p "$p" 2>/dev/null | tr -d ' ')
            rss=$((rss + ${r:-0}))
        done
        if [ "$rss" -gt "$MAX_RSS_KB" ]; then
            log "fs_usage RSS ${rss}KB exceeds cap ${MAX_RSS_KB}KB — restarting pipeline"
            pkill -x fs_usage 2>/dev/null
            exit 0
        fi
    done
) &
CAPPID=$!
trap 'kill "$CAPPID" 2>/dev/null' EXIT

# fs_usage -w: wide output (full path); -f filesys: filesystem calls only.
# Output includes: timestamp, syscall, process_name, pid
guard_run "fs-usage" /usr/bin/fs_usage -w -f filesys 2>/dev/null \
  | grep -F --line-buffered "$TARGET" \
  | while IFS= read -r line; do
      log "$line"
      # On any write-class event, snapshot the plist and process list
      if echo "$line" | grep -qiE "write|unlink|rename|open.*[Ww]"; then
        log "--- SNAPSHOT at write event ---"
        /usr/bin/plutil -p /var/db/com.apple.xpc.launchd/disabled.501.plist 2>&1 \
          | while IFS= read -r pline; do log "  $pline"; done
        log "--- process list ---"
        /bin/ps -eo pid,ppid,comm 2>&1 \
          | while IFS= read -r pline; do log "  $pline"; done
        log "--- end snapshot ---"
      fi
    done

log "=== evw-plist-monitor exited ==="
