#!/bin/bash
# Boot-time monitor for modifications to disabled.501.plist.
# Runs as a LaunchDaemon (root). Logs the full ES event (process, pid, paths)
# for every write-class event touching the target file. Survives across reboots.
#
# 2026-10-02: fs_usage replaced by eslogger (Endpoint Security). fs_usage
# buffers the whole-system kernel trace in userspace and grows without bound
# (117 GB RSS on 2026-09-02 — primary driver of that night's watchdog panic;
# measured ~40-100 MB/s on this system under load, so every RSS cap became a
# restart-every-minute loop). eslogger streams events with flat memory.
# It runs as its OWN LaunchDaemon (com.evw.plist-eslogger) executing
# /usr/bin/eslogger directly, so TCC Full Disk Access attributes to eslogger
# itself rather than to /bin/bash.
#
# Read visibility (lstat/open-R, ~99% of the old 43MB log) is dropped by
# design: write-class events only. For read forensics, run a short fs_usage
# burst by hand — the right tool at that timescale.

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
STREAM="/private/var/log/evw-eslogger-stream.jsonl"
LOG="/private/var/log/evw-plist-monitor.log"
# Not root (e.g. manual run as user)? Fall back to a user-writable log
# instead of spamming "Permission denied" on every log line.
if ! touch "$LOG" 2>/dev/null; then LOG="$HOME/Library/Logs/$(basename "$LOG")"; fi
mkdir -p "$(dirname "$LOG")" 2>/dev/null || true

log() { printf '%s %s\n' "$(date -Iseconds)" "$*" >> "$LOG"; }

log "=== evw-plist-monitor started (PID=$$, eslogger consumer) ==="
log "Target: /var/db/com.apple.xpc.launchd/$TARGET"
log "Stream: $STREAM"

# Stream housekeeping: bound the raw ES event file. On overflow, rotate and
# restart eslogger (KeepAlive respawns it; launchd opens a fresh stream file
# for the new instance). 50 MB raw ≈ tens of thousands of events — the grep
# filter is what protects the real log.
MAX_STREAM_BYTES=$((50 * 1024 * 1024))
(
    while sleep 60; do
        [ -f "$STREAM" ] || continue
        bytes=$(wc -c < "$STREAM" 2>/dev/null | tr -d ' ')
        if [ "${bytes:-0}" -gt "$MAX_STREAM_BYTES" ]; then
            mv -f "$STREAM" "$STREAM.1" 2>/dev/null
            pkill -x eslogger 2>/dev/null
            sleep 2
            chmod 600 "$STREAM" 2>/dev/null
            log "stream rotated at ${bytes} bytes; eslogger restarted for fresh handle"
        fi
    done
) &
ROTPID=$!
trap 'kill "$ROTPID" 2>/dev/null' EXIT

chmod 600 "$STREAM" 2>/dev/null || true

# Consumer loop: every matching event IS write-class (the eslogger daemon
# subscribes only to write/unlink/rename/create), so log it, then snapshot —
# debounced to one snapshot per SNAP_MIN_INTERVAL seconds so a hammer storm
# can't turn the log into a ps dump (that was most of the old 43MB).
SNAP_MIN_INTERVAL=60
last_snap=0
guard_run "stream-watch" tail -n 0 -F "$STREAM" 2>/dev/null \
  | grep -F --line-buffered "$TARGET" \
  | while IFS= read -r line; do
      log "$line"
      now=$(date +%s)
      if (( now - last_snap >= SNAP_MIN_INTERVAL )); then
        last_snap=$now
        log "--- SNAPSHOT at write-class event (debounced ${SNAP_MIN_INTERVAL}s) ---"
        /usr/bin/plutil -p /var/db/com.apple.xpc.launchd/disabled.501.plist 2>&1 \
          | while IFS= read -r pline; do log "  $pline"; done
        log "--- process list ---"
        /bin/ps -eo pid,ppid,comm 2>&1 \
          | while IFS= read -r pline; do log "  $pline"; done
        log "--- end snapshot ---"
      fi
    done

log "=== evw-plist-monitor exited ==="
