#!/bin/bash
# Boot-time monitor for writes to disabled.501.plist.
# Runs as a LaunchDaemon (root). Logs process name, PID, and call type for
# every fs event touching the target file. Survives across reboots.

TARGET="disabled.501.plist"
LOG="/private/var/log/evw-plist-monitor.log"

log() { printf '%s %s\n' "$(date -Iseconds)" "$*" >> "$LOG"; }

log "=== evw-plist-monitor started (PID=$$) ==="
log "Target: /var/db/com.apple.xpc.launchd/$TARGET"

# fs_usage -w: wide output (full path); -f filesys: filesystem calls only.
# Output includes: timestamp, syscall, process_name, pid
/usr/bin/fs_usage -w -f filesys 2>/dev/null \
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
