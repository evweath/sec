#!/bin/bash
# binding-monitor.sh — Detect and optionally kill any process bound to 0.0.0.0.
#
# Runs every 5 min via LaunchDaemon (com.ew.binding-monitor.plist).
# On violation:
#   1. Logs the offending process + port
#   2. Sends a macOS notification (visible to the console user)
#   3. If AUTO_KILL=1, sends SIGTERM to the process after GRACE_SECONDS
#
# Allowlist: processes intentionally permitted to bind externally.
# Format: "process_name:port" or "process_name:*" or "*:port"

LOG=/var/log/binding-monitor.log
ALERT_TITLE="Binding Monitor"
AUTO_KILL=${AUTO_KILL:-0}      # Set to 1 to auto-terminate violating processes
GRACE_SECONDS=${GRACE_SECONDS:-10}

# ── Allowlist ─────────────────────────────────────────────────────────────────
# Each entry: "process:port" — port can be * for any port.
# These are intentionally LAN-accessible. Keep this list minimal and documented.
ALLOWLIST=(
    # "nginx:80"       # example: web server intentionally on LAN
    # "python3.13:8743"  # if you want donut-intel accessible from other devices
    "symptomsd:*"      # Apple network-quality diagnostics daemon — uses random high ports on all interfaces
    "ControlCe:*"      # Apple Control Center helper
    "rapportd:*"       # Apple Handoff/AirDrop coordination daemon
)

# ── Helpers ───────────────────────────────────────────────────────────────────
log() {
    local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$ts] $*" >> "$LOG"
}

notify_user() {
    local msg="$1"
    # Find the console user's UID so we can send to the right session
    local console_uid
    console_uid=$(id -u "$(stat -f '%Su' /dev/console 2>/dev/null)" 2>/dev/null || echo "")
    if [[ -n "$console_uid" ]]; then
        launchctl asuser "$console_uid" \
            osascript -e "display notification \"$msg\" with title \"$ALERT_TITLE\"" \
            2>/dev/null || true
    fi
}

is_allowed() {
    local proc="$1" port="$2"
    for entry in "${ALLOWLIST[@]}"; do
        local ap="${entry%%:*}" aport="${entry##*:}"
        if { [[ "$ap" == "*" ]] || [[ "$ap" == "$proc" ]]; } && \
           { [[ "$aport" == "*" ]] || [[ "$aport" == "$port" ]]; }; then
            return 0
        fi
    done
    return 1
}

# ── Main scan ─────────────────────────────────────────────────────────────────
log "=== Binding scan ==="

VIOLATIONS=0

# lsof -nP: no hostname resolution, no port name lookup
# -sTCP:LISTEN: only listening sockets
# grep '*:' matches 0.0.0.0 and [::] (shown as *: in lsof output)
while IFS= read -r line; do
    # Fields: COMMAND PID USER FD TYPE DEVICE SIZE NODE NAME
    proc=$(echo "$line" | awk '{print $1}')
    pid=$(echo  "$line" | awk '{print $2}')
    name=$(echo "$line" | awk '{print $9}')   # e.g. *:8000 or 0.0.0.0:8000

    # Extract port from NAME field
    port="${name##*:}"

    # Skip loopback (127.* and [::1])
    case "$name" in
        127.*|"[::1]"*|localhost*) continue ;;
    esac

    # Only flag 0.0.0.0 / wildcard listeners (shown as *:port or 0.0.0.0:port)
    case "$name" in
        \*:*|0.0.0.0:*|\[:\:?\]:*) ;;   # wildcard — check it
        *) continue ;;
    esac

    if is_allowed "$proc" "$port"; then
        log "  ALLOWED  pid=$pid  proc=$proc  addr=$name"
        continue
    fi

    VIOLATIONS=$((VIOLATIONS + 1))
    log "  VIOLATION  pid=$pid  proc=$proc  addr=$name"
    notify_user "VIOLATION: $proc (pid $pid) is listening on $name — accessible from LAN!"

    if [[ "$AUTO_KILL" -eq 1 ]]; then
        log "  Waiting ${GRACE_SECONDS}s then sending SIGTERM to pid=$pid"
        sleep "$GRACE_SECONDS"
        if kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null && log "  SIGTERM sent to pid=$pid" \
                || log "  SIGTERM failed (may need root)"
        else
            log "  pid=$pid no longer running"
        fi
    fi

done < <(lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | tail -n +2)

if [[ "$VIOLATIONS" -eq 0 ]]; then
    log "  No violations found."
else
    log "  $VIOLATIONS violation(s) found."
fi

log "=== Scan complete ==="
