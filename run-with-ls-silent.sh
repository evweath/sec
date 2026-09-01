#!/usr/bin/env bash
# run-with-ls-silent.sh
# Flip Little Snitch to "Silent Mode – Allow Connections" for the duration of
# a command (default: harden.sh), then restore the previous mode no matter how
# the wrapped command exits (success, failure, or Ctrl-C).
#
# Little Snitch activeSilentMode values:
#   0 = Alert Mode (prompt on unknown)
#   1 = Silent Mode – Allow Connections
#   2 = Silent Mode – Deny Connections
#
# Usage:
#   ./run-with-ls-silent.sh                  # wraps ./harden.sh
#   ./run-with-ls-silent.sh /path/to/cmd a b # wraps any command

set -uo pipefail

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error-guard.sh)
_eg_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
while [ "$_eg_d" != "/" ] && [ ! -f "$_eg_d/lib/error-guard.sh" ]; do _eg_d="$(dirname "$_eg_d")"; done
[ -f "$_eg_d/lib/error-guard.sh" ] && . "$_eg_d/lib/error-guard.sh"; unset _eg_d
command -v guard_run >/dev/null 2>&1 || guard_run() { shift; "$@"; }
command -v guard_throw >/dev/null 2>&1 || guard_throw() { printf 'error-guard: throw: %s\n' "$*" >&2; return 1; }

LS_CLI="/Applications/Little Snitch.app/Contents/Components/littlesnitch"
WRAPPED=( "${@:-/Users/evw/dev/security/harden.sh}" )

RED=$'\033[0;31m'; GRN=$'\033[0;32m'; YLW=$'\033[0;33m'; BLU=$'\033[0;34m'; NC=$'\033[0m'
log()  { printf "%s[ls-silent]%s %s\n" "$BLU" "$NC" "$*"; }
ok()   { printf "%s[ls-silent]%s %s\n" "$GRN" "$NC" "$*"; }
warn() { printf "%s[ls-silent]%s %s\n" "$YLW" "$NC" "$*"; }
err()  { printf "%s[ls-silent]%s %s\n" "$RED" "$NC" "$*"; }

[[ "$(uname)" == "Darwin" ]] || { err "macOS only"; exit 1; }
[[ -x "$LS_CLI" ]]           || { err "Little Snitch CLI not found at $LS_CLI"; exit 1; }
[[ "$EUID" -ne 0 ]]          || { err "Do NOT run as root — script will sudo where needed"; exit 1; }

# Prime sudo + keepalive (the LS CLI requires root for read/write-preference,
# and the wrapped command will also need its own sudo).
log "Priming sudo…"
sudo -v || { err "sudo required"; exit 1; }
( while true; do sudo -n true; sleep 50; kill -0 "$$" 2>/dev/null || exit; done ) 2>/dev/null &
SUDO_KEEPALIVE=$!

# Capture current mode so we can restore it
PREV_MODE="$(sudo "$LS_CLI" read-preference activeSilentMode 2>/dev/null | tr -d '[:space:]')"
case "$PREV_MODE" in
    0|1|2) ok "Current Little Snitch mode: $PREV_MODE (will restore on exit)" ;;
    *)     warn "Could not read activeSilentMode (got: '$PREV_MODE') — defaulting restore target to 0 (Alert)"
           PREV_MODE=0 ;;
esac

restore_mode() {
    local rc=$?
    log "Restoring Little Snitch mode → $PREV_MODE"
    # Retry the restore up to 3 times; if the captured mode still won't stick,
    # fall back to explicitly writing Alert Mode (0) — fail-closed.
    local target="$PREV_MODE" attempt restored=""
    for attempt in 1 2 3 4 5 6; do
        if [ "$attempt" -eq 4 ]; then
            target=0
            warn "Could not restore mode $PREV_MODE — falling back to explicit Alert Mode (0) (fail-closed)"
        fi
        if guard_run "ls-restore-mode" sudo "$LS_CLI" write-preference activeSilentMode "$target" >/dev/null 2>&1; then
            restored=1
            break
        fi
        warn "Restore attempt $attempt/6 failed — retrying…"
        [ "$attempt" -lt 6 ] && sleep 2
    done
    if [ -n "$restored" ]; then
        if [ "$target" != "$PREV_MODE" ]; then
            warn "Little Snitch forced to Alert Mode (0) instead of $PREV_MODE — re-check settings."
        else
            ok "Mode restored."
        fi
    else
        err "FAILED to restore Little Snitch mode — it may still be in silent-allow!"
        osascript -e 'display alert "Little Snitch restore FAILED" message "run-with-ls-silent.sh could not restore Little Snitch from silent-allow. Open Little Snitch settings NOW and re-enable Alert Mode manually." as critical' >/dev/null 2>&1 || true
        [ "$rc" -eq 0 ] && rc=1
    fi
    kill "$SUDO_KEEPALIVE" 2>/dev/null || true
    exit "$rc"
}
# Restore on any exit path
trap restore_mode EXIT INT TERM HUP

# Flip to silent-allow
log "Setting Little Snitch → Silent Mode (Allow Connections)…"
if guard_run "ls-silent-mode" sudo "$LS_CLI" write-preference activeSilentMode 1 >/dev/null 2>&1; then
    ok "Silent-allow active."
else
    err "Could not set silent mode. Aborting before running wrapped command."
    exit 1
fi

# Run the wrapped command
log "Running: ${WRAPPED[*]}"
guard_run "wrapped-cmd" "${WRAPPED[@]}"
# trap handles restore + exit code propagation
