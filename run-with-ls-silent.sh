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
    sudo "$LS_CLI" write-preference activeSilentMode "$PREV_MODE" >/dev/null 2>&1 \
        && ok "Mode restored." \
        || err "FAILED to restore mode. Set it back manually in Little Snitch settings."
    kill "$SUDO_KEEPALIVE" 2>/dev/null || true
    exit "$rc"
}
# Restore on any exit path
trap restore_mode EXIT INT TERM HUP

# Flip to silent-allow
log "Setting Little Snitch → Silent Mode (Allow Connections)…"
if sudo "$LS_CLI" write-preference activeSilentMode 1 >/dev/null 2>&1; then
    ok "Silent-allow active."
else
    err "Could not set silent mode. Aborting before running wrapped command."
    exit 1
fi

# Run the wrapped command
log "Running: ${WRAPPED[*]}"
"${WRAPPED[@]}"
# trap handles restore + exit code propagation
