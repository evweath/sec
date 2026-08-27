#!/bin/bash
# config-sentinel.sh — Hash-based change detector for API keys, credentials,
# Claude config files, plist files, and system security files.
#
# On any detected change:
#   1. Logs the event
#   2. Sends an email to ALERT_EMAIL via Mail.app
#   3. Shows a blocking macOS dialog popup
#   4. Sends a macOS banner notification
#
# Modes:
#   --baseline   Compute and save SHA-256 hashes (run after any known-good change)
#   --scan       Compare against baseline — default, runs via LaunchAgent every 5 min
#   --list       Show all watched files and their current status
#   --report     Show the change log

set -uo pipefail

SENTINEL_DIR="${HOME}/.config-sentinel"
BASELINE_FILE="${SENTINEL_DIR}/baseline.sha256"
CHANGE_LOG="${SENTINEL_DIR}/changes.log"
ALERT_EMAIL="eric@unitybakery.com"
ALERT_TITLE="Config Sentinel — Security Alert"

mkdir -p "$SENTINEL_DIR"
rm -f "${SENTINEL_DIR}/sentinel.lock"   # legacy pid-based lock file

# Acquire an exclusive lock. mkdir is the primitive: atomic on APFS and needs
# no pid-file read (the previous noclobber + pid-read scheme raced on bash 3.2
# and let concurrent instances overlap). GOT_LOCK tracks ownership so a skipped
# instance's trap never removes a live lock. A lock older than 15 minutes is
# treated as stale (a scan completes in seconds).
LOCK_DIR="${SENTINEL_DIR}/sentinel.lock.d"
GOT_LOCK=0
if mkdir "$LOCK_DIR" 2>/dev/null; then
    GOT_LOCK=1
elif [[ -z "$(find "$LOCK_DIR" -maxdepth 0 -mmin -15 2>/dev/null)" ]]; then
    if rmdir "$LOCK_DIR" 2>/dev/null && mkdir "$LOCK_DIR" 2>/dev/null; then
        GOT_LOCK=1
    fi
fi
if [[ "$GOT_LOCK" != 1 ]]; then
    echo "Another instance is running — skipping." >&2
    exit 0
fi
trap '[[ "$GOT_LOCK" == 1 ]] && rmdir "$LOCK_DIR"' EXIT INT TERM

# ── Watched file list ─────────────────────────────────────────────────────────

watched_files() {
    # ── Claude auth & config ───────────────────────────────────────────────
    echo "${HOME}/.claude.json"
    echo "${HOME}/.claude/CLAUDE.md"
    echo "${HOME}/.claude/settings.json"
    echo "${HOME}/.claude/settings.local.json"
    echo "${HOME}/.claude/policy-limits.json"

    # ── Claude hooks (executable — high-value tamper target) ───────────────
    for f in "${HOME}/.claude/hooks/"*.sh; do
        [[ -f "$f" ]] && echo "$f"
    done

    # ── API key .env files and OAuth credentials (real files in ~/.credentials/)
    echo "${HOME}/.credentials/ai-orchestrator.env"
    echo "${HOME}/.credentials/shopify.env"
    echo "${HOME}/.credentials/google-client-secrets.json"

    # ── LaunchAgent service scripts (startup code) ─────────────────────────
    echo "${HOME}/Library/Application Support/ai-orchestrator/start-backend.sh"
    echo "${HOME}/Library/Application Support/ai-orchestrator/start-frontend.sh"

    # ── User LaunchAgent plists ────────────────────────────────────────────
    for f in "${HOME}/Library/LaunchAgents/"*.plist; do
        [[ -f "$f" ]] && echo "$f"
    done

    # ── System LaunchDaemon plists (/Library — world-readable, hashable as user)
    for f in /Library/LaunchDaemons/*.plist; do
        [[ -f "$f" ]] && echo "$f"
    done

    # ── Shell init files ───────────────────────────────────────────────────
    echo "${HOME}/.zshrc"
    echo "${HOME}/.zprofile"
    echo "${HOME}/.profile"
    echo "${HOME}/.bash_profile"
    echo "${HOME}/.bashrc"

    # ── SSH ────────────────────────────────────────────────────────────────
    echo "${HOME}/.ssh/authorized_keys"
    echo "${HOME}/.ssh/config"

    # ── Custom security scripts ────────────────────────────────────────────
    echo "${HOME}/dev/security/scripts/seccheck.sh"
    echo "${HOME}/dev/security/scripts/binding-monitor.sh"
    echo "${HOME}/dev/security/scripts/setup-pf.sh"
    echo "${HOME}/dev/security/scripts/pf-devports.conf"
    echo "${HOME}/dev/security/scripts/file-sentinel.py"
    echo "${HOME}/dev/security/scripts/config-sentinel.sh"

    # ── Little Snitch rules snapshot ───────────────────────────────────────
    echo "${HOME}/.little-snitch-monitor/rules.txt"

    # ── Homebrew binaries & Postgres auth config (trojan target) ───────────
    for f in /opt/homebrew/bin/*; do
        [[ -f "$f" ]] && echo "$f"
    done
    echo /opt/homebrew/var/postgresql@16/pg_hba.conf

    # ── System LaunchAgents & PATH persistence points ──────────────────────
    for f in /Library/LaunchAgents/*.plist /etc/paths /etc/paths.d/*; do
        [[ -f "$f" ]] && echo "$f"
    done

    # ── Postgres client password file ──────────────────────────────────────
    echo "${HOME}/.pgpass"

    # ── secdash app (local security dashboard) ─────────────────────────────
    echo "${HOME}/dev/security/sec/secdash.py"
    echo "${HOME}/dev/security/sec/hardening.sh"
    echo "${HOME}/dev/security/sec/lockdown.sh"
    echo "${HOME}/dev/security/sec/launchd/com.ew.lockdown.plist"

    # ── Extra watches (managed via secdash UI; one absolute path per line) ──
    local extra="${SENTINEL_DIR}/extra-watches"
    if [[ -f "$extra" ]]; then
        while IFS= read -r line; do
            [[ -n "$line" && "$line" != \#* ]] && echo "$line"
        done < "$extra"
    fi
}

# ── Helpers ───────────────────────────────────────────────────────────────────
ts()  { date '+%Y-%m-%d %H:%M:%S'; }
log() { echo "[$(ts)] $*" | tee -a "$CHANGE_LOG"; }

hash_file() {
    local path="$1"
    if [[ ! -e "$path" ]]; then
        echo "ABSENT"
    else
        shasum -a 256 "$path" 2>/dev/null | awk '{print $1}' || echo "ERROR"
    fi
}

# Exact-match lookup of a path's baseline hash.
# (grep -F "  $path" substring-matches prefix paths — /etc/paths also hits
# /etc/paths.d/*, python3 hits python3.14 — producing phantom CHANGED alerts.)
baseline_hash_for() {
    awk -v p="$1" '{ i = index($0, "  "); if (i > 0 && substr($0, i+2) == p) { print $1; exit } }' \
        "$BASELINE_FILE" 2>/dev/null
}

# Replace the hash field for exactly one path (same exact-match discipline).
baseline_set_hash() {
    local tmp="${BASELINE_FILE}.tmp.$$"
    awk -v p="$1" -v h="$2" \
        '{ i = index($0, "  "); if (i > 0 && substr($0, i+2) == p) { printf "%s  %s\n", h, substr($0, i+2) } else print }' \
        "$BASELINE_FILE" > "$tmp" && mv "$tmp" "$BASELINE_FILE"
}

# ── Email via Mail.app ────────────────────────────────────────────────────────
# Requires Mail.app to be configured with a sending account.
send_email() {
    local subject="$1"
    local body="$2"

    # Escape backslashes and double-quotes for AppleScript string literal
    local safe_subject safe_body
    safe_subject=$(printf '%s' "$subject" | sed 's/\\/\\\\/g; s/"/\\"/g')
    safe_body=$(printf '%s' "$body"    | sed 's/\\/\\\\/g; s/"/\\"/g')

    osascript 2>/dev/null <<APPLESCRIPT
tell application "Mail"
    set theMsg to make new outgoing message with properties ¬
        {subject:"${safe_subject}", content:"${safe_body}", visible:false}
    tell theMsg
        make new to recipient at end of to recipients ¬
            with properties {address:"${ALERT_EMAIL}"}
    end tell
    send theMsg
end tell
APPLESCRIPT

    local rc=$?
    if [[ $rc -ne 0 ]]; then
        log "  [WARN] Email send failed (Mail.app may not be running or account not configured)"
    fi
    return $rc
}

# ── Blocking popup dialog ─────────────────────────────────────────────────────
# Stays on screen for up to 1 hour; user must click Acknowledge to dismiss.
show_popup() {
    local change_type="$1"   # CHANGED / NEW / DELETED
    local filepath="$2"
    local old_hash="${3:-n/a}"
    local new_hash="${4:-n/a}"
    local timestamp; timestamp=$(ts)
    local filename; filename=$(basename "$filepath")

    local safe_path safe_old safe_new
    safe_path=$(printf '%s' "$filepath" | sed 's/\\/\\\\/g; s/"/\\"/g')
    safe_old=$(printf '%s' "$old_hash"  | sed 's/\\/\\\\/g; s/"/\\"/g')
    safe_new=$(printf '%s' "$new_hash"  | sed 's/\\/\\\\/g; s/"/\\"/g')

    osascript 2>/dev/null <<APPLESCRIPT
display dialog "⚠️  SECURITY ALERT  ⚠️

Config Sentinel detected: ${change_type}

File:    ${safe_path}
Time:    ${timestamp}

Old hash: ${safe_old}
New hash: ${safe_new}

Verify this change is authorized, then run:
  ~/dev/security/scripts/config-sentinel.sh --baseline

If this change is unexpected, treat your system as potentially compromised." ¬
    buttons {"Acknowledge"} default button "Acknowledge" ¬
    with icon stop ¬
    with title "Config Sentinel — Security Alert" ¬
    giving up after 3600
APPLESCRIPT
}

# ── Notification banner ───────────────────────────────────────────────────────
send_notification() {
    local msg="$1"
    osascript -e "display notification \"${msg}\" with title \"${ALERT_TITLE}\" sound name \"Basso\"" 2>/dev/null || true
}

# ── Fire all three alert channels ────────────────────────────────────────────
alert() {
    local change_type="$1"  # CHANGED / NEW / DELETED
    local filepath="$2"
    local old_hash="${3:-}"
    local new_hash="${4:-}"
    local filename; filename=$(basename "$filepath")
    local timestamp; timestamp=$(ts)

    # 1. Banner notification (immediate, non-blocking)
    send_notification "${change_type}: ${filename}"

    # 2. Email
    local email_body
    email_body="Config Sentinel — Security Alert
$(printf '%.0s─' {1..60})
Change type : ${change_type}
File        : ${filepath}
Time        : ${timestamp}

Old SHA-256 : ${old_hash:-n/a}
New SHA-256 : ${new_hash:-n/a}

If this change is AUTHORIZED, update the baseline:
  ~/dev/security/scripts/config-sentinel.sh --baseline

If this change is NOT authorized, your system may be compromised.
Review the change log:
  ~/dev/security/scripts/config-sentinel.sh --report"

    send_email "⚠️ Security Alert: ${change_type} — ${filename}" "$email_body"

    # 3. Blocking dialog popup (runs in background so it doesn't hold up the scan loop)
    show_popup "$change_type" "$filepath" "$old_hash" "$new_hash" &
}

# ── Commands ──────────────────────────────────────────────────────────────────

cmd_baseline() {
    log "=== Baseline created ==="
    # Write to a temp file, then atomically move into place — a concurrent
    # scan must never see a half-written baseline (causes phantom NEW floods).
    local tmp="${BASELINE_FILE}.tmp.$$"
    : > "$tmp"
    local count=0
    while IFS= read -r path; do
        local h; h=$(hash_file "$path")
        printf '%s  %s\n' "$h" "$path" >> "$tmp"
        count=$((count + 1))
        printf '  %s  %s\n' "$h" "$path"
    done < <(watched_files)
    mv "$tmp" "$BASELINE_FILE"
    log "Saved $count entries to $BASELINE_FILE"
    echo ""
    echo "Baseline saved. Run --scan to detect changes."
}

cmd_scan() {
    if [[ ! -f "$BASELINE_FILE" ]]; then
        echo "No baseline found — run: $0 --baseline" >&2
        exit 1
    fi

    log "=== Scan started ==="
    local changes=0 new_files=0 missing=0

    while IFS= read -r path; do
        local current; current=$(hash_file "$path")
        local baseline; baseline=$(baseline_hash_for "$path")

        if [[ -z "$baseline" ]]; then
            log "  NEW      $path  ($current)"
            alert "NEW" "$path" "" "$current"
            new_files=$((new_files + 1))
            printf '%s  %s\n' "$current" "$path" >> "$BASELINE_FILE"

        elif [[ "$current" == "ABSENT" && "$baseline" != "ABSENT" ]]; then
            log "  DELETED  $path  (was $baseline)"
            alert "DELETED" "$path" "$baseline" ""
            missing=$((missing + 1))
            baseline_set_hash "$path" "ABSENT"

        elif [[ "$current" != "$baseline" ]]; then
            log "  CHANGED  $path"
            log "           old: $baseline"
            log "           new: $current"
            alert "CHANGED" "$path" "$baseline" "$current"
            changes=$((changes + 1))
            # Update so we only alert once per distinct change
            baseline_set_hash "$path" "$current"
        fi
    done < <(watched_files)

    local total=$((changes + new_files + missing))
    if [[ $total -eq 0 ]]; then
        log "  No changes detected."
    else
        log "  Summary: $changes changed, $new_files new, $missing deleted"
    fi
}

cmd_list() {
    local total=0 present=0 absent=0
    echo ""
    echo "Watched files:"
    while IFS= read -r path; do
        total=$((total + 1))
        if [[ -f "$path" ]]; then
            local perms; perms=$(stat -f "%Sp" "$path" 2>/dev/null)
            printf '  %-10s  %s\n' "$perms" "$path"
            present=$((present + 1))
        else
            printf '  %-10s  %s\n' "ABSENT" "$path"
            absent=$((absent + 1))
        fi
    done < <(watched_files)
    echo ""
    echo "Total: $total  |  Present: $present  |  Absent (expected): $absent"
}

cmd_report() {
    if [[ ! -f "$CHANGE_LOG" ]]; then
        echo "No change log yet."
        return
    fi
    echo ""
    echo "=== Config Sentinel Change Log ==="
    echo "File: $CHANGE_LOG"
    echo ""
    tail -200 "$CHANGE_LOG"
}

# ── Test mode ─────────────────────────────────────────────────────────────────
cmd_test() {
    echo "Firing test alert (email + popup) — check for email at ${ALERT_EMAIL} ..."
    alert "CHANGED" \
        "${HOME}/.claude/settings.json  [TEST — ignore this alert]" \
        "abc123def456abc123def456abc123def456abc123def456abc123def456abc1" \
        "999999def456abc123def456abc123def456abc123def456abc123def456abc1"
    echo "Test alert sent. Waiting for popup to appear..."
    wait
    echo "Done. Check email at ${ALERT_EMAIL} for the test message."
}

# ── Dispatch ──────────────────────────────────────────────────────────────────
case "${1:---scan}" in
    --baseline) cmd_baseline ;;
    --scan)     cmd_scan     ;;
    --list)     cmd_list     ;;
    --report)   cmd_report   ;;
    --test)     cmd_test     ;;
    *) echo "Usage: $0 [--baseline|--scan|--list|--report|--test]"; exit 1 ;;
esac
