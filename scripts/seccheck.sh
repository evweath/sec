#!/bin/bash
# seccheck.sh — Comprehensive security posture check.
# Run anytime: ./seccheck.sh
# For full checks (audit, PF): sudo ./seccheck.sh

set -uo pipefail

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error-guard.sh)
_eg_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
while [ "$_eg_d" != "/" ] && [ ! -f "$_eg_d/lib/error-guard.sh" ]; do _eg_d="$(dirname "$_eg_d")"; done
[ -f "$_eg_d/lib/error-guard.sh" ] && . "$_eg_d/lib/error-guard.sh"; unset _eg_d
command -v guard_run >/dev/null 2>&1 || guard_run() { shift; "$@"; }
command -v guard_throw >/dev/null 2>&1 || guard_throw() { printf 'error-guard: throw: %s\n' "$*" >&2; return 1; }

PASS=0; FAIL=0; WARN=0

ok()   { echo "  [OK]   $1"; ((PASS++)); }
fail() { echo "  [FAIL] $1"; ((FAIL++)); }
warn() { echo "  [WARN] $1"; ((WARN++)); }
info() { echo "         $1"; }

NEED_ROOT=0
[[ $EUID -eq 0 ]] && NEED_ROOT=1

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║         Security Check — $(date '+%Y-%m-%d %H:%M:%S')          ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# ─────────────────────────────────────────────────────────────
echo "── 1. System Integrity ──────────────────────────────────"
if csrutil status 2>/dev/null | grep -q "enabled"; then
    ok "SIP is enabled"
else
    fail "SIP is DISABLED — critical"
fi

if spctl --status 2>/dev/null | grep -q "enabled"; then
    ok "Gatekeeper is enabled"
else
    warn "Gatekeeper is disabled"
fi

if fdesetup status 2>/dev/null | grep -q "On"; then
    ok "FileVault is ON"
else
    fail "FileVault is OFF — disk unprotected if physically accessed"
fi

if /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | grep -qiE "enabled|State = 1|State = 2"; then
    ok "macOS Application Firewall enabled"
else
    warn "macOS Application Firewall disabled"
fi

if /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null | grep -q "enabled"; then
    ok "Firewall stealth mode enabled"
else
    warn "Firewall stealth mode disabled (consider enabling)"
fi

# ─────────────────────────────────────────────────────────────
echo ""
echo "── 2. Network Defences ──────────────────────────────────"

# Tor
if pgrep -x tor &>/dev/null; then ok "Tor is running"; else warn "Tor is NOT running (brew services start tor)"; fi

# Unbound / DNS
DNS_SERVER=$(scutil --dns 2>/dev/null | awk '/nameserver/{print $3; exit}')
if pgrep -x unbound &>/dev/null; then ok "Unbound DNS resolver is running"; else fail "Unbound is NOT running — DNS unprotected"; fi
if [[ "$DNS_SERVER" == "127.0.0.1" || "$DNS_SERVER" == "::1" ]]; then
    ok "DNS routes through localhost (Unbound)"
else
    fail "DNS is NOT through localhost — pointing to $DNS_SERVER"
fi

# Little Snitch
if pgrep -ix "Little Snitch" &>/dev/null || pgrep -x "lsd" &>/dev/null; then
    ok "Little Snitch is running"
else
    warn "Little Snitch not detected"
fi

# LuLu
if pgrep -x "LuLu" &>/dev/null || pgrep -ix lulu &>/dev/null; then
    ok "LuLu firewall is running"
else
    warn "LuLu not detected"
fi

# PF anchor
if [[ $NEED_ROOT -eq 1 ]]; then
    RULE_COUNT=$(guard_run "pf-devports-rules" pfctl -a com.ew.devports -s rules 2>/dev/null | wc -l | tr -d ' ')
    if [[ "$RULE_COUNT" -gt 2 ]]; then
        ok "PF dev-port lockdown active ($RULE_COUNT rules)"
    else
        fail "PF dev-port anchor com.ew.devports not loaded (run: sudo setup-pf.sh)"
    fi
else
    info "(skip PF check — needs root)"
fi

# ClamAV
if pgrep -x clamd &>/dev/null || pgrep -x freshclam &>/dev/null; then
    ok "ClamAV daemon running"
else
    warn "ClamAV not running (brew services start clamav)"
fi

# ─────────────────────────────────────────────────────────────
echo ""
echo "── 3. 0.0.0.0 / External Binding Scan ──────────────────"

EXTERNAL_LISTENERS=0
while IFS= read -r line; do
    PROC=$(echo "$line" | awk '{print $1}')
    PID=$(echo  "$line" | awk '{print $2}')
    ADDR=$(echo "$line" | awk '{print $9}')
    PORT="${ADDR##*:}"

    case "$ADDR" in
        127.*|"[::1]"*|localhost*) continue ;;
        \*:*|0.0.0.0:*|\[:\:?\]:*) ;;
        *) continue ;;
    esac

    # Skip known macOS system listeners
    case "$PROC" in
        ControlCe|launchd|rapportd|mDNSRespo|symptomsd) continue ;;
    esac

    fail "EXTERNAL LISTENER: $PROC (pid $PID) on $ADDR"
    EXTERNAL_LISTENERS=$((EXTERNAL_LISTENERS + 1))
done < <(lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | tail -n +2)

[[ $EXTERNAL_LISTENERS -eq 0 ]] && ok "No processes bound to 0.0.0.0 / external interfaces"

echo ""
echo "── 4. Open Listening Ports ──────────────────────────────"
info "All TCP listeners:"
lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | tail -n +2 | awk '{printf "         %-20s %s\n", $1"("$2")", $9}' | sort -u

# ─────────────────────────────────────────────────────────────
echo ""
echo "── 5. .env Credential Files ─────────────────────────────"

ENV_ISSUES=0
while IFS= read -r envfile; do
    # %Op = octal permissions, e.g. 100600 → last 3 digits = 600
    PERMS_OCT=$(stat -L -f "%Op" "$envfile" 2>/dev/null | tail -c 4 | head -c 3)
    PERMS_SYM=$(stat -L -f "%Sp" "$envfile" 2>/dev/null)
    # Other (world) bits: octal digit 3  → chars 8-10 of symbolic
    # Group bits:         octal digit 2  → chars 5-7 of symbolic
    OTHER_BITS="${PERMS_OCT:2:1}"
    GROUP_BITS="${PERMS_OCT:1:1}"
    if [[ "$OTHER_BITS" != "0" ]]; then
        fail ".env world-readable: $envfile ($PERMS_SYM) — run: chmod 600 \"$envfile\""
        ENV_ISSUES=$((ENV_ISSUES + 1))
    elif [[ "$GROUP_BITS" != "0" ]]; then
        warn ".env group-readable: $envfile ($PERMS_SYM) — run: chmod 600 \"$envfile\""
        ENV_ISSUES=$((ENV_ISSUES + 1))
    else
        ok ".env permissions OK ($PERMS_SYM): $(basename "$(dirname "$envfile")")/$(basename "$envfile")"
    fi
    KEY_COUNT=$(grep -cE "^[A-Z_]+=.+" "$envfile" 2>/dev/null || true)
    info "$KEY_COUNT populated keys"
done < <(find "$HOME/Downloads" "$HOME/Library" -name ".env" -o -name ".env.local" \
    -o -name ".env.production" 2>/dev/null | grep -v node_modules | grep -v .venv)

[[ $ENV_ISSUES -eq 0 ]] && ok "All .env files have safe permissions"

# ─────────────────────────────────────────────────────────────
echo ""
echo "── 6. LaunchAgent / LaunchDaemon Audit ──────────────────"

KNOWN_AGENTS=(
    "at.obdev.littlesnitch.agent"
    "com.ai-orchestrator.backend"
    "com.ai-orchestrator.frontend"
    "com.donutintel.app"
    "com.ew.config-sentinel"
    "com.ew.rotate-mac"
    "com.google.GoogleUpdater.wake"
    "com.google.keystone.agent"
    "com.google.keystone.xpcservice"
    "com.user.ls-monitor"
    "homebrew.mxcl.tor"
)

KNOWN_DAEMONS=(
    "at.obdev.littlesnitch.daemon"
    "com.ew.rotate-hostname"
    "com.ew.pf-devports"
    "com.ew.binding-monitor"
    "com.ew.file-sentinel"
    "homebrew.mxcl.clamav"
    "homebrew.mxcl.freshclam"
    "homebrew.mxcl.unbound"
    "io.macfuse.app.launchservice.daemon"
    "org.wireshark.ChmodBPF"
)

# com.apple.* daemons that legitimately belong in /Library/LaunchDaemons
# (Apple ships system daemons in /System/Library, NOT here — anything with
# a com.apple.* label in /Library/LaunchDaemons is a red flag and must be
# explicitly listed here with a documented reason, or it will FAIL the audit)
KNOWN_APPLE_DAEMONS_IN_LIBRARY=(
    # none expected — this list should stay empty; add only with strong justification
)

UNKNOWN_FOUND=0
for plist in ~/Library/LaunchAgents/*.plist; do
    [[ -f "$plist" ]] || continue
    label=$(defaults read "$plist" Label 2>/dev/null || basename "$plist" .plist)
    known=0
    for k in "${KNOWN_AGENTS[@]}"; do [[ "$label" == "$k" ]] && known=1 && break; done
    if [[ $known -eq 0 ]]; then
        warn "UNKNOWN LaunchAgent: $label ($plist)"
        UNKNOWN_FOUND=$((UNKNOWN_FOUND + 1))
    fi
done
for plist in /Library/LaunchDaemons/*.plist; do
    [[ -f "$plist" ]] || continue
    label=$(defaults read "$plist" Label 2>/dev/null || basename "$plist" .plist)
    [[ "$label" == org.cups.* ]] && continue
    # com.apple.* in /Library/LaunchDaemons is a major red flag:
    # Apple ships its own daemons in /System/Library, never /Library.
    # Check against explicit allowlist; anything else is suspicious.
    if [[ "$label" == com.apple.* ]]; then
        known=0
        for k in ${KNOWN_APPLE_DAEMONS_IN_LIBRARY[@]+"${KNOWN_APPLE_DAEMONS_IN_LIBRARY[@]}"}; do [[ "$label" == "$k" ]] && known=1 && break; done
        if [[ $known -eq 0 ]]; then
            fail "IMPERSONATION RISK: com.apple.* label in /Library/LaunchDaemons: $label ($plist)"
            UNKNOWN_FOUND=$((UNKNOWN_FOUND + 1))
        fi
        continue
    fi
    known=0
    for k in "${KNOWN_DAEMONS[@]}"; do [[ "$label" == "$k" ]] && known=1 && break; done
    if [[ $known -eq 0 ]]; then
        warn "UNKNOWN LaunchDaemon: $label ($plist)"
        UNKNOWN_FOUND=$((UNKNOWN_FOUND + 1))
    fi
done
[[ $UNKNOWN_FOUND -eq 0 ]] && ok "All LaunchAgents/Daemons are known"

# ─────────────────────────────────────────────────────────────
echo ""
echo "── 7. Little Snitch Rule Quality ───────────────────────"

LS_CLI="/Applications/Little Snitch.app/Contents/Components/littlesnitch"
LS_RULES_FILE=~/.little-snitch-monitor/rules.txt
LS_ISSUES=0

if [[ -x "$LS_CLI" ]]; then
    RULES_TEXT=$("$LS_CLI" show-rules 2>/dev/null)
else
    RULES_TEXT=$(cat "$LS_RULES_FILE" 2>/dev/null)
fi

if [[ -z "$RULES_TEXT" ]]; then
    warn "Could not read Little Snitch rules"
else
    # Dangerous: nc/netcat allowed to "any" destination
    if echo "$RULES_TEXT" | grep -q "via: identifier.APPLE/com.apple.nc" && \
       echo "$RULES_TEXT" | grep -A5 "via: identifier.APPLE/com.apple.nc" | grep -q "destination: any"; then
        fail "DANGEROUS LS RULE: nc (netcat) allowed to destination:any — exfiltration risk"
        LS_ISSUES=$((LS_ISSUES + 1))
    else
        ok "No nc wildcard allow rules"
    fi

    # Check for 0.0.0.0 binding-related inbound rules
    if echo "$RULES_TEXT" | grep -q "direction: incoming"; then
        INBOUND=$(echo "$RULES_TEXT" | grep -c "direction: incoming")
        info "$INBOUND inbound rules found — review manually"
    fi

    # DENY rule count
    DENY_COUNT=$(echo "$RULES_TEXT" | grep -c "^action: deny" || true)
    ALLOW_COUNT=$(echo "$RULES_TEXT" | grep -c "^action: allow" || true)
    ok "LS rules: $ALLOW_COUNT allow, $DENY_COUNT deny"
fi

[[ $LS_ISSUES -eq 0 ]] && ok "No dangerous LS rule patterns found"

# ─────────────────────────────────────────────────────────────
echo ""
echo "── 8. SSH State ─────────────────────────────────────────"

AUTH_KEYS=~/.ssh/authorized_keys
if [[ ! -f "$AUTH_KEYS" ]] || [[ ! -s "$AUTH_KEYS" ]]; then
    ok "No SSH authorized_keys (no remote access possible)"
else
    fail "SSH authorized_keys EXISTS and is non-empty — review:"
    cat "$AUTH_KEYS"
fi

# com.openssh.ssh-agent is the keychain SSH key agent — normal and harmless.
# Only flag com.openssh.sshd or enabled Remote Login (the actual daemon).
if guard_run "launchctl-list" launchctl list 2>/dev/null | grep -q "com.openssh.sshd"; then
    warn "SSH daemon (sshd) is loaded — disable in System Settings → Sharing unless intentional"
elif sudo systemsetup -getremotelogin 2>/dev/null | grep -qi "on"; then
    warn "Remote Login (SSH) is ON in System Settings"
else
    ok "SSH daemon not running"
fi

# ─────────────────────────────────────────────────────────────
echo ""
echo "── 9. Certificates ──────────────────────────────────────"

ROGUE_CA=$(guard_run "security-find-certificate" security find-certificate -a -p /Library/Keychains/System.keychain 2>/dev/null | \
    openssl x509 -noout -subject 2>/dev/null | grep -v "com.apple\|Apple\|DigiCert\|Let's Encrypt\|GlobalSign")
if [[ -z "$ROGUE_CA" ]]; then
    ok "No unexpected CA certs in System.keychain"
else
    fail "UNEXPECTED CA CERT(S) in System.keychain — possible MITM proxy installed:"
    echo "$ROGUE_CA"
fi

# ─────────────────────────────────────────────────────────────
echo ""
echo "── 10. File Sentinel (kqueue) ───────────────────────────"

# BSM audit removed in macOS 26 Tahoe — file-sentinel now uses kqueue instead
SENTINEL_LOG="/var/log/file-sentinel.log"
SENTINEL_ERR="/var/log/file-sentinel-err.log"

if [[ -f "$SENTINEL_LOG" ]]; then
    # Check log was written within last 10 min (daemon is alive and running)
    LOG_MOD=$(stat -f "%m" "$SENTINEL_LOG" 2>/dev/null || echo 0)
    NOW_TS=$(date +%s)
    AGE=$(( NOW_TS - LOG_MOD ))
    if [[ $AGE -le 600 ]]; then
        ok "file-sentinel active (kqueue, log updated $AGE s ago)"
    else
        warn "file-sentinel log stale (${AGE}s old) — daemon may not be running"
    fi
else
    # No log yet — check if the LaunchDaemon plist is installed
    if [[ -f /Library/LaunchDaemons/com.ew.file-sentinel.plist ]]; then
        warn "file-sentinel daemon installed but not yet started — run: sudo launchctl bootstrap system /Library/LaunchDaemons/com.ew.file-sentinel.plist"
    else
        warn "file-sentinel not installed — run: sudo cp /Users/evw/dev/security/scripts/com.ew.file-sentinel.plist /Library/LaunchDaemons/ && sudo launchctl bootstrap system /Library/LaunchDaemons/com.ew.file-sentinel.plist"
    fi
fi

# Flag errors only if they are newer than the sentinel log itself (stale pre-restart errors are ignored)
if [[ -f "$SENTINEL_ERR" && -f "$SENTINEL_LOG" ]]; then
    ERR_MOD=$(stat -f "%m" "$SENTINEL_ERR" 2>/dev/null || echo 0)
    LOG_MOD=$(stat -f "%m" "$SENTINEL_LOG" 2>/dev/null || echo 0)
    if [[ $ERR_MOD -gt $LOG_MOD ]]; then
        ERR_COUNT=$(wc -l < "$SENTINEL_ERR" 2>/dev/null | tr -d ' ')
        [[ "$ERR_COUNT" -gt 0 ]] && warn "file-sentinel has recent error(s) in $SENTINEL_ERR"
    fi
fi

# ─────────────────────────────────────────────────────────────
echo ""
echo "── 11. Network Interfaces ───────────────────────────────"

# en0 = Wi-Fi, en1/en2/en5/en6 = Thunderbolt bridge / USB Ethernet (PROMISC is normal for these)
# Only flag en0 or unexpected PROMISC on the primary Wi-Fi adapter
PROMISC_UNEXPECTED=$(ifconfig 2>/dev/null | grep -B5 PROMISC | grep "^en" | awk -F: '{print $1}' | grep -v "^en[1-9][0-9]*" | grep "^en0")
PROMISC_ALL=$(ifconfig 2>/dev/null | grep -B5 PROMISC | grep "^en" | awk -F: '{print $1}' | tr '\n' ' ')
if [[ -n "$PROMISC_UNEXPECTED" ]]; then
    warn "Promiscuous mode on primary Wi-Fi (en0) — packet capture may be active"
elif [[ -n "$PROMISC_ALL" ]]; then
    ok "Promiscuous mode only on bridge/Thunderbolt adapters ($PROMISC_ALL) — normal"
else
    ok "No promiscuous interfaces"
fi

CURRENT_MAC=$(ifconfig en0 2>/dev/null | awk '/ether/{print $2}')
GW=$(netstat -rn 2>/dev/null | awk '/^default.*en0/{print $2}' | head -1)
info "MAC (en0): $CURRENT_MAC"
info "Gateway:   $GW"

# ─────────────────────────────────────────────────────────────
echo ""
echo "── 12. Config Sentinel (Credential & Claude File Integrity) ──"

BASELINE=~/.config-sentinel/baseline.sha256
CHANGE_LOG=~/.config-sentinel/changes.log

if [[ ! -f "$BASELINE" ]]; then
    warn "config-sentinel has no baseline — run: /Users/evw/dev/security/scripts/config-sentinel.sh --baseline"
else
    # Read the change log rather than running a new scan (avoids race with the LaunchAgent)
    RECENT_CHANGES=""
    if [[ -f "$CHANGE_LOG" ]]; then
        # Look for CHANGED/NEW/DELETED in the last 10 min (600 seconds)
        NOW=$(date +%s)
        while IFS= read -r line; do
            # Log format: [2026-05-12 11:48:01]   CHANGED  /path
            if echo "$line" | grep -qE "CHANGED|NEW|DELETED"; then
                # Extract timestamp from brackets
                LOG_TS=$(echo "$line" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}')
                if [[ -n "$LOG_TS" ]]; then
                    LOG_EPOCH=$(date -j -f "%Y-%m-%d %H:%M:%S" "$LOG_TS" +%s 2>/dev/null || echo 0)
                    AGE=$((NOW - LOG_EPOCH))
                    [[ $AGE -le 600 ]] && RECENT_CHANGES="${RECENT_CHANGES}
${line}"
                fi
            fi
        done < "$CHANGE_LOG"
    fi

    if [[ -n "$RECENT_CHANGES" ]]; then
        COUNT=$(echo "$RECENT_CHANGES" | grep -c "CHANGED\|NEW\|DELETED" || true)
        fail "config-sentinel: $COUNT change(s) in last 10 min"
        echo "$RECENT_CHANGES" | grep -E "CHANGED|NEW|DELETED" | while IFS= read -r l; do info "$l"; done
    else
        ok "config-sentinel: no changes to watched files (last 10 min)"
    fi

    if guard_run "launchctl-list" launchctl list 2>/dev/null | grep -q "com.ew.config-sentinel"; then
        ok "config-sentinel LaunchAgent loaded (scans every 5 min)"
    else
        warn "config-sentinel LaunchAgent not loaded — run: launchctl load -w ~/Library/LaunchAgents/com.ew.config-sentinel.plist"
    fi
fi

# ─────────────────────────────────────────────────────────────
echo ""
echo "── 13. CORS / API Config Check ──────────────────────────"

# Scan all main.py / app.py for wildcard CORS
CORS_ISSUES=0
while IFS= read -r pyfile; do
    if grep -q 'allow_origins.*\*\|allow_origins.*\["\\*"\]\|CORSMiddleware' "$pyfile" 2>/dev/null; then
        if grep -q 'allow_origins.*\["\\*"\]\|allow_origins=\["\\*"\]' "$pyfile" 2>/dev/null; then
            fail "Wildcard CORS in $pyfile — exploitable with allow_credentials=True"
            CORS_ISSUES=$((CORS_ISSUES + 1))
        else
            ok "CORS in $pyfile (not wildcard)"
        fi
    fi
done < <(find "$HOME/Downloads" -name "main.py" -o -name "app.py" 2>/dev/null | grep -v ".venv\|__pycache__")

[[ $CORS_ISSUES -eq 0 ]] && ok "No wildcard CORS configs found"

# ─────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
printf  "║  Summary: %3d OK  %3d warnings  %3d failures              ║\n" $PASS $WARN $FAIL
echo    "╚══════════════════════════════════════════════════════════╝"
echo ""

if [[ $FAIL -gt 0 ]]; then
    echo "  ACTION REQUIRED: fix the failures above."
    exit 1
elif [[ $WARN -gt 0 ]]; then
    echo "  Review the warnings above."
    exit 0
else
    echo "  All checks passed."
    exit 0
fi
