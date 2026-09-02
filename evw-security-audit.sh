#!/bin/bash
# evw-security-audit.sh — unattended security audit, runs at boot (root
# LaunchDaemon com.evw.security-audit) and at each login (user LaunchAgent
# com.evw.security-audit-login).
#
# User mode (login)  : hashes, posture, persistence, processes, network,
#                      kexts/sysexts, guards + user-TCC, summary line.
# Root mode (boot)   : all of the above + LS model export with the 4 rule
#                      analyses + system TCC audit (tcc-audit.sh).
#
# Output: scan-YYYY-MM-DD/ artifacts (same layout as the manual audits) plus
# one status line appended to logs/boot-audit.log. Debounced: a second run
# within 10 min (boot immediately followed by login) is a no-op.
#
# Install: sudo bash ~/dev/security/evw-security-audit-setup.sh
# Manual:  bash ~/dev/security/evw-security-audit.sh        (user subset)
#          sudo bash /usr/local/bin/evw-security-audit.sh   (full)

set -uo pipefail

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error-guard.sh)
# As root, only trust a root-owned lib (user-writable ancestor = privesc vector).
_eg_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
_eg_ok() { [ -f "$1" ] && { [ "$EUID" -ne 0 ] || [ "$(stat -f %u "$1" 2>/dev/null)" = "0" ]; }; }
while [ "$_eg_d" != "/" ] && ! _eg_ok "$_eg_d/lib/error-guard.sh"; do _eg_d="$(dirname "$_eg_d")"; done
_eg_ok "$_eg_d/lib/error-guard.sh" && . "$_eg_d/lib/error-guard.sh"; unset _eg_d; unset -f _eg_ok
command -v guard_run >/dev/null 2>&1 || guard_run() { shift; "$@"; }

SEC=/Users/evw/dev/security
DATE=$(date -u +%Y-%m-%d)
SCAN="$SEC/scan-$DATE"
LOGDIR="$SEC/logs"
STAMP=/var/tmp/evw-security-audit.last
DEBOUNCE=600   # seconds

# ── debounce (boot + login fire seconds apart) ───────────────────────────────
now=$(date +%s)
last=$(cat "$STAMP" 2>/dev/null || echo 0)
if [ $((now - last)) -lt $DEBOUNCE ]; then
    echo "$(date -Iseconds) skip (debounce: ran $((now - last))s ago)"
    exit 0
fi
echo "$now" > "$STAMP" 2>/dev/null || true

mkdir -p "$SCAN" "$LOGDIR"
MODE=user; [ "$EUID" -eq 0 ] && MODE=root
FINDINGS=0
note() { echo "$1"; FINDINGS=$((FINDINGS + 1)); }
info() { echo "$1"; }

# ── 1. file-integrity hashes + delta (their own script handles prev-scan diff)
guard_run "scan-hashes" bash "$SEC/scan-hashes.sh" "$SCAN" >/dev/null 2>&1 \
    && echo "[ok] hashes" || note "[!!] scan-hashes failed"

# ── 2. posture ───────────────────────────────────────────────────────────────
{
    echo "# posture — $(date -u +%Y-%m-%dT%H:%M:%SZ) [$MODE]"
    csrutil status 2>&1
    fdesetup status 2>&1
    /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>&1
    /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>&1
    spctl --status 2>&1
} > "$SCAN/posture.txt" 2>&1
csrutil status 2>/dev/null | grep -q enabled || note "[!!] SIP not enabled"
fdesetup status 2>/dev/null | grep -q "FileVault is On" || note "[!!] FileVault off"
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null \
    | grep -q "State = 2" || note "[!!] firewall not in block-all mode"

# ── 3. persistence + processes + network ─────────────────────────────────────
{
    echo "# persistence — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    ls -la /Users/evw/Library/LaunchAgents/ /Library/LaunchAgents/ /Library/LaunchDaemons/ 2>&1
} > "$SCAN/persistence.txt" 2>&1
ps auxww > "$SCAN/processes.txt" 2>&1
{
    echo "# network — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "== DNS =="; scutil --dns 2>&1 | grep -E "nameserver\[" | sort -u
    echo "== routes =="; netstat -rn -f inet 2>&1 | head -4
    echo "== listeners =="; lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null
    echo "== utun =="; for u in $(ifconfig -l | tr ' ' '\n' | grep '^utun'); do ifconfig "$u" 2>/dev/null | grep -E "^$u|inet "; done
} > "$SCAN/network-state.txt" 2>&1
# listeners: anything bound to a non-loopback address is a finding
lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | grep -vE "127\.0\.0\.1|\[::1\]|^COMMAND" \
    | grep -q . && note "[!!] non-loopback TCP listener — see network-state.txt"

# ── 4. kexts / sysexts ───────────────────────────────────────────────────────
{
    kmutil showloaded 2>/dev/null | grep -viE "com\.apple|^Index" || true
    systemextensionsctl list 2>&1
} > "$SCAN/kexts-sysexts.txt" 2>&1

# ── 5. guarded processes must not accumulate ─────────────────────────────────
pgrep -q replayd && note "[!!] replayd RUNNING (guard should have killed it)"
pgrep -q studentd && info "[..] studentd alive at audit time (guard reaps ≤5 min — routine)"

# ── 6. user TCC (screen/accessibility/listen/post) ───────────────────────────
TCCROWS=$(sqlite3 "/Users/evw/Library/Application Support/com.apple.TCC/TCC.db" \
    "SELECT COUNT(*) FROM access WHERE service IN ('kTCCServiceScreenCapture','kTCCServiceAccessibility','kTCCServiceListenEvent','kTCCServicePostEvent') AND auth_value=2;" 2>/dev/null || echo "?")
[ "$TCCROWS" = "0" ] || note "[!!] sensitive TCC grants present (count=$TCCROWS)"

# ── 7. root-only: LS export + 4 analyses, system TCC ─────────────────────────
LSCLI="/Applications/Little Snitch.app/Contents/Components/littlesnitch"
if [ "$MODE" = root ]; then
    if guard_run "ls-export" "$LSCLI" export-model "$SCAN/ls-model.json" 2>/dev/null; then
        python3 "$SEC/ls-full-analysis.py" "$SCAN/ls-model.json" \
            > "$SCAN/ls-full-analysis.txt" 2>&1 || note "[!!] ls-full-analysis failed"
        python3 "$SEC/ls-domain-audit.py" "$SCAN/ls-model.json" \
            > "$SCAN/ls-domain-audit.txt" 2>&1 || true
        python3 "$SEC/ls-permissive-analysis.py" "$SCAN/ls-model.json" \
            > "$SCAN/ls-permissive-analysis.txt" 2>&1 || true
        python3 "$SEC/scan-2026-08-10/ls-rules-deep-audit.py" "$SCAN/ls-model.json" \
            "$SCAN/ls-rules-deep-audit.txt" >/dev/null 2>&1 || true
        grep -q "❌ MISSING" "$SCAN/ls-full-analysis.txt" \
            && note "[!!] LS critical deny rules MISSING — ls-full-analysis.txt"
        grep -q "ALL CRITICAL DENY RULES PRESENT" "$SCAN/ls-full-analysis.txt" \
            && echo "[ok] LS critical denies"
    else
        note "[!!] LS export-model failed (CLI access disabled?)"
    fi
    guard_run "tcc-audit" bash "$SEC/tcc-audit.sh" "$SCAN" >/dev/null 2>&1 || true
    # keep the user's repo user-owned
    chown -R evw:staff "$SCAN" 2>/dev/null || true
fi

# ── summary ──────────────────────────────────────────────────────────────────
LINE="$(date -Iseconds) [$MODE] findings=$FINDINGS scan=$SCAN"
echo "$LINE" >> "$LOGDIR/boot-audit.log"
[ "$MODE" = root ] && chown evw:staff "$LOGDIR/boot-audit.log" 2>/dev/null || true
echo "$LINE"
[ "$FINDINGS" -gt 0 ] && echo "review: $SCAN (and logs/boot-audit.log)"
exit 0
