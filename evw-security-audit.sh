#!/bin/bash
# evw-security-audit.sh — unattended security audit, runs at boot (root
# LaunchDaemon com.evw.security-audit) and at each login (user LaunchAgent
# com.evw.security-audit-login).
#
# User mode (login)  : hashes (ALL brew/local/app binaries + plists), posture,
#                      persistence, processes, network, kexts/sysexts, guards,
#                      log-doctor (security-log abnormality scan) + user-TCC.
# Root mode (boot)   : all of the above + LS model export with the 4 rule
#                      analyses + system TCC audit (tcc-audit.sh) + full
#                      evw-integrity sweep (tiers A-D = every covered file) +
#                      log-doctor auto-remediation. Every helper executed in
#                      this mode is a root-owned copy under /usr/local/bin.
#
# Output: scan-YYYY-MM-DD/ artifacts (same layout as the manual audits) plus
# one status line appended to logs/boot-audit.log. Debounce applies only to
# --auto runs (boot immediately followed by login); manual runs always scan.
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

# ── debounce — AUTOMATED invocations only ────────────────────────────────────
# The boot LaunchDaemon and login LaunchAgent fire seconds apart; --auto is
# what they pass, and only --auto is debounced. Every manual/menu invocation
# runs a real scan, every time. Previously any run within 10 min of another
# exited 0 after one line, so callers (menu, user) saw the STALE previous
# scan reported as a fresh clean result (2026-09-28 + 2026-10-01 complaints).
now=$(date +%s)
last=$(cat "$STAMP" 2>/dev/null || echo 0)
if [[ "${1:-}" == "--auto" && $((now - last)) -lt $DEBOUNCE ]]; then
    echo "$(date -Iseconds) SKIP (debounce: auto run $((now - last))s after the previous run — NO SCAN PERFORMED)"
    exit 0
fi
# World-writable stamp: boot (root) and login (user) runs share this file;
# 0666 lets either EUID rewrite it — otherwise the loser never debounces and
# concurrent audits can race the scan artifacts.
{ echo "$now" > "$STAMP" && chmod 666 "$STAMP"; } 2>/dev/null || true

mkdir -p "$SCAN" "$LOGDIR"
MODE=user; [ "$EUID" -eq 0 ] && MODE=root
HELPERS="$SEC"
if [ "$MODE" = root ]; then
    HELPERS=/usr/local/bin
    for tool in scan-hashes.sh evw-log-doctor.py ls-full-analysis.py \
                ls-domain-audit.py ls-permissive-analysis.py \
                ls-rules-deep-audit.py tcc-audit.sh; do
        if [ ! -x "$HELPERS/$tool" ] \
            || [ "$(stat -f %u "$HELPERS/$tool" 2>/dev/null)" != 0 ] \
            || [ "$(stat -f %Lp "$HELPERS/$tool" 2>/dev/null)" != 755 ]; then
            echo "ERROR: unsafe/missing root helper $HELPERS/$tool — rerun evw-security-audit-setup.sh" >&2
            exit 1
        fi
    done
fi
FINDINGS=0
note() { echo "$1"; FINDINGS=$((FINDINGS + 1)); echo "$1" >> "$SCAN/findings.txt"; }
info() { echo "$1"; }

# ── 1. file-integrity hashes + delta (their own script handles prev-scan diff)
guard_run "scan-hashes" env EVW_SECURITY_DIR="$SEC" bash "$HELPERS/scan-hashes.sh" "$SCAN" >/dev/null 2>&1 \
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

# ── 4b. deployment drift — repo vs /usr/local/bin ────────────────────────────
# The boot/login daemons run the /usr/local/bin copies; a repo fix that never
# gets deployed leaves the running system vulnerable (the 2026-10-21 integrity
# drift: fixed code sat undeployed while the daemon crash-looped). Flag every
# deployed evw-* file whose repo counterpart differs.
for f in /usr/local/bin/evw-*; do
    [ -f "$f" ] || continue
    b=$(basename "$f")
    [ -f "$SEC/$b" ] || continue
    cmp -s "$SEC/$b" "$f" \
        || note "[!!] deployed /usr/local/bin/$b differs from repo — re-run its install/setup"
done
if [ -f /usr/local/lib/error-guard.sh ] && [ -f "$SEC/lib/error-guard.sh" ]; then
    cmp -s "$SEC/lib/error-guard.sh" /usr/local/lib/error-guard.sh \
        || note "[!!] deployed /usr/local/lib/error-guard.sh differs from repo"
fi

# ── 4c. change control — uncommitted security-toolkit edits ──────────────────
# Security tooling is change-controlled (2026-10-20 lesson: an AI session left
# an uncommitted ls-sentinel-deny.py edit). Uncommitted = unaudited.
if git -C "$SEC" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    DIRTY=$(git -C "$SEC" status --porcelain --untracked-files=no 2>/dev/null)
    if [ -n "$DIRTY" ]; then
        note "[!!] uncommitted changes in security toolkit — commit or revert: $(echo "$DIRTY" | head -3 | awk '{print $2}' | paste -sd, -)"
    fi
fi

# ── 5. guarded processes must not accumulate ─────────────────────────────────
# replayd respawns constantly and (since 2026-09-28) the guard lets each
# instance live GRACE=20s so the Screenshot tool works, then kills it. Flag
# only when an instance is older than 40s (grace + guard interval + margin) —
# that means the guard is not reaping. (macOS ps has etime, not etimes.)
pid_age_s() {
    local et d=0 h=0 m=0 s=0
    et=$(ps -p "$1" -o etime= 2>/dev/null | tr -d ' ')
    [ -n "$et" ] || return 1
    case "$et" in *-*) d=${et%%-*}; et=${et#*-} ;; esac
    case "$et" in
        *:*:*) IFS=: read -r h m s <<< "$et" ;;
        *:*)   IFS=: read -r m s <<< "$et" ;;
        *)     s=$et ;;
    esac
    echo $(( 10#$d * 86400 + 10#${h:-0} * 3600 + 10#${m:-0} * 60 + 10#${s:-0} ))
}
RPID=$(pgrep -x replayd | head -1)
if [ -n "$RPID" ]; then
    RAGE=$(pid_age_s "$RPID")
    if [ -n "$RAGE" ] && [ "$RAGE" -gt 40 ]; then
        note "[!!] replayd PID=$RPID alive ${RAGE}s — beyond guard grace (20s), guard not reaping?"
    else
        info "[..] replayd PID=$RPID age ${RAGE:-?}s within guard grace window (≤20s cap — routine)"
    fi
fi
pgrep -q studentd && info "[..] studentd alive at audit time (guard reaps ≤5 min — routine)"

# ── 5b. wazuh agent (if installed) ───────────────────────────────────────────
if pkgutil --pkg-info com.wazuh.pkg.wazuh-agent >/dev/null 2>&1; then
    pgrep -qf wazuh-agentd && info "[ok] wazuh agent running" \
        || note "[!!] wazuh agent installed but wazuh-agentd NOT running"
    pgrep -qf evw-wazuh-guard.sh \
        || note "[!!] wazuh keep-alive guard missing (run evw-wazuh-setup.sh)"
    pgrep -qf evw-wazuh-monitor.py \
        || note "[!!] wazuh log monitor missing (run evw-wazuh-setup.sh)"
fi

# ── 5c. security-log doctor — every scan checks the security logs ────────────
# New-content scan of all evw-* logs for tracebacks / recurring error
# signatures / spam storms. Root mode auto-remediates: rotates oversized err
# logs, restarts a crash-looping daemon once per signature per 24h, and posts
# a CRITICAL alert when a failure persists (alert-center picks it up).
# Lesson of 2026-10-20/21: integrity crash-looped 20h and ls-watchdog logged
# fake failures for weeks — both invisible because nobody read the err logs.
LOGDOC_ARGS=(--scan-dir "$SCAN")
[ "$MODE" = root ] && LOGDOC_ARGS+=(--root)
LOGDOC_SUM=$(guard_run "log-doctor" python3 "$HELPERS/evw-log-doctor.py" "${LOGDOC_ARGS[@]}" 2>&1 | tail -1)
echo "$LOGDOC_SUM"
case "$LOGDOC_SUM" in
    *abnormalities=[1-9]*) note "[!!] security-log abnormalities — see log-doctor-report.txt" ;;
esac

# ── 6. user TCC (screen/accessibility/listen/post) ───────────────────────────
# TCC.db is FDA-protected even for root; the signed helper holds the FDA grant
# (scoped to this one read). Direct sqlite3 only works from FDA'd shells.
TCC_READER=/usr/local/bin/evw-tcc-reader
if [ -x "$TCC_READER" ] && TCCOUT=$("$TCC_READER" user 2>/dev/null); then
    TCCROWS=$(printf '%s\n' "$TCCOUT" | awk -F'|' \
        '$1 ~ /kTCCService(ScreenCapture|Accessibility|ListenEvent|PostEvent)/ && $4==2' | wc -l | tr -d ' ')
else
    TCCROWS=$(sqlite3 "/Users/evw/Library/Application Support/com.apple.TCC/TCC.db" \
        "SELECT COUNT(*) FROM access WHERE service IN ('kTCCServiceScreenCapture','kTCCServiceAccessibility','kTCCServiceListenEvent','kTCCServicePostEvent') AND auth_value=2;" 2>/dev/null || echo "?")
fi
if [ "$TCCROWS" = "?" ]; then
    info "[..] user TCC db unreadable (no FDA on helper/shell) — interactive check 2026-09-08: 0 sensitive grants"
elif [ "$TCCROWS" != "0" ]; then
    note "[!!] sensitive TCC grants present (count=$TCCROWS)"
fi

# ── 7. root-only: LS export + 4 analyses, system TCC ─────────────────────────
LSCLI="/Applications/Little Snitch.app/Contents/Components/littlesnitch"
if [ "$MODE" = root ]; then
    if guard_run "ls-export" "$LSCLI" export-model "$SCAN/ls-model.json" 2>/dev/null; then
        python3 "$HELPERS/ls-full-analysis.py" "$SCAN/ls-model.json" \
            > "$SCAN/ls-full-analysis.txt" 2>&1 || note "[!!] ls-full-analysis failed"
        python3 "$HELPERS/ls-domain-audit.py" "$SCAN/ls-model.json" \
            > "$SCAN/ls-domain-audit.txt" 2>&1 || true
        python3 "$HELPERS/ls-permissive-analysis.py" "$SCAN/ls-model.json" \
            > "$SCAN/ls-permissive-analysis.txt" 2>&1 || true
        python3 "$HELPERS/ls-rules-deep-audit.py" "$SCAN/ls-model.json" \
            "$SCAN/ls-rules-deep-audit.txt" >/dev/null 2>&1 || true
        grep -q "❌ MISSING" "$SCAN/ls-full-analysis.txt" \
            && note "[!!] LS critical deny rules MISSING — ls-full-analysis.txt"
        grep -q "ALL CRITICAL DENY RULES PRESENT" "$SCAN/ls-full-analysis.txt" \
            && echo "[ok] LS critical denies"
    else
        note "[!!] LS export-model failed (CLI access disabled?)"
    fi
    # Root-owned copies only: the Homebrew Lynis tree and /Applications copy of
    # KnockKnock are user-writable and must never be executed by this root job.
    LYNIS=/usr/local/opt/lynis/bin/lynis
    if [ -x "$LYNIS" ] && [ "$(stat -f %u "$LYNIS" 2>/dev/null)" = 0 ]; then
        (cd /usr/local/opt/lynis && ./bin/lynis audit system --quick --no-colors \
            --usecwd --plugindir /usr/local/opt/lynis/plugins \
            --log-file "$SCAN/lynis.log" --report-file "$SCAN/lynis-report.dat") \
            >/dev/null 2>&1 && info "[ok] lynis" || note "[!!] lynis failed"
    else
        note "[!!] root-owned Lynis copy missing — rerun evw-security-audit-setup.sh"
    fi
    KK="/usr/local/libexec/KnockKnock.app/Contents/MacOS/KnockKnock"
    if [ -x "$KK" ] && [ "$(stat -f %u "$KK" 2>/dev/null)" = 0 ]; then
        "$KK" -whosthere -skipVT > "$SCAN/knockknock.json" 2>/dev/null \
            && info "[ok] knockknock" || note "[!!] knockknock failed"
    else
        note "[!!] root-owned KnockKnock copy missing — rerun evw-security-audit-setup.sh"
    fi
    guard_run "tcc-audit" bash "$HELPERS/tcc-audit.sh" "$SCAN" >/dev/null 2>&1 || true

    # ── 7b. full integrity sweep — every covered file, every scan (tiers A-D) ─
    # /usr/local/bin, launchd, /etc, LS_CONFIG (A) · /Applications, /opt/homebrew,
    # SEC_DIR, /Library/Frameworks, PrivilegedHelperTools (B) · /Library,
    # ~/Library/Preferences (C) · HOME (D; caches/node_modules excluded).
    # Commits a new baseline each run and lists anything outside auto-heal
    # scope as AWAITING APPROVAL in integrity-full.txt.
    if [ -x /usr/local/bin/evw-integrity.py ]; then
        guard_run "integrity-full" /usr/local/bin/evw-integrity.py full --tiers A,B,C,D \
            --report "$SCAN/integrity-full.txt" >/dev/null 2>&1 \
            && echo "[ok] integrity full sweep (all files)" \
            || note "[!!] integrity full sweep failed"
        grep -q '!!! INCIDENT' "$SCAN/integrity-full.txt" 2>/dev/null \
            && note "[!!] integrity MASS-CHANGE incident — integrity-full.txt"
        # G6: an ever-growing unreviewed backlog defeats the baseline
        AWAIT=$(awk '/AWAITING APPROVAL/{f=1;next} f&&/^  \//{n++} f&&/^$/{exit} END{print n+0}' \
            "$SCAN/integrity-full.txt" 2>/dev/null)
        [ "${AWAIT:-0}" -gt 50 ] \
            && note "[!!] integrity: $AWAIT paths awaiting approval (>50) — review: evw-rollback.py restore --all --dry-run"
    fi

    # ── 7c. macOS patch currency (weekly) ────────────────────────────────────
    # softwareupdate was unreachable 2026-10-20 (security-stack interference
    # suspected) and no job watched patch level. Weekly root check, 180s cap.
    SW_STAMP=/var/tmp/evw-swupdate-check.last
    SW_LAST=$(cat "$SW_STAMP" 2>/dev/null || echo 0)
    NOW_S=$(date +%s)
    if [ $((NOW_S - SW_LAST)) -gt 604800 ]; then
        echo "$NOW_S" > "$SW_STAMP" 2>/dev/null && chmod 666 "$SW_STAMP" 2>/dev/null || true
        if guard_run "swupdate" python3 -c "
import subprocess, sys
try:
    r = subprocess.run(['softwareupdate', '-l'], capture_output=True, text=True, timeout=180)
    open('$SCAN/macos-updates.txt', 'w').write(r.stdout + r.stderr)
    sys.exit(0 if r.returncode == 0 else 1)
except Exception as e:
    open('$SCAN/macos-updates.txt', 'w').write('check failed: %r' % e)
    sys.exit(1)"; then
            grep -qi 'No new software available' "$SCAN/macos-updates.txt" \
                && info "[ok] macOS up to date" \
                || note "[!!] macOS updates pending — macos-updates.txt"
        else
            info "[..] softwareupdate check failed/blocked — macos-updates.txt"
        fi
    fi
    # keep the user's repo user-owned
    chown -R evw:staff "$SCAN" 2>/dev/null || true
fi

# ── summary ──────────────────────────────────────────────────────────────────
LINE="$(date -Iseconds) [$MODE] findings=$FINDINGS scan=$SCAN"
echo "$LINE" >> "$LOGDIR/boot-audit.log"
[ "$MODE" = root ] && chown evw:staff "$LOGDIR/boot-audit.log" 2>/dev/null || true
echo "$LINE"
[ "$MODE" = user ] && [ "$FINDINGS" -gt 0 ] \
    && info "[..] user mode: root-only checks skipped (system TCC, root err logs, integrity store) — boot audit covers those"
ARTIFACTS=$(ls "$SCAN" 2>/dev/null | wc -l | tr -d ' ')
echo "scan complete: $ARTIFACTS artifacts written to $SCAN [mode=$MODE]"
[ "$FINDINGS" -gt 0 ] && echo "review: $SCAN (and logs/boot-audit.log)"

# ── G1: findings must reach a human, not just a log file ─────────────────────
# Root mode: alert-center contract JSON (GUI alert until acked). User mode:
# osascript desktop notification (can't write the root-owned alerts dir).
if [ "$FINDINGS" -gt 0 ]; then
    if [ "$MODE" = root ]; then
        ALERTS_DIR=/var/db/evw-security-system/alerts
        mkdir -p "$ALERTS_DIR" 2>/dev/null \
            && guard_run "audit-alert" python3 -c "
import json, os, sys, time
d = '$ALERTS_DIR'
aid = 'audit-%d' % int(time.time())
body = open('$SCAN/findings.txt').read()[:4000] if os.path.exists('$SCAN/findings.txt') else 'see $SCAN'
doc = {'id': aid, 'ts': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
       'severity': 'WARNING',
       'title': 'security audit: $FINDINGS finding(s) — review $SCAN'[:80],
       'body': body, 'source': 'evw-security-audit', 'persist': True}
tmp = os.path.join(d, '.' + aid + '.tmp')
open(tmp, 'w').write(json.dumps(doc))
os.replace(tmp, os.path.join(d, aid + '.json'))
os.chmod(os.path.join(d, aid + '.json'), 0o644)  # alert-center (user evw) must read it
print('alert posted:', aid)" \
            && echo "[✓] alert posted to alert-center" || echo "[!] alert posting failed" >&2
    else
        osascript -e "display notification \"$FINDINGS finding(s) — review $(basename "$SCAN")\" with title \"evw security audit\" sound name \"Basso\"" \
            >/dev/null 2>&1 || true
    fi
fi
exit 0
