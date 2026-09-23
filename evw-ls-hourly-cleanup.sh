#!/bin/bash
# evw-ls-hourly-cleanup.sh — full Little Snitch ruleset cleanup, every hour.
#
# LaunchDaemon: com.evw.ls-hourly-cleanup (root, StartInterval=3600, one-shot).
# The 5-min ls-hygiene-guard and 10-min ls-watchdog handle narrow tactical
# hygiene; this job runs the FULL manual cleanup chain unattended so rules
# that re-accumulate between audits are re-normalized within the hour:
#
#   1. export-model (live — never a stale snapshot)
#   2. ls-dedup.py             duplicate rules out
#   3. ls-tighten-all.py       guarded-daemon denies, monitor-unused prune,
#                              stale-binary prune, browser/Terminal tcp:443
#   4. ls-security-rescan.py   tracker/posture denies, tracker allows out,
#                              any-remote suggestions out, specific-host 443
#   5. ls-hole-audit.py        any-remote untrusted allows out, guarded-process
#                              allows out, critical denies replanted
#   6. restore-model ONLY if the ruleset actually changed (no-op cycles cost
#      nothing; restores briefly interrupt flows)
#   7. verify critical denies post-import; alert in the log if any missing
#
# Safety: pre-change backup + per-run undo + reports kept in /var/log/mac-sentinel/
# (last 30 backups), every applied run appended to AUTO-ACTIONS.md. Only
# root-owned transforms under /usr/local/bin are executed (privesc hygiene).
# Rules created by LS alerts during the export→restore window are dropped on
# restore — same accepted window as the manual apply scripts and the 5-min
# hygiene guard; the window here is seconds.
#
# Install: sudo bash ~/dev/security/evw-ls-hourly-cleanup-setup.sh

set -uo pipefail
umask 077

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error-guard.sh)
# As root, only trust a root-owned lib (user-writable ancestor = privesc vector).
_eg_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
_eg_ok() { [ -f "$1" ] && { [ "$EUID" -ne 0 ] || [ "$(stat -f %u "$1" 2>/dev/null)" = "0" ]; }; }
while [ "$_eg_d" != "/" ] && ! _eg_ok "$_eg_d/lib/error-guard.sh"; do _eg_d="$(dirname "$_eg_d")"; done
_eg_ok "$_eg_d/lib/error-guard.sh" && . "$_eg_d/lib/error-guard.sh"; unset _eg_d; unset -f _eg_ok
command -v guard_run >/dev/null 2>&1 || guard_run() { shift; "$@"; }
# EVW_GUARD_POLICY unset: launchd one-shot — a tripped breaker aborts (no TTY).

LSCLI="/Applications/Little Snitch.app/Contents/Components/littlesnitch"
BIN=/usr/local/bin
LOG=/private/var/log/evw-ls-hourly-cleanup.log
LOGDIR=/var/log/mac-sentinel
REPORTS=/Users/evw/dev/security/security-system/reports

mkdir -p "$LOGDIR" "$REPORTS"
log() { printf '[%s] %s\n' "$(date -Iseconds)" "$*" >> "$LOG"; }

# Log rotation: keep last 2 MB
if [[ -f "$LOG" ]] && (( $(wc -c < "$LOG") > 2097152 )); then
    guard_run "log-rotate" mv "$LOG" "${LOG}.1"
fi

log "--- hourly cleanup tick ---"

if [[ ! -x "$LSCLI" ]]; then
    log "ERROR: Little Snitch CLI not found at $LSCLI"
    exit 1
fi
for t in ls-dedup.py ls-tighten-all.py ls-security-rescan.py ls-hole-audit.py; do
    if [[ ! -x "$BIN/$t" ]]; then
        log "ERROR: $BIN/$t missing — run evw-ls-hourly-cleanup-setup.sh"
        exit 1
    fi
done

WORK=$(mktemp -d /var/tmp/ls-hourly.XXXXXXXX) || exit 1
trap 'rm -rf "$WORK"' EXIT

if ! guard_run "ls-export" "$LSCLI" export-model "$WORK/pre.json" 2>>"$LOG"; then
    log "ERROR: export-model failed (LS CLI access disabled?)"
    exit 1
fi
IN=$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["rules"]))' "$WORK/pre.json" 2>/dev/null || echo "?")

guard_run "dedup"   /usr/bin/python3 "$BIN/ls-dedup.py" \
    "$WORK/pre.json" "$WORK/step1.json" >>"$LOG" 2>&1
guard_run "tighten" /usr/bin/python3 "$BIN/ls-tighten-all.py" \
    "$WORK/step1.json" "$WORK/step2.json" --report "$WORK/report-tighten.txt" >>"$LOG" 2>&1
guard_run "rescan"  /usr/bin/python3 "$BIN/ls-security-rescan.py" \
    "$WORK/step2.json" "$WORK/step3.json" --report "$WORK/report-rescan.txt" >>"$LOG" 2>&1
cp "$WORK/step3.json" "$WORK/final.json"
guard_run "hole-audit" /usr/bin/python3 "$BIN/ls-hole-audit.py" \
    "$WORK/final.json" --apply --report "$WORK/report-holes.md" \
    --undo "$WORK/undo.json" >>"$LOG" 2>&1

for f in step1.json step2.json step3.json final.json; do
    if [[ ! -s "$WORK/$f" ]]; then
        log "ERROR: transform chain broke at $f — live model untouched"
        exit 1
    fi
done

CHANGED=$(python3 - "$WORK/pre.json" "$WORK/final.json" <<'EOF'
import json, sys
a = json.load(open(sys.argv[1])).get("rules", [])
b = json.load(open(sys.argv[2])).get("rules", [])
print("YES" if a != b else "NO")
EOF
)
OUT=$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["rules"]))' "$WORK/final.json" 2>/dev/null || echo "?")

if [[ "$CHANGED" != "YES" ]]; then
    log "clean: rules=$IN — no changes needed"
    exit 0
fi

TS=$(date +%Y%m%d-%H%M%S)
cp "$WORK/pre.json" "$LOGDIR/ls-model-pre-hourly-$TS.json"
cp "$WORK/undo.json" "$LOGDIR/ls-hourly-undo-$TS.json" 2>/dev/null || true
for r in report-tighten.txt report-rescan.txt report-holes.md; do
    [[ -f "$WORK/$r" ]] || continue
    dst="$REPORTS/ls-hourly-${r#report-}-$TS"
    [[ "$r" == *.txt ]] && dst="${dst%.md}.txt" || dst="$dst"
    cp "$WORK/$r" "$dst" 2>/dev/null || true
done

if ! guard_run "ls-restore" "$LSCLI" restore-model "$WORK/final.json" 2>>"$LOG"; then
    log "ERROR: restore-model failed — live model unchanged. Backup: $LOGDIR/ls-model-pre-hourly-$TS.json"
    exit 1
fi
log "APPLIED: rules $IN -> $OUT (backup ls-model-pre-hourly-$TS.json)"
printf '%s [AUTO-EVW-LS] hourly cleanup applied: rules %s -> %s undo=%s\n' \
    "$(date -Iseconds)" "$IN" "$OUT" "$LOGDIR/ls-hourly-undo-$TS.json" \
    >> "$LOGDIR/AUTO-ACTIONS.md"

# Verify: re-export and confirm critical denies survived
if guard_run "ls-export-verify" "$LSCLI" export-model "$WORK/verify.json" 2>>"$LOG"; then
    MISSING=$(python3 - "$WORK/verify.json" <<'EOF'
import json, sys
rules = json.load(open(sys.argv[1])).get("rules", [])
procs = ["apsd", "sharingd", "replicatord", "screensharingd", "replayd",
         "remotemanagementd", "studentd", "launchctl", "privatecloudcomputed"]
domains = ["gator.volces.com", "apmplus.volces.com",
           "apmplus.ap-southeast-1.volces.com", "tab.volces.com",
           "queniuck.com", "tiktok.com", "bytedance.com", "zohopublic.com"]
missing = []
for p in procs:
    if not any(r.get("action") == "deny" and p in str(r.get("process", "")) for r in rules):
        missing.append("process:" + p)
for d in domains:
    if not any(r.get("action") == "deny" and d in str(r.get("remote-domains", "")) for r in rules):
        missing.append("domain:" + d)
print("\n".join(missing))
EOF
)
    if [[ -n "$MISSING" ]]; then
        log "ALERT: critical denies MISSING after cleanup restore:"$'\n'"$MISSING"
        printf '%s [AUTO-EVW-LS] hourly cleanup ALERT: missing critical denies: %s\n' \
            "$(date -Iseconds)" "$(echo "$MISSING" | tr '\n' ' ')" \
            >> "$LOGDIR/AUTO-ACTIONS.md"
        exit 1
    fi
    log "verified: all critical denies present"
fi

# prune old backups, keep last 30
ls -t "$LOGDIR"/ls-model-pre-hourly-*.json 2>/dev/null | tail -n +31 | xargs rm -f 2>/dev/null
chown -R evw:staff "$REPORTS" 2>/dev/null || true
log "--- tick done ---"
