#!/usr/bin/env bash
# =============================================================================
# tests/test-integrity.sh — user-space round-trip tests for evw-integrity +
# evw-rollback. No root needed: fixture tree + store live under /tmp.
#
#   bash /Users/evw/dev/security/tests/test-integrity.sh
#
# Flow: init → seed sweep (tagged "seed") → tamper → detection + unified
# diffs → rollback --since seed (re-baselines store) → heal round-trips
# (NEW quarantine, CHANGED restore, REMOVED restore) → deploy window →
# full rollback --all --since seed → clean sweep → verify.
# =============================================================================

set -uo pipefail

T=/tmp/evw-integrity-test
ROOT="$T/root"
STORE="$T/store"
PY=/usr/bin/python3
INT=/Users/evw/dev/security/evw-integrity.py
RBK=/Users/evw/dev/security/evw-rollback.py
PASS=0; FAIL=0

export EVW_INTEGRITY_TIERS="{\"A\": [\"$ROOT/Library/LaunchDaemons\", \"$ROOT/usr/local/bin\", \"$ROOT/private/etc\", \"$ROOT/Applications\"]}"
export EVW_INTEGRITY_HEAL="[\"$ROOT/Library/LaunchDaemons\", \"$ROOT/usr/local/bin\", \"$ROOT/private/etc\"]"

check() {
    if eval "$2"; then echo "  [PASS] $1"; PASS=$((PASS+1));
    else echo "  [FAIL] $1"; FAIL=$((FAIL+1)); fi
}

echo "== fixture =="
rm -rf "$T"
mkdir -p "$ROOT/Library/LaunchDaemons" "$ROOT/usr/local/bin" "$ROOT/private/etc" "$ROOT/Applications"
cat > "$ROOT/Library/LaunchDaemons/com.test.daemon.plist" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>Label</key><string>com.test.daemon</string></dict></plist>
EOF
printf '#!/bin/bash\necho evw-test-tool v1\n' > "$ROOT/usr/local/bin/evw-test-tool.sh"
chmod 755 "$ROOT/usr/local/bin/evw-test-tool.sh"
printf '127.0.0.1 localhost\n::1 localhost\n' > "$ROOT/private/etc/hosts"
printf 'fake-app-content-v1\n' > "$ROOT/Applications/fake.bin"

echo "== 1. init + seed sweep =="
$PY "$INT" init --store "$STORE" >/dev/null
check "store initialized" "[ -d $STORE/tree/.git ] && [ -f $STORE/index.db ]"
$PY "$INT" sweep --tiers A --store "$STORE" > "$T/sweep1.txt" 2>&1
check "seed: 4 new files tracked" "grep -q 'confirmed: +4 new' $T/sweep1.txt"
check "seed: commit tagged 'seed'" "git -C $STORE/tree rev-parse --verify seed >/dev/null 2>&1"

echo "== 2. tamper =="
printf '127.0.0.1 localhost\n::1 localhost\n6.6.6.6 evil.example\n' > "$ROOT/private/etc/hosts"
printf '#!/bin/bash\necho PWNED\n' > "$ROOT/usr/local/bin/evw-test-tool.sh"
printf 'malicious persistence\n' > "$ROOT/Library/LaunchDaemons/com.evil.backdoor.plist"
printf 'changed-app-v2\n' > "$ROOT/Applications/fake.bin"
rm "$ROOT/Library/LaunchDaemons/com.test.daemon.plist"

echo "== 3. detection + diffs (no heal) =="
$PY "$INT" sweep --tiers A --store "$STORE" > "$T/sweep2.txt" 2>&1
check "detected 1 new (evil plist)" "grep -q '+1 new' $T/sweep2.txt"
check "detected 3 changed" "grep -q '~3 changed' $T/sweep2.txt"
check "detected 1 removed" "grep -q '\-1 removed' $T/sweep2.txt"
check "diff shows injected hosts line" "grep -q '+6.6.6.6 evil.example' $T/sweep2.txt"
check "diff shows PWNED tool" "grep -q '+echo PWNED' $T/sweep2.txt"
check "no heal without --heal" "[ -f $ROOT/Library/LaunchDaemons/com.evil.backdoor.plist ]"

echo "== 4. rollback --since seed =="
$PY "$RBK" list --store "$STORE" --since seed > "$T/rblist.txt" 2>&1
check "list shows changed hosts" "grep -q 'CHANGED.*/private/etc/hosts' $T/rblist.txt"
check "list shows missing plist" "grep -q 'MISSING.*com.test.daemon.plist' $T/rblist.txt"
check "list shows new evil plist" "grep -q 'NEW.*com.evil.backdoor.plist' $T/rblist.txt"
$PY "$RBK" restore --paths "$ROOT/private/etc/hosts,$ROOT/Library/LaunchDaemons/com.test.daemon.plist,$ROOT/usr/local/bin/evw-test-tool.sh" --since seed --store "$STORE" --dry-run > "$T/rbdry.txt" 2>&1
check "dry-run makes no changes" "grep -q '6.6.6.6' $ROOT/private/etc/hosts"
$PY "$RBK" restore --paths "$ROOT/private/etc/hosts,$ROOT/Library/LaunchDaemons/com.test.daemon.plist,$ROOT/usr/local/bin/evw-test-tool.sh" --since seed --store "$STORE" --apply > "$T/rbapp.txt" 2>&1
check "hosts content restored" "! grep -q '6.6.6.6' $ROOT/private/etc/hosts"
check "deleted plist restored" "[ -f $ROOT/Library/LaunchDaemons/com.test.daemon.plist ]"
check "tool restored to v1" "grep -q 'evw-test-tool v1' $ROOT/usr/local/bin/evw-test-tool.sh"
check "quarantine captured suspect" "find $STORE/quarantine -name hosts | grep -q ."
check "UNDO manifest written" "find $STORE/quarantine -name UNDO.json | grep -q ."
check "plist lint passes" "plutil -lint $ROOT/Library/LaunchDaemons/com.test.daemon.plist >/dev/null"
check "store re-baselined (known-good tag)" "git -C $STORE/tree rev-parse --verify known-good >/dev/null 2>&1"

echo "== 5. heal round-trips =="
printf '#!/bin/bash\necho PWNED-AGAIN\n' > "$ROOT/usr/local/bin/evw-test-tool.sh"
printf 'another intruder\n' > "$ROOT/Library/LaunchDaemons/com.evil.second.plist"
rm "$ROOT/Library/LaunchDaemons/com.test.daemon.plist"
$PY "$INT" sweep --tiers A --heal --store "$STORE" > "$T/sweep3.txt" 2>&1
check "heal quarantined NEW evil plist" "[ ! -f $ROOT/Library/LaunchDaemons/com.evil.second.plist ]"
check "healed evil plist in quarantine" "find $STORE/quarantine -name com.evil.second.plist | grep -q ."
check "heal restored tampered tool to committed v1" "grep -q 'evw-test-tool v1' $ROOT/usr/local/bin/evw-test-tool.sh"
check "heal restored REMOVED plist" "[ -f $ROOT/Library/LaunchDaemons/com.test.daemon.plist ]"
check "report records HEALED" "grep -q 'HEALED' $T/sweep3.txt"

echo "== 6. deploy window =="
date +%s > "$STORE/deploy.marker"
printf 'deploy-time-change\n' >> "$ROOT/private/etc/hosts"
$PY "$INT" sweep --tiers A --heal --store "$STORE" > "$T/sweep4.txt" 2>&1
check "deploy window: no heal, auto-approved" "grep -q 'DEPLOY WINDOW ACTIVE' $T/sweep4.txt"
check "deploy change kept" "grep -q 'deploy-time-change' $ROOT/private/etc/hosts"
rm -f "$STORE/deploy.marker"
# revert deploy change back to seed state for the final all-rollback check
printf '127.0.0.1 localhost\n::1 localhost\n' > "$ROOT/private/etc/hosts"

echo "== 7. full rollback --all --since seed =="
$PY "$RBK" restore --all --since seed --store "$STORE" --apply > "$T/rball.txt" 2>&1
check "evil backdoor quarantined by --all" "[ ! -f $ROOT/Library/LaunchDaemons/com.evil.backdoor.plist ]"
check "evil backdoor preserved in quarantine" "find $STORE/quarantine -name com.evil.backdoor.plist | grep -q ."
check "fake app restored to v1" "grep -q 'fake-app-content-v1' $ROOT/Applications/fake.bin"
$PY "$INT" sweep --tiers A --heal --store "$STORE" > "$T/sweep5.txt" 2>&1
check "post-rollback sweep is clean" "grep -q 'confirmed: +0 new, ~0 changed, -0 removed' $T/sweep5.txt"

echo "== 8. verify + full =="
$PY "$INT" verify --store "$STORE" --sample 50 > "$T/verify.txt" 2>&1
check "verify fsck OK" "grep -q 'git fsck: OK' $T/verify.txt"
check "verify sample clean" "grep -qE 'sample re-hash: [0-9]+/[0-9]+ clean' $T/verify.txt"
$PY "$INT" full --tiers A --store "$STORE" > "$T/full.txt" 2>&1
check "full scan runs" "grep -q 'FULL SCAN' $T/full.txt"

echo "== 9. full detects same-size, same-mtime tamper =="
MT=$(/usr/bin/sqlite3 "$STORE/index.db" "SELECT mtime_ns FROM files WHERE path='$ROOT/Applications/fake.bin';")
SIZE=$(stat -f %z "$ROOT/Applications/fake.bin")
$PY -c 'import os,sys; p=sys.argv[1]; mt=int(sys.argv[2]); size=int(sys.argv[3]); data=open(p,"rb").read(); assert len(data)==size; open(p,"wb").write(bytes((b+1)%256 for b in data)); os.utime(p,ns=(mt,mt))' "$ROOT/Applications/fake.bin" "$MT" "$SIZE"
$PY "$INT" sweep --tiers A --store "$STORE" > "$T/sweep-metadata.txt" 2>&1
check "metadata sweep misses invisible tamper" "grep -q 'confirmed: +0 new, ~0 changed, -0 removed' $T/sweep-metadata.txt"
$PY "$INT" full --tiers A --store "$STORE" > "$T/full-metadata.txt" 2>&1
check "full re-hash detects invisible tamper" "grep -q '~1 changed' $T/full-metadata.txt"

echo "== 10. unreadable paths and scan lock =="
chmod 000 "$ROOT/Applications/fake.bin"
$PY "$INT" sweep --tiers A --store "$STORE" > "$T/sweep-unreadable.txt" 2>&1
check "report names unreadable file" "grep -q 'HASH-FAILED.*/Applications/fake.bin' $T/sweep-unreadable.txt"
chmod 644 "$ROOT/Applications/fake.bin"
$PY -c 'import fcntl,sys,time; f=open(sys.argv[1],"a+"); fcntl.flock(f,fcntl.LOCK_EX); time.sleep(2)' "$STORE/scan.lock" &
LOCKPID=$!
sleep 0.3
EVW_INTEGRITY_LOCK_TIMEOUT=0.5 $PY "$INT" sweep --tiers A --store "$STORE" > "$T/sweep-locked.txt" 2>&1
LOCK_RC=$?
wait "$LOCKPID"
check "overlapping scan exits 75" "[ $LOCK_RC -eq 75 ]"
check "lock error explains active scan" "grep -q 'integrity store is locked' $T/sweep-locked.txt"

echo "== 11. backup completeness =="
BKROOT="$T/backups"
BKSRC="$T/backup-src"
BKDST="$T/backup-dst"
mkdir -p "$BKROOT" "$BKSRC/scan-2026-10-28" "$BKDST"
printf 'root report\n' > "$BKSRC/scan-2026-10-28/report.txt"
cat > "$BKROOT/test-BACKUP-STATUS.md" <<EOF
# Backup status — test
Backup source: \`$BKSRC/\`
Backup destination: \`$BKDST/\`
- \`scan-2026-10-28/report.txt\`
EOF
$PY /Users/evw/dev/security/evw-backup-check.py --backups-root "$BKROOT" --report "$T/backup-missing.txt" > /dev/null 2>&1
BK_RC=$?
check "backup checker flags missing file" "[ $BK_RC -eq 1 ] && grep -q 'BACKUP-MISSING' $T/backup-missing.txt"
mkdir -p "$BKDST/scan-2026-10-28"
cp "$BKSRC/scan-2026-10-28/report.txt" "$BKDST/scan-2026-10-28/report.txt"
$PY /Users/evw/dev/security/evw-backup-check.py --backups-root "$BKROOT" --report "$T/backup-clean.txt" > /dev/null 2>&1
check "backup checker passes matching file" "grep -q 'total issues: 0' $T/backup-clean.txt"
printf 'changed report\n' > "$BKDST/scan-2026-10-28/report.txt"
$PY /Users/evw/dev/security/evw-backup-check.py --backups-root "$BKROOT" --report "$T/backup-changed.txt" > /dev/null 2>&1
BK_RC=$?
check "backup checker flags changed file" "[ $BK_RC -eq 1 ] && grep -q 'CHANGED' $T/backup-changed.txt"

echo "== 12. GitHub restore =="
GHROOT="$T/repo-root"
mkdir -p "$GHROOT/tools" "$T/fakebin"
cat > "$T/fakebin/gh" <<'EOF'
#!/bin/bash
printf 'restored by github\n'
EOF
chmod 755 "$T/fakebin/gh"
GHTARGET="$GHROOT/tools/deleted.sh"
PATH="$T/fakebin:$PATH" $PY "$RBK" restore --store "$STORE" --source github --repo evw/test --ref main --repo-root "$GHROOT" --paths "$GHTARGET" --dry-run > "$T/gh-dry.txt" 2>&1
check "GitHub dry-run does not create file" "[ ! -f $GHTARGET ] && grep -q 'WOULD-RESTORE-GITHUB' $T/gh-dry.txt"
PATH="$T/fakebin:$PATH" $PY "$RBK" restore --store "$STORE" --source github --repo evw/test --ref main --repo-root "$GHROOT" --paths "$GHTARGET" --apply > "$T/gh-apply.txt" 2>&1
check "GitHub restore creates missing file" "grep -q 'restored by github' $GHTARGET"
check "GitHub restore verified" "grep -q 'RESTORED-GITHUB' $T/gh-apply.txt"

echo ""
echo "════════════════════════════════"
echo "RESULT: $PASS passed, $FAIL failed"
echo "fixture left at $T"
[ $FAIL -eq 0 ]
