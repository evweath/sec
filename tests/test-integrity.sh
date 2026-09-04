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

echo ""
echo "════════════════════════════════"
echo "RESULT: $PASS passed, $FAIL failed"
echo "fixture left at $T"
[ $FAIL -eq 0 ]
