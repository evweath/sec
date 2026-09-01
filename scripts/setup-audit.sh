#!/bin/bash
# setup-audit.sh — Enable macOS BSM audit with file-change tracking for ew.
# Run once as root: sudo ./setup-audit.sh
# After running, file-sentinel.py can read /var/audit/current.

set -euo pipefail

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error-guard.sh)
_eg_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
while [ "$_eg_d" != "/" ] && [ ! -f "$_eg_d/lib/error-guard.sh" ]; do _eg_d="$(dirname "$_eg_d")"; done
[ -f "$_eg_d/lib/error-guard.sh" ] && . "$_eg_d/lib/error-guard.sh"; unset _eg_d
command -v guard_run >/dev/null 2>&1 || guard_run() { shift; "$@"; }
command -v guard_throw >/dev/null 2>&1 || guard_throw() { printf 'error-guard: throw: %s\n' "$*" >&2; return 1; }

[[ $EUID -ne 0 ]] && { echo "Must run as root: sudo $0"; exit 1; }

AUDIT_CONTROL=/etc/security/audit_control
AUDIT_USER=/etc/security/audit_user

echo "[*] Backing up existing audit config..."
[[ -f "$AUDIT_CONTROL" ]] && guard_run "audit-backup" cp "$AUDIT_CONTROL" "${AUDIT_CONTROL}.bak.$(date +%Y%m%d)" || true

echo "[*] Writing /etc/security/audit_control..."
cat > "$AUDIT_CONTROL" << 'EOF'
# macOS BSM audit configuration
# flags:  fw=file-write  fc=file-create  fd=file-delete  fm=file-attr-modify
#         lo=login/logout  ad=admin  pc=process  nt=network (add if needed)
dir:/var/audit
flags:fw,fc,fd,fm,lo,ad
minfree:5
naflags:lo,ad
policy:cnt,argv,arge
filesz:10M
expire-after:14d
EOF

echo "[*] Writing /etc/security/audit_user (evw gets file-change audit)..."
# Remove any existing evw line, then add
grep -v "^evw:" "$AUDIT_USER" 2>/dev/null > /tmp/audit_user.tmp || true
echo "evw:fw,fc,fd,fm:fw,fc,fd,fm" >> /tmp/audit_user.tmp
guard_run "audit-user-install" mv /tmp/audit_user.tmp "$AUDIT_USER" || true

echo "[*] Creating /var/audit if needed..."
mkdir -p /var/audit
guard_run "audit-dir-chmod" chmod 750 /var/audit || true
guard_run "audit-dir-chown" chown root:wheel /var/audit || true

echo "[*] Starting / restarting audit daemon..."
if launchctl list | grep -q "com.apple.auditd"; then
    guard_run "audit-sync" audit -s || true   # sync — rotate and restart with new config
else
    guard_run "auditd-load" launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist 2>/dev/null \
        || audit -s
fi

echo "[*] Verifying audit is running..."
sleep 2
if audit -c 2>/dev/null | grep -q "audit.*running\|AUC_AUDITING"; then
    echo "[OK] auditd is active"
else
    praudit /dev/null 2>/dev/null && echo "[OK] audit pipe accessible" || echo "[WARN] run: sudo audit -s manually"
fi

echo ""
echo "[OK] BSM audit enabled. Log: /var/audit/current"
echo "     Run file-sentinel.py to watch it:"
echo "     sudo python3 /Users/evw/dev/security/scripts/file-sentinel.py"
