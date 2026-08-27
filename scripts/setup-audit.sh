#!/bin/bash
# setup-audit.sh — Enable macOS BSM audit with file-change tracking for ew.
# Run once as root: sudo ./setup-audit.sh
# After running, file-sentinel.py can read /var/audit/current.

set -euo pipefail

[[ $EUID -ne 0 ]] && { echo "Must run as root: sudo $0"; exit 1; }

AUDIT_CONTROL=/etc/security/audit_control
AUDIT_USER=/etc/security/audit_user

echo "[*] Backing up existing audit config..."
[[ -f "$AUDIT_CONTROL" ]] && cp "$AUDIT_CONTROL" "${AUDIT_CONTROL}.bak.$(date +%Y%m%d)"

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
mv /tmp/audit_user.tmp "$AUDIT_USER"

echo "[*] Creating /var/audit if needed..."
mkdir -p /var/audit
chmod 750 /var/audit
chown root:wheel /var/audit

echo "[*] Starting / restarting audit daemon..."
if launchctl list | grep -q "com.apple.auditd"; then
    audit -s   # sync — rotate and restart with new config
else
    launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist 2>/dev/null \
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
