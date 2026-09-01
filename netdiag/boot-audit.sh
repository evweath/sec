#!/bin/bash
# netdiag/boot-audit.sh — root-only persistence/boot-config audit + LS model export.
# Output: /Users/evw/dev/fix/netdiag/logs/boot-audit.txt (chowned to evw) + LS model copy.
OUT=/Users/evw/dev/fix/netdiag/logs/boot-audit.txt
exec > >(tee "$OUT") 2>&1
echo "=== boot-audit $(date) ==="
[ "$(id -u)" -ne 0 ] && { echo "ERROR: must run as root"; exit 1; }

echo "── /etc/sudoers.d:"
ls -la /etc/sudoers.d 2>&1
for f in /etc/sudoers.d/*; do [ -f "$f" ] && { echo "### $f"; cat "$f"; }; done
echo "── /etc/sudoers non-comment lines:"
grep -vE '^\s*#|^\s*$' /etc/sudoers

echo "── /var/root/.ssh:"
ls -la /var/root/.ssh 2>&1 || echo "  (absent — good)"
[ -f /var/root/.ssh/authorized_keys ] && cat /var/root/.ssh/authorized_keys || echo "  no root authorized_keys — good"

echo "── /var/cron/tabs:"
ls -la /var/cron/tabs 2>&1; for f in /var/cron/tabs/*; do [ -f "$f" ] && { echo "### $f"; cat "$f"; }; done

echo "── user accounts (UID>=500):"
dscl . -list /Users UniqueID | awk '$2>=500'
echo "── admin group:"
dscl . -read /Groups/admin GroupMembership

echo "── print-disabled system (security-relevant):"
launchctl print-disabled system 2>/dev/null | grep -iE "ssh|smb|screen|telnet|ftp|nfs|remote|ard|airport|wifi|bluetoo|mdns|configd|bonsai" | head -20

echo "── third-party kexts:"
kextstat 2>/dev/null | grep -v com.apple | head -10
echo "── /Library/Extensions:"
ls -la /Library/Extensions 2>&1

echo "── /etc/pam.d files modified in last 120 days:"
find /etc/pam.d -mtime -120 -type f 2>/dev/null | while read -r f; do echo "### $f"; ls -la "$f"; grep -vE '^\s*#|^\s*$' "$f" | head -10; done

echo "── BTM (background items) dump:"
sfltool dumpbtm 2>&1 | grep -iE "name|path|url|identifier" | head -40

echo "── hash compare root-owned scripts vs audited sources:"
for pair in "/usr/local/lib/mac-sentinel/mac-sentinel.py:/Users/evw/dev/security/scripts/mac-sentinel.py" \
            "/usr/local/lib/mac-sentinel/ip_intel.py:/Users/evw/dev/security/scripts/ip_intel.py" \
            "/usr/local/bin/evw-lockdown.sh:/Users/evw/dev/security/sec/lockdown.sh"; do
  a="${pair%%:*}"; b="${pair##*:}"
  ha=$(shasum -a 256 "$a" 2>/dev/null | cut -d' ' -f1); hb=$(shasum -a 256 "$b" 2>/dev/null | cut -d' ' -f1)
  [ "$ha" = "$hb" ] && echo "OK   $a" || echo "DIFF $a vs $b"
done

echo "── LS model export:"
"/Applications/Little Snitch.app/Contents/Components/littlesnitch" export-model /var/log/mac-sentinel/ls-model-current.json \
  && cp /var/log/mac-sentinel/ls-model-current.json /Users/evw/dev/fix/netdiag/logs/ls-model-current.json \
  && echo "exported"

chown -R evw:staff /Users/evw/dev/fix/netdiag/logs/boot-audit.txt /Users/evw/dev/fix/netdiag/logs/ls-model-current.json 2>/dev/null
chmod 600 /Users/evw/dev/fix/netdiag/logs/ls-model-current.json
echo "=== boot-audit done ==="
