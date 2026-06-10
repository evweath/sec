# Security Scan Checklist
<!-- APPEND-ONLY: Add new items at the end of each section. Never remove items. -->
<!-- VERSION: 1.0 — 2026-06-10 -->
<!-- To generate PDF: python3 ~/dev/security/checklist-pdf.py -->

---

## How to Use

1. Run through each section in order
2. Mark each item ✅ PASS / ⚠️ WARN / 🔴 FAIL
3. Any FAIL → open a new entry in VIOLATIONS-REGISTER.md immediately
4. After the scan, run `python3 ~/dev/security/checklist-pdf.py` to export PDF
5. Append new checklist items at the bottom of the relevant section (never delete items)

---

## SECTION A — Pre-Scan Setup

### A-1. Create scan directory
```bash
SCANDIR="$HOME/dev/security/scan-$(date +%Y-%m-%d)"
mkdir -p "$SCANDIR"
```

### A-2. Export current Little Snitch model (requires sudo)
```bash
sudo /Applications/Little\ Snitch.app/Contents/Components/littlesnitch export-model "$SCANDIR/ls-model.json"
echo "Rules: $(python3 -c "import json; m=json.load(open('$SCANDIR/ls-model.json')); print(len(m.get('rules',[])))")"
```
**Expected:** Export succeeds. Rule count consistent with prior scan (delta < ±100 rules without a known reason).

### A-3. Run LS permissive analysis
```bash
python3 ~/dev/security/ls-permissive-analysis.py "$SCANDIR/ls-model.json" 2>&1 | tee "$SCANDIR/ls-permissive-top30.txt"
```
**Pass criteria:**
- `[OK] No allow-any rules via unsigned binary`
- `[OK] No non-ICMP any-process allow-any rules`
- Review top-20 list against known-good baseline

---

## SECTION B — Persistence Layer

### B-1. Verify schg flag on disabled.501.plist
```bash
ls -lO /var/db/com.apple.xpc.launchd/disabled.501.plist
```
**Expected:** `schg` flag present. If missing → re-apply `sudo chflags schg ...` and escalate immediately.

### B-2. Verify all 11 disable entries in plist
```bash
sudo plutil -p /var/db/com.apple.xpc.launchd/disabled.501.plist
```
**Expected (all => true):**
- com.apple.RemoteManagementAgent
- com.apple.remotemanagementd
- com.apple.sharingd
- com.apple.identityservicesd
- com.apple.replicatord
- com.apple.studentd
- com.apple.privatecloudcomputed
- com.apple.aps.remotemanagementd.http.apns-dev
- com.apple.aps.remotemanagementd.http.apns-prod
- com.apple.replayd ← added 2026-06-03 (V-003)
- com.apple.replaykit.sharingsession ← added 2026-06-03 (V-003)

**If any entry missing:** schg was cleared or plist was reset. Treat as CRITICAL — log to violations register.

### B-3. Verify launchctl runtime state matches plist (add 2026-06-10)
```bash
launchctl print-disabled gui/$(id -u) | grep -E "replayd|replaykit|RemoteManagement|sharingd|identityservices|replicatord|studentd|privatecloudcomputed"
```
**Expected:** All entries show `=> disabled`.  
**Note:** macOS updates can reset runtime state without modifying the plist. If runtime shows enabled but plist shows true, re-run the disable commands even though plist is correct.

### B-4. Check plist-monitor log for write attempts
```bash
sudo tail -30 /private/var/log/evw-plist-monitor.log
sudo tail -10 /private/var/log/evw-plist-monitor-err.log
```
**Expected:** Start banner + target line. Any write/unlink/rename/open-W event is a CRITICAL finding.

### B-5. Check launch agents and daemons (non-Apple)
```bash
ls ~/Library/LaunchAgents/ | grep -v "^com.apple\."
ls /Library/LaunchDaemons/ | grep -v "^com.apple\."
ls /Library/LaunchAgents/ | grep -v "^com.apple\."
```
**Expected:** Only known items:
- `com.evw.donut-intel.plist` (user LaunchAgent)
- `at.obdev.littlesnitch.daemon.plist`
- `com.evw.audit-monitor.plist`
- `com.evw.plist-monitor.plist`
- `com.evw.replayd-guard.plist`

### B-6. Check cron jobs
```bash
crontab -l 2>/dev/null || echo "No crontab"
ls /private/var/at/tabs/ 2>/dev/null
ls /etc/cron.d/ 2>/dev/null
```
**Expected:** No crontab. No user cron files.

### B-7. Check login items
```bash
sfltool dumpbtm 2>/dev/null | grep -E "Name:|URL:|TeamID:" | head -30
```
**Expected:** Only Little Snitch, plist-monitor, replayd-guard, audit-monitor, donut-intel (uvicorn).

---

## SECTION C — Network State

### C-1. Check monitored services have no external network connections
```bash
for svc in RemoteManagementAgent remotemanagementd sharingd identityservicesd replicatord studentd privatecloudcomputed replayd; do
  pid=$(pgrep -x "$svc" 2>/dev/null | head -1)
  if [ -n "$pid" ]; then
    net=$(lsof -a -p "$pid" -i 2>/dev/null | grep -v "COMMAND\|UDP \*" | grep -v "^$")
    echo "$svc PID=$pid  net: ${net:-NONE}"
  else
    echo "$svc: not running ✓"
  fi
done
```
**Expected:** All show `NONE` or `not running`. Any ESTABLISHED connection to external IP = CRITICAL escalation.

### C-2. Check all active outbound connections
```bash
lsof -i -n -P 2>/dev/null | grep ESTABLISHED | grep -v "127.0.0.1\|::1"
```
**Expected:** Only known processes (Claude Code CLI → Anthropic, browsers, donut-intel if active).  
For each unknown PID: `ps -p <PID> -o pid,ppid,user,comm,args`

### C-3. Check listening services
```bash
lsof -i -n -P 2>/dev/null | grep LISTEN
```
**Expected:** Only `python3 127.0.0.1:8743` (donut-intel). Any service listening on 0.0.0.0 or non-loopback = CRITICAL.

### C-4. Verify DNS servers
```bash
scutil --dns | grep nameserver | head -5
```
**Expected:** Quad9 (9.9.9.9, 149.112.112.112). Any other nameserver = WARN.

---

## SECTION D — Screen Recording & Privacy

### D-1. Check replayd status
```bash
pgrep replayd && echo "ALERT: replayd running" || echo "OK: not running"
ls ~/Library/Preferences/com.apple.replayd.plist 2>/dev/null && \
  plutil -p ~/Library/Preferences/com.apple.replayd.plist | grep "video" || echo "OK: no replayd plist"
```
**Expected:** Not running. Plist absent or `video = 0`.  
**If running:** Check for open video files: `lsof -p $(pgrep replayd) | grep -iE "\.mov|\.mp4|screen|IOSurface"`  
**If video file open:** CRITICAL — kill, remove plist, log to violations register, escalate to V-003.

### D-2. Check replayd-guard is running and killing spawns
```bash
pgrep -f evw-replayd-guard && echo "Guard running" || echo "ALERT: Guard not running"
sudo tail -10 /private/var/log/evw-replayd-guard.log
```
**Expected:** Guard running. Log shows kills only (no sustained spawn loops).  
**If guard not running:** `sudo launchctl kickstart system/com.evw.replayd-guard`

### D-3. Audit TCC screen capture and accessibility grants
```bash
sudo sqlite3 "/Library/Application Support/com.apple.TCC/TCC.db" \
  "SELECT service, client, auth_value, last_modified FROM access \
   WHERE service IN ('kTCCServiceScreenCapture','kTCCServiceAccessibility','kTCCServiceListenEvent','kTCCServicePostEvent') \
   ORDER BY service, auth_value DESC;"
```
**Expected:** Only known Apple processes and explicitly authorized tools (Little Snitch).  
Any `auth_value=2` for ScreenCapture/Accessibility/ListenEvent on third-party app = CRITICAL.

### D-4. Check privatecloudcomputed containers
```bash
ls ~/Library/Daemon\ Containers/ 2>/dev/null | wc -l
ls ~/Library/Daemon\ Containers/ 2>/dev/null
```
**Expected:** Container count consistent with prior scan (delta < 5 without known AI feature use).  
Each container = a PCC task Apple AI processed. LS deny rule must be active to block network.

---

## SECTION E — Integrity Monitoring

### E-1. Audit-monitor daemon health
```bash
sudo launchctl print system/com.evw.audit-monitor | grep -E 'state|pid|last exit'
sudo tail -5 /private/var/log/evw-audit-monitor.log
```
**Expected:** `state = running`, `last exit code = (never exited)`. Log shows `[LOG-STREAM] started`.  
**If not running:** `sudo launchctl kickstart -k system/com.evw.audit-monitor`

### E-2. Check audit alerts log for events since last scan
```bash
sudo tail -50 /private/var/log/evw-audit-alerts.log
```
**Expected:** Empty or contains only known/benign events. Any `ALERT:` line with unknown binary = investigate.

### E-3. BSM auditd status (updated 2026-06-10)
```bash
pgrep auditd && ps aux | grep auditd | grep -v grep || echo "NOT RUNNING"
sudo ls -la /var/audit/ 2>/dev/null | head -10
```
**Expected on macOS 26.5+:** Running (PID low, started at boot). Audit log files in `/var/audit/`.  
**Expected on pre-26.5:** NOT RUNNING — Apple security policy previously blocked auditd.  
**If running and /var/audit/ is empty:** Verify `audit_control` flags are correct (`flags:lo,aa,ex,pc`).

### E-4. Process accounting
```bash
ls -la /var/account/acct 2>/dev/null || echo "MISSING — needs re-enable after each boot"
sudo lastcomm --file /var/account/acct 2>/dev/null | head -20
```
**Expected:** File exists, recently modified. `lastcomm` shows recent exec history.  
**If missing:** `sudo mkdir -p /var/account && sudo touch /var/account/acct && sudo chmod 600 /var/account/acct && sudo accton /var/account/acct`

### E-5. Keybag state — check for unauthorized passcode/UUID reset
```bash
sudo log show --predicate 'process == "keybagd"' --last 24h | grep -E "kb_set_user_uuid|fv_bind_keybag|days_since_passcode"
```
**Expected:** No `kb_set_user_uuid` or `fv_bind_keybag_to_kek` since last boot.  
**If present:** Keybag UUID re-bound → Touch ID wipe pending → investigate reboot cause immediately.

---

## SECTION F — Binary Integrity

### F-1. Compute current binary hashes
```bash
shasum -a 256 /bin/* /sbin/* /usr/bin/* /usr/sbin/* /usr/libexec/* 2>/dev/null | sort > "$SCANDIR/system-binary-hashes.txt"
echo "Hash count: $(wc -l < "$SCANDIR/system-binary-hashes.txt")"
```

### F-2. Diff vs most recent prior scan
```bash
PREV=$(ls -d ~/dev/security/scan-*/system-binary-hashes.txt 2>/dev/null | sort | tail -2 | head -1 | xargs dirname)
diff <(sort "$SCANDIR/system-binary-hashes.txt") <(sort "$PREV/system-binary-hashes.txt") | grep "^[<>]" | wc -l
echo "changes vs $PREV"
```
**Expected:** 0 changes (no OS update). If >100 changes, check for OS update (`sw_vers`).  
Any hash change on a path not attributable to an OS update = CRITICAL.

### F-3. Diff vs 2026-05-18 baseline
```bash
diff <(sort "$SCANDIR/system-binary-hashes.txt") <(sort ~/dev/security/scan-2026-05-18/system-binary-hashes.txt) | grep "^<" | awk '{print $3}' | head -20
```
**Expected:** Only paths added/changed by OS upgrades. Any unexpected new binary in /usr/libexec or /usr/sbin = CRITICAL.

### F-4. Verify signature of all new/changed binaries
```bash
# For each binary in the diff
codesign -dv --verbose=2 <binary_path> 2>&1 | grep -E "Identifier|TeamID|Authority"
```
**Expected:** Apple-signed (TeamID not set, Authority includes Apple Root CA). Unsigned or unknown TeamID = CRITICAL.

---

## SECTION G — System Extensions & Kernel

### G-1. List system extensions
```bash
systemextensionsctl list
```
**Expected:** Only `at.obdev.littlesnitch.networkextension (MLZF7K7B5R)`.  
Any new system extension = investigate immediately.

### G-2. List kernel extensions
```bash
kextstat 2>/dev/null | grep -v "com.apple"
```
**Expected:** Empty (no third-party kexts).

---

## SECTION H — LS Rules Hygiene

### H-1. Verify critical deny rules active
In LS Rules window (⌘R), confirm deny-all rules exist for:
- `privatecloudcomputed`
- `remotemanagementd`
- `RemoteManagementAgent`
- `ARDAgent`
- `launchctl`
- `replayd`

### H-2. Check for any new auto-allow rules since last scan
```bash
# Compare rule count vs prior export
python3 -c "
import json
curr = json.load(open('$SCANDIR/ls-model.json'))
prev = json.load(open('$PREV/ls-model.json'))  # adjust path
new_allows = [r for r in curr.get('rules',[]) if r.get('action')=='allow' and r not in prev.get('rules',[])]
print(f'{len(new_allows)} new allow rules')
for r in new_allows[:10]:
    print(r.get('process','?'), r.get('remote','?'))
"
```
**Expected:** 0 new allow rules without explicit user action. Any auto-allow rule = review immediately.

### H-3. Run permissive rules analysis
Already covered in A-3. Reference `$SCANDIR/ls-permissive-top30.txt`.

---

## SECTION I — Violations Register

### I-1. Review all OPEN violations
```bash
grep -E "^### V-|Status:" ~/dev/security/VIOLATIONS-REGISTER.md
```
**Required:** Each OPEN violation reviewed. Status updated if changed. New violations appended immediately on discovery.

### I-2. Confirm mitigated violations have not regressed
Check each MITIGATED violation's mitigation is still in place:
- **V-001:** LS has no Terminal→any via unsigned binary
- **V-003:** replayd not running (or guard killing it); no new .mov files on Desktop
- **V-005:** schg on plist; plist-monitor running
- **V-007:** LS deny rule for privatecloudcomputed active
- **V-008:** DNS = Quad9

---

## SECTION J — Post-Scan

### J-1. Export scan to PDF
```bash
python3 ~/dev/security/checklist-pdf.py --scan-dir "$SCANDIR"
```
**Output:** `$SCANDIR/SECURITY-SCAN-REPORT-$(date +%Y-%m-%d).pdf`

### J-2. Commit scan artifacts to git
```bash
cd ~/dev/security
git add scan-$(date +%Y-%m-%d)/
git add VIOLATIONS-REGISTER.md
git add SECURITY-CHECKLIST.md
git commit -m "Security scan $(date +%Y-%m-%d): <summary of key findings>"
```

### J-3. Back up to ~/.claude_home
```bash
cp -R ~/dev/security/scan-$(date +%Y-%m-%d)/ ~/.claude_home/security/scan-$(date +%Y-%m-%d)/
```

### J-4. Update SESSION.md and L5 hash log
Covered by session backup procedure in CLAUDE.md.

---

## APPENDIX — Item History

| Item | Added | Reason |
|------|-------|--------|
| A-1 through I-2 | 2026-06-10 | Initial checklist created from 3-week scan history |
| B-3 (launchctl runtime state) | 2026-06-10 | macOS update reset runtime state despite correct plist — caught replayd running |
| D-2 (replayd-guard) | 2026-06-10 | Guard daemon added 2026-06-03; verify it's running each scan |
| E-3 (BSM auditd updated) | 2026-06-10 | auditd now running on macOS 26.5 (was blocked on earlier Darwin 25.x) |

---

*Checklist version history lives in git. Run `git log SECURITY-CHECKLIST.md` for full history.*
