# Security Violations Register
# Append-only. New violations added at bottom of their status section.
# Updated: 2026-06-09
# Owner: evw

---

## STATUS KEY
- 🔴 OPEN — violation active, root cause unresolved, fix not yet applied
- 🟡 MITIGATED — controls applied, but root cause unknown or recurrence possible
- 🟢 CLOSED — root cause confirmed, fix verified, no recurrence
- 🔵 MONITOR — no fix possible (SIP-protected), watching for recurrence

---

## OPEN VIOLATIONS

### V-001 | Terminal Blanket Network Allow via Anonymous Binary
**Severity:** CRITICAL
**Discovered:** 2026-06-09 (rule created 2026-05-28)
**Type:** Unauthorized persistent network rule / unknown binary execution

**What happened:**
On 2026-05-28, an unidentified binary ran inside Terminal.app and connected to
`equipmentplus.myshopify.com`. Little Snitch was in network-monitor mode and
auto-created a blanket allow rule: Terminal → any destination / any port / any protocol.
The binary could not be identified by code signing — only by SHA256 hash.

**Evidence:**
- LS rule: `process=com.apple.Terminal, remote=any, origin=monitor, useCount=1761`
- Via: `identifier.SHA256/84915e7c242d8cb3f80ab9940a1aeaba1553467be7e02c0172014af764a53b70`
- Original peer: `equipmentplus.myshopify.com`
- useCount 1,761 — rule was actively used after creation
- Rule artifact: `scan-2026-06-09/ls-permissive-top30.md`

**Fix required:**
1. Import cleaned LS model (removes this rule):
   `sudo /Applications/Little\ Snitch.app/Contents/Components/littlesnitch restore-model /tmp/ls-minus-terminal-any.json`
2. Search for binary: `find ~/dev ~/Library /usr/local -type f -newer /tmp/ls-current.json 2>/dev/null | xargs shasum -a 256 2>/dev/null | grep 84915e7c`
3. If binary found: hash it, submit to VirusTotal, quarantine

**Status:** OPEN — LS model import pending user confirmation

---

### V-002 | Microphone Access Audit — No Records Found
**Severity:** HIGH (unverified)
**Discovered:** 2026-06-09
**Type:** Missing audit / potential covert recording

**What happened:**
No microphone (kTCCServiceMicrophone) audit has ever been run. Given that a
screen-recording violation occurred (V-003) using a TCC-bypass entitlement, the
same vector may exist for audio/microphone. The replayd entitlement
`com.apple.private.screencapturekit.noprompt` bypasses TCC entirely — equivalent
audio entitlements exist on macOS.

**Checks required:**
```bash
# TCC microphone grants
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT service,client,auth_value,last_modified FROM access WHERE service='kTCCServiceMicrophone' ORDER BY auth_value DESC;"

# Processes currently accessing microphone
sudo lsof /dev/dsp* /dev/audio* 2>/dev/null
ioreg -l | grep -i "IOAudioEngine\|microphone\|capture" | head -20

# Recent audio hardware access in unified log
log show --last 24h --predicate 'subsystem == "com.apple.coreaudio" OR subsystem == "com.apple.avfoundation"' --style compact 2>/dev/null | grep -i "microphone\|record\|capture\|input" | head -30
```

**Status:** OPEN — audit not yet run

---

## MITIGATED VIOLATIONS

### V-003 | Unauthorized Screen Recording by replayd (8.5 hours, 4.03 GB)
**Severity:** CRITICAL
**Date:** 2026-06-02 09:26 CDT → 19:41 CDT (8.5 hours)
**Type:** Covert screen recording / TCC entitlement bypass

**What happened:**
`/usr/libexec/replayd` (Apple's Replay screen recorder) was triggered at boot by
an unidentified client (PID 1373, identity lost — logs rotated before investigation).
It recorded the screen for 8.5 hours producing a 4.03 GB .MOV file on the Desktop.
No orange recording indicator was shown. No TCC prompt was shown. No TCC entry exists.
The process used the private entitlement `com.apple.private.screencapturekit.noprompt`
which bypasses all TCC checks and user prompts. The file was never deleted by the attacker —
it was discovered during the Jun 3 scan.

**Evidence:**
- File: `~/Desktop/Screen Recording 2026-06-02 at 6.24.56 PM.mov` (4.03 GB, preserved)
- Log: `replayd Starting!` at 09:26:09 CDT; crash + restart at 19:41 CDT
- TCC.db: no entry for replayd (entitlement bypass confirmed)
- Triggering client: PID 1373 (identity lost — logs rotated)
- MASTER-SECURITY-LOG.md lines 392–450

**Mitigations applied:**
- `launchctl disable gui/501/com.apple.replayd` ✅ 2026-06-03
- `com.apple.replayd.plist` deleted ✅ 2026-06-03
- `com.apple.replayd` + `com.apple.replaykit.sharingsession` → disabled.501.plist ✅ 2026-06-03
- LS deny rule: `/usr/libexec/replayd → DENY any` ✅ 2026-06-03
- replayd-guard daemon (kills replayd every 5s if running) ✅ 2026-06-03

**Still unknown:**
- Identity of PID 1373 (the triggering client)
- Whether attacker retrieved the recording before it was discovered
- Whether this was remote-triggered or a local process

**Status:** MITIGATED — controls prevent recurrence, but triggering client never identified

---

### V-004 | DuckDuckGo WhatsApp URL Tab Injection
**Severity:** HIGH
**Date:** 2026-06-08 (discovered 2026-06-09 morning)
**Type:** Browser manipulation / social engineering via LaunchServices URL delivery

**What happened:**
A new tab appeared in DuckDuckGo browser pointing to:
`https://api.whatsapp.com/send?phone=+8615937826701&text=Hello`
(+86 = China mainland, 159 = China Mobile). User did not navigate to this URL.
Most likely vector: a process called macOS LaunchServices `open url` API (requires
zero TCC permissions) to deliver the URL to DDG as an unloaded tab. DDG
session-restore then re-opened the tab on every subsequent launch.
LS blocked all TCP connections to api.whatsapp.com (8 blocks confirmed same day).

**Evidence:**
- DDG session restore plist contained the URL
- No WebKit storage for whatsapp.com (page never loaded — LS blocked it)
- LS api.whatsapp.com rule: useCount=8 (blocked 8 attempts Jun 9)
- MASTER-SECURITY-LOG.md lines 860+

**Mitigations applied:**
- LS deny rules: api.whatsapp.com, web.whatsapp.com, www.whatsapp.com ✅
- DDG tab should be closed by user ⚠️ PENDING

**Still unknown:**
- Which process delivered the URL via LaunchServices
- BSM auditing would have captured this; auditd blocked by macOS 16 policy

**Status:** MITIGATED — network blocked; URL delivery process not identified

---

### V-005 | Persistent Plist Regression (4 Consecutive Sessions)
**Severity:** HIGH
**Dates:** 2026-05-27 through 2026-06-01 (4 sessions)
**Type:** Persistent unauthorized state reset / launchd manipulation

**What happened:**
Every session, all 6 launchctl-disable entries vanished from disabled.501.plist.
The services disabled were exactly: RemoteManagementAgent, remotemanagementd,
sharingd, identityservicesd, replicatord, studentd — the full set of remote access
and telemetry services. The pattern was too specific to be coincidental.
Root cause confirmed: M-flag (Managed) services bypass launchctl disable writes.
Fix: PlistBuddy direct-write + schg immutable flag applied 2026-06-01.

**Mitigations applied:**
- schg flag applied to disabled.501.plist ✅ 2026-06-01
- All 11 entries re-added via PlistBuddy ✅ 2026-06-01
- plist-monitor daemon installed (detects writes) ✅ 2026-06-03

**Status:** MITIGATED — schg prevents regression; plist-monitor watches for attempts

---

### V-006 | DuckDuckGo Default Zoom Set to 50%
**Severity:** MEDIUM
**Date:** 2026-06-03 (discovered during scan 15)
**Type:** Browser configuration tampering

**What happened:**
DDG's page zoom was found set to 50% (0.5) in preferences. User did not set this.
Occurred the same session as the replayd recording incident (V-003). If attacker
had access to replayd stream, they could interact with the desktop via CGEventTap
or Remote Management to change settings.

**Mitigations applied:**
- Zoom reset to 1.0 ✅ 2026-06-03

**Still unknown:**
- Which process wrote the zoom preference

**Status:** MITIGATED — setting corrected; root cause unresolved

---

### V-007 | privatecloudcomputed 36 Outbound Connection Attempts
**Severity:** HIGH
**Date:** 2026-05-28
**Type:** Unauthorized exfiltration attempt (blocked)

**What happened:**
`privatecloudcomputed` (Apple Private Cloud Compute) made 36 outbound connection
attempts. All were blocked by LS deny rules. No data confirmed exfiltrated.

**Mitigations applied:**
- LS deny rule: privatecloudcomputed → DENY any ✅

**Status:** MITIGATED — network blocked; process still SIP-protected and running

---

### V-008 | DNS Total Loss
**Severity:** HIGH
**Date:** 2026-05-29
**Type:** Network configuration sabotage

**What happened:**
`dnsEncryptionConfigurations` was zeroed out after a LS model API violation at boot.
DoH (DNS-over-HTTPS) to Quad9 stopped working — all DNS failed. Caused by
unclean config write during May 28 session shutdown.

**Mitigations applied:**
- DNS configuration restored ✅
- Quad9 (9.9.9.9, 149.112.112.112) confirmed active ✅

**Status:** MITIGATED — monitoring for recurrence each boot

---

## CLOSED VIOLATIONS

### V-009 | AI Orchestrator Backdoor Discovery
**Severity:** CRITICAL
**Date:** 2026-05-11
**Type:** Supply chain / AI agent compromise

**What happened:**
Evidence of an AI orchestrator backdoor was discovered. Full details in
MASTER-SECURITY-LOG.md INCIDENT #1 and RESILIENCE-MANUAL.pdf.

**Status:** CLOSED — full remediation completed per resilience architecture

---

## SCAN CHECKLIST ADDITIONS (from this register)

Add to every scan:

```bash
# V-001: Verify Terminal→any LS rule is gone
python3 /Users/evw/dev/security/ls-permissive-analysis.py /tmp/ls-current.json | grep "CRITICAL\|UNSIGNED"
# Expected: [OK] No allow-any rules via unsigned binary

# V-002: Microphone TCC audit
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT service,client,auth_value,last_modified FROM access WHERE service='kTCCServiceMicrophone' ORDER BY auth_value DESC;"

# V-003: replayd still idle
pgrep replayd && echo "ALERT" || echo "OK"
sudo tail -3 /private/var/log/evw-replayd-guard.log

# V-004: WhatsApp LS blocks still active
python3 -c "import json; d=json.load(open('/tmp/ls-current.json')); wa=[r for r in d['rules'] if 'whatsapp' in str(r).lower() and r.get('action')=='deny']; print(f'WhatsApp deny rules: {len(wa)} (expect 3)')"

# V-005: plist schg + 11 entries
ls -lO /var/db/com.apple.xpc.launchd/disabled.501.plist | grep schg
sudo plutil -p /var/db/com.apple.xpc.launchd/disabled.501.plist | grep -c '"=> true"'
```
