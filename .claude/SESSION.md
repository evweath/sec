# Session State — 2026-06-02T17:10:00Z

## Accomplished This Session

- **Ran full daily scan (scan-2026-06-02)** — vs scan-2026-06-01b baseline.
- **schg flag confirmed survived** — mtime still Jun 1 13:38, flag present after overnight.
- **All monitored services CLEAR** — remotemanagementd, RemoteManagementAgent, sharingd, identityservicesd, replicatord, studentd, privatecloudcomputed — all NONE network. LS deny rules effective.
- **Zero binary hash changes** — all 14 monitored binaries identical to scan-2026-06-01b.
- **Security controls all green** — SIP, FileVault, Gatekeeper, Firewall, no MDM, no profiles.
- **LS deny rules analyzed** — May 29 backup (2,062 rules, 483 deny). Core hardening blocks verified: privatecloudcomputed, all RemoteManagement processes + XPC subscribers, studentd, telemetry trackers.
- **Verified encrypted memories intact** — short_term HMAC ✓ (2026-06-01T18:46:11Z), long_term HMAC ✓ chain of 13 entries (2026-06-01T20:20:46Z). Initial read attempt failed transiently; user-run attempt succeeded. Keychain key is intact.

## In Progress

Nothing actively in progress.

## Next Steps (ordered)

1. **URGENT — Verify plist entries (sudo required):**
   ```bash
   ! sudo plutil -p /var/db/com.apple.xpc.launchd/disabled.501.plist
   ```
   Expected: all 9 entries `=> true`. If missing, schg was somehow removed — escalation.

2. **Check plist-monitor log (sudo required):**
   ```bash
   ! sudo cat /private/var/log/evw-plist-monitor.log | tail -30
   ! sudo cat /private/var/log/evw-plist-monitor-err.log | tail -10
   ```
   Expected: start banner from last boot, no write-attempt entries.

3. **Export current LS model (sudo required):**
   ```bash
   ! sudo /Applications/Little\ Snitch.app/Contents/Components/littlesnitch export-model /Users/evw/dev/security/scan-2026-06-02/ls-model.json
   ```
   Then compare rule counts vs May 29 backup (2,062 total, 483 deny).

4. **Verify launchctl + ARDAgent deny rules in LS GUI:**
   These were in `deny-rules-remotemanagement-2026-05-29.lsrules` but not visible in the May 29 model backup — verify they're active in LS Rules window (search: `launchctl`, `ARDAgent`).

## Key Context

- **schg on disabled.501.plist** — mtime Jun 1 13:38 unchanged; flag confirmed present.
- **plist-monitor daemon** — should be operational (`/usr/local/bin/evw-plist-monitor.sh`); log needs sudo to check.
- **Memory key state** — Keychain item intact; both memories verified readable. Recovery key fingerprint: `56830115...2205b9` (paper, desk).
- **LS model** — last readable backup is May 29 (2,062 rules, 483 deny). Jun 1 backup at 16:59 exists but requires root. Current model export requires root.
- **privatecloudcomputed + RemoteManagementAgent** — running with high PIDs (5862, 5938) — dasd respawned them ~6-7m post-boot. Both NONE network. LS deny rules working.
- **Daemon Containers** — now 0 (was 17 in Jun 1 scan). Normal cleanup.
- **OS version** — macOS 26.5 (25F71).
- **External connections** — Claude Code (2.1.160) → Anthropic only. Clean.

## Open Investigations

1. **LS model API violations on boot** — monitor at each boot.
3. **osascript spawning ~60s** — needs Terminal FDA.
4. **6 wrong-domain launchctl entries** — M-flag symptom; low priority.
5. **XPC requester for privatecloudcomputed** — dasd is scheduler; original requester unknown.
6. **influxdata.com (Terminal, ~46 uses)** — confirm if Homebrew telemetry; deny if so.

---

# Session State — 2026-06-03 (appended)

## Accomplished This Session

- **Touch ID investigation**: Root cause identified — unexplained reboot at 09:26 CDT Jun 2 triggered keybagd UUID repair (`kb_set_user_uuid [501:-501]` + `fv_bind_keybag_to_kek`), wiping Touch ID enrollment (enrolledIdentityCount 1→0). Persistent `user_uuid_mismatch=1` / `group_uuid_mismatch=1` in keybag traced to ew→evw migration May 15 (straight file copy, no Secure Enclave migration). Logged as INCIDENT #15.
- **replayd screen recording**: Found `com.apple.replayd` (PID 1472) running with `video=1`, capturing near-full-screen region (1463×736 pts at X=7, Y=123). Wrote 2148 MB over 8.5 hours (09:26–18:47 CDT Jun 2) before OS killed it. Plist re-written 19:41 after crash. User did NOT enable this. Logged as INCIDENT #14.
- **Spontaneous 500% zoom**: Checked all user-space vectors — no mechanism found. Logged as INCIDENT #16, OPEN.
- **Long-term log**: 3 entries appended (#14 replayd, #15 Touch ID/reboot, #16 zoom). Now 16 entries.
- **Short-term memory**: Updated with immediate actions and next-session checklist.
- **Scan checklist updated**: Added steps 6 (replayd), 7 (TCC screen-capture audit), 8 (keybag mismatch).
- **MEMORY.md updated**.
- **Policy established**: Security records are append-only; SESSION.md gets new dated sections appended, never overwritten.

## In Progress

- **replayd not yet killed/disabled** — run immediately (see Next Steps #1).
- **Touch ID not yet re-enrolled** — System Settings action needed.
- **Zoom mechanism unresolved** — needs root-level TCC audit.

## Next Steps (ordered — highest priority first)

### IMMEDIATE — run now

1. **Kill and disable replayd:**
   ```bash
   ! kill $(pgrep replayd) 2>/dev/null; echo "kill sent"
   ! rm ~/Library/Preferences/com.apple.replayd.plist
   ! launchctl disable gui/501/com.apple.replayd
   ! launchctl disable gui/501/com.apple.replaykit.sharingsession
   ! sleep 2; pgrep replayd && echo "STILL RUNNING — escalate" || echo "OK: dead"
   ```

2. **Re-enroll Touch ID**: System Settings → Touch ID & Password → Add Fingerprint

3. **Reset DuckDuckGo zoom**: Cmd+0 in browser; confirm View menu shows 100%.

### Next scan session (requires sudo)

4. **Audit TCC grants:**
   ```bash
   ! sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
     "SELECT service, client, auth_value, last_modified FROM access \
      WHERE service IN ('kTCCServiceScreenCapture','kTCCServiceAccessibility','kTCCServiceListenEvent') \
      ORDER BY service, auth_value DESC;"
   ```

5. **Add replayd to disabled.501.plist** (belt-and-suspenders):
   ```bash
   ! sudo chflags noschg /var/db/com.apple.xpc.launchd/disabled.501.plist
   ! sudo /usr/libexec/PlistBuddy -c "Add :com.apple.replayd bool true" /var/db/com.apple.xpc.launchd/disabled.501.plist
   ! sudo /usr/libexec/PlistBuddy -c "Add :com.apple.replaykit.sharingsession bool true" /var/db/com.apple.xpc.launchd/disabled.501.plist
   ! sudo chflags schg /var/db/com.apple.xpc.launchd/disabled.501.plist
   ```

6. **Investigate reboot cause** (pre-boot logs need root):
   ```bash
   ! sudo log show --predicate 'process == "kernel" OR process == "shutdown"' \
     --start "2026-06-01 20:00:00" --end "2026-06-02 09:30:00" \
     | grep -iE "shutdown|reboot|panic|update|restart"
   ```

7. **Prior open items** (carried forward):
   - Verify disabled.501.plist 9 entries + schg
   - Check plist-monitor log
   - Export LS model + compare vs May 29 (2,062 total, 483 deny)
   - Verify ARDAgent + launchctl deny rules in LS GUI
   - influxdata.com — deny if Homebrew telemetry

## Key Context

- **replayd**: label `com.apple.replayd`, PID 1472. Plist born Jun 2 19:41 CDT. video=1, region 1463×736 at X=7 Y=123.
- **Touch ID**: unenrolled. keybag UUID mismatch persists — Touch ID wipe will recur on future keybag repair events.
- **User UUID**: `87EA61F4-6B7C-458F-9B10-E6AE78B74957` (evw, UID 501).
- **Memory key**: Keychain intact. Recovery fingerprint: `56830115...2205b9` (paper, desk).
- **OS**: macOS 26.5 (25F71). No MDM, no profiles.

## Open Investigations

1. Who triggered replayd — TCC audit with root needed
2. What caused Jun 2 reboot — root logs needed
3. Spontaneous zoom — no mechanism found; firmware/kernel implant cannot be excluded
4. keybag UUID mismatch — Touch ID wipe expected to recur
5. influxdata.com — ~46 Terminal connections, deny in LS pending
6. osascript spawning ~60s post-boot — needs Terminal FDA
7. XPC requester for privatecloudcomputed — dasd is scheduler; original requester unknown
