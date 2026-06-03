# Session State — 2026-06-03T17:45:00Z

## Policy
Security records are append-only. This file gets new dated sections appended, never overwritten.

---

# Session State — 2026-06-02 (prior session summary)

## Accomplished
- schg applied to disabled.501.plist — first clean post-reboot plist in 4+ sessions
- plist-monitor daemon fixed and deployed
- LS model exported (3,140 rules), launchctl + ARDAgent deny rules re-added
- influxdata.com Terminal deny rule confirmed active
- L5 (OpenTimestamps) implemented: 28-file manifest + 1,984-file fs-baseline, both Bitcoin-anchored
- MASTER-SECURITY-LOG.md created (549 lines), PDF generated
- utun interfaces verified: all Apple system processes, no ProtonVPN, all idle

---

# Session State — 2026-06-03

## Accomplished This Session

- **Full security scan** — all controls green, all 7 monitored services NONE network, 0 binary changes
- **LS rule audit** — all 14 critical deny rules present, 15/15 XPC subscribers blocked, 0 drops, model at 3,188 rules / 1,348 deny
- **Discovered INCIDENT #14: replayd unauthorized screen recording**
  - 4.03 GB, 8.5 hours (09:26–19:41 CDT Jun 2), no user prompt, no orange dot, no TCC entry
  - SHA-256: `2bd93974e2a91d9e74fad6c73399047a32a7118cf18d3baece2b409685a83898`
  - File: `Screen Recording 2026-06-02 at 6.24.56 PM.mov` (Desktop, U+202F in filename)
  - Entitlement `com.apple.private.screencapturekit.noprompt` bypasses TCC entirely
  - ControlCenter has `suppress-screen-indicator` — recording dot hidden
  - Client PID 1373 connected at boot — identity unknown (logs rotated)
- **replayd mitigations applied:**
  - `launchctl disable gui/501/com.apple.replayd` ✓
  - `launchctl disable gui/501/com.apple.replaykit.sharingsession` ✓
  - `~/Library/Preferences/com.apple.replayd.plist` deleted ✓
  - LS deny rule for `/usr/libexec/replayd` → DENY any ✓
  - `com.apple.replayd` + `com.apple.replaykit.sharingsession` added to disabled.501.plist via PlistBuddy ✓
  - schg re-applied ✓
- **Plist entry count expanded: 9 → 11**
- **Scan checklist updated** to verify 11 entries
- **plist-monitor grep fix redeployed** (`-F` fixed-string matching confirmed active)
- **OTS proofs upgraded** — both fs-baseline and manifest Bitcoin-confirmed (3 calendar attestations)
- **MASTER-SECURITY-LOG.md updated** — Scan 15, Incident 6, updated defense state, PDF regenerated (50KB)

## In Progress

Nothing actively in progress.

## Next Steps (ordered — highest priority first)

### IMMEDIATE

1. **Preserve the recording file offline:**
   - File: `~/Desktop/Screen Recording 2026-06-02 at 6.24.56 PM.mov` (4.03 GB)
   - Hash confirmed: `2bd93974e2a91d9e74fad6c73399047a32a7118cf18d3baece2b409685a83898`
   - Copy to encrypted offline storage (L3/L4) before it disappears
   - Do NOT delete — it is forensic evidence

2. **At next reboot — verify all 11 plist entries survived:**
   ```bash
   ! sudo plutil -p /var/db/com.apple.xpc.launchd/disabled.501.plist | grep -E "replayd|replaykit|RemoteManagement|sharingd|identityservices|replicatord|studentd|privatecloudcomputed|apns"
   ```
   Expected: all 11 entries `=> true`

3. **At next reboot — check if replayd starts another recording:**
   ```bash
   ! pgrep replayd && lsof -p $(pgrep replayd) | grep -v "txt\|mem\|cwd\|rtd\|DEL\|metal\|functions\|libraries"
   ```
   If any video file is open: escalate immediately

4. **TCC audit — requires root:**
   ```bash
   ! sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
     "SELECT service,client,auth_value,last_modified FROM access \
      WHERE service IN ('kTCCServiceScreenCapture','kTCCServiceAccessibility','kTCCServiceListenEvent') \
      ORDER BY service, auth_value DESC;"
   ```

5. **Investigate Jun 2 reboot — requires root:**
   ```bash
   ! sudo log show --predicate 'process == "kernel" OR process == "shutdown"' \
     --start "2026-06-01 20:00:00" --end "2026-06-02 09:30:00" \
     | grep -iE "shutdown|reboot|panic|update|restart"
   ```

6. **Re-enroll Touch ID:** System Settings → Touch ID & Password → Add Fingerprint

### Next scan session

7. **Run standard checklist** — verify 11 plist entries, check plist-monitor log, export LS model
8. **Run weekly L5 stamp:** `bash ~/dev/security/l5-stamp.sh`
9. **Consider Citizen Lab / Access Now contact** — replayd incident + plist regression pattern meets reporting threshold

## Key Context

- **disabled.501.plist** — schg present (Jun 1 13:38 mtime); now 11 required entries
  - To reverse schg: `sudo chflags noschg /var/db/com.apple.xpc.launchd/disabled.501.plist`
  - To add entries: `sudo /usr/libexec/PlistBuddy -c "Add :label bool true" /var/db/...`
- **replayd** — SIP-protected M-flag service; cannot be permanently killed; mitigations in place
  - Currently running but idle (no open video files as of Jun 3 11:43 CDT)
  - User plist deleted; launchctl disabled; LS deny rule active; disabled.plist entries added
- **Recording file** — Desktop, 4.03 GB, U+202F in filename (use python3 os.listdir to find exact name)
- **L5 OTS** — both proofs Bitcoin-confirmed. Next weekly stamp: `bash ~/dev/security/l5-stamp.sh`
- **LS model** — 3,188 rules / 1,348 deny. Saved: `scan-2026-06-03/ls-model.json`
- **Memory key** — Keychain intact. Recovery fingerprint: `56830115...2205b9` (paper, desk)
- **OS** — macOS 26.5 (25F71). No MDM, no profiles. Claude Code v2.1.161 (updated from 2.1.160)

## Open Investigations

1. **replayd trigger** — client PID 1373 at boot Jun 2; identity unknown; logs rotated
2. **Jun 2 reboot** — unexplained; triggered replayd recording; root logs needed
3. **Touch ID keybag UUID mismatch** — from ew→evw migration May 15; wipe expected to recur
4. **LS model API violations at boot** — monitor each boot
5. **osascript spawning ~60s** — needs Terminal FDA
6. **XPC requester for privatecloudcomputed** — dasd is scheduler; original unknown
