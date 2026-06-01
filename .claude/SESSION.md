# Session State — 2026-06-01T14:30:00-05:00

## Accomplished This Session

- **Ran full daily scan (scan-2026-06-01b)** — post-reboot, vs scan-2026-06-01 baseline.
- **Confirmed schg survived reboot** — plist mtime unchanged (13:38) after boot at 13:48 CDT. First successful persistence in 4+ sessions.
- **Confirmed all 9 plist entries intact post-reboot** — first clean plist after reboot in recorded history. 4-session regression cycle is broken.
- **Fixed plist-monitor daemon** — copied `evw-plist-monitor.sh` to `/usr/local/bin/`, kickstarted `system/com.evw.plist-monitor`. Daemon running (PID 3411), logging to `/private/var/log/evw-plist-monitor.log`.
- **Investigated `com.apple.macos.studentd => false`** — confirmed phantom entry; filename ≠ label. Real service label is `com.apple.studentd` which IS disabled (true). No action needed.
- **Scan-2026-06-01b artifacts** saved in `~/dev/security/scan-2026-06-01b/`.

## In Progress

Nothing actively in progress.

## Next Steps (ordered)

1. **At next boot — verify schg + plist still clean:**
   ```bash
   ls -lO /var/db/com.apple.xpc.launchd/disabled.501.plist
   sudo plutil -p /var/db/com.apple.xpc.launchd/disabled.501.plist
   ```
   Expected: schg flag present, all 9 entries true, mtime still 2026-06-01 13:38.

2. **After next boot — check monitor log for write attempts:**
   ```bash
   sudo cat /private/var/log/evw-plist-monitor.log
   sudo cat /private/var/log/evw-plist-monitor-err.log
   ```
   Expected: start banner + target line, then any write-attempt forensics. If fs_usage had permission issues, the err log will show it.

3. **Run standard checklist** (`memory/project_scan_checklist.md`) — updated below to reflect new permanent state.

4. **Update scan checklist** (low priority — do at start of next session):
   - Replace "re-apply launchctl disables" with "verify schg flag present"
   - Add "check monitor log for write attempts since last boot"
   - Remove regression as expected finding — it is now expected to NOT occur

## Key Context

- **disabled.501.plist is schg-immutable** at `/var/db/com.apple.xpc.launchd/disabled.501.plist`
  - To reverse: `sudo chflags noschg /var/db/com.apple.xpc.launchd/disabled.501.plist`
  - All 9 required entries confirmed present post-reboot as of 2026-06-01 ~14:00 CDT
- **plist-monitor daemon now operational**
  - Script: `/usr/local/bin/evw-plist-monitor.sh` (source: `/Users/evw/dev/security/evw-plist-monitor.sh`)
  - Log: `/private/var/log/evw-plist-monitor.log`
  - Error log: `/private/var/log/evw-plist-monitor-err.log`
  - Daemon plist: `/Library/LaunchDaemons/com.evw.plist-monitor.plist`
  - `runs = 178` is historical (prior failed attempts); stable now
- **Defense-in-depth now complete:**
  - schg blocks writes to plist at kernel level
  - plist-monitor logs any write attempt with process name/PID + plist snapshot
  - LS deny rules block network for managed services
- **Root cause confirmed (prior session):** Managed (M-flag) services ignore disabled.plist — launchctl disable is futile for them. schg is the correct persistence mechanism.
- **M A services (will always run):** sharingd, studentd, identityservicesd, replicatord
- **No-M services (launchctl disable works):** remotemanagementd
- **LS DoH:** `https://9.9.9.9/dns-query` (IP-based); hosts entry `9.9.9.9 dns.quad9.net` present
- **LS deny rules active:** privatecloudcomputed, remotemanagementd, RemoteManagementAgent, ARDAgent kickstart, launchctl
- **Memory manager:** `python3 ~/dev/security/security-memory-manager.py` — key in Keychain `claude-security-memory-v1 / claude-ai`
- **Recovery key:** Paper, locked in desk. Fingerprint: `56830115...2205b9`
- **GitHub remote:** `https://github.com/evweath/sec.git` — encrypted blobs only

## Open Investigations

1. **LS model API violations on boot** — caused the May 29 DoH incident. Monitor at next boot.
2. **osascript spawning ~60s** — needs Terminal FDA.
3. **6 wrong-domain launchctl entries** — understood as M-flag symptom; low priority.
4. **XPC requester for privatecloudcomputed** — dasd is scheduler; original requester unknown.
5. **fs_usage permissions in monitor** — confirm at next boot that err log is empty and write events are being captured.
