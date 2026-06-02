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
