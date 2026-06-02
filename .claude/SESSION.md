# Session State — 2026-06-02T17:10:00Z

## Accomplished This Session

- **Ran full daily scan (scan-2026-06-02)** — vs scan-2026-06-01b baseline.
- **schg flag confirmed survived** — mtime still Jun 1 13:38, flag present after overnight.
- **All monitored services CLEAR** — remotemanagementd, RemoteManagementAgent, sharingd, identityservicesd, replicatord, studentd, privatecloudcomputed — all NONE network. LS deny rules effective.
- **Zero binary hash changes** — all 14 monitored binaries identical to scan-2026-06-01b.
- **Security controls all green** — SIP, FileVault, Gatekeeper, Firewall, no MDM, no profiles.
- **LS deny rules analyzed** — May 29 backup (2,062 rules, 483 deny). Core hardening blocks verified: privatecloudcomputed, all RemoteManagement processes + XPC subscribers, studentd, telemetry trackers.
- **Identified memory key loss** — Keychain item `claude-security-memory-v1 / claude-ai` was missing at session start (last reboot likely cleared it). First `read short` call regenerated a new random key at 11:45 CDT. Both csmem files are now unreadable with the new key.
- **Identified memory key was lost, not tampered** — the `_get_or_create_key()` in `security-memory-manager.py:60-72` creates a new key when the Keychain item is absent. The item was absent (reboot or Keychain reset cleared it). The new key (created today at 11:45 CDT) does not match the csmem files.

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

4. **Recover encrypted memories OR re-initialize:**
   - Option A (recovery): `! python3 ~/dev/security/security-memory-manager.py import-recovery-key <hex-key-from-paper>`
     Then retry: `python3 ~/dev/security/security-memory-manager.py read short`
   - Option B (reinit): Re-build short-term and long-term memories from scan artifacts and SESSION.md history.

5. **Verify launchctl + ARDAgent deny rules in LS GUI:**
   These were in `deny-rules-remotemanagement-2026-05-29.lsrules` but not visible in the May 29 model backup — verify they're active in LS Rules window (search: `launchctl`, `ARDAgent`).

## Key Context

- **schg on disabled.501.plist** — mtime Jun 1 13:38 unchanged; flag confirmed present.
- **plist-monitor daemon** — should be operational (`/usr/local/bin/evw-plist-monitor.sh`); log needs sudo to check.
- **Memory key state** — new random key in Keychain as of Jun 2 11:45 CDT. Old key is GONE. Recovery key fingerprint from prior session: `56830115...2205b9`.
  - Paper recovery key in desk. Import with: `python3 security-memory-manager.py import-recovery-key <hex>`
- **LS model** — last readable backup is May 29 (2,062 rules, 483 deny). Jun 1 backup at 16:59 exists but requires root. Current model export requires root.
- **privatecloudcomputed + RemoteManagementAgent** — running with high PIDs (5862, 5938) — dasd respawned them ~6-7m post-boot. Both NONE network. LS deny rules working.
- **Daemon Containers** — now 0 (was 17 in Jun 1 scan). Normal cleanup.
- **OS version** — macOS 26.5 (25F71).
- **External connections** — Claude Code (2.1.160) → Anthropic only. Clean.

## Open Investigations

1. **Memory key loss on reboot** — Keychain item `claude-security-memory-v1` cleared at or before boot today. Root cause unknown: Keychain reset, OS behavior, or something else. Monitor across sessions.
2. **LS model API violations on boot** — monitor at each boot.
3. **osascript spawning ~60s** — needs Terminal FDA.
4. **6 wrong-domain launchctl entries** — M-flag symptom; low priority.
5. **XPC requester for privatecloudcomputed** — dasd is scheduler; original requester unknown.
6. **influxdata.com (Terminal, ~46 uses)** — confirm if Homebrew telemetry; deny if so.
