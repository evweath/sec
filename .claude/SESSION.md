# Session State — 2026-05-29T21:30:00-05:00

## Accomplished This Session

- **Ran daily scan** vs scan-2026-05-28 baseline. All controls green. 0 core binary hash changes. Output in `scan-2026-05-29/`.
- **Resolved disabled.501.plist regression (3rd consecutive session).** Re-applied all 7 launchctl disables interactively. Added APNS wakeup endpoint disables (`apns-dev`, `apns-prod`). Added LS deny-all rules for remotemanagementd, RemoteManagementAgent, ARDAgent kickstart, launchctl (`deny-rules-remotemanagement-2026-05-29.lsrules`).
- **Bootout attempts:** remotemanagementd already gone; RemoteManagementAgent SIP-blocked but zero network connections.
- **Diagnosed and resolved LS DNS over HTTPS failure.** Full root cause traced (see TRIAGE-REPORT.md). Fix: added `9.9.9.9 dns.quad9.net` to `/etc/hosts`; changed LS DoH server URL to `https://9.9.9.9/dns-query`. DNS confirmed stable (10/10 lookups clean).
- **Deep investigation into DoH config wipe.** Root cause: API violations at boot (08:32) caused LS to clean orphaned/duplicate rules from in-memory model, silently zeroing `dnsEncryptionConfigurations`. First GUI open at 15:01 flushed cleaned model to disk, triggering NE reload and hard timeout loop. Caused by unclean config write at end of May 28 session.

## In Progress

Nothing actively in progress.

## Next Steps (ordered)

1. **At start of next session — run checklist** (`memory/project_scan_checklist.md`):
   - `plutil -p /var/db/com.apple.xpc.launchd/disabled.501.plist` — verify all 9 entries present (7 core + 2 APNS endpoints)
   - Confirm privatecloudcomputed has no network connections
   - Confirm LS deny rules for remotemanagementd still active
   - Check `/etc/hosts` still has `9.9.9.9 dns.quad9.net`
2. **Verify memory integrity:**
   - `python3 ~/dev/security/security-memory-manager.py verify short`
   - `python3 ~/dev/security/security-memory-manager.py verify long`
3. **Authorize LS CLI export-model** in LS Preferences → Security so `sudo littlesnitch export-model` works (needed to verify rule count and deny rules without GUI)
4. **Run full daily scan** → new `scan-YYYY-MM-DD/` dir, diff vs `scan-2026-05-29/`
5. **Archive scan + commit + push** at end of session

## Key Context

- **disabled.501.plist — now 9 required entries** (previously 7):
  `RemoteManagementAgent`, `remotemanagementd`, `sharingd`, `identityservicesd`, `replicatord`, `studentd`, `privatecloudcomputed`, `aps.remotemanagementd.http.apns-dev`, `aps.remotemanagementd.http.apns-prod`
- **LS DoH:** `https://9.9.9.9/dns-query` (IP-based, not hostname — prevents bootstrap circular dependency)
- **LS DoH recovery command:** `sudo killall -HUP at.obdev.littlesnitch.daemon`
- **hosts entry:** `9.9.9.9 dns.quad9.net` added as bootstrap safety net
- **LS model API violations on boot:** indicator to watch — if they recur next boot it's a pattern (LS 6.3.3 bug or repeated unclean shutdown)
- **LS deny rules file:** `~/dev/security/scan-2026-05-29/deny-rules-remotemanagement-2026-05-29.lsrules`
- **LS CLI auth:** `sudo littlesnitch export-model` returns empty (not authorized) — authorize in LS Preferences → Security
- **Recovery key:** Paper, locked in desk. Fingerprint: `56830115...2205b9`
- **GitHub remote:** `https://github.com/evweath/sec.git` — encrypted blobs only
- **Memory manager:** `python3 ~/dev/security/security-memory-manager.py` — key in Keychain `claude-security-memory-v1 / claude-ai`
- **Open investigations:**
  - disabled.501.plist regression root cause (launchd boot reset?)
  - LS model API violations on boot (unclean write or LS 6.3.3 bug?)
  - osascript spawning ~60s (needs Terminal FDA)
  - 6 wrong-domain launchctl disabled entries
  - XPC requester for privatecloudcomputed
