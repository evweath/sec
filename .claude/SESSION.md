# Session State — 2026-05-28T21:15:00-05:00

## Accomplished This Session

- **Security scan vs 2026-05-27 baseline.** Output in `scan-2026-05-28/`. All controls green. 0 core binary changes. Findings: disabled.501.plist regressed (all 2026-05-27 disables missing), RemoteManagementAgent demand-started at 10:26 AM.
- **Re-applied all launchctl disables.** Interactive sudo confirmed persisted: RemoteManagementAgent, remotemanagementd, sharingd, identityservicesd, replicatord, studentd, privatecloudcomputed — all `=> true` in `disabled.501.plist`.
- **Disabled and killed privatecloudcomputed.** Deleted attestation store (`~/Library/Daemon Containers/D85CF66F-EC1E-4AF6-8179-27941EEEB340`). dasd background tasks keep respawning it in current session (SIP blocks bootout) — will not start after reboot.
- **Added LS deny-any-outgoing rule for privatecloudcomputed.** privatecloudcomputed had made 36 connection attempts to `gateway-oblivious.apple.com:443` before rule applied. Rule confirmed in model: `action=deny remote=any origin=unknown`. LS model now 2,033 rules.
- **Investigated python3.13 LS signature alert.** False positive — pyenv adhoc-signed binary, LS lost fingerprint cache after 2026-05-26 model restore.
- **Built encrypted security memory system** (`security-memory-manager.py`):
  - `memory/short_term.csmem` — AES-256-CBC, HMAC-verified, Keychain-keyed pending tasks
  - `memory/long_term.csmem` — AES-256-CBC, HMAC-chained append-only event log (7 entries)
  - `memory/scans/*.enc` — all 10 scan directories archived as encrypted tarballs
- **Committed and pushed to GitHub** (`github.com/evweath/sec`). Plaintext scan dirs excluded via `.gitignore`.
- **Exported recovery key** — paper copy locked in desk. Fingerprint: `56830115...2205b9`.

## In Progress

Nothing actively in progress.

## Next Steps (ordered)

1. **At start of next session — run checklist** (`memory/project_scan_checklist.md`):
   - `plutil -p /var/db/com.apple.xpc.launchd/disabled.501.plist` — verify all 7 entries present
   - Confirm privatecloudcomputed did not rebuild attestation store
   - Confirm LS deny rule for privatecloudcomputed still active
2. **Verify memory integrity** before anything else:
   - `python3 ~/dev/security/security-memory-manager.py verify short`
   - `python3 ~/dev/security/security-memory-manager.py verify long`
3. **Run full daily scan** → new `scan-YYYY-MM-DD/` dir, diff vs `scan-2026-05-28/` and `scan-2026-05-18/` baseline
4. **Archive scan + commit + push** at end of session

## Key Context

- **disabled.501.plist regression pattern**: All 2026-05-27 disables vanished by 2026-05-28. Suspected cause: `privatecloudcomputed` dasd background tasks resetting launchd config. Now disabled — monitor whether regression recurs.
- **privatecloudcomputed**: Disabled in plist + LS deny-any rule active. dasd XPC tasks still respawn it in running sessions (SIP blocks bootout) — no network connections possible. Will not start after reboot.
- **Recovery key**: Paper, locked in desk. Hex: `56830115a8ae8c040e4d98151febdc0092b46d47d35313dd2b6730b82b2205b9`. Restore cmd: `python3 security-memory-manager.py import-recovery-key <hex>`
- **GitHub remote**: `https://github.com/evweath/sec.git` — encrypted blobs only, no plaintext scan data
- **Little Snitch CLI**: Must be authorized in LS Preferences → Security before `sudo littlesnitch export-model` works
- **Scan convention**: diff new scans against `scan-2026-05-28/` (latest) and `scan-2026-05-18/` (deep baseline)
- **Memory manager**: `python3 ~/dev/security/security-memory-manager.py` — key in Keychain `claude-security-memory-v1 / claude-ai`
- **Open investigations**:
  - osascript spawning every ~60s — needs Terminal FDA for `fs_usage` to trace parent
  - 6 wrong-domain launchctl disabled entries (LaunchAgents disabled at system domain — no effect)
  - What process is the original XPC requester waking privatecloudcomputed (dasd is scheduler, not originator)
