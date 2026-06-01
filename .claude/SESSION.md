# Session State — 2026-06-01T20:00:00-05:00

## Accomplished This Session

- **Ran full daily scan** vs scan-2026-05-29 baseline. Output in `scan-2026-06-01/`.
- **Confirmed disabled.501.plist regression (4th consecutive session).** 6 of 9 entries missing at scan start.
- **Identified root cause of recurring regression.** 5 of 6 target services carry the `M` (Managed) flag in launchd — `launchctl disable gui/501/X` is a no-op for Managed services. The managed registry (APNS/push-wakeup layer) controls their enabled state independently of disabled.plist. `remotemanagementd` survives because it has no M flag.
- **Re-applied all 9 launchctl disables interactively.** All 9 verified present via `plutil`.
- **Applied BSD `schg` (system immutable) flag** to `/var/db/com.apple.xpc.launchd/disabled.501.plist`. Write-blocked confirmed (`Operation not permitted` even for current user). Flag survives reboots. No SIP change required.
- **Identified plist-monitor daemon as broken.** Script missing at `/usr/local/bin/evw-plist-monitor.sh` — has been failing since installation. Source at `/Users/evw/dev/security/evw-plist-monitor.sh`.
- **Generated PDF report** (`scan-2026-06-01/security-scan-2026-06-01.pdf`) covering all findings, root cause analysis, and controls.
- **All other controls clean:** 0 binary hash changes, all signatures valid, memory HMAC valid, no privatecloudcomputed attestation store, network = Claude → Anthropic only.

## In Progress

Nothing actively in progress.

## Next Steps (ordered)

1. **After next reboot — verify schg held:**
   ```
   ls -lO /var/db/com.apple.xpc.launchd/disabled.501.plist && plutil -p /var/db/com.apple.xpc.launchd/disabled.501.plist
   ```
   Confirm: `schg` flag still present, all 9 entries still `true`.
   Also check: do managed services (sharingd, studentd, identityservicesd, replicatord) still start? Expected: yes (M flag wins for running state). Expected improvement: entries no longer disappear from plist.

2. **Fix plist-monitor daemon:**
   ```
   sudo cp /Users/evw/dev/security/evw-plist-monitor.sh /usr/local/bin/evw-plist-monitor.sh
   sudo chmod 755 /usr/local/bin/evw-plist-monitor.sh
   sudo launchctl kickstart system/com.evw.plist-monitor
   ```
   Note: the monitor tries to write to the plist — with schg set, those writes will fail. May need to update the script to use `noschg → write → schg` pattern, or change it to monitor-only (no write) and alert instead.

3. **Run checklist at start of next session** (`memory/project_scan_checklist.md`):
   - Verify `schg` flag still on plist
   - Verify all 9 entries still present
   - Confirm privatecloudcomputed has no network connections
   - Confirm LS deny rules for remotemanagementd still active

4. **Update scan checklist** to reflect new permanent state:
   - Remove "re-apply launchctl disables" from remediation steps for managed services
   - Add "verify schg flag" as checklist item #1
   - Add note: schg is the persistence mechanism now; launchctl disable re-application only needed if flag is cleared

## Key Context

- **disabled.501.plist is now schg-immutable** at `/var/db/com.apple.xpc.launchd/disabled.501.plist`
  - To reverse: `sudo chflags noschg /var/db/com.apple.xpc.launchd/disabled.501.plist`
  - Contains all 9 required entries as of 2026-06-01T13:38 CDT
- **Root cause confirmed:** Managed (M-flag) services ignore disabled.plist — launchctl disable is futile for them. LS deny rules are the correct/only network-layer mitigation.
- **M A services (will always run, can't disable via launchctl):** sharingd, studentd, identityservicesd, replicatord
- **M D services (already disabled by managed framework):** RemoteManagementAgent, RemoteManagementAgent.store
- **No-M services (launchctl disable works):** remotemanagementd
- **plist-monitor daemon broken** — script missing at `/usr/local/bin/evw-plist-monitor.sh`; needs copy from `/Users/evw/dev/security/evw-plist-monitor.sh`. Also needs logic update if it tries to write to the now-immutable plist.
- **LS DoH:** `https://9.9.9.9/dns-query` (IP-based); hosts entry `9.9.9.9 dns.quad9.net` still present
- **LS deny rules active:** privatecloudcomputed (from 2026-05-28), remotemanagementd, RemoteManagementAgent, ARDAgent kickstart, launchctl (all from 2026-05-29)
- **Memory manager:** `python3 ~/dev/security/security-memory-manager.py` — key in Keychain `claude-security-memory-v1 / claude-ai`
- **Recovery key:** Paper, locked in desk. Fingerprint: `56830115...2205b9`
- **GitHub remote:** `https://github.com/evweath/sec.git` — encrypted blobs only

## Open Investigations

1. **schg effectiveness on managed services** — does immutable plist affect managed service startup at boot? Won't know until next reboot.
2. **LS model API violations on boot** — caused the May 29 DoH incident. Monitor at next boot.
3. **osascript spawning ~60s** — needs Terminal FDA.
4. **6 wrong-domain launchctl entries** — understood as M-flag symptom; low priority.
5. **XPC requester for privatecloudcomputed** — dasd is scheduler; original requester unknown.
