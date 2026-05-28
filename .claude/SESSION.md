# Session State — 2026-05-21T19:05:00-05:00

## Accomplished This Session

- **Security scan vs 2026-05-18 baseline.** Output in `/Users/evw/dev/security/scan-2026-05-21/`. All security controls verified on (SIP, FileVault, Gatekeeper, App Firewall + stealth, no MDM, no DEP, no config profiles). Diff vs baseline: +134/-3 system binary hashes, all in macOS cache paths (`/usr/libexec/*.mlmodelc/`, `.momd/`, TrustKitResources) — normal regeneration, not tampering. Reports: `persistence-launch.txt`, `persistence-kexts-sysexts.txt`, `network-state.txt`, `signature-audit.txt`, `suspect-paths.txt`, `security-controls.txt`, `system-binary-hashes.txt`, `diff-hashes.txt`.
- **Investigated white screen flash every ~20s.** Identified mechanism: WindowServer's coreanimation cursor briefly disables (`Cursor disabled: failed set_cursor_surface` log error) at ~30s intervals. WindowServer is in a 1Hz redraw loop emitting `_CGXPackagesSetWindowConstraints: Invalid window` on thread 0x1853 at 23.8% CPU. Correlated with periodic `osascript` spawn-and-die (every ~60s) and `studentd` hangs during WindowServer pings. Conclusion: cosmetic display bug, not active exfiltration. Captured 1018-line `flash-stream.log`.
- **Disabled Apple RemoteManagement stack.** Ran `disable-remotemgmt.sh` then `kill-remotemgmt.sh` via sudo. 24 RemoteManagement processes (remotemanagementd PID 1250 + 11 XPC subscribers in `_rmd` domain + RemoteManagementAgent PID 1329 + 12 subscribers in user 501 domain) all killed and **did NOT respawn** — confirmed at +3s, +13s, and 10+ min later.
- **Attempted studentd disable, partially succeeded.** Apple Classroom student daemon at `/usr/libexec/studentd`. Plist filename is `com.apple.macos.studentd.plist` but the actual `Label` field is `com.apple.studentd` — this mismatch caused all prior disable attempts to silently fail. `fix-studentd-final.sh` correctly targeted `gui/501/com.apple.studentd` and deleted KeepAlive trigger file `~/Library/studentd/isConnected`, but **studentd respawned anyway** (SIP-protected essential service). Disabled list is correctly populated now: `com.apple.studentd => disabled` in `gui/501`, stale `com.apple.macos.studentd` wrong-label entry cleared.
- **Audited launchd disabled-state files.** Cross-referenced every entry in `/var/db/com.apple.xpc.launchd/disabled.plist` (system, 22 entries) and `disabled.501.plist` (user, 7 entries) against actual plist files. Report: `scan-2026-05-21/disabled-audit-report.txt`. Findings: **6 WRONG_DOMAIN entries** (LaunchAgents disabled at system level): `com.apple.RemoteDesktop.agent`, `com.apple.amp.mediasharingd`, `com.apple.screensharing.MessagesAgent`, `com.apple.screensharing.agent`, `com.apple.screensharing.menuextra`, `com.apple.studentd`. **5+ NOT_FOUND entries**: `com.apple.AppleFileServer`, `com.apple.InternetSharing`, `com.apple.classroom`, `com.apple.classroomd`, `com.apple.classroomkit`, `com.apple.ftpd`, `com.apple.teacherd`. 57 system-wide filename-vs-Label mismatches in `launchd-filename-label-mismatches.txt`.
- **Exported Little Snitch model.** 491KB JSON at `scan-2026-05-21/ls-model.json`, 661 rules. Analyzed: 8 outgoing-allow any-host any-port (5 Apple-protected factory, 3 user-added — 2 of which are already disabled). **DuckDuckGo's `any` rule has useCount=3,776 and is still ENABLED** — biggest single fix. 264 specific-host allow rules lack port restriction. 25 enabled allow rules for non-Apple processes (22 are DuckDuckGo, including outgoing to `datadoghq.com`, `found.io`, `base44.com`, `anthropic.com`, `claude.ai`).
- **Generated `proposed-deny-rules.lsrules`** with 20 deny rules: 2 DuckDuckGo telemetry blocks (`*.datadoghq.com`, `*.found.io`), 1 `/usr/libexec/studentd` block, 17 `RemoteManagement.framework` family blocks. Validated JSON. **NOT YET IMPORTED into Little Snitch.**
- **Updated `~/.claude/settings.json` globally:**
  - `"model": "claude-sonnet-4-6"` — new sessions default to Sonnet 4.6 instead of Opus 4.7
  - 41 read-only diagnostic patterns added to bash allowlist: `pgrep`, `lsof`, `ps`, `launchctl list/print/print-disabled`, `plutil -p/-extract/-convert`, `codesign -dv`, `log show/stream`, `defaults read`, `scutil`, `ifconfig`, `netstat`, `arp`, `find /System|/Library|/usr|/var|/tmp|/opt`, `stat`, `file`, `date`, `diff`, `profiles status/list`, `systemextensionsctl list`, `kmutil showloaded`, `csrutil status`, `fdesetup status`, `spctl --status`, `sw_vers`, `id`, `crontab -l`.
- **Saved memory:** `~/.claude/projects/-Users-evw-dev-security/memory/feedback_autonomy.md` — execute reasonable next steps without menu-prompting; confirm only for destructive/irreversible actions. Indexed in `MEMORY.md`.

## In Progress

Nothing actively in progress at end-of-session.

## Next Steps (ordered)

1. **Import `proposed-deny-rules.lsrules` into Little Snitch.** Path: `/Users/evw/dev/security/scan-2026-05-21/proposed-deny-rules.lsrules`. Open Little Snitch.app → Rules window (⌘+R) → drag the file in → review each rule in the import dialog → accept what's wanted.
2. **Edit the DuckDuckGo any-any rule in Little Snitch UI.** Cannot be modified via `.lsrules` import. In LS Rules window, search `duckduckgo`, find the rule with Remote=Any + Port=any (useCount 3776), change Action → Deny, or delete it.
3. **(Optional) Fix the 6 wrong-domain and 5 not-found entries in launchctl disabled lists.** Script not yet written; would re-disable at the correct `gui/501` domain with correct Labels.
4. **(Optional) Tighten 264 specific-host allow rules with port=443 restrictions.** Risky — would require per-rule judgment about which port to allow. Most are Apple system services or browser HTTPS endpoints.
5. **(Optional) Investigate what's spawning osascript every 60s.** First attempt (`hunt-osascript-parent.sh` using `fs_usage`) failed — `fs_usage` needs Full Disk Access for Terminal. Grant Terminal FDA in System Settings → Privacy & Security and retry, or try `sudo log stream --predicate 'eventMessage CONTAINS "osascript"'` with a wider window.

## Key Context

- **User's threat model**: nation-state-level. ~4 prior compromise cycles. Memory: `[[user-threat-model]]`, `[[project-resilience-architecture]]`. Hardening hasn't stuck across cycles; defending the WORK (L1–L6 framework) is the strategic move, not defending the device.
- **User wants high autonomy.** Saved in `[[feedback-autonomy]]`. Don't gate every recommendation behind a menu. Confirm for destructive ops only.
- **studentd / remotemanagementd respawn = Apple SIP-protection, not adversarial.** Confirmed: no MDM, no DEP, no config profiles, no network connections from remotemanagementd, no install.log re-enable evidence. The "disable didn't stick" perception is explained by the filename-vs-Label mismatch (`com.apple.studentd` Label vs `com.apple.macos.studentd.plist` filename) and the WRONG_DOMAIN issue (LaunchAgents disabled at system domain — no effect).
- **Screen flash is cosmetic.** WindowServer in a 1Hz invalid-window redraw loop. NOT screen-capture / exfil. Logging out + back in restarts WindowServer; reboot definitely clears it.
- **Little Snitch rules can be ADDED via `.lsrules` drag-and-drop, but not MODIFIED.** To change an existing rule's action you must use the LS GUI. The `littlesnitch` CLI (`/Applications/Little Snitch.app/Contents/Components/littlesnitch`) requires root and supports: `export-model`, `restore-model` (full replace, dangerous), `rulegroup` (enable/disable groups), `list-preferences`, `log`, `log-traffic`. No incremental import command.
- **Scripts in `/Users/evw/dev/security/scan-2026-05-21/`:**
  - `disable-remotemgmt.sh` — disables system + user level RemoteManagement/ScreenSharing/RemoteDesktop launchd services
  - `kill-remotemgmt.sh` — force-kills all `RemoteManagement.framework` processes; verifies respawn at +3s and +13s
  - `disable-studentd.sh` — v1, broken (used `id -u` under sudo → got UID 0)
  - `disable-studentd-v2.sh` — v2, used wrong Label
  - `fix-studentd-final.sh` — final, correctly targets `gui/${SUDO_UID}/com.apple.studentd` and deletes `isConnected` trigger
  - `export-littlesnitch.sh` — exports LS model
  - `hunt-osascript-parent.sh` — DIDN'T WORK (fs_usage needs FDA); kept for reference
- **Scan directory convention**: diff future scans against `scan-2026-05-21/` (latest) and `scan-2026-05-18/` (deep baseline with RESILIENCE-MANUAL.pdf).
- **Git state**: untracked changes in `scan-2026-05-21/` will be auto-committed by the Stop hook in `~/.claude/settings.json`, which also rsyncs the tree to `~/.claude_home/security/`.
- **Date**: 2026-05-21. Last boot: 2026-05-21 11:09. macOS: 26.5, build 25F71.
