# NETDIAG STATE — intermittent internet outage investigation
# Read this file FIRST when resuming after a disconnect. Do not start over.
# Working dir: /Users/evw/dev/fix/netdiag/   (user: evw, macOS 26.6.2, MacBook Pro Apple Silicon)
# Last updated: 2026-09-01 11:01 CDT

## GOAL
Fix internet outages every ~1–2 minutes affecting Safari + Brave (all apps, really).
User suspected "hackers". Evidence points to a local cause (see ROOT CAUSE).

## HOW TO RESUME (if Kimi session was disconnected)
1. Read this file.
2. Check the monitor is alive:  pgrep -fl monitor.sh
   If dead, restart:           cd /Users/evw/dev/fix/netdiag && nohup ./monitor.sh >/dev/null 2>&1 &
3. Review new outage events:   grep CHANGE /Users/evw/dev/fix/netdiag/logs/monitor.log | tail -20
4. Continue from "CURRENT STEP" below.

## MONITOR (durable, survives disconnects via nohup)
- Script: /Users/evw/dev/fix/netdiag/monitor.sh  (pid in logs/monitor.pid)
- Log:    /Users/evw/dev/fix/netdiag/logs/monitor.log  (one line per ~2s)
- Columns: wifi (en0 link) | gw (ping gateway) | net (ping 1.1.1.1) |
           dns (dig @1.1.1.1) | sysdns (mDNSResponder) | http (HTTPS to api.moonshot.cn — the
           only host Little Snitch allows curl to reach; captive.apple.com:80 is LS-blocked)
- *** CHANGE *** marks state transitions.

## ROOT CAUSE (identified 2026-09-01 11:00, confidence: HIGH)
The "anti-hacker" hardening stack installed 2026-08-31 16:36 in /Library/LaunchDaemons
(com.evw.*, com.ew.*, local.* — built by a previous AI session; source in
/Users/evw/dev/security/) is CAUSING the outages. Specifically:

  com.evw.comms-guard  →  /usr/local/bin/evw-comms-guard.sh (root, KeepAlive)
  SIGKILLs bluetoothd, bluetoothaudiod, BTLEServer, rapportd, sharingd, nearbyd,
  AirPlay*, universalcontrol, mediaremoted etc. EVERY 25 SECONDS.

Evidence:
- Monitor caught full drops at 10:50:25, 10:52:10, 10:53:52 (~100s apart, 10–20s long):
  wifi=inactive and/or default route gone (gwip=none). ~1 outage per ~100s = every 4th kill.
- At 10:53:52.074 (exact drop second) airportd logged
  "INVALIDATED XPC CLIENT CONNECTION [bluetoothd (pid=37853, euid=0)]" — bluetoothd died
  and Wi-Fi lost its Bluetooth-coexistence partner. Wi-Fi+BT share one radio on Apple
  Silicon; killing bluetoothd flaps the Wi-Fi link.
- `ps` showed bluetoothd/rapportd/sharingd/nearbyd with ages of seconds — constant respawn.
- airportd XPC invalidations for euid=0 clients burst every ~26s.
- Network is an Android phone hotspot (DHCP option ANDROID_METERED), ch149 5GHz, RSSI −35 dBm
  (excellent signal; hotspot itself is not the prime suspect).

NOT the cause (ruled out): Little Snitch rules (kills flows, not interfaces — but it does
block curl → cosmetic http=FAIL noise), pf com.ew.devports anchor (inbound only), DNS
(1.1.1.1/1.0.0.1/8.8.8.8/9.9.9.9 pinned, dns-guard no-ops), DHCP lease (1h), MDM/profiles
(none), VPNs (none). No evidence of any external attacker found anywhere.

## REMEDIATION PLAN — STATUS: ROOT CAUSE FIXED + VERIFIED 2026-09-01 11:12 CDT
STEP 1 DONE: com.evw.comms-guard stopped and plist quarantined to
/Library/LaunchDaemons.disabled/com.evw.comms-guard.plist (~11:04:30 by user running the
direct command; remediate.sh confirmed + logged at 11:05:56 via GUI admin dialog).
No sudoers grant was ever created — nothing to clean up there.

VERIFICATION (baseline before fix: drop every ~100–104s, 10–20s each):
- Last drop: 11:04:18, recovered 11:04:32 — that was the final one.
- 11:04:32 → 11:12:02: ZERO drops (≈5 expected under old regime). All probes green,
  http_code=200 throughout.
- bluetoothd/rapportd/sharingd ages now climb past 6 min (previously never > ~25s).
Undo (if ever needed): see remediate.sh header comment.

CURRENT STEP: RESOLVED. Remaining OPTIONAL cleanup (user decision — these are NOT causing
outages but are heavy/noisy; all reversible via the same quarantine pattern):
- com.evw.ls-watchdog (+ -monitor): auto-DELETES Little Snitch rules every 600s, including
  rules the user approved in LS alert dialogs (origin=alert). Currently failing on CLI
  auth, so inert — but if CLI access is ever enabled it will silently prune LS rules.
- com.evw.mac-sentinel: very heavy root daemon (full-disk SUID find every 5 min,
  system_profiler every 15s, log show every 30s) — CPU/battery. Monitors only; no outage.
- com.evw.replayd-guard / plist-monitor / audit-monitor / dns-guard, com.ew.binding-monitor /
  file-sentinel / lockdown / pf-devports, local.awdl-down (errors every 60s: awdl0 absent),
  local.security.harden (daily 09:00), com.ew.config-sentinel (user agent, 300s): noise.
- Little Snitch itself: legitimate, keep. Its CLI is unauthorized (Preferences > Security).
Monitor left running (nohup, logs/monitor.log) as a safety net; kill via logs/monitor.pid.
1. Stop the killer:   sudo launchctl bootout system/com.evw.comms-guard
   and quarantine:    sudo mkdir -p /Library/LaunchDaemons.disabled &&
                      sudo mv /Library/LaunchDaemons/com.evw.comms-guard.plist /Library/LaunchDaemons.disabled/
   (Reversible. Scripts stay in /usr/local/bin untouched.)
2. VERIFY 10 min: watch monitor.log — expect ZERO wifi=inactive / gwip=none events
   (baseline was ~1 per 100s). Also `ps -eo etime,comm | grep bluetoothd` → age should
   climb past minutes instead of resetting every ~25s.
3. If drops persist → next suspects: mac-sentinel.py (root daemon, heavy: find / SUID scan
   every 5min, system_profiler every 15s, log show every 30s), then the phone hotspot itself.
4. Cleanup candidates AFTER verification (discuss with user): replayd-guard, plist-monitor,
   ls-watchdog (auto-deletes user's Little Snitch rules!), ls-watchdog-monitor, dns-guard,
   binding-monitor, file-sentinel, audit-monitor, mac-sentinel, local.awdl-down (errors every
   60s: awdl0 does not exist), local.security.harden (daily 09:00), com.ew.lockdown (boot),
   com.ew.pf-devports (boot), com.ew.config-sentinel (user agent, 300s).
   Little Snitch itself is legitimate — keep, unless user wants it gone too.
5. Remove temp sudo grant: sudo rm /etc/sudoers.d/99-netdiag-fix  (if it was created)

## KEY FILE INVENTORY
- Snapshots: logs/snapshot-network.txt, logs/snapshot-security.txt
- Guard stack source: /Users/evw/dev/security/ (scripts/, sec/, harden.sh, install-all.sh)
- mac-sentinel source (readable): /Users/evw/dev/security/scripts/mac-sentinel.py
  Installed copy: /usr/local/lib/mac-sentinel/ (root 700 — needs sudo to read)
- Guard logs (root, some unreadable without sudo): /private/var/log/evw-*.log,
  /var/log/mac-sentinel/, /var/log/binding-monitor.log, /var/log/pf-devports.log

## CONSTRAINTS / NOTES
- sudo needs a password in this session (no NOPASSWD yet).
- Do NOT AskUserQuestion (auto mode) — ask in plain chat text when user input is required.
- User instruction: "if Little Snitch rules are allowing this, disable those rules" →
  LS rules are NOT the cause (interface-level drops). LS CLI is unauthorized anyway
  (needs Little Snitch.app > Preferences > Security toggle). Explained to user.

## 2026-09-01 11:30 UPDATE — recurrence-proofing + commits (all DONE except push)
Fix still holding: ZERO interface-level drops since 11:04:32 (~26 min). One app-layer
HTTPS blip at 11:25:18 (moonshot probe only, all lower layers green) — not the old pattern.

Recurrence-proofing edits in ~/dev/security (committed as f3eb371 on main):
- evw-comms-guard.sh: gated — exits 0 with a DISABLED notice unless COMMS_GUARD_ENABLED=1.
  Neutered copy also installed over /usr/local/bin/evw-comms-guard.sh (deploy.sh).
- evw-comms-setup.sh: refuses to install unless COMMS_GUARD_ENABLED=1.
- security-menu.sh: comms-guard + comms-setup menu entries commented out.
- install-all.sh: INSTALL_LS_WATCHDOG=0 (was 1; it deleted user-approved LS rules),
  INSTALL_COMMS_GUARD=0 with incident note. (sec/ dir NOT in outer repo — it is its own
  git repo, committed locally; it has NO remote.)
- scripts/mac-sentinel.py: alerts write to ONE tty (console user's first real tty,
  "console" entry skipped) instead of every tty in `who`. Installed to
  /usr/local/lib/mac-sentinel/ and daemon restarted (kickstart -k; self-hash re-baselined).
- cleanup.sh quarantined: com.evw.ls-watchdog, com.evw.ls-watchdog-monitor, local.awdl-down
  (all in /Library/LaunchDaemons.disabled/ — reversible).
- config-sentinel re-baselined (151 entries) so quarantine changes don't alert every 5 min.

Git: security repo committed (f3eb371) — PUSH PENDING: no GitHub auth on this Mac
(no SSH keys existed, gh not logged in). Generated ~/.ssh/id_ed25519 (pub key printed in
chat). To finish: user adds that key at github.com → Settings → SSH keys, OR runs
`gh auth login`. Then: git -C /Users/evw/dev/security push origin main.
netdiag committed locally (/Users/evw/dev/fix, repo init'd, 96b9992) — push needs a remote.
Monitor still running (logs/monitor.log) — kill via logs/monitor.pid when satisfied.

## 2026-09-01 12:05 FINAL — pushed + studentd-guard added
- sec repo PUSHED to github.com:evweath/sec (60f4968..5016fbc). Required: new SSH key
  (user added to GitHub), childcustody.zip (186MB, over GitHub 100MB limit) purged from
  unpushed history via filter-branch + gitignored. FILE REMAINS on disk at
  ~/dev/security/scripts/childcustody.zip — it was NOT uploaded. If it must be backed up
  to GitHub: use git-lfs (and only if the repo is private — it contains custody documents).
- com.evw.studentd-guard installed + running: kills studentd every 300s.
  airportd/bluetoothd/wifid/mDNSResponder/configd blacklisted in-script (user confirmed
  2026-09-01: do NOT kill airportd — it would recreate the outages). Verified: studentd
  killed, Wi-Fi stayed green throughout. Menu entry added; config-sentinel re-baselined.
- sec/ subrepo: committed locally only (no remote configured).
- netdiag repo: committed locally (f11432e); push needs a GitHub repo created first
  (gh auth login, or create empty repo + tell me the name).

## 2026-09-01 12:20 — file-vault + IP intel deployed (commit 082710a)
- com.evw.file-vault RUNNING: versioned snapshots of security-critical files
  (/etc, sudoers, LaunchDaemons/Agents, /usr/local, ~/.ssh, shell rc, cron) at
  baseline + on every change/delete. Vault: /var/log/mac-sentinel/file-vault/ (root 700).
  Restore: sudo vault-restore.sh <path> [version]  (no version = list).
  Log: /var/log/mac-sentinel/file_vault.jsonl.
- mac-sentinel connection logs now carry ip_intel for every NEW remote IP (v4+v6):
  kind, PTR, fcrdns_ok, RDAP org/net_name/country/cidr + kill_hint/block_hint.
  Cache: /var/log/mac-sentinel/ip-intel-cache.json. Logs: /var/log/mac-sentinel/*.jsonl
  (root 600 — read with sudo). Smoke test passed (1.1.1.1 → APNIC-LABS/AU, FCrDNS ok).
- CAVEAT (honest): macOS cannot attribute file writes to remote connections without an
  Endpoint Security entitlement; vault covers reversibility instead. No remote-login
  path exists on this Mac anyway (sshd/ARD/screensharing disabled by lockdown).
- 12:04:42 single route-loss event (~2 min), Wi-Fi link stayed active, no daemon kills,
  no cadence — hotspot-side stall, not the comms-guard pattern. Monitor still running.
- config-sentinel re-baselined (new file-vault plist absorbed).

## 2026-09-01 12:45 — [AUTO-EVW] conn-guard live (commit 5ee3724, pushed)
- com.evw.auto-conn-guard RUNNING: 30s lsof scan, scores D1-D5 (hardcoded-IP proxy,
  DNS cross-check disjoint=hijack alert, FCrDNS fail, long-lived non-browser,
  TLS anomaly via 2s active probe). Score>=5 + unprotected → verified SIGKILL +
  1h pf block (anchor com.ew.autoblock, table auto_evw_block — MUST use
  `pfctl -a com.ew.autoblock -t ...` ; root-scope -t misses it, fixed 12:41).
- LS deny rules: queued per block, merged by evw-auto-ls-sync.sh (debounced 10min;
  model backup kept in /var/log/mac-sentinel/). LS CLI access ENABLED by user 12:36
  (539-rule model export verified).
- UNDO: sudo evw-auto-undo.sh list | <action_id> | all-blocks. Audit:
  /var/log/mac-sentinel/AUTO-ACTIONS.md (+ auto-actions.jsonl). Blocks self-expire
  1h; unexpired ones re-applied after daemon restart.
- Protections hardcoded: gateway, live DNS, trusted resolvers, Apple 17/8,
  api.moonshot.cn, browsers/system/self (python). DNS-hijack check is ALERT-ONLY.
- Verified: table add/delete live, guard restart clean, zero Wi-Fi impact of pf reload.

## 2026-09-01 13:00 — boot-persistence audit CLEAN + LS hygiene applied
BOOT AUDIT (full record: logs/boot-audit.txt): sudoers.d empty, sudoers stock, no
root ssh keys, no cron, 1 user (evw 501), stock PAM (all OS-dated), no 3rd-party
kexts, BTM shows only known daemons, all guard-script hashes == audited sources,
quarantined 4 plists inert (not loaded). NO bad-code remnants at boot.
LS HYGIENE (applied 12:58, verified 540->524 rules; report+undo in logs/):
- deleted 12 tracker allows (klaviyo x8, acdn.adnxs, ads.pro-market, bat.bing —
  several contradicted the user's own deny rules for the same hosts)
- deleted 2 trustd denies -> OCSP certificate-revocation checking RESTORED
- deleted 2 configd denies (ports 67/any -> DHCP renewal risk removed)
- left alone (deliberate posture): apsd/push denies, Brave denies, inbound mDNS denies.
Undo: full rule copies in logs/ls-hygiene-undo.json; model backup in
/var/log/mac-sentinel/ls-model-pre-hygiene-*.json. Tool: scripts/ls-hygiene.py.

## 2026-09-01 13:18 — LS rescan #2 + durable tracker denies
Rescan (553 rules): 9 tracker allows had REGENERATED in 16 min via LS alert dialogs
(user clicking Allow), plus 1 new OCSP-killing deny (ocsp.sectigo.com). Applied:
deleted 10, planted 4 durable any-process DENY rules tagged [AUTO-EVW-LS] for
tracker hosts lacking one (a./fast.a./static./static-tracking klaviyo.com) — with a
deny in place LS stops alerting, so they cannot be accidentally re-allowed.
Final: 547 rules, 0 tracker allows. Model backup in /var/log/mac-sentinel/.
USER GUIDANCE: when LS alerts about trustd / ocsp.* — click ALLOW (trustd is the
certificate-revocation checker; denying it weakens TLS). For unknown tracker-ish
hosts, click Deny once and the rule sticks.

## 2026-09-01 13:22 — LS rescan #3: ruleset verified clean
Deep audit across all risk categories: 0 any-process allows, 0 CIDR allows,
0 unsigned-binary allows, 0 suspicious-port allows, 0 inbound non-factory allows,
0 broad-domain risks. 1 tracker allow regenerated (static-forms.klaviyo.com via
alert) — deleted. Final: 548 rules, 0 tracker allows, 4 durable auto-denies holding.
NOTE: tracker allows keep regenerating when LS alerts are approved — if desired,
ls-hygiene.py can be run periodically (same backup+undo safety).

## 2026-09-01 13:45 — tm-restore.sh (Time Machine permission fixer)
scripts/tm-restore.sh: offline, hours-safe, resumable TM restore tool.
- copies folders from read-only TM backup -> ~/Desktop/TM-Restore-<ts>/ (rsync),
  fixes locks/ACLs/owner/perms, copies fixed folders back to the LIVE TM volume
  (<TMVOL>/TM-Restored/<ts>/, outside the protected bundle)
- --all mode: every subfolder of backup Users dir, OLDEST mtime FIRST -> newest
  (ALL_ROOT=".../Macintosh HD - Data" for the entire backed-up volume)
- autodetects live TM volume via mount table (df is WRONG for .timemachine
  firmlinks — parse `mount` instead); override with TMVOL=
- resume: STAGE=<dir> + .done markers per folder; MOVE=1 drops staging after verify
- MUST run in a Full-Disk-Access Terminal with sudo (TCC blocks TM reads and
  removable-volume writes from other contexts — verified: agent dialog context
  gets EPERM on /Volumes/passport1). If volume mounted RO: sudo mount -uw /Volumes/passport1
- validated here: syntax, oldest-first ordering, volume autodetect -> /Volumes/passport1

## 2026-09-01 14:00 — MERGED into security repo + full verification (03e1055)
The fix/netdiag tree is now merged into /Users/evw/dev/security/netdiag/ (commit
03e1055, pushed). THIS COPY IS NOW CANONICAL; /Users/evw/dev/fix remains as an
untouched local archive (its own git repo) and can be deleted when convenient.
Verification sweep (all green):
- A: all 26 session artifacts present in security (scripts, netdiag tools, STATE)
- B: gates/tags intact: comms-guard + comms-setup DISABLED gates, install-all
  LS_WATCHDOG=0/COMMS_GUARD=0, mac-sentinel single-tty + ip_intel, conn-guard
  anchored pf (-a com.ew.autoblock), 6 menu entries incl. ls-hygiene + tm-restore
- C: bash -n + py_compile pass on every new script
- D: deployed copies in /usr/local/bin == sources (7/7 hash match;
  /usr/local/lib/mac-sentinel verified earlier via boot-audit as root)
- E: security/netdiag == fix/netdiag (only monitor.log differs — living file;
  netdiag/.gitignore added in security to keep LS model exports + boot-audit local)
- Root .gitignore logs/ pattern anchored to /logs/ so netdiag/logs is tracked.

## 2026-09-01 14:10 — tm-restore v3: fully automatic troubleshooting ladder
Per user req: no files left on Desktop (per-folder move, staging deleted after
verified copy-back; log/manifest/.done markers live in the TM-disk dest; staging
dir removed on clean finish) + automatic troubleshooting without human input:
S1 auto-failover to newest usable snapshot in /Volumes/.timemachine if default
path gone; S2 read probe retries 3x10s (TCC/FDA grant is the ONLY step no script
can automate — hard macOS boundary, one-time GUI action); S3 auto mount -uw +
re-probe (also retried on copy-back failure); S4 engine ladder rsync->ditto->
cp -Rp; S5 second-pass rsync then MISSING-<name>.txt diagnostic, staging kept
only for genuinely mismatched folders; S6 staging disk guard (skip oversized
folder, logged); S7 destination disk guard. Oldest-mtime-first ordering, --all
mode, resume via STAGE env unchanged. Validated: syntax + ordering + autodetect.

## 2026-09-01 14:49 — mac-sentinel: human timestamps on every entry
Every sentinel log entry now carries ts_human ("Tuesday, September 01, 2026
02:48:42 PM CST" — weekday, day, month, year, time, AM/PM, tz) alongside the
machine ISO ts (kept for the event correlator), and every alert message
(notification + tty) leads with the human timestamp. Verified live after
kickstart. (Note: tz label prints as CST — cosmetic macOS tzname quirk.)

## 2026-09-01 15:05 — tm-restore v4: ALL 20 TM snapshots accessible
Root cause of "2 folders in Terminal vs 20 in Finder": the TM disk holds 20 APFS
snapshots (verified: diskutil apfs listSnapshots /dev/disk9s3 = 20 found) but
macOS auto-mounts only ~3 under /Volumes/.timemachine; Finder displays all
snapshots as folders. v4 enumerates ALL snapshots and mounts the rest itself
(read-only, mount -t apfs -o -s=<name>), with fallback to existing auto-mounts
("Resource busy" = already mounted — use that path). New modes:
--list-snapshots, --snapshot <date>, --all-snapshots (oldest first across ALL
backups; per-snapshot dest TM-Restored/<date>/). Mounting non-auto-mounted
snapshots is TCC-restricted (EPERM 77 from non-FDA contexts — works from a
Full-Disk-Access Terminal). Per-folder move, engine ladder, disk guards,
missing-file diagnostics all preserved from v3.

## 2026-09-01 15:26 — tm-restore v4.1: field-tested fixes from first real run
User's FDA-terminal run proved the pipeline end-to-end (Shared restored,
copy-back to passport1 OK). Fixes from that run:
- tshoot() now writes to STDERR — previously a self-mount [TSHOOT] line was
  captured by root=$(snapshot_root ...) corrupting the root path for all 17
  non-auto-mounted snapshots
- --all / --all-snapshots now default ALL_ROOT to the backed-up VOLUME ROOT
  (was Users/, which legitimately contains only ew + Shared = "2 folders");
  volatile dirs skipped (.vol mnt cores sw pkg MobileSoftwareUpdate .Trashes
  .TemporaryItems .fseventsd .Spotlight-V100 .DocumentRevisions-V100 dev net home)
- user interrupt (rsync rc=20/^C) now ABORTS cleanly with a resume hint instead
  of falling back to ditto and restarting a 60GB copy from scratch
- validated: syntax, tshoot-capture purity, skip-list filter

## 2026-09-01 15:42 — ls-hygiene-guard: LS rule check every 5 min, persistent
User clarified: conn-guard stays at 30s scans; the 30-min thing they remembered
was the LS rules check (old ls-watchdog ran 10min, removed today; its manual
successor ls-hygiene.py had no timer). NEW com.evw.ls-hygiene-guard daemon:
every 300s exports LS model, applies ls-hygiene (tracker allows, OCSP/configd
denies, durable tracker denies), restores ONLY on change (no pointless reloads).
Per applied change: pre-patch model backup (last 30 kept), undo JSON, and
[AUTO-EVW-LS] line in AUTO-ACTIONS.md. First cycle already removed 2
regenerated risk rules. Persistent across reboots (LaunchDaemon).

## 2026-09-01 15:56 — sentinel alert terminal (boot-spawned, numbered, logged)
All six requested changes live (verified end-to-end):
1. sentinel starts each boot (pre-existing LaunchDaemon, unchanged)
2. NEW com.evw.sentinel-alert-term LaunchAgent opens a Terminal at every login
   running /usr/local/bin/evw-sentinel-alert-display.sh
3. display header prints full log paths at top of the terminal
4. entries numbered from #1 each boot (counter resets per display session)
5. everything displayed mirrors to /Users/evw/Library/Logs/mac-sentinel-alert-display.log
   (source feed: .../mac-sentinel-alert-feed.log, single-line JSON per alert,
   written by mac-sentinel _trigger_alert, rotated at 2MB, 0644)
6. mac-sentinel restarted (kickstart -k); live alerts confirmed flowing (#1 #2
   real, #3 synthetic pipeline test). config-sentinel re-baselined (new plist).

## 2026-09-01 16:15 — full sentinel log review: ALL LEGIT, no hacker/malware
Reviewed every sentinel log (connections, root procs, sudo/auth, file changes,
canary, USB, self-integrity, anomalies, conn-guard, daemon log) — full report:
netdiag/logs/sentinel-analysis.txt. Every connection resolved to expected orgs
(browsers→CDNs incl. Alibaba=Kimi, curl×213=our moonshot monitor, ssh=git pushes,
Apple daemons→Apple/Fastly). Root procs: only /System,/usr/{libexec,sbin},LS,our
tooling. Zero sudo/auth events, canary clean, no USB, no tamper, no anomalies.
One fix from review: D2 DNS check false-positived on github.com A-record
rotation (12 alerts) — now suppressed when sys/public answer sets share the
same RDAP org; alerts only on genuinely different owners. Deployed + restarted.

## 2026-09-01 16:21 — alert terminal v2: severity colors + 1500x20 scrollable
Display script now colorizes per-entry in the TERMINAL (CRITICAL=red,
WARNING=yellow, INFO=plain; display log stays plain-text, no ANSI) with a
legend line in the header. New evw-sentinel-alert-launch.sh spawns Terminal via
AppleScript and sets 1500 cols x 20 rows (macOS clamps to screen width) with
normal scrollback — single-line JSON alerts stay on one line. LaunchAgent plist
now runs the launcher. Reloaded live; launchd log clean; entries #6-#13
flowing with the new format.

## 2026-09-01 16:29 — alert terminal v3: Apple-events-free spawn (TCC-proof)
Respawn attempt hit -1743 (Not authorized to send Apple events to Terminal) —
launchd-spawned osascript has unreliable Automation consent. Fix: plist back to
`open -a Terminal <display.sh>` (LaunchServices, no consent needed) and the
display script now resizes/titles its OWN window via xterm escape sequences
(\e[8;20;1500t + OSC title) — no Apple events anywhere. Verified: new session
header at 16:28:19, numbering from #1, colors live, window self-sized 1500x20.

## 2026-09-01 16:43 — remote-connectivity daemons: killed + permanently guarded
Killed all 10 running remote-access processes (remoted, studentd, AirPlayUIAgent,
AirPlayXPCHelper, rapportd, sharingd, identityservicesd, nearbyd, mediaremoted,
avconferenced). evw-studentd-guard KILL_LIST expanded to the full set (19 procs:
remote desktop/screensharing/ARD, AirPlay, Continuity, Nearby, media-remote,
conferencing, hotspot, SMB) — guard restarted and instantly re-killed respawns.
bluetoothd EXCLUDED per user's own condition: killing it DOES affect Wi-Fi
(proven root cause of today's outages). fairplayd left (DRM, not remote access).
Monitor confirms zero Wi-Fi events during the kill sweep.

## 2026-09-01 17:16 — remote-access suppression: the honest ceiling
User asked for a simpler permanent solution than the kill loop. Proven today:
launchctl disable (both domains, correct labels incl. com.apple.macos.studentd
which was missed) is IGNORED by macOS for the continuity stack; bootout is SIP
error 150; removing triggers (Handoff advertising+receiving off, AirDrop off)
did NOT stop respawns; binaries are SIP-sealed; "bad credentials" is N/A — these
daemons use the user's iCloud identity certs, not per-service passwords (the only
credential lever is FaceTime/Messages sign-out). Also from the LS model: deny
rules already exist for the network-active members (studentd, identityservicesd);
rapportd/sharingd/mediaremoted/nearbyd/avconferenced/AirPlay agents have ZERO
outbound connections in the LS model (local-link only, already neutered).
CONCLUSION: outside enforcement (the guard) IS the permanent solution; interval
tuned 300s -> 60s -> 15s. Dead-time: ~0% at 300s, ~50% at 60s, ~80% at 15s —
relaunch is instant, so 15s is the practical ceiling; anything shorter is churn.
Guard persists at boot (RunAtLoad+KeepAlive). bluetoothd stays excluded.

## 2026-09-01 17:27 — LS blanket denies for all remote-access daemons
User asked which of the 19 LS doesn't block: answer was 17 unruled + 2 with
narrow per-host denies only (studentd: www.apple.com; identityservicesd: a few
Apple init hosts). LS is in ALERT mode (activeSilentMode:0) so unruled conns
would prompt, but none of the 17 ever attempted one (no LS model entries).
FIX: 16 tagged any-remote deny rules planted via codesign-verified identifiers
(com.apple.studentd/remoted/RemoteDesktopAgent/remotemanagementd/
RemoteManagementAgent/AirPlayUIAgent/AirPlayXPCHelper/rapportd/sharingd/
identityservicesd/nearbyd/mediaremoted/avconferenced/smbd/netbiosd/
screensharing.daemon). Verified in model (577 rules, 16 [AUTO-EVW] blanket
denies). Backup: /var/log/mac-sentinel/ls-model-pre-denyremote-*.json; undo
manifest: netdiag/logs/ls-deny-remote-undo.json. Not on disk under macOS 26:
universalcontrol, PersonalHotspotAgent, AirPlayReceiver (skipped). No conflict
with ls-hygiene-guard (its T1-T3 policy doesn't touch these).

## 2026-09-01 17:37 — LS blanket denies: screen-sharing/remote-desktop programs
24 tagged ([AUTO-EVW] block screen-sharing) any-remote deny rules planted +
verified (601 rules total). Apple: ScreenSharing client, screensharing.agent,
screensharing.menuextra (daemon already denied earlier). Third-party (inert
unless installed): TeamViewer x3, AnyDesk, Chrome Remote Desktop x2, RealVNC x2,
Splashtop x2, LogMeIn x2, GoToMyPC, RustDesk, Parsec, NoMachine x2, Zoho
Assist, DWService, Supremo, MS RDP client. SKIPPED: com.apple.RemoteDesktop
(substring collision with already-denied RemoteDesktopAgent) — non-issue: the
ARD admin app is not installed. Backup: /var/log/mac-sentinel/ls-model-pre-
denyss-*.json; undo: netdiag/logs/ls-deny-screenshare-undo.json.
