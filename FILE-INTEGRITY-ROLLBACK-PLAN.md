# FILE-INTEGRITY & ROLLBACK SYSTEM — Design Plan
Date: 2026-09-03 (append updates below, never overwrite)
Status: PROPOSED — pending approval to implement Phase 0

## 1. Goal

Detect **any** unauthorized file change anywhere on disk — from a corrupted
extension, accidental malware install, or an intruder who got past a loose
Little Snitch rule — with:

1. **Complete coverage** — every folder on disk, including OS files.
2. **Content-level answers** — not just *that* a file changed, but *what
   changed*: old content vs new content, line by line.
3. **Granular rollback** — restore any single file, any subset, or all
   changes, from a tamper-evident history.
4. **Self-healing** — scan results feed evw-security-system, which closes the
   intrusion vector (quarantine, rollback, disable, alert) as it occurs.

## 2. Honest constraints (macOS 26, this machine)

- **/System is sealed** (Authenticated Root: enabled, verified 2026-09-03).
  OS files cannot be modified without breaking the APFS seal and boot. So for
  /System the correct mechanism is **seal verification + kext/sysexp audit**,
  not per-file hashing/rollback. Apple's own snapshot is the rollback.
- **SIP-protected user-space paths** (e.g. /usr/libexec Apple daemons) can be
  hashed but not restored without Recovery Mode. Detection: yes. Rollback:
  flag-only (and these paths can't be written by attackers either).
- **"Every file" is ~200k files** outside the seal (measured 2026-09-03):
  /Library ~73k, ~/ ~84k, /opt/homebrew ~23k, /Applications ~21k,
  /private/etc ~230, /usr/local 29. Full-hash scans of 200k files are
  batch jobs (30–60 min), not real-time — so detection is **3-speed**
  (§5). Coverage of *content snapshots* is capped by file size (§6).
- **Root is required** to read everything (TCC.db, /var/db, other users,
  root-owned configs). All scanners run from the existing root daemon
  (com.evw.security-system), never as user.
- **Self-DoS risk**: an integrity system that reverts the admin's own
  legitimate changes is worse than useless (precedent: ls-watchdog retired
  2026-09-02 as "a loaded gun"). All automation is gated by a **deploy-marker
  protocol** (§8.4) and tiered auto/manual policies (§8.3).

## 3. Architecture

```
                     ┌────────────────────────────────────────────┐
                     │   com.evw.security-system (root daemon)     │
                     │                                            │
  fast lane          │  job: fs-pulse      (60 s, ~200 files)     │
  (persistence + ───▶│  job: fs-sweep      (5 min, stat→hash)     │
   security set)     │  job: fs-full       (daily, full hash)     │
                     │  job: fs-verify     (weekly, store fsck)   │
                     │  job: fs-heal       (policy engine)        │
                     └───────┬───────────────────┬────────────────┘
                             │                   │
                    ┌────────▼─────────┐   ┌─────▼──────────────┐
                    │ evw-integrity.py │   │  evw-rollback.py   │
                    │ scanner + indexer│   │  restore engine    │
                    └────────┬─────────┘   └─────┬──────────────┘
                             │                   │
                    ┌────────▼───────────────────▼───────────────┐
                    │  /var/db/evw-integrity/ (root:wheel 700)   │
                    │   tree/     mirror of watched files        │
                    │   repo.git  versioned history (every scan) │
                    │   index.db  sqlite stat+hash index         │
                    │   quarantine/  pre-rollback suspect copies │
                    │   logs/       append-only event log        │
                    └───────────────────┬────────────────────────┘
                                        │ commit hash per scan
                                        ▼
                              OpenTimestamps anchor
                          (Bitcoin-proof: this known-good
                           state existed at this time)
```

New executables live in the repo and deploy to /usr/local/bin like the rest
of the toolkit. Git is the snapshot engine on purpose: content-addressed,
compressed, battle-tested, gives `git diff`/`git log` per file for free —
no bespoke format to get wrong.

## 4. Coverage tiers

| Tier | Paths | Files (est.) | Hash | Content snapshot | Scan mode |
|------|-------|-------------|------|------------------|-----------|
| A — security-critical | /usr/local/bin, /Library/Launch{Agents,Daemons}, ~/Library/LaunchAgents, /private/etc, LS config, ~/dev/security, shell rc/profile files, /Library/Preferences (non-ByHost) | ~3k | every sweep | full (≤10 MB/file) | 60 s–5 min |
| B — installed software | /Applications, /opt/homebrew, /usr/local (rest), /Library/{Frameworks,PrivilegedHelperTools,Internet Plug-Ins,Fonts} | ~45k | sweep-on-stat-change | full (≤10 MB) | 5 min sweep, daily full |
| C — system-adjacent | /Library (rest), /private/var/db (selective: launchd, TCC-readable copies where permitted), ~/Library/{Preferences,Application Support selective} | ~60k | sweep-on-stat-change | text/plist ≤1 MB; binaries hash+codesign only | 5 min sweep, daily full |
| D — bulk home | rest of ~ (Documents, dev trees, etc.) | ~90k | sweep-on-stat-change | text ≤1 MB | daily full |
| E — OS seal | /System | — | APFS seal check + kext/sysexp list diff (existing boot-audit) | n/a | boot + daily |
| X — excluded (config) | */Caches, */Logs, /private/var/vm, /dev, Trash, LS TrafficLog, browser cache, node_modules, .git objects | — | — | — | stat anomaly count only |

Tier X is not fully ignored: the sweep counts files in excluded roots per
run and alerts on anomalous growth (e.g. malware staging in ~/Library/Caches).

## 5. Three-speed detection

1. **fs-pulse (60 s)** — Tier A persistence subset only
   (/Library/Launch{Agents,Daemons}, ~/Library/LaunchAgents, /usr/local/bin,
   /etc/hosts, /etc/pf.conf, /etc/sudoers, /etc/ssh/*, LS config ≈ 200 files).
   Full hash + snapshot-diff each run; cost is trivial. This is the
   "attacker drops a persistence item" tripwire — detection ≤ 60 s.
2. **fs-sweep (5 min)** — stat-only walk of Tiers A–C (path, inode, size,
   mtime, mode, uid/gid, flags) against index.db; only changed candidates get
   hashed and snapshotted. Expected wall time 1–3 min, CPU trivial. Detection
   latency for most of the disk: ≤ 5 min.
3. **fs-full (daily + on-demand + post-incident)** — hash *every* covered
   file (catches in-place edits that preserve mtime/size), snapshot changed
   files, rebuild index, OTS-anchor. This is the ground truth that makes the
   fast lanes safe.

Trigger escalation: any Tier A change outside a deploy window → immediate
fs-sweep; sweep anomaly count over threshold → immediate fs-full + INCIDENT
mode (§8.5).

## 6. Content snapshots and diffs ("what changed")

- On every confirmed change, the new file content is copied into the store
  mirror and committed with metadata (scan id, trigger, prev commit).
- **Text/config files**: report embeds `git diff` unified output.
- **Plists**: normalized with `plutil -convert xml1` before snapshotting, so
  diffs are human-readable key changes, not binary noise.
- **Binaries (Mach-O, apps)**: recorded as old/new SHA-256, size delta,
  `codesign -dv` team-identifier and signature-status change, quarantine
  xattr state. Content snapshot kept if ≤10 MB so rollback is always
  possible for Tier A/B.
- Delta report per scan written to `scan-<date>/fs-integrity-<ts>.txt` and
  appended to `logs/fs-integrity.log` (append-only), matching existing
  artifact conventions.

## 7. Rollback engine (evw-rollback.py)

- `list [--since <commit|date>]` — changed files with classification and
  diff stats.
- `restore <path>… | --file list | --all [--since …] [--dry-run]`
- Per file: (1) copy **current** (suspect) content to
  `quarantine/<timestamp>/` — forensic evidence, never just delete;
  (2) restore content from store at the chosen commit; (3) restore
  mode/uid/gid/flags (re-applies schg where it was set); (4) restore xattrs
  recorded in the index (skip quarantine xattr); (5) verify: SHA-256 match,
  `codesign --verify` for binaries, `plutil -lint` for plists,
  `launchctl kickstart` for affected daemons; (6) append undo manifest
  (rollback itself is reversible), OTS-anchor the rollback event, log to
  MASTER-SECURITY-LOG.
- Rollback **requires root**; dry-run is default in interactive use, apply
  needs `--apply` (same APPLY-confirmation idiom as ls-apply-*.sh).
- SIP-protected files: reported as restore-blocked-by-SIP (cannot have been
  attacker-modified anyway).

## 8. Self-healing integration (evw-security-system job: fs-heal)

### 8.1 Policy table (trigger → action)

| Trigger (outside deploy window) | Auto action | Approval |
|---|---|---|
| New/changed file in /Library/LaunchDaemons, /Library/LaunchAgents, ~/Library/LaunchAgents | bootout if loaded, quarantine, rollback to last committed state, CRITICAL alert | auto |
| Changed file in /usr/local/bin (security toolkit) | rollback + re-verify vs repo HEAD, CRITICAL alert | auto |
| /etc/hosts, /etc/pf.conf, /etc/sudoers, /etc/ssh/* changed | diff attached; rollback unless deploy marker | auto |
| LS config/model changed | hand off to existing ls-change-watch (hole-audit closes loosened rules — the "loose LS rule" vector) | auto (existing) |
| New unsigned (identifier.SHA256) binary referenced by any persistence item | quarantine binary + item, CRITICAL alert | auto |
| Tier B/C change (apps, homebrew, prefs) | report + diff; rollback queued for user approval | manual |
| Mass-change event (>500 confirmed changes/sweep, or excluded-root growth >20%) | INCIDENT mode: freeze auto-approvals, immediate fs-full, CRITICAL alert with top-50 diffs | manual gate |
| APFS seal invalid / new kext / new sysexp | CRITICAL alert + boot-audit escalation (existing) | auto-alert |

### 8.2 Where it plugs in
- New jobs registered in `JOBS`/`JOB_ORDER` in evw-security-system.py —
  inheriting the existing circuit breaker, state.json, alert-center
  notifications, and reports/ conventions. No new scheduler.
- Incidents recorded to VIOLATIONS-REGISTER.md and MASTER-SECURITY-LOG.md
  per standing policy.

### 8.3 Auto-rollback is Tier-A-only
Auto-remediation is deliberately limited to the small set where false
positives are rare and the cost of a wrong revert is low (persistence items,
security tools, core configs). Everything user-facing defaults to
report-and-approve via the alert center.

### 8.4 Deploy-marker protocol (keeps the system from fighting the admin)
- Any of our own deploy/harden scripts (deploy-*.sh, install-all.sh,
  *-setup.sh) writes `/var/db/evw-integrity/deploy.marker` (timestamp +
  script name) as step 0 and removes it on exit.
- Changes during a marker window are auto-approved, logged as
  `origin=deploy:<script>`, and snapshotted as the new known-good.
- Unexplained changes outside a marker window are the alertable event.
  (This directly encodes the lesson from the 2026-09-03 baseline review:
  every delta traced to our own deploy scripts.)

### 8.5 INCIDENT mode
On mass-change or Tier-A compromise: freeze auto-approvals, run fs-full,
snapshot everything changed, present a single rollback manifest
(`evw-rollback.py --all --dry-run` output) so the entire intrusion can be
reverted in one reviewed action.

## 9. Tamper-evidence of the integrity system itself

- Store is root:wheel 700; all writers run from the root daemon.
- Every scan commit → SHA-256 of `git rev-parse HEAD` + scan manifest →
  OTS stamp (Bitcoin-anchored). An attacker rewriting history breaks the
  chain provably. (Prereq: reinstall opentimestamps-client — missing since
  the August churn, noted in the 2026-09-03 baseline run.)
- fs-verify (weekly): `git fsck`, index re-hash sample (1,000 random files),
  OTS proof continuity check, store size report.
- Event log append-only; daily digest into security-system/reports/.
- Canary self-test (daily): job writes `/usr/local/share/evw-canary` with a
  random token; fs-pulse must detect, diff, and auto-restore it within
  10 minutes — failure = CRITICAL "integrity system blind" alert.

## 10. Implementation phases

| Phase | Deliverables | Depends on |
|---|---|---|
| **P0 — foundation** | `/var/db/evw-integrity` store + git init; `evw-integrity.py` with `sweep` mode for **Tier A only**; snapshot-on-change; delta reports with unified diffs; first OTS-anchored commit; artifact conventions per scan-<date>/ | — |
| **P1 — rollback core** | `evw-rollback.py` (list/restore/dry-run/quarantine/verify/undo manifest); sacrificial-file round-trip test documented in scan dir; runbook section in MASTER-SECURITY-LOG | P0 |
| **P2 — full coverage** | Tiers B–D; sqlite stat index; `full` mode (nightly); excludes config; seal+kext check folded in (reuses boot-audit code) | P0 |
| **P3 — daemon wiring** | jobs fs-pulse/fs-sweep/fs-full/fs-verify in evw-security-system; alert-center messages; deploy.marker support added to deploy-*.sh and *-setup.sh | P0–P2 |
| **P4 — self-heal** | fs-heal policy engine per §8.1 (auto tier first, manual queue via alert center); INCIDENT mode; canary self-test | P1, P3 |
| **P5 — hardening** | OTS anchoring of every scan commit; weekly fsck + proof continuity; store GC/retention policy; performance report; final runbook | P3, P4 |

Each phase ships runnable, leaves the system better off, and gets its own
MASTER-SECURITY-LOG entry. Existing build-fs-baseline.sh and l5-stamp.sh
keep running unchanged until P2 lands, then fold into fs-full.

## 11. Performance budget (targets, measured in P0/P2)

- fs-pulse: <5 s wall, negligible CPU.
- fs-sweep: ≤3 min, ≤10% of one core average.
- fs-full: ≤60 min overnight window; rate-limited I/O.
- Store: initial ~1–3 GB compressed; growth ≈ churn volume (est.
  50–200 MB/month from OS/app churn); monthly `git gc` in fs-verify.
- No measurable impact on interactive use; scanner runs at utility priority
  (nice 10, I/O throttled) — hard requirement after INCIDENT #22 showed what
  runaway background tooling costs on a 24 GB machine.

## 12. Testing & validation (per phase)

- **Round-trip**: modify canary file → detect ≤10 min → diff correct →
  restore → hash matches original → undo manifest restores the modification.
- **Persistence drill**: drop a fake LaunchDaemon plist → fs-pulse detects
  ≤60 s, fs-heal bootouts + quarantines + rolls back, CRITICAL alert fires.
- **Deploy-window drill**: run a deploy script → same changes logged as
  origin=deploy, no rollback, no alert.
- **Incident drill**: batch-touch 600 files in a temp tree inside Tier D →
  INCIDENT mode triggers, single-manifest rollback reverts all.
- **Tamper drill**: hand-edit a store commit → fs-verify fsck/OTS continuity
  fails → CRITICAL.
- **Load test**: fs-full at night, confirm no resource guard trips and
  morning watchdog/LS state is clean.

## 13. What this closes (mapped to the stated breach classes)

- **Corrupted extension** → kext/sysexp diff (boot-audit feed) + Tier B
  hashing of /Library/Extensions & StagedExtensions + auto quarantine policy.
- **Accidental malware install** → Tier B/D sweep catches new binaries;
  unsigned-binary policy quarantines; rollback removes it file-for-file.
- **Intruder via loose LS rule** → ls-change-watch closes the rule hole
  (existing); fs-integrity catches everything they touched afterward;
  INCIDENT rollback reverts the whole session's filesystem footprint.

---
_End of plan. Implementation begins on your go-ahead (suggest P0+P1 first)._

---

## Addendum 2026-09-03 — IMPLEMENTED (P0–P5 core complete)

All phases built and tested in one session. Where implementation diverged
from the plan above, the implementation is correct and this addendum is the
authority.

### Shipped
| Component | File | Status |
|---|---|---|
| Scanner (init/sweep/full/verify/canary) | `evw-integrity.py` | ✅ 34/34 round-trip tests pass |
| Rollback engine (list/restore/--all/--since) | `evw-rollback.py` | ✅ tested |
| Root installer (store + 4 daemons) | `evw-integrity-setup.sh` | ✅ syntax-checked, awaiting sudo run |
| Test suite (user-space, no root) | `tests/test-integrity.sh` | ✅ 34/34 |
| Deploy-marker in install-all.sh | `install-all.sh` | ✅ patched |

### Architecture refinements made during build
1. **Standalone daemons, not in-daemon jobs.** Four LaunchDaemons
   (pulse 120 s Tier A + heal, sweep 900 s Tier B/C, full daily 03:47,
   verify weekly Sun 04:12) instead of jobs inside evw-security-system.py.
   Rationale: a defect in the integrity system cannot take down the
   self-healing daemon (same decoupling lesson as ls-watchdog's retirement);
   per-tool plists are also the dominant project pattern.
2. **Heal-before-commit.** The healer restores protected-scope files from
   the last git COMMIT *before* new snapshots are taken, so tampered content
   never enters the store at all (the first draft snapshotted tampered
   content and then "healed" from it — caught by tests).
3. **Rollback re-baselines the store.** After `--apply`, restored/quarantined
   state is committed to the mirror and tagged `known-good` (`seed` tags the
   first baseline). Without this, a rollback would be re-detected as
   tampering and "healed" back to the tampered state on the next sweep.
4. **REMOVED-file healing** added: deletion of a protected-scope file is
   restored from its committed blob, same as modification.
5. **Auto-heal scope narrowed** to persistence dirs + /usr/local/bin +
   /private/etc. ~/dev/security (the git working repo) is report-only — the
   source of truth must never be auto-reverted.
6. **`--all --since` handles post-baseline arrivals**: files tracked in the
   index but absent from the target commit are quarantined, so a full
   intrusion footprint can be reverted in one action (`--keep-new` opts out).

### Deployment (one sudo command)
```
sudo bash /Users/evw/dev/security/evw-integrity-setup.sh
```
Then prove the round trip: `sudo /usr/local/bin/evw-integrity.py canary`,
tamper the canary, watch the 120 s pulse restore it.

### Deferred
- OTS anchoring of scan commits (ots client missing since August — reinstall
  opentimestamps-client; `ots_stamp()` already calls it when present).
- fs-heal "unsigned binary in persistence item" classifier (needs the
  codeRequirements parser from ls tooling; policy currently covered by
  NEW-file quarantine).
