# Rebuild This Mac From Ground Zero

Two scripts, one goal: fresh unconfigured macOS → current secured state in
**~15–25 minutes + ~5 minutes of GUI clicks**.

## Files

| File | Purpose |
|---|---|
| `../rebuild-mac.sh` | The orchestrator. Idempotent; safe to re-run. |
| `capture-state.sh` | Snapshots this Mac's restorable state into `state/`. |
| `state/` | LS model, LS license, Brewfile, LaunchAgents, /etc pieces, disabled.501 list, inventories. |
| `LAST-RUN-MANUAL-STEPS.txt` | Regenerated each rebuild run — the GUI checklist. |

## Rebuild procedure (on the fresh Mac)

1. Sign in as admin user `evw` (skip iCloud during Setup Assistant — do NOT sign in).
2. Get this repo onto the machine, fastest first:
   - **Passport/offline copy**: `rsync -a /Volumes/Passport/sec/ ~/dev/security/`
   - **GitHub**: `git clone git@github.com:evweath/sec.git ~/dev/security`
     (needs network; on a brand-new Mac without your SSH key use the Passport path)
3. Run:
   ```bash
   bash ~/dev/security/rebuild-mac.sh              # core security state
   # or, to also install Homebrew + apps + Little Snitch cask:
   bash ~/dev/security/rebuild-mac.sh --full-apps
   ```
4. Follow the printed manual checklist (LS system-extension approval, TCC
   prompts, Touch ID, GitHub SSH key, memory restore, OTS reinstall).
5. Reboot, then confirm: `bash ~/dev/security/scripts/verify.sh`

Re-running `rebuild-mac.sh` after Little Snitch is fully approved restores
the rule model if the first attempt failed — it is idempotent by design.

## What it restores

- Security toolkit daemons/agents (via `install-all.sh`, security-system/audit
  setups) with verification
- Little Snitch: license + full rule model (`littlesnitch restore-model`)
- Hardening: `harden-now.sh` (DNS pin has a NAT64 safety gate) + explicit
  posture: disabled.501.plist entries + schg, Bluetooth off, WoL/PowerNap off,
  immediate password-on-wake, mDNS quiet, AirDrop/UniversalControl/Handoff
  off, Remote Login off + sshd_config 600, /etc/hosts, HighPoint kext purge,
  pf anchors
- User LaunchAgents (alert-center, sentinels, ls-resource-guard)
- Homebrew packages/apps (with `--full-apps`)

## What it cannot restore (and why)

- **TCC grants, system-extension approval, license entry** — Apple requires
  physical-user GUI consent. This is the bulk of the ~5 manual minutes.
- **Keychain / encrypted memory (*.csmem)** — restore from Passport via
  `security-memory-manager.py`; never committed to git.
- **iCloud/FaceTime/Messages** — intentionally NOT restored; the verified
  clean state (2026-09-03) is signed-out everywhere.

## Keeping the state fresh

State rots. Re-run capture **monthly, after deliberate config changes, and
always before a rebuild**:

```bash
sudo bash ~/dev/security/rebuild/capture-state.sh
```

(sudo captures the live LS model export and the true disabled.501.plist
entries; without sudo it falls back to the latest scan export and seeds.)

Then commit: `git add rebuild/state && git commit -m "rebuild state refresh"`.

## Known limits

- Tested: syntax + every delegated installer is individually battle-tested
  (install-all/harden-now/setup scripts run routinely on this machine).
  A full bare-metal run has NOT been executed yet — treat the first real
  rebuild as the field test and expect to note gaps in this README.
- Little Snitch cask install requires `--full-apps` and network.
- If GitHub is unreachable and no Passport copy exists, the repo cannot
  bootstrap — keep the Passport copy current.
