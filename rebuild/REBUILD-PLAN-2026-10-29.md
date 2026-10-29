# Complete Security System Rebuild Runbook

**Version:** 2026-10-29  
**Scope:** Rebuild the macOS security workstation and its full local security stack from a clean macOS install, without relying on Time Machine.  
**Classification:** Operational security material. Store locally or in an encrypted/offline backup. Do not publish.

---

## 0. What this rebuild covers

This runbook rebuilds:

- macOS hardening posture and disabled remote-access services
- Little Snitch, its license, rule model, guards, and rule hygiene tools
- LaunchDaemons and LaunchAgents
- file-integrity monitoring, snapshots, rollback, and backup-completeness checks
- process, plist, Endpoint Security, audit, DNS, network, and screen-sharing guards
- alert center and the alert-history GUI
- Wazuh manager/indexer/dashboard stack, local agent, and Colima/Docker runtime
- PostgreSQL launch service used by local development
- PF inbound dev-port protections
- GitHub/`gh` based recovery for repository-tracked files
- validation, evidence capture, and recurring maintenance

It does **not** rely on Time Machine. GitHub restores only repository-tracked files. Local-only secrets, ignored scan reports, credentials, Wazuh keys, Little Snitch license material, and historical security artifacts must come from the encrypted/offline backup created before the rebuild.

---

## 1. Current baseline recorded at plan creation

- Machine/user path assumption: `/Users/evw`
- Security repository: `/Users/evw/dev/security`
- Offline backup area: `/Users/evw/dev/security-backups`
- Integrity store: `/var/db/evw-integrity`
- Security-system state: `/var/db/evw-security-system`
- Current macOS at inventory: 26.6.2 (25G83)
- Little Snitch: 6.4.1, system extension team `MLZF7K7B5R`
- Current LS rule count at last audit: 6,065
- Colima 0.10.3, Lima 2.2.1
- Docker/Wazuh/PostgreSQL are local services and should remain loopback-bound.

Current root LaunchDaemons include:

- `at.obdev.littlesnitch.daemon`
- `com.evw.audit-monitor`
- `com.evw.auto-conn-guard`
- `com.evw.dns-guard`
- `com.evw.file-vault`
- `com.evw.integrity-pulse`
- `com.evw.integrity-sweep`
- `com.evw.integrity-full`
- `com.evw.integrity-verify`
- `com.evw.ls-hourly-cleanup`
- `com.evw.ls-hygiene-guard`
- `com.evw.ls-watchdog-monitor`
- `com.evw.ls-watchdog`
- `com.evw.mac-sentinel`
- `com.evw.plist-eslogger`
- `com.evw.plist-monitor`
- `com.evw.replayd-guard`
- `com.evw.security-audit`
- `com.evw.security-system`
- `com.evw.studentd-guard`
- `com.evw.wazuh-guard`
- `com.evw.wazuh-monitor`
- `com.ew.binding-monitor`
- `com.ew.file-sentinel`
- `com.ew.lockdown`
- `com.ew.pf-devports`
- `com.wazuh.agent`
- `local.awdl-down`
- `local.security.harden`

Current user LaunchAgents include:

- `com.evw.alert-center`
- `com.evw.alert-viewer`
- `com.evw.colima`
- `com.evw.ls-resource-guard`
- `com.evw.security-audit-login`
- `com.evw.sentinel-alert-term`
- `com.ew.config-sentinel`
- `homebrew.mxcl.postgresql@16`
- `at.obdev.littlesnitch.agent`

Current Homebrew leaves/casks include Colima, Docker, Docker Compose, `gh`, Python 3.13/3.14/3.15, `python-tk@3.15`, PostgreSQL 16, Lynis, Node, tmux, Xcode helpers, and related development tools.

---

## 2. Non-negotiable rebuild rules

1. **Do not use Migration Assistant or Time Machine for the security stack.** They can reimport unknown state. Build clean, restore only reviewed artifacts.
2. **Do not sign in to iCloud during first boot.** Add accounts only after the security stack is verified.
3. **Do not commit credentials, private keys, Wazuh secrets, Little Snitch registration files, raw logs, or ignored scan artifacts to GitHub.**
4. **Do not weaken permissions to make backups easier.** Use a reviewed elevated copy command, preserve modes, and verify hashes.
5. **Do not auto-heal the whole home directory.** Home changes are detected and snapshotted, but restoration requires explicit review.
6. **Do not treat the local rebuild as finished until all validation gates pass.**

---

## 3. Phase 0 — preserve the existing system before erasing it

Do this on the current machine before any erase/reinstall.

### 3.1 Record the current repository state without changing it

```bash
cd /Users/evw/dev/security
git status --short --branch
git log -5 --oneline --decorate
```

Do not commit unrelated pre-existing deletions or generated reports as part of rebuild preparation.

### 3.2 Refresh rebuild state

This needs sudo so the live Little Snitch model, license, and launchd disabled list are captured:

```bash
sudo bash /Users/evw/dev/security/rebuild/capture-state.sh
```

Verify the manifest:

```bash
cat /Users/evw/dev/security/rebuild/state/CAPTURE-MANIFEST.txt
python3 - <<'PY'
import json
p='/Users/evw/dev/security/rebuild/state/ls-model.json'
m=json.load(open(p))
print('Little Snitch rules:', len(m.get('rules', [])))
PY
```

### 3.3 Complete the known partial local backup

The current backup report says 22 root-owned files are still missing from:

`/Users/evw/dev/security-backups/security-pre-gh-20261028-182804/`

Create the file list from the status report:

```bash
python3 - <<'PY'
import re
status='/Users/evw/dev/security-backups/security-pre-gh-20261028-182804-BACKUP-STATUS.md'
out='/tmp/security-backup-missing-files.txt'
with open(status) as f:
    paths=[line.split('`')[1] for line in f if line.startswith('- `')]
with open(out,'w') as f:
    f.write('\n'.join(paths)+'\n')
print(out, len(paths))
PY
```

Copy only those listed paths, preserving ownership, permissions, and timestamps:

```bash
sudo rsync -a --files-from=/tmp/security-backup-missing-files.txt \
  /Users/evw/dev/security/ \
  /Users/evw/dev/security-backups/security-pre-gh-20261028-182804/
```

Verify with the new checker:

```bash
python3 /Users/evw/dev/security/evw-backup-check.py
```

Expected result after a correct copy: `total issues: 0`.

### 3.4 Preserve root-only and ignored security state

Create a root-owned staging bundle, then encrypt it. This is intentionally outside GitHub.

Include:

- `/var/db/evw-integrity/`
- `/var/db/evw-security-system/`
- `/Library/Ossec/etc/` and `/Library/Ossec/queue/` if Wazuh history must survive
- `/Library/Application Support/Objective Development/Little Snitch/`
- `/Users/evw/dev/security/logs/`
- `/Users/evw/dev/security/scan-*/`
- `/Users/evw/dev/security-backups/`
- `/Users/evw/.colima/` if Colima/Wazuh container state must survive

Example:

```bash
sudo mkdir -p /var/tmp/evw-rebuild-preserve
sudo rsync -a \
  /var/db/evw-integrity/ \
  /var/db/evw-security-system/ \
  /Library/Ossec/etc/ \
  /Library/Ossec/queue/ \
  "/Library/Application Support/Objective Development/Little Snitch/" \
  /Users/evw/dev/security/logs/ \
  /Users/evw/dev/security-backups/ \
  /var/tmp/evw-rebuild-preserve/
```

For Colima, stop it before copying its disk:

```bash
colima stop
sudo rsync -a /Users/evw/.colima/ /var/tmp/evw-rebuild-preserve/colima/
```

Package and encrypt:

```bash
sudo tar -C /var/tmp -czf /var/tmp/evw-rebuild-preserve.tar.gz evw-rebuild-preserve
sudo shasum -a 256 /var/tmp/evw-rebuild-preserve.tar.gz | tee /var/tmp/evw-rebuild-preserve.sha256
openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt \
  -in /var/tmp/evw-rebuild-preserve.tar.gz \
  -out /Users/evw/dev/security-backups/evw-rebuild-preserve-2026-10-29.tar.gz.enc
shasum -a 256 \
  /Users/evw/dev/security-backups/evw-rebuild-preserve-2026-10-29.tar.gz.enc \
  > /Users/evw/dev/security-backups/evw-rebuild-preserve-2026-10-29.sha256
```

Copy the encrypted bundle and SHA file to at least two offline/off-host locations. Keep the passphrase separate.

### 3.5 Preserve the repository both ways

Use GitHub only for reviewed, tracked source:

```bash
cd /Users/evw/dev/security
git diff --check
gh repo view evweath/sec --json nameWithOwner,defaultBranchRef
```

Use a local copy for ignored/local artifacts:

```bash
rsync -a --delete /Users/evw/dev/security/ /Volumes/RESTORE-USB/security/
```

Replace `/Volumes/RESTORE-USB` with the actual offline volume.

### 3.6 Run a final pre-rebuild audit

```bash
sudo bash /usr/local/bin/evw-security-audit.sh --auto
```

Review:

- `scan-2026-10-29/integrity-full.txt`
- `scan-2026-10-29/backup-check.txt`
- `scan-2026-10-29/ls-full-analysis.txt`
- `scan-2026-10-29/network-state.txt`
- `scan-2026-10-29/tcc-audit.txt`

Resolve unauthorized changes before erasing, or document them as intentional.

---

## 4. Phase 1 — erase and install clean macOS

1. Record the Mac serial and current OS build.
2. Verify the encrypted preservation bundle exists off the machine.
3. Verify the offline repository copy exists.
4. Boot into Recovery.
5. Erase the internal volume using Disk Utility or Erase All Content and Settings.
6. Install the current supported macOS release.
7. Do not connect unknown external media after installation.

---

## 5. Phase 2 — first boot and account setup

1. Select language, region, and network.
2. Skip Apple ID/iCloud sign-in.
3. Skip Migration Assistant.
4. Create the admin account named `evw`.
5. Use a strong local password.
6. Skip Siri, analytics, Screen Time, and personalized advertising prompts.
7. Enable FileVault when prompted, or immediately after login:

```bash
sudo fdesetup enable
```

8. Store the recovery key offline.

---

## 6. Phase 3 — bootstrap the security repository

Preferred source is the offline copy, because it contains ignored local state that GitHub does not.

```bash
mkdir -p /Users/evw/dev
rsync -a /Volumes/RESTORE-USB/security/ /Users/evw/dev/security/
```

If only GitHub is available:

```bash
mkdir -p /Users/evw/dev
git clone git@github.com:evweath/sec.git /Users/evw/dev/security
```

If SSH is not yet configured, use `gh` after authenticating:

```bash
gh auth login --hostname github.com --git-protocol ssh
gh repo clone evweath/sec /Users/evw/dev/security
```

Verify:

```bash
cd /Users/evw/dev/security
git status --short --branch
git remote -v
test -f install-all.sh && test -f rebuild-mac.sh
```

---

## 7. Phase 4 — prerequisites and applications

### 7.1 Xcode Command Line Tools

```bash
xcode-select --install
```

Wait for the GUI installer to finish.

### 7.2 Homebrew

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
eval "$(/opt/homebrew/bin/brew shellenv)"
```

### 7.3 Install packages and applications

Refresh and inspect the Brewfile first:

```bash
cat /Users/evw/dev/security/rebuild/state/Brewfile
```

Then install:

```bash
brew bundle --file /Users/evw/dev/security/rebuild/state/Brewfile
```

Add currently required packages if the captured Brewfile is stale:

```bash
brew install colima docker docker-compose gh lynis postgresql@16 python-tk@3.15 tmux
brew install --cask iterm2 brave-browser knockknock little-snitch
```

Install or reinstall Xcode, Xcodes, Obsidian, LibreOffice, Kimi, and Double Commander only if still needed.

---

## 8. Phase 5 — Little Snitch

1. Install Little Snitch.
2. Approve the Objective Development network extension in System Settings.
3. Open Little Snitch once.
4. Restore the license only from the offline state copy:

```bash
sudo install -m 600 -o root -g wheel \
  /Users/evw/dev/security/rebuild/state/ls-registration.xpl \
  "/Library/Application Support/Objective Development/Little Snitch/registration.xpl"
```

5. Restore the rule model:

```bash
sudo "/Applications/Little Snitch.app/Contents/Components/littlesnitch" \
  restore-model /Users/evw/dev/security/rebuild/state/ls-model.json
```

6. Verify the extension and rules:

```bash
systemextensionsctl list
sudo "/Applications/Little Snitch.app/Contents/Components/littlesnitch" \
  export-model /tmp/ls-rebuild-verify.json
python3 - <<'PY'
import json
m=json.load(open('/tmp/ls-rebuild-verify.json'))
print('rules:', len(m.get('rules', [])))
PY
rm -f /tmp/ls-rebuild-verify.json
```

---

## 9. Phase 6 — security stack installation order

Run these in order. Do not skip the deployment commands; they install the current fixed code.

### 9.1 Base guards and services

```bash
sudo bash /Users/evw/dev/security/install-all.sh --yes
```

This installs the core plist monitor, replay guard, audit monitor, file sentinel, binding monitor, DNS guard, PF dev-port protection, hardening rescan, and Wazuh-related setup.

### 9.2 Self-healing security system

```bash
sudo bash /Users/evw/dev/security/evw-security-system-setup.sh
```

This installs:

- `evw-security-system.py`
- `evw-alert-center.py`
- Little Snitch deny/hole-analysis helpers
- `com.evw.security-system`
- `com.evw.alert-center`

### 9.3 Security audit daemon and helper set

```bash
sudo bash /Users/evw/dev/security/evw-security-audit-setup.sh
```

This installs the audit script and root-owned helpers, including the backup checker.

### 9.4 Integrity scanner and rollback system

```bash
sudo bash /Users/evw/dev/security/evw-integrity-setup.sh
```

This installs:

- `evw-integrity.py`
- `evw-rollback.py`
- `/var/db/evw-integrity`
- pulse, sweep, full, and verify LaunchDaemons
- deterministic `/Users/evw` coverage and report placement
- serialized store locking

### 9.5 Little Snitch maintenance guards

```bash
sudo bash /Users/evw/dev/security/evw-ls-watchdog-setup.sh
sudo bash /Users/evw/dev/security/evw-ls-hourly-cleanup-setup.sh
```

Confirm the hygiene/watchdog daemons are registered:

```bash
sudo launchctl print system/com.evw.ls-watchdog
sudo launchctl print system/com.evw.ls-watchdog-monitor
sudo launchctl print system/com.evw.ls-hygiene-guard
sudo launchctl print system/com.evw.ls-hourly-cleanup
```

### 9.6 User LaunchAgents

Restore the captured agents:

```bash
mkdir -p /Users/evw/Library/LaunchAgents
cp /Users/evw/dev/security/rebuild/state/launchagents/*.plist \
  /Users/evw/Library/LaunchAgents/
```

Load each one:

```bash
for plist in /Users/evw/Library/LaunchAgents/com.evw.*.plist \
             /Users/evw/Library/LaunchAgents/com.ew.*.plist; do
  label=$(basename "$plist" .plist)
  launchctl bootout "gui/$(id -u)/$label" 2>/dev/null || true
  launchctl bootstrap "gui/$(id -u)" "$plist"
done
```

Add current agents that postdate the captured state if absent:

- `com.evw.alert-viewer.plist`
- `com.evw.colima.plist`
- `homebrew.mxcl.postgresql@16.plist`

Restart the alert viewer after any code change:

```bash
launchctl kickstart -k gui/501/com.evw.alert-viewer
```

---

## 10. Phase 7 — hardening posture

Run the reviewed hardening script:

```bash
sudo bash /Users/evw/dev/security/harden-now.sh
```

Then verify these outcomes:

- SSH remote login off
- Screen sharing off
- Remote Management off
- Bluetooth off unless explicitly required
- AirDrop, Handoff, and Universal Control off
- Wake-on-LAN and Power Nap off
- immediate password on wake
- mDNS advertisements quiet
- `/etc/hosts` matches the captured reviewed copy
- PF anchors loaded
- no third-party kernel extensions
- only the Little Snitch system extension is active

Commands:

```bash
sudo systemsetup -getremotelogin
sudo launchctl print-disabled system | grep -E 'ssh|screen|remote|ARD|nfs|smb'
systemextensionsctl list
kextstat | grep -v com.apple || true
sudo pfctl -s info
sudo pfctl -a com.ew.devports -s rules
```

---

## 11. Phase 8 — Wazuh, Colima, Docker, and PostgreSQL

### 11.1 Colima

The launch agent starts Colima at login. To install and start manually:

```bash
colima start
colima status
```

Expected:

- runtime: docker
- mount type: virtiofs
- Docker socket under `/Users/evw/.colima/default/docker.sock`
- SSH and service forwards on loopback
- Lima pseudo-loopback listeners on 53/443 protected by Lima and PF

### 11.2 Docker/Wazuh stack

```bash
cd /Users/evw/dev/security/wazuh-stack
docker compose up -d
docker ps
```

Expected containers:

- `wazuh-stack-wazuh.manager-1`
- `wazuh-stack-wazuh.indexer-1`
- `wazuh-stack-wazuh.dashboard-1`
- application database containers such as `likecostco-db-1` when that project is active

Ports must remain loopback-only in Docker:

- `127.0.0.1:443`
- `127.0.0.1:9200`
- `127.0.0.1:1514`
- `127.0.0.1:1515`
- `127.0.0.1:55000`
- `127.0.0.1:55432`

### 11.3 Host Wazuh agent

Install through the existing setup path:

```bash
sudo bash /Users/evw/dev/security/evw-wazuh-setup.sh
```

Verify:

```bash
sudo launchctl print system/com.wazuh.agent
sudo launchctl print system/com.evw.wazuh-monitor
sudo launchctl print system/com.evw.wazuh-guard
```

### 11.4 PostgreSQL

If PostgreSQL is required:

```bash
brew services start postgresql@16
launchctl print "gui/$(id -u)/homebrew.mxcl.postgresql@16"
```

It must listen only on `127.0.0.1` and `::1`.

---

## 12. Phase 9 — initialize integrity and backup verification

### 12.1 Run the first fixed full scan

```bash
sudo /usr/local/bin/evw-integrity.py full --tiers A,B,C,D
```

Review the report:

```bash
ls -t /Users/evw/dev/security/scan-*/integrity-full.txt | head -1
```

Confirm:

- no `UNREADABLE / SKIPPED` section unless every path is reviewed
- no mass-change incident
- no unexpected user-home changes
- no unexpected `/Users/evw/dev/security-backups` changes
- reports land under `/Users/evw/dev/security/scan-<date>/`, not `/var/root`

### 12.2 Verify backup completeness

```bash
sudo python3 /usr/local/bin/evw-backup-check.py \
  --report /Users/evw/dev/security/scan-$(date +%F)/backup-check.txt
```

Expected: zero issues after any intentional backup copy.

### 12.3 Verify rollback inventory

```bash
sudo /usr/local/bin/evw-rollback.py list
```

Review before applying anything:

```bash
sudo /usr/local/bin/evw-rollback.py restore --all --dry-run
```

Do not use `--apply` unless the reviewed dry run is exactly the intended change set.

---

## 13. Phase 10 — GitHub-based recovery

Use this only for repository-tracked files.

Dry run:

```bash
sudo /usr/local/bin/evw-rollback.py restore \
  --source github \
  --repo-root /Users/evw/dev/security \
  --paths /Users/evw/dev/security/path/to/file \
  --dry-run
```

Apply:

```bash
sudo /usr/local/bin/evw-rollback.py restore \
  --source github \
  --repo-root /Users/evw/dev/security \
  --paths /Users/evw/dev/security/path/to/file \
  --apply
```

Rules:

- Never use GitHub restore with `--all`.
- Use `--ref` when a specific commit or tag is needed.
- Do not use GitHub for secrets, ignored scans, Wazuh keys, or Little Snitch registration.
- Use local integrity rollback for files covered by `/var/db/evw-integrity`.
- Use the encrypted preservation bundle for local-only material.

---

## 14. Phase 11 — final validation gate

Run the full root audit:

```bash
sudo bash /usr/local/bin/evw-security-audit.sh --auto
```

Then verify each item:

### 14.1 Daemon registration

```bash
for label in \
  com.evw.security-system \
  com.evw.security-audit \
  com.evw.integrity-pulse \
  com.evw.integrity-sweep \
  com.evw.integrity-full \
  com.evw.integrity-verify \
  com.evw.plist-monitor \
  com.evw.plist-eslogger \
  com.evw.replayd-guard \
  com.evw.studentd-guard \
  com.evw.audit-monitor \
  com.evw.auto-conn-guard \
  com.evw.mac-sentinel \
  com.evw.file-vault \
  com.evw.dns-guard \
  com.evw.ls-watchdog \
  com.evw.ls-watchdog-monitor \
  com.evw.ls-hygiene-guard \
  com.evw.ls-hourly-cleanup \
  com.ew.file-sentinel \
  com.ew.binding-monitor \
  com.ew.pf-devports \
  com.ew.lockdown \
  com.wazuh.agent \
  com.evw.wazuh-monitor \
  com.evw.wazuh-guard; do
  sudo launchctl print "system/$label" >/dev/null 2>&1 \
    && echo "OK $label" || echo "MISSING $label"
done
```

### 14.2 User agents

```bash
for label in \
  com.evw.alert-center \
  com.evw.alert-viewer \
  com.evw.colima \
  com.evw.ls-resource-guard \
  com.evw.security-audit-login \
  com.evw.sentinel-alert-term \
  com.ew.config-sentinel \
  homebrew.mxcl.postgresql@16; do
  launchctl print "gui/$(id -u)/$label" >/dev/null 2>&1 \
    && echo "OK $label" || echo "MISSING $label"
done
```

### 14.3 Listeners

```bash
sudo lsof -nP -iTCP -sTCP:LISTEN
```

Expected: only reviewed loopback services plus Lima pseudo-loopback ports protected by Lima and PF. Any unknown non-loopback listener is a failure.

### 14.4 Outbound connections

```bash
sudo lsof -nP -iTCP -sTCP:ESTABLISHED
```

Every non-Apple destination must resolve to a known service and expected process.

### 14.5 TCC

Review `tcc-audit.txt`. No third-party screen capture, accessibility, input monitoring, or posting grants should exist without explicit approval.

### 14.6 Little Snitch

Review:

- `ls-full-analysis.txt`
- `ls-domain-audit.txt`
- `ls-rules-deep-audit.txt`
- `ls-permissive-analysis.txt`

Critical deny rules must be present, no guarded process may have an allow exception, and no unsigned binary may be allowed.

### 14.7 Integrity verification

```bash
sudo /usr/local/bin/evw-integrity.py verify --sample 5000
```

Expected: `git fsck: OK`; investigate every mismatch or skipped path.

### 14.8 Alert viewer

```bash
launchctl print gui/501/com.evw.alert-viewer
```

Open the alert viewer, single-click an entry, then double-click it. Expected: the lower pane updates on single click and a scrollable detail popup opens on double-click.

---

## 15. Failure and rollback procedure

### If an installer fails

1. Read the last red/error line.
2. Fix only that cause.
3. Re-run the same installer; the stack is intended to be idempotent.
4. Do not continue to later phases until the current phase verifies.

### If Little Snitch model restore fails

1. Approve its network extension.
2. Open Little Snitch once.
3. Re-run the restore command.
4. Re-run the security audit.

### If integrity reports many unexpected changes

1. Do not auto-heal.
2. Review `integrity-full.txt`.
3. Check whether a known deployment window was active.
4. Use `evw-rollback.py list` and `restore --dry-run`.
5. Apply only the reviewed paths.

### If a tracked security file is deleted

1. Try local integrity rollback first:

```bash
sudo /usr/local/bin/evw-rollback.py restore \
  --paths /Users/evw/dev/security/path/to/file \
  --dry-run
```

2. If no local snapshot exists, use GitHub:

```bash
sudo /usr/local/bin/evw-rollback.py restore \
  --source github \
  --repo-root /Users/evw/dev/security \
  --paths /Users/evw/dev/security/path/to/file \
  --dry-run
```

3. Apply only after reviewing the source, ref, hash, and quarantine plan.

### If the system appears compromised during rebuild

1. Disconnect the network.
2. Stop changing the machine.
3. Preserve logs and the integrity store.
4. Rebuild again from known-clean offline artifacts.
5. Do not import local-only state until its provenance is verified.

---

## 16. Ongoing maintenance schedule

### Every boot

- Root security audit runs automatically.
- Guards and daemon registration are checked.
- Colima starts through its LaunchAgent.

### Every 2 minutes

- Integrity pulse checks protected Tier A paths.

### Every 15 minutes

- Integrity sweep checks installed software and library tiers.

### Daily

- Full integrity scan covers the user home, backups, security repository, apps, Homebrew, `/etc`, launchd, and Little Snitch configuration.

### Weekly

- Integrity store verification samples 5,000 files.
- Review alert history and security reports.

### Monthly

```bash
sudo bash /Users/evw/dev/security/rebuild/capture-state.sh
```

Then review the state diff, refresh the offline repository copy, refresh the encrypted preservation bundle, and test one local rollback and one GitHub dry-run restore.

### Before any rebuild

Always run:

```bash
sudo bash /Users/evw/dev/security/rebuild/capture-state.sh
sudo python3 /usr/local/bin/evw-backup-check.py
sudo bash /usr/local/bin/evw-security-audit.sh --auto
```

---

## 17. Final acceptance criteria

The rebuild is complete only when all are true:

- FileVault enabled
- SIP enabled
- application firewall and PF protections active
- no remote-login, screen-sharing, ARD, NFS, or SMB service listening
- only Little Snitch system extension active
- no unknown third-party kexts
- all expected root daemons and user agents registered
- current Little Snitch model restored and critical denies verified
- integrity full scan covers `/Users/evw`
- skipped/unreadable paths are either zero or explicitly reviewed
- backup checker reports zero unreviewed missing/changed files
- Wazuh containers and host agent are connected
- Colima and PostgreSQL are loopback-bound
- alert viewer popup behavior verified manually
- local rollback dry run succeeds
- GitHub dry-run restore succeeds through `gh`
- a fresh encrypted preservation bundle exists off the machine

---

## 18. Files produced with this runbook

- `REBUILD-PLAN-2026-10-29.md` — source Markdown
- `REBUILD-PLAN-2026-10-29.html` — printable/offline HTML
- `REBUILD-PLAN-2026-10-29.zip` — local downloadable archive containing both files

Store the archive in the offline backup area only after reviewing it. Do not upload it to GitHub.
