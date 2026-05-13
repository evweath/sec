# Session State — 2026-05-13T07:45:00-00:00

## Accomplished This Session
- Full security post-mortem completed
- Identified attack artifact: `/Library/LaunchDaemons/com.apple.iokitd.plist` (fake Apple daemon, installed Apr 30)
- Identified memory/process crash loop: ai-orchestrator frontend (KeepAlive=true, missing /tmp/localcert/key.pem)
- Fixed `/Users/ew/scripts/pf-devports.conf`: removed `table <devports> const {}` (macOS pfctl unsupported in anchors), inlined port list into block rules so PF can actually load them
- Fixed `/Users/ew/scripts/seccheck.sh`: removed `com.apple.iokitd` from KNOWN_DAEMONS; changed audit to FAIL on any `com.apple.*` label in /Library/LaunchDaemons (impersonation detection); added `KNOWN_APPLE_DAEMONS_IN_LIBRARY` explicit allowlist
- Confirmed seccheck.sh now flags the fake daemon as [FAIL] IMPERSONATION RISK

## Pending (Requires User Action with sudo)

### CRITICAL — Must Do First
```bash
# Remove fake daemon (still trying to launch every 5 sec)
sudo launchctl bootout system /Library/LaunchDaemons/com.apple.iokitd.plist
sudo rm /Library/LaunchDaemons/com.apple.iokitd.plist
sudo rm -rf /usr/local/lib/mac-sentinel/
```

### Fix Memory Crash Loop
```bash
# Stop ai-orchestrator frontend (KeepAlive loop crashing on missing /tmp/localcert/key.pem)
launchctl unload ~/Library/LaunchAgents/com.ai-orchestrator.frontend.plist
```

### Reload PF Rules (after pf-devports.conf fix)
```bash
sudo /Users/ew/scripts/setup-pf.sh
sudo pfctl -a com.ew.devports -s rules   # verify rules loaded
```

### Update config-sentinel Baseline
```bash
# .claude.json changes are from Claude Code session management — not an attack
/Users/ew/scripts/config-sentinel.sh --baseline
```

### Run Full Security Check as Root
```bash
sudo /Users/ew/scripts/seccheck.sh
```

## Key Context

### Attack Details
- **Attack entry date**: April 30, 2026 at 14:29
- **Persistence mechanism**: `/Library/LaunchDaemons/com.apple.iokitd.plist`
  - Label `com.apple.iokitd` bypasses old seccheck.sh (which skipped all `com.apple.*`)
  - Ran `/usr/local/lib/mac-sentinel/mac-sentinel.py` as root, KeepAlive=true
  - Script had root access for ~12 days before removal
  - Script itself was already deleted (in previous session); plist remains
  - Directory `/usr/local/lib/mac-sentinel/` owned root:staff, now empty
- **What the script did**: Unknown — it's been deleted. Root access for 12 days is worst-case compromise.

### Process Issues
- **ai-orchestrator frontend** (`com.ai-orchestrator.frontend.plist`): KeepAlive=true, crashes every boot because `/tmp/localcert/key.pem` is cleared on reboot. Node.js spawns ~100MB per attempt, creating memory pressure.
- **file-sentinel daemon** (`/Library/LaunchDaemons/com.ew.file-sentinel.plist`): Log stale 756s+, error log has old audit-based error messages. May not be running. Check with `sudo launchctl list | grep file-sentinel`.

### PF Rules Status
- `/etc/pf.anchors/com.ew.devports` had `table <devports> const {}` syntax — macOS pfctl rejects this in anchor files
- Fixed to use inline port list in block rules
- PF was NOT blocking dev ports despite LaunchDaemon being loaded
- Needs `sudo /Users/ew/scripts/setup-pf.sh` to apply fix

### seccheck.sh Section 6 Bypass
- The `com.apple.*` skip (`[[ "$label" == com.apple.* ]] && continue`) was exploited
- Fixed: any com.apple.* label in /Library/LaunchDaemons now fails the check
- The KNOWN_APPLE_DAEMONS_IN_LIBRARY list is empty and should stay empty

### .claude.json "Changes"
- Config-sentinel flags ~/.claude.json as changed — this is Claude Code's own session state updates, not an attack
- Update baseline after each Claude Code session: `config-sentinel.sh --baseline`
