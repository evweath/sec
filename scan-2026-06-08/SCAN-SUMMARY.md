# Security Scan — 2026-06-08

**Scan time:** 2026-06-08T ~13:00Z  
**OS:** macOS 26.5 (25F71)  
**Uptime at scan:** ~5.5h (boot ~07:42 CDT)  
**Diff baseline:** scan-2026-06-04  
**Status:** ✅ CLEAN — all controls intact, no unauthorized changes, no tunnels, no active sharing

---

## Checklist Results

| Item | Status | Notes |
|------|--------|-------|
| schg flag on disabled.501.plist | ✅ PRESENT | Jun 3 11:39 mtime — holding since Jun 3 |
| disabled.501.plist contents | ✅ 18 entries | All Jun 5 entries present + rapportd added this session |
| plist-monitor running | ✅ RUNNING | `pgrep -f evw-plist-monitor` confirms (runs as bash) |
| replayd guard running | ✅ ACTIVE | 2,656 kills logged |
| RemoteManagementAgent network | ✅ NONE | |
| remotemanagementd network | ✅ NONE | |
| sharingd network | ✅ NONE | Running but all features disabled by prefs |
| identityservicesd network | ✅ NONE | |
| replicatord network | ✅ NONE | UDP bound :63688 (iCloud, expected) |
| studentd network | ✅ NONE | |
| privatecloudcomputed network | ✅ NONE | |
| AirDrop discoverable | ✅ OFF | `DiscoverableMode = Off` |
| Handoff advertising/receiving | ✅ OFF | ActivityAdvertising/ReceivingAllowed = 0 |
| SharingServicesEnabled | ✅ 0 | |
| Screen Sharing | ✅ NOT LOADED | |
| Remote Login (SSH) | ✅ NOT LOADED | |
| Remote Desktop | ✅ NOT LOADED | |
| File Sharing (SMB/AFP) | ✅ NOT LOADED | |

---

## Security Controls

| Control | Status |
|---------|--------|
| SIP | Enabled ✓ |
| FileVault | On ✓ |
| Gatekeeper | Enabled ✓ |
| App Firewall | Enabled ✓ |
| MDM enrollment | None ✓ |
| Config profiles | None ✓ |
| Third-party kexts | None ✓ |
| System extensions | LS 6.3.3 only ✓ |

---

## Binary Hashes vs scan-2026-06-04

5 modified (all expected), 4 new, 2 removed:
- Modified: SESSION.md, settings.local.json, l5-hash-log.txt, memory/short_term.csmem, memory/long_term.csmem
- New: Claude Code 2.1.165, 2.1.168 (version updates)
- Removed: Claude Code 2.1.160, 2.1.161 (superseded)

**Zero unexpected binary changes.**

---

## Little Snitch Rule Audit

| Metric | Value |
|--------|-------|
| Rules before dedup | 3,283 |
| True duplicates found | 62 |
| Rules after dedup | 3,221 |
| Rules after restore+verify | 3,226 |
| Current model (+ OTS + catch-all) | 3,263 |
| Critical deny rules | 15/15 ✅ |

Dedup script: `ls-dedup.py` — fingerprint includes all remote fields (remote, remote-hosts, remote-domains, remote-addresses).

---

## Network State

**Active TCP connections:**
| Process | Remote | What |
|---------|--------|------|
| Claude Code 2.1.168 | 35.190.46.17:443, 2607:6bc0::10:443 | Anthropic API (GCP) |
| Claude Code 2.1.168 | 2607:f8b0:4023:1::443 | Google infrastructure |
| com.apple.MAS | 127.0.0.1:8743 | → local donut-intel dev server |

**Default route:** `10.141.222.172 via en0` only (WiFi). All internet traffic exits via en0.

**Tunnel interfaces (utun0–3):**
- utun0, utun2, utun3: owned by identityservicesd (iCloud identity)
- utun1: owned by rapportd (Universal Control — disabled by prefs + now in disabled.501.plist)
- All utun interfaces: link-local IPv6 (fe80::) ONLY, no routable addresses
- Total utun traffic since boot: <5 bytes per interface (neighbor discovery only)
- **No data tunneling. No VPN.**

---

## L5 Integrity Verification

### Security manifest (1,147 files)
- File: `l5-manifest-full-2026-06-08.txt`
- SHA-256: `063b0a6b8838f2af0987b9799b1c8ffc065cc892105a5e760b1cf9d7b05117f8`
- OTS proof: `l5-manifest-full-2026-06-08.txt.ots` — Bitcoin pending → upgrade required
- Diff vs Jun 3: 159 modified (all expected), 35 new, 10 removed

### Full home scan (83,413 files)
- File: `l5-full-home-2026-06-08.txt`
- SHA-256: `d02c5d9fa7dc300ab5107696f9a5eea1c77710d85df492e606638e33c0f23133`
- OTS proof: `l5-full-home-2026-06-08.txt.ots` — Bitcoin pending → upgrade required
- Diff vs Jun 5: 822 modified, 1,191 new, 1,691 removed — all expected activity

---

## Hardening Actions This Session

### 1. Little Snitch Deduplication
- Exported live model (3,283 rules)
- Removed 62 true duplicates (corrected fingerprint: all remote fields)
- Restored deduped model (3,226 rules after verify)
- All 15 critical deny rules confirmed present post-dedup

### 2. OTS Bitcoin Timestamping — Root Cause Resolved
**Root cause of prior failures:** Two conditions combined:
1. `(any)→deny any` catch-all LS rule blocked hostname-based TCP with EBADF
2. `activeSilentMode=0` (alert mode) — without catch-all, LS prompted and timed out

**Fix:** Restore model without catch-all + `run-with-ls-silent.sh` wrapper (sets mode=1 for duration).

**Procedure for future OTS stamps:**
```
sudo restore-model /tmp/ls-stamp-ready.json   # removes catch-all
run-with-ls-silent.sh ots stamp ...           # silent-allow mode
sudo restore-model /tmp/ls-with-ots.json      # restores catch-all
```

### 3. rapportd Disabled
- Added `com.apple.rapportd => true` to disabled.501.plist
- Universal Control was already `Enabled=0` by preference
- utun1 persists in live session via XPC re-activation (SIP prevents full removal)
- LS catch-all deny rule blocks all rapportd outbound connections
- schg re-applied to disabled.501.plist after edit

---

## Pending Actions

1. **OTS upgrade** (after Bitcoin confirmation): `ots upgrade l5-manifest-full-2026-06-08.txt.ots l5-full-home-2026-06-08.txt.ots`
2. **TCC audit** (requires sudo): `sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db "SELECT service,client,auth_value,last_modified FROM access WHERE service IN ('kTCCServiceScreenCapture','kTCCServiceAccessibility','kTCCServiceListenEvent') ORDER BY service,auth_value DESC;"`
3. **Touch ID re-enrollment**: System Settings → Touch ID & Password → Add Fingerprint (pending since Jun 5 keybag UUID mismatch)

---

## Artifacts

`~/dev/security/scan-2026-06-08/`:
- `ls-model-original.json` — 3,283 rules (pre-dedup)
- `ls-model-deduped.json` — 3,221 rules (62 removed)
- `ls-model-verified.json` — 3,226 rules (post-restore export)
- `file-hashes.txt` — 77 security-file binary hashes
- `file-hash-diff-vs-scan-2026-06-04.txt` — diff report

`~/dev/security/`:
- `l5-manifest-full-2026-06-08.txt` + `.ots`
- `l5-full-home-2026-06-08.txt` + `.ots`
- `ls-dedup.py` — corrected dedup script
- `/tmp/ls-stamp-ready.json` — LS model without catch-all (for future OTS stamps)
- `/tmp/ls-with-ots.json` — current live model (3,263 rules)
