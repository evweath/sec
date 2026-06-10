#!/bin/bash
# ls-tighten-rules.sh
# Applies recommended Little Snitch rule changes:
#   PHASE 1 — DELETE 11 rules:
#     - All 7 rules via unsigned binary SHA256:84915e7c (V-001 + related)
#     - 1 duplicate mDNSResponder any-remote monitor rule (0 uses)
#     - 1 Little Snitch network extension → any monitor rule (0 uses)
#     - 2 disabled any-remote monitor rules (mobileassetd, syspolicyd)
#   PHASE 2 — TIGHTEN ~282 rules:
#     - Add port "443" to all rules with specific remote-hosts but no port restriction
#
# Must run as root: sudo bash /Users/evw/dev/security/ls-tighten-rules.sh
# DRY-RUN mode:     sudo bash /Users/evw/dev/security/ls-tighten-rules.sh --dry-run

set -euo pipefail

DRY_RUN=false
if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=true
    echo "=== DRY RUN MODE — no changes will be applied ==="
fi

LSCLI="/Applications/Little Snitch.app/Contents/Components/littlesnitch"
TS=$(date +%s)
EXPORT="/var/tmp/ls-pre-tighten-${TS}.json"
MODIFIED="/var/tmp/ls-tightened-${TS}.json"
BACKUP="/Users/evw/dev/security/scan-$(date +%Y-%m-%d)/ls-model-pre-tighten-${TS}.json"
REPORT="/Users/evw/dev/security/scan-$(date +%Y-%m-%d)/ls-tighten-report-${TS}.txt"

mkdir -p "$(dirname "$BACKUP")"

echo "================================================================"
echo "Little Snitch Rule Remediation Script"
echo "$(date)"
echo "================================================================"
echo ""

# ── Step 1: Export current model ────────────────────────────────────
echo "[1/4] Exporting current LS model..."
"$LSCLI" export-model "$EXPORT" || true   # LS CLI returns non-zero even on success
if [ ! -f "$EXPORT" ]; then
    echo "ERROR: export produced no file. Is Little Snitch running? Are you root?"
    exit 1
fi
EXPORT_SIZE=$(wc -c < "$EXPORT")
echo "      Exported ${EXPORT_SIZE} bytes → ${EXPORT}"

# Save backup
cp "$EXPORT" "$BACKUP"
echo "      Backup saved → ${BACKUP}"
echo ""

# ── Step 2: Apply changes via Python ────────────────────────────────
echo "[2/4] Applying rule changes..."
python3 << PYEOF
import json, sys

UNSIGNED = "identifier.SHA256/84915e7c242d8cb3f80ab9940a1aeaba1553467be7e02c0172014af764a53b70"
DRY_RUN = "${DRY_RUN}" == "true"
src = "${EXPORT}"
dst = "${MODIFIED}"
report_path = "${REPORT}"

with open(src) as f:
    model = json.load(f)

rules = model.get("rules", [])
original_count = len(rules)

deleted = []
tightened = []

new_rules = []
for r in rules:
    action = r.get("action", "")
    proc = r.get("process", "")
    remote = r.get("remote", "")
    via = r.get("via", "")
    origin = r.get("origin", "")
    protected = r.get("protected", False)
    disabled = r.get("disabled", False)
    uses = r.get("useCount", 0)
    has_remote_hosts = bool(r.get("remote-hosts"))

    # Extract peer from factoryHelpText for logging
    peer = ""
    for line in r.get("factoryHelpText", "").split("\n"):
        if line.startswith("peer: "):
            peer = line[6:]

    # ── PHASE 1: Rules to DELETE ─────────────────────────────────────

    # 1a. All rules via unsigned binary SHA256:84915e7c
    if via == UNSIGNED:
        deleted.append(f"  [DELETE] unsigned-binary  proc={proc.split('/')[-1][:30]}  peer={peer}  uses={uses}")
        continue

    # 1b. Duplicate mDNSResponder any-remote monitor rules with 0 uses
    if (proc.endswith("mDNSResponder")
            and remote == "any"
            and origin == "monitor"
            and not protected
            and uses == 0):
        deleted.append(f"  [DELETE] mDNS-dup-any    proc={proc.split('/')[-1][:30]}  uses=0  origin=monitor")
        continue

    # 1c. Little Snitch network extension → any monitor rule
    if ("littlesnitch.networkextension" in proc
            and remote == "any"
            and origin == "monitor"
            and not protected):
        deleted.append(f"  [DELETE] ls-ext-any      proc={proc.split('/')[-1][:40]}  uses={uses}")
        continue

    # 1d. Other disabled any-remote monitor rules (mobileassetd, syspolicyd)
    if (remote == "any"
            and origin == "monitor"
            and disabled
            and not protected
            and proc.endswith(("mobileassetd", "syspolicyd"))):
        deleted.append(f"  [DELETE] disabled-any    proc={proc.split('/')[-1][:30]}  uses={uses}  disabled=true")
        continue

    # ── PHASE 2: Rules to TIGHTEN ────────────────────────────────────

    # Add port "443" to rules with specific remote-hosts but no port restriction
    # Condition: allow rule, has remote-hosts, no ports set, not protected, not disabled, not UDP
    if (action == "allow"
            and has_remote_hosts
            and not r.get("ports")
            and not protected
            and not disabled
            and r.get("protocol", "any") not in ("udp", "icmp")):
        host = r.get("remote-hosts", "")
        r = dict(r)  # copy to avoid mutating original
        r["ports"] = "443"
        r["protocol"] = "tcp"
        tightened.append(f"  [TIGHTEN] +port=443  proc={proc.split('/')[-1][:30]}  host={str(host)[:50]}  uses={uses}")

    new_rules.append(r)

model["rules"] = new_rules
final_count = len(new_rules)

# Print summary
lines = []
lines.append(f"Original rule count:  {original_count}")
lines.append(f"Deleted:              {len(deleted)}")
lines.append(f"Tightened:            {len(tightened)}")
lines.append(f"Final rule count:     {final_count}")
lines.append("")
lines.append("=== DELETED RULES ===")
lines.extend(deleted)
lines.append("")
lines.append("=== TIGHTENED RULES (first 30) ===")
lines.extend(tightened[:30])
if len(tightened) > 30:
    lines.append(f"  ... and {len(tightened)-30} more")

report_text = "\n".join(lines)
print(report_text)

# Save report
with open(report_path, "w") as f:
    f.write(report_text + "\n")

if not DRY_RUN:
    # Write modified model
    with open(dst, "w") as f:
        json.dump(model, f, indent=2, separators=(",", " : "))
        f.write("\n")
    print(f"\nModified model written to {dst}")
else:
    print("\n[DRY RUN] No output file written.")
    sys.exit(0)
PYEOF

echo ""

# ── Step 3: Verify the modified model exists ────────────────────────
if [ "$DRY_RUN" = "true" ]; then
    echo "[3/4] Dry-run mode — skipping import"
    echo "[4/4] Done. Review report at: ${REPORT}"
    exit 0
fi

if [ ! -f "$MODIFIED" ]; then
    echo "ERROR: Python script produced no output file. Aborting."
    exit 1
fi

MODIFIED_SIZE=$(wc -c < "$MODIFIED")
echo "[3/4] Modified model: ${MODIFIED_SIZE} bytes → ${MODIFIED}"
echo ""

# ── Step 4: Import modified model ───────────────────────────────────
echo "[4/4] Importing modified model into Little Snitch..."
"$LSCLI" restore-model "$MODIFIED"
echo ""
echo "================================================================"
echo "SUCCESS — Rule changes applied"
echo "  Backup:  ${BACKUP}"
echo "  Report:  ${REPORT}"
echo "================================================================"
echo ""
echo "Next steps:"
echo "  1. Open Little Snitch Rules (Cmd+R) to verify changes"
echo "  2. Check: no Terminal→any unsigned-binary rule"
echo "  3. Check: specific-host rules now show port 443"
echo "  4. Run: python3 ~/dev/security/ls-permissive-analysis.py /tmp/ls-verify.json"

# Cleanup temp files
rm -f "$EXPORT" "$MODIFIED"
