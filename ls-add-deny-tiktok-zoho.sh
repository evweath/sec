#!/bin/bash
# ls-add-deny-tiktok-zoho.sh
#
# 1. Removes all existing allow/suggestion rules for TikTok and Zoho tracking domains
# 2. Adds domain-level deny rules for TikTok (all subdomains)
# 3. Adds targeted deny rules for Zoho tracking/analytics subdomains
#    (does NOT block zoho.com broadly — only the tracker/widget endpoints)
#
# Must run as root: sudo bash ~/dev/security/ls-add-deny-tiktok-zoho.sh

set -euo pipefail

LSCLI="/Applications/Little Snitch.app/Contents/Components/littlesnitch"
TS=$(date +%s)
EXPORT="/var/tmp/ls-pre-deny-${TS}.json"
MODIFIED="/var/tmp/ls-post-deny-${TS}.json"
BACKUP="/Users/evw/dev/security/scan-$(date +%Y-%m-%d)/ls-model-pre-deny-${TS}.json"
REPORT="/Users/evw/dev/security/scan-$(date +%Y-%m-%d)/ls-deny-report-${TS}.txt"

mkdir -p "$(dirname "$BACKUP")"

echo "================================================================"
echo "ls-add-deny-tiktok-zoho.sh"
echo "$(date)"
echo "================================================================"
echo ""

echo "[1/3] Exporting current LS model..."
"$LSCLI" export-model "$EXPORT" || true
[[ -f "$EXPORT" ]] || { echo "ERROR: export failed"; exit 1; }
cp "$EXPORT" "$BACKUP"
echo "      $(wc -c < "$EXPORT") bytes → backup: $BACKUP"
echo ""

echo "[2/3] Applying changes..."
python3 << PYEOF
import json, sys
from datetime import timezone, datetime

src  = "${EXPORT}"
dst  = "${MODIFIED}"
rpt  = "${REPORT}"
NOW  = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

with open(src) as f:
    model = json.load(f)

rules = model.get("rules", [])
orig_count = len(rules)

# ── TikTok: domains to block at the domain level (matches all subdomains) ───
TIKTOK_DOMAINS = [
    "tiktok.com",
    "tiktokcdn-us.com",
    "tiktokv.us",
    "tiktokw.us",
    "ttcdn-us.com",
    "tiktokshops.us",
    "bytedance.com",
]

# ── Zoho: only the analytics/tracking/widget endpoints — NOT zoho.com broadly ─
# zohopublic.com and zohocdn.com are Zoho's widget-embedding CDN domains
# (vts.zohopublic.com = visitor tracking, salesiq = live chat, zohocdn = widget assets)
ZOHO_BLOCK_DOMAINS = [
    "zohopublic.com",   # domain-level: vts.*, salesiq.*, us4-files.*, etc.
    "zohocdn.com",      # domain-level: css.*, js.*, static.* (SalesIQ widget CDN)
]
ZOHO_BLOCK_HOSTS = [
    "salesiq.zoho.com",
    "pagesense-collect.zoho.com",
    "pagesense-hb-collect.zoho.com",
]

ALL_BLOCK_DOMAINS = set(TIKTOK_DOMAINS + ZOHO_BLOCK_DOMAINS)
ALL_BLOCK_HOSTS   = set(ZOHO_BLOCK_HOSTS)


def host_matches(r: dict) -> bool:
    """Return True if this rule references a domain/host we want to block."""
    for field in ("remote-hosts", "remote-domains"):
        v = str(r.get(field, ""))
        if not v:
            continue
        for h in v.replace(",", " ").split():
            h = h.strip().lstrip("*.")
            # Check against block-domains (any suffix match)
            for bd in ALL_BLOCK_DOMAINS:
                if h == bd or h.endswith("." + bd):
                    return True
            # Check against block-hosts (exact)
            if h in ALL_BLOCK_HOSTS:
                return True
    return False


removed = []
kept    = []
for r in rules:
    action = r.get("action", "")
    if action in ("allow", "suggestion") and host_matches(r):
        proc = r.get("process", "<ANY>")
        if proc.startswith("identifier.APPLE/"):
            proc = proc[17:]
        elif proc.startswith("identifier."):
            proc = proc.split("/")[-1]
        remote = r.get("remote-hosts") or r.get("remote-domains") or r.get("remote", "")
        removed.append(f"  [REMOVE {action}] {proc:<40}  {remote}  uses={r.get('useCount',0)}")
    else:
        kept.append(r)

# ── Build new deny rules ─────────────────────────────────────────────────────
def deny_domain(domain: str, note: str) -> dict:
    return {
        "action":           "deny",
        "creationDate":     NOW,
        "modificationDate": NOW,
        "notes":            note,
        "origin":           "ruleImport",
        "remote-domains":   domain,
    }

def deny_host(host: str, note: str) -> dict:
    return {
        "action":           "deny",
        "creationDate":     NOW,
        "modificationDate": NOW,
        "notes":            note,
        "origin":           "ruleImport",
        "remote-hosts":     host,
    }

new_denies = []
for d in TIKTOK_DOMAINS:
    new_denies.append(deny_domain(d, f"Block TikTok/ByteDance data collection — audit 2026-06-10"))
for d in ZOHO_BLOCK_DOMAINS:
    new_denies.append(deny_domain(d, f"Block Zoho analytics/tracking widgets — audit 2026-06-10"))
for h in ZOHO_BLOCK_HOSTS:
    new_denies.append(deny_host(h, f"Block Zoho analytics/tracking widgets — audit 2026-06-10"))

model["rules"] = kept + new_denies
final_count = len(model["rules"])

# ── Report ───────────────────────────────────────────────────────────────────
lines = [
    f"Original rule count:  {orig_count}",
    f"Removed (allow/sug):  {len(removed)}",
    f"New deny rules added: {len(new_denies)}",
    f"Final rule count:     {final_count}",
    "",
    "=== REMOVED RULES ===",
] + removed + [
    "",
    "=== NEW DENY RULES ===",
] + [f"  [DENY] {r['remote-domains'] if 'remote-domains' in r else r['remote-hosts']}" for r in new_denies]

report_text = "\n".join(lines)
print(report_text)

with open(rpt, "w") as f:
    f.write(report_text + "\n")

with open(dst, "w") as f:
    json.dump(model, f, indent=2, separators=(",", " : "))
    f.write("\n")
PYEOF

echo ""

echo "[3/3] Importing modified model..."
"$LSCLI" restore-model "$MODIFIED"

rm -f "$EXPORT" "$MODIFIED"

echo ""
echo "================================================================"
echo "Done. Report: $REPORT"
echo ""
echo "Verify in Little Snitch Rules (Cmd+R):"
echo "  — search 'tiktok' → should show only deny rules"
echo "  — search 'zoho'   → should show deny for zohopublic.com / zohocdn.com"
echo "  — salesiq.zoho.com, pagesense*.zoho.com → deny"
echo "================================================================"
