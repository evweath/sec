#!/usr/bin/env python3
"""Deduplicate Little Snitch rules model.
Usage: python3 ls-dedup.py <input-model.json> <output-model.json>
"""
import json, sys
from collections import defaultdict

INPUT  = sys.argv[1] if len(sys.argv) > 1 else '/tmp/ls-model-2026-06-08.json'
OUTPUT = sys.argv[2] if len(sys.argv) > 2 else '/tmp/ls-model-deduped.json'

with open(INPUT) as f:
    model = json.load(f)

rules = model.get('rules', [])
print(f"Input rules: {len(rules)}")

def norm(v):
    """Normalize a field value for fingerprinting."""
    if isinstance(v, list):
        return str(sorted(str(x) for x in v))
    return str(v) if v is not None else ''

def fingerprint(r):
    """Functional identity of a rule — all fields that define what it matches."""
    return (
        r.get('action', ''),
        r.get('direction', ''),
        r.get('process', ''),
        norm(r.get('remote', '')),
        norm(r.get('remote-hosts', '')),
        norm(r.get('remote-domains', '')),
        norm(r.get('remote-addresses', '')),
        r.get('protocol', ''),
        norm(r.get('ports', '')),
    )

def rule_priority(r):
    """Higher = prefer to keep. Protected factory rules win; then higher useCount."""
    protected = 1 if r.get('protected') else 0
    use_count = r.get('useCount', 0)
    return (protected, use_count)

# Group rules by fingerprint
groups = defaultdict(list)
for i, r in enumerate(rules):
    groups[fingerprint(r)].append((i, r))

kept = []
removed_count = 0
removed_by_action = defaultdict(int)

for fp, copies in groups.items():
    if len(copies) == 1:
        kept.append(copies[0][1])
    else:
        # Sort: highest priority first (keep that one)
        copies.sort(key=lambda x: rule_priority(x[1]), reverse=True)
        best = dict(copies[0][1])
        # Merge useCount so statistics aren't lost
        best['useCount'] = sum(c[1].get('useCount', 0) for c in copies)
        kept.append(best)
        removed_count += len(copies) - 1
        removed_by_action[fp[0]] += len(copies) - 1
        if len(copies) > 3:
            action = fp[0].upper()
            proc = (fp[2] or '(any)')[-50:]
            remote = (fp[3] or fp[4] or fp[5] or fp[6] or 'any')[:30]
            print(f"  DEDUP [{action:5}] {proc}  remote={remote}  x{len(copies)} → 1  (removed {len(copies)-1})")

print(f"\nRemoved {removed_count} duplicate rules by action:")
for action, count in sorted(removed_by_action.items(), key=lambda x: -x[1]):
    print(f"  {action:12} -{count}")

print(f"\nOutput rules: {len(kept)}  (was {len(rules)}, -{removed_count})")

model['rules'] = kept
with open(OUTPUT, 'w') as f:
    json.dump(model, f, indent=2)
print(f"Saved to {OUTPUT}")

# Verify critical deny rules survived
CRITICAL = [
    'replayd', 'privatecloudcomputed', 'remotemanagementd',
    'RemoteManagementAgent', 'studentd', 'launchctl', 'kickstart',
    'datadoghq', 'influxdata', 'found.io',
    # TikTok/Zoho tracker denies (carried over from retired ls-add-deny-tiktok-zoho.sh)
    'tiktok', 'bytedance', 'zohopublic', 'zohocdn', 'salesiq', 'pagesense',
]
print("\nVerifying critical deny rules survived dedup:")
deny_rules = [r for r in kept if r.get('action') == 'deny']
for name in CRITICAL:
    found = any(name in str(r) for r in deny_rules)
    status = "✅" if found else "❌ MISSING"
    print(f"  {status}  {name}")
