#!/usr/bin/env python3
"""Complete Little Snitch rule analysis.
Usage: sudo /path/to/littlesnitch export-model /tmp/ls-full.json && python3 ls-full-analysis.py /tmp/ls-full.json [prev-model.json]
"""
import json, sys, os
from collections import defaultdict, Counter
from datetime import datetime

MODEL_PATH = sys.argv[1] if len(sys.argv) > 1 else '/tmp/ls-check-now.json'
PREV_PATH  = sys.argv[2] if len(sys.argv) > 2 else \
    os.path.expanduser('~/dev/security/scan-2026-06-03/ls-model.json')
SAVE_PATH  = os.path.expanduser(
    f'~/dev/security/scan-{datetime.utcnow().strftime("%Y-%m-%d")}/ls-model.json')

with open(MODEL_PATH) as f:
    model = json.load(f)
rules = model.get('rules', [])
deny  = [r for r in rules if r.get('action') == 'deny']
allow = [r for r in rules if r.get('action') == 'allow']
ask   = [r for r in rules if r.get('action') == 'ask']
sugg  = [r for r in rules if r.get('action') == 'suggestion']

W = 70

def section(title):
    print(f'\n{"─"*W}')
    print(title)
    print(f'{"─"*W}')

def proc_label(r):
    p = r.get('process', '')
    # strip long identifier prefix
    if '/' in p:
        return p.split('/')[-1]
    if p.startswith('identifier.'):
        parts = p.split('/')
        return parts[-1] if len(parts) > 1 else p
    return p or '(any)'

def remote_label(r):
    for key in ('remote-domains', 'remote-hosts', 'remote-addresses', 'remote'):
        v = r.get(key)
        if v:
            return str(v)[:50]
    return 'any'

# ── Header ────────────────────────────────────────────────────────────────────
print('='*W)
print('LITTLE SNITCH — COMPLETE RULE ANALYSIS')
print(f'Model: {MODEL_PATH}')
print(f'Date:  {datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")}')
print('='*W)
print(f'  Total rules : {len(rules)}')
print(f'  Deny        : {len(deny)}')
print(f'  Allow       : {len(allow)}')
print(f'  Ask         : {len(ask)}')
print(f'  Suggestions : {len(sugg)}')

# ── 1. Critical deny rule verification ───────────────────────────────────────
section('1. CRITICAL DENY RULES')

CRITICAL = [
    ('replayd → DENY any',
        lambda r: r.get('action')=='deny' and 'replayd' in str(r.get('process',''))),
    ('privatecloudcomputed → DENY any',
        lambda r: r.get('action')=='deny' and 'privatecloudcomputed' in str(r.get('process',''))),
    ('remotemanagementd → DENY any',
        lambda r: r.get('action')=='deny' and 'remotemanagementd' in str(r.get('process',''))),
    ('RemoteManagementAgent → DENY any',
        lambda r: r.get('action')=='deny' and 'RemoteManagementAgent' in str(r.get('process',''))),
    ('ARDAgent/kickstart → DENY any',
        lambda r: r.get('action')=='deny' and 'kickstart' in str(r.get('process',''))),
    ('/bin/launchctl → DENY any',
        lambda r: r.get('action')=='deny' and 'launchctl' in str(r.get('process',''))),
    ('studentd → DENY any',
        lambda r: r.get('action')=='deny' and 'studentd' in str(r.get('process',''))),
    ('identityservicesd → DENY any',
        lambda r: r.get('action')=='deny' and 'identityservicesd' in str(r.get('process',''))),
    ('symptomsd → DENY any',
        lambda r: r.get('action')=='deny' and 'symptomsd' in str(r.get('process',''))),
    ('SubmitDiagInfo → DENY any',
        lambda r: r.get('action')=='deny' and 'SubmitDiagInfo' in str(r.get('process',''))),
    ('ScreenSharingSubscriber → DENY any',
        lambda r: r.get('action')=='deny' and 'ScreenSharingSubscriber' in str(r.get('process',''))),
    ('ManagedAppsSubscriber → DENY any',
        lambda r: r.get('action')=='deny' and 'ManagedAppsSubscriber' in str(r.get('process',''))),
    ('datadoghq.com → DENY (global)',
        lambda r: r.get('action')=='deny' and 'datadoghq.com' in str(r.get('remote-domains',''))),
    ('found.io → DENY (global)',
        lambda r: r.get('action')=='deny' and 'found.io' in str(r.get('remote-domains',''))),
    ('influxdata.com → DENY (Terminal)',
        lambda r: r.get('action')=='deny' and 'influxdata.com' in str(r.get('remote-domains',''))
                  and 'Terminal' in str(r.get('process',''))),
]

missing = []
for label, fn in CRITICAL:
    found = any(fn(r) for r in rules)
    status = '✅' if found else '❌ MISSING'
    # Show matching rule details if found
    matches = [r for r in rules if fn(r)]
    print(f'  {status}  {label}')
    if found:
        for m in matches[:2]:
            remote = remote_label(m)
            print(f'         process={m.get("process","")[-60:]}  remote={remote}')
    else:
        missing.append(label)

# ── 2. RemoteManagement XPC subscribers ──────────────────────────────────────
section('2. REMOTEMANAGEMENT XPC SUBSCRIBERS')
xpc_targets = [
    'ASConfigurationSubscriber','AccountSubscriber','DiskManagementSubscriber',
    'InteractiveLegacyProfilesSubscriber','LegacyProfilesSubscriber',
    'ManagedAppsSubscriber','ManagedConfigurationFilesSubscriber',
    'ManagedPreferencesSubscriber','ManagedSettingsSubscriber',
    'ManagementTestSubscriber','MigrationSubscriber','PasscodeSettingsSubscriber',
    'ScreenSharingSubscriber','SecuritySubscriber','SoftwareUpdateSubscriber',
]
xpc_found = [x for x in xpc_targets
             if any(x in str(r.get('process','')) and r.get('action')=='deny' for r in rules)]
xpc_missing = [x for x in xpc_targets if x not in xpc_found]
print(f'  {len(xpc_found)}/{len(xpc_targets)} blocked')
for x in xpc_missing:
    print(f'  ❌ MISSING: {x}')
    missing.append(f'XPC: {x}')

# ── 3. Deny rules by process (top 30) ────────────────────────────────────────
section('3. DENY RULES BY PROCESS (top 30)')
by_proc = Counter(proc_label(r) for r in deny)
for proc, count in by_proc.most_common(30):
    print(f'  {count:4d}  {proc}')

# ── 4. Deny-any rules (broadest coverage) ────────────────────────────────────
section('4. DENY-ANY RULES (process → deny all connections)')
deny_any = [r for r in deny if remote_label(r) == 'any']
if deny_any:
    for r in sorted(deny_any, key=lambda r: proc_label(r)):
        prot = r.get('protocol', 'any')
        owner = r.get('owner', 'user')
        print(f'  {proc_label(r):<50} proto={prot}  owner={owner}')
else:
    print('  (none)')

# ── 5. Allow rules for sensitive processes ────────────────────────────────────
section('5. ALLOW RULES FOR SENSITIVE PROCESSES')
SENSITIVE = ['replayd','remotemanagement','RemoteManagement','privatecloudcomputed',
             'studentd','identityservices','screensharing','launchctl','kickstart',
             'ARDAgent','wifivelocityd','searchpartyuseragent']
found_allows = []
for r in allow:
    proc = str(r.get('process',''))
    if any(s.lower() in proc.lower() for s in SENSITIVE):
        found_allows.append(r)
if found_allows:
    for r in found_allows:
        print(f'  ⚠️  ALLOW  proc={r.get("process","")[-70:]}  remote={remote_label(r)}')
else:
    print('  ✅ No allow rules for sensitive processes')

# ── 6. Rules with unusual lifetimes ───────────────────────────────────────────
section('6. TEMPORARY / SESSION-SCOPED DENY RULES')
temp_deny = [r for r in deny if r.get('lifetime') and r.get('lifetime') != 'forever']
if temp_deny:
    for r in temp_deny:
        print(f'  lifetime={r.get("lifetime"):<15} proc={proc_label(r):<40} remote={remote_label(r)}')
else:
    print('  (none — all deny rules are permanent)')

# ── 7. Recently added deny rules (since prev scan) ───────────────────────────
section('7. DENY RULE DIFF vs PREVIOUS MODEL')

IGNORE = {'lastUsed', 'useCount', 'modificationDate'}

def stable_key(r):
    return json.dumps({k: v for k, v in sorted(r.items()) if k not in IGNORE})

try:
    with open(PREV_PATH) as f:
        prev_model = json.load(f)
    prev_deny_keys = set(stable_key(r) for r in prev_model.get('rules',[]) if r.get('action')=='deny')
    curr_deny_keys = set(stable_key(r) for r in deny)
    prev_allow_keys = set(stable_key(r) for r in prev_model.get('rules',[]) if r.get('action')=='allow')
    curr_allow_keys = set(stable_key(r) for r in allow)

    dropped_deny  = [json.loads(k) for k in prev_deny_keys - curr_deny_keys]
    added_deny    = [json.loads(k) for k in curr_deny_keys - prev_deny_keys]
    dropped_allow = [json.loads(k) for k in prev_allow_keys - curr_allow_keys]
    added_allow   = [json.loads(k) for k in curr_allow_keys - prev_allow_keys]

    prev_rules = prev_model.get('rules', [])
    prev_d = len([r for r in prev_rules if r.get('action')=='deny'])
    prev_a = len([r for r in prev_rules if r.get('action')=='allow'])
    print(f'  Baseline: {PREV_PATH}')
    print(f'  Deny:  {prev_d} → {len(deny)}  ({len(deny)-prev_d:+d})')
    print(f'  Allow: {prev_a} → {len(allow)}  ({len(allow)-prev_a:+d})')

    if dropped_deny:
        print(f'\n  ⚠️  DENY RULES DROPPED ({len(dropped_deny)}):')
        for r in dropped_deny:
            print(f'    proc={proc_label(r):<45} remote={remote_label(r)}')
    else:
        print('\n  ✅ No deny rules dropped')

    if added_deny:
        print(f'\n  New deny rules ({len(added_deny)}):')
        for r in sorted(added_deny, key=proc_label)[:30]:
            print(f'    proc={proc_label(r):<45} remote={remote_label(r)}')
        if len(added_deny) > 30:
            print(f'    ... and {len(added_deny)-30} more')
    else:
        print('  No new deny rules')

    if added_allow:
        print(f'\n  New allow rules ({len(added_allow)}):')
        for r in sorted(added_allow, key=proc_label)[:20]:
            print(f'    proc={proc_label(r):<45} remote={remote_label(r)}')
except FileNotFoundError:
    print(f'  (no previous model at {PREV_PATH})')

# ── 8. Rules by origin ────────────────────────────────────────────────────────
section('8. DENY RULES BY ORIGIN')
by_origin = Counter(r.get('origin', 'unknown') for r in deny)
for origin, count in by_origin.most_common():
    print(f'  {count:5d}  {origin}')

# ── Summary ───────────────────────────────────────────────────────────────────
print(f'\n{"="*W}')
if missing:
    print(f'⚠️  {len(missing)} CRITICAL ITEMS MISSING:')
    for m in missing:
        print(f'   - {m}')
else:
    print('✅ ALL CRITICAL DENY RULES PRESENT')
print(f'{"="*W}\n')

# ── Save model ────────────────────────────────────────────────────────────────
import shutil, os
os.makedirs(os.path.dirname(os.path.expanduser(SAVE_PATH)), exist_ok=True)
shutil.copy(MODEL_PATH, os.path.expanduser(SAVE_PATH))
print(f'Model saved to {SAVE_PATH}')
