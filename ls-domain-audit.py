#!/usr/bin/env python3
"""
ls-domain-audit.py — deep inspection of all LS rule domains and hosts.

Checks:
  1. All unique domains/hosts with the processes that access them
  2. Suspicious TLDs and domain patterns (DGA, unusual ccTLDs, etc.)
  3. Rules for processes that are now disabled/killed
  4. New rules since a prior model (diff)
  5. Rules via unsigned/unusual identifiers
  6. Monitor-origin rules that are actively used (auto-allows that stuck)
  7. Rules where domain/process pairing is unexpected
  8. Creation-date clusters (rules created in bursts may indicate attack)

Usage:
  python3 ls-domain-audit.py <current-model.json> [prior-model.json]
"""

import json
import re
import sys
from collections import defaultdict
from pathlib import Path


# ── Helpers ──────────────────────────────────────────────────────────────────

def short_proc(r: dict) -> str:
    p = r.get('process', '<ANY>')
    if p.startswith('identifier.APPLE/'):
        return p[len('identifier.APPLE/'):]
    if p.startswith('identifier.'):
        return p.split('/')[-1] if '/' in p else p
    return p

def short_via(r: dict) -> str:
    v = r.get('via', '')
    if isinstance(v, str) and v.startswith('identifier.SHA256/'):
        return 'SHA256:' + v[18:26] + '… UNSIGNED'
    if isinstance(v, str) and v.startswith('identifier.'):
        return v.split('/')[-1] if '/' in v else v
    return str(v)[:60] if v else ''

def rule_remote(r: dict) -> str:
    for k in ('remote', 'remote-hosts', 'remote-domains', 'remote-addresses'):
        v = r.get(k)
        if v:
            return str(v)
    return ''

def all_hosts(r: dict) -> list[str]:
    """Extract individual hostnames from a rule."""
    hosts = []
    for k in ('remote-hosts', 'remote-domains'):
        v = r.get(k, '')
        if isinstance(v, str):
            hosts.extend(h.strip() for h in v.split(',') if h.strip())
        elif isinstance(v, list):
            hosts.extend(str(h) for h in v)
    if r.get('remote') not in (None, '', 'any', 'local-net', 'bpf'):
        hosts.append(str(r['remote']))
    return hosts

def tld(host: str) -> str:
    parts = host.strip('.').split('.')
    return '.' + parts[-1] if parts else ''

def is_suspicious_domain(host: str) -> str | None:
    """Return a reason string if the domain looks suspicious, else None."""
    if not host or host in ('any', 'local-net', 'bpf'):
        return None
    # Known-good patterns to skip
    known_safe_tlds = {'.com', '.net', '.org', '.io', '.ai', '.dev',
                       '.app', '.co', '.info', '.edu', '.gov', '.mil',
                       '.apple', '.icloud', '.me'}
    # Flag unusual / high-abuse TLDs
    risky_tlds = {'.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq',
                  '.cn', '.ru', '.su', '.pw', '.cc', '.biz', '.club',
                  '.site', '.online', '.icu', '.live', '.vip', '.work',
                  '.link', '.click', '.download', '.zip', '.mov',
                  '.rest', '.ws', '.to', '.info', '.tv'}
    t = tld(host)
    if t in risky_tlds:
        return f'risky TLD {t}'
    # DGA-like: long random-looking subdomain
    parts = host.split('.')
    for part in parts[:-1]:  # not the TLD
        if len(part) >= 12 and re.match(r'^[a-z0-9]+$', part):
            consonants = sum(1 for c in part if c not in 'aeiou0123456789')
            if consonants / len(part) > 0.65:
                return f'DGA-like label "{part}"'
    # Very short hostname (single label like "localhost" is OK, but "a.b" is odd)
    if len(parts) == 2 and len(parts[0]) <= 3 and parts[0] not in ('www', 'api', 'cdn',
                                                                     'ftp', 'ns1', 'ns2'):
        return f'suspiciously short hostname'
    # IP address
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
        # Not inherently suspicious but worth flagging raw IPs in allow rules
        parts4 = host.split('.')
        if not (parts4[0] in ('10', '192', '172') or host.startswith('127.')):
            return f'raw external IP in allow rule'
    return None

# Processes that are disabled/guarded — rules for them are dead weight or suspicious
DISABLED_PROCS = {
    'com.apple.replayd', 'replayd',
    'com.apple.studentd', 'studentd',
    'com.apple.remotemanagementd', 'remotemanagementd',
    'com.apple.RemoteManagementAgent', 'RemoteManagementAgent',
    'com.apple.replicatord', 'replicatord',
    'com.apple.sharingd', 'sharingd',
    'com.apple.identityservicesd', 'identityservicesd',
    'com.apple.privatecloudcomputed', 'privatecloudcomputed',
    'com.apple.universalcontrol', 'universalcontrol',
    'com.apple.AirPlayReceiver', 'AirPlayReceiver',
    'com.apple.rapportd', 'rapportd',
    'com.apple.bluetoothd', 'bluetoothd',
    'com.apple.screensharingd', 'screensharingd',
    'com.apple.ARDAgent', 'ARDAgent',
    'com.apple.nearbyd', 'nearbyd',
}


def load(path: str) -> list[dict]:
    with open(path) as f:
        return json.load(f).get('rules', [])


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} <current-model.json> [prior-model.json]')
        sys.exit(1)

    current_path = sys.argv[1]
    prior_path = sys.argv[2] if len(sys.argv) > 2 else None

    rules = load(current_path)
    allow = [r for r in rules if r.get('action') == 'allow' and not r.get('disabled')]
    deny  = [r for r in rules if r.get('action') == 'deny']

    print(f'Model: {current_path}')
    print(f'Total rules: {len(rules)}  |  Allow (active): {len(allow)}  |  Deny: {len(deny)}')
    print()

    # ── 1. Suspicious / unusual domains ─────────────────────────────────────
    print('═' * 80)
    print('SECTION 1 — SUSPICIOUS DOMAIN PATTERNS')
    print('═' * 80)

    flagged = []
    for r in allow:
        for host in all_hosts(r):
            reason = is_suspicious_domain(host)
            if reason:
                flagged.append((reason, host, short_proc(r),
                                r.get('useCount', 0), r.get('creationDate', '?')[:10],
                                short_via(r), r.get('origin', '')))

    if flagged:
        flagged.sort(key=lambda x: (-x[3], x[1]))
        print(f'{"Reason":<30}  {"Host":<40}  {"Process":<30}  {"Uses":>6}  {"Created"}')
        print('-' * 130)
        for reason, host, proc, uses, created, via, origin in flagged:
            via_tag = f'  via={via}' if via else ''
            orig_tag = f'  origin={origin}' if origin == 'monitor' else ''
            print(f'{reason:<30}  {host:<40}  {proc:<30}  {uses:>6}  {created}{via_tag}{orig_tag}')
    else:
        print('[OK] No suspicious domain patterns detected')
    print()

    # ── 2. Rules for disabled/guarded processes ──────────────────────────────
    print('═' * 80)
    print('SECTION 2 — ALLOW RULES FOR DISABLED/GUARDED PROCESSES')
    print('═' * 80)
    print('(These processes are killed by comms-guard; their allow rules are dead weight')
    print(' or could be used if the guard fails)')
    print()

    disabled_rules = []
    for r in allow:
        proc = short_proc(r)
        if any(d in proc for d in DISABLED_PROCS):
            disabled_rules.append(r)

    if disabled_rules:
        by_proc = defaultdict(list)
        for r in disabled_rules:
            by_proc[short_proc(r)].append(r)
        for proc, rs in sorted(by_proc.items()):
            print(f'  {proc}  ({len(rs)} allow rules):')
            for r in rs[:5]:
                print(f'    → {rule_remote(r):<40}  port={r.get("ports","any"):<8}  '
                      f'uses={r.get("useCount",0):<6}  origin={r.get("origin","")}')
            if len(rs) > 5:
                print(f'    … and {len(rs)-5} more')
    else:
        print('[OK] No allow rules for disabled processes found')
    print()

    # ── 3. Monitor-origin allow rules actively being used ────────────────────
    print('═' * 80)
    print('SECTION 3 — MONITOR-ORIGIN ALLOW RULES (auto-created, actively used)')
    print('═' * 80)
    print('(These were silently auto-approved by LS monitor mode; high use = impactful)')
    print()

    monitor_allow = [r for r in allow if r.get('origin') == 'monitor'
                     and r.get('useCount', 0) >= 10]
    monitor_allow.sort(key=lambda r: -r.get('useCount', 0))

    if monitor_allow:
        print(f'  {"Uses":>6}  {"Created":>10}  {"Process":<35}  {"Remote":<35}  {"Port":<8}  Via')
        print('  ' + '-' * 110)
        for r in monitor_allow[:40]:
            proc = short_proc(r)[:34]
            remote = rule_remote(r)[:34]
            port = str(r.get('ports', 'any'))[:7]
            via = short_via(r)[:40]
            created = r.get('creationDate', '?')[:10]
            uses = r.get('useCount', 0)
            flag = '  !!!' if 'UNSIGNED' in via else ''
            print(f'  {uses:>6}  {created}  {proc:<35}  {remote:<35}  {port:<8}  {via}{flag}')
    else:
        print('[OK] No active monitor-origin allow rules with >=10 uses')
    print()

    # ── 4. Any-remote allow rules ────────────────────────────────────────────
    print('═' * 80)
    print('SECTION 4 — ANY-REMOTE ALLOW RULES')
    print('═' * 80)

    any_remote = [r for r in allow if r.get('remote') in ('any', '*')]
    if any_remote:
        any_remote.sort(key=lambda r: -r.get('useCount', 0))
        for r in any_remote:
            proc = short_proc(r)
            proto = r.get('protocol', 'any')
            port = r.get('ports', 'any')
            uses = r.get('useCount', 0)
            origin = r.get('origin', '')
            via = short_via(r)
            flag = '  [CRITICAL: UNSIGNED]' if 'UNSIGNED' in via else ''
            print(f'  {proc:<40}  proto={proto:<6}  port={port:<8}  uses={uses:<6}  '
                  f'origin={origin:<10}  via={via}{flag}')
    else:
        print('[OK] No any-remote allow rules')
    print()

    # ── 5. Rules with unsigned/SHA256 via ────────────────────────────────────
    print('═' * 80)
    print('SECTION 5 — RULES VIA UNSIGNED BINARY (SHA256 identifier)')
    print('═' * 80)

    unsigned = [r for r in allow
                if str(r.get('via', '')).startswith('identifier.SHA256/')]
    if unsigned:
        for r in sorted(unsigned, key=lambda r: -r.get('useCount', 0)):
            via = r.get('via', '')
            sha = via[18:82] if len(via) > 18 else via
            print(f'  proc={short_proc(r):<40}  remote={rule_remote(r):<30}  '
                  f'uses={r.get("useCount",0):<6}  sha={sha[:16]}…')
    else:
        print('[OK] No allow rules via unsigned binary')
    print()

    # ── 6. Creation-date clusters ─────────────────────────────────────────────
    print('═' * 80)
    print('SECTION 6 — RULE CREATION DATE CLUSTERS (top dates by new rule count)')
    print('═' * 80)
    print('(Spikes on unexpected dates may indicate attacker or compromised session)')
    print()

    date_counts: dict[str, list] = defaultdict(list)
    for r in allow:
        d = r.get('creationDate', '')[:10]
        if d:
            date_counts[d].append(r)

    for date, rs in sorted(date_counts.items(), key=lambda x: -len(x[1])):
        monitor_n = sum(1 for r in rs if r.get('origin') == 'monitor')
        user_n = len(rs) - monitor_n
        bar = '█' * min(len(rs) // 5, 50)
        print(f'  {date}  {len(rs):>4} rules  '
              f'(monitor={monitor_n}, user={user_n})  {bar}')
    print()

    # ── 7. Domain frequency across all allow rules ───────────────────────────
    print('═' * 80)
    print('SECTION 7 — ALL DOMAINS/HOSTS (sorted by total use count, allow rules only)')
    print('═' * 80)
    print()

    domain_uses: dict[str, int] = defaultdict(int)
    domain_procs: dict[str, set] = defaultdict(set)
    domain_rules: dict[str, list] = defaultdict(list)

    for r in allow:
        uses = r.get('useCount', 0)
        proc = short_proc(r)
        for host in all_hosts(r):
            domain_uses[host] += uses
            domain_procs[host].add(proc)
            domain_rules[host].append(r)

    sorted_domains = sorted(domain_uses.items(), key=lambda x: -x[1])
    print(f'  {"Domain/Host":<45}  {"TotalUses":>9}  {"Rules":>5}  Processes')
    print('  ' + '-' * 110)
    for host, uses in sorted_domains:
        rules_n = len(domain_rules[host])
        procs = ', '.join(sorted(domain_procs[host]))[:60]
        susp = is_suspicious_domain(host)
        flag = f'  ← {susp}' if susp else ''
        print(f'  {host:<45}  {uses:>9}  {rules_n:>5}  {procs}{flag}')
    print()

    # ── 8. New rules since prior model ───────────────────────────────────────
    if prior_path:
        print('═' * 80)
        print(f'SECTION 8 — NEW ALLOW RULES vs {Path(prior_path).parent.name}')
        print('═' * 80)

        prior_rules = load(prior_path)
        prior_allow = [r for r in prior_rules if r.get('action') == 'allow']

        # Fingerprint: process + remote + ports + via
        def fingerprint(r: dict) -> str:
            return '|'.join([
                str(r.get('process', '')),
                rule_remote(r),
                str(r.get('ports', '')),
                str(r.get('via', '')),
            ])

        prior_fps = {fingerprint(r) for r in prior_allow}
        new_rules = [r for r in allow if fingerprint(r) not in prior_fps]
        new_rules.sort(key=lambda r: -r.get('useCount', 0))

        if new_rules:
            print(f'  {len(new_rules)} new allow rules since prior model:')
            print()
            print(f'  {"Uses":>6}  {"Created":>10}  {"Process":<35}  {"Remote":<35}  {"Port":<8}  {"Via"}')
            print('  ' + '-' * 110)
            for r in new_rules:
                proc = short_proc(r)[:34]
                remote = rule_remote(r)[:34]
                port = str(r.get('ports', 'any'))[:7]
                via = short_via(r)[:40]
                created = r.get('creationDate', '?')[:10]
                uses = r.get('useCount', 0)
                origin = r.get('origin', '')
                flag = '  [UNSIGNED]' if 'UNSIGNED' in via else ''
                orig_tag = '  [monitor]' if origin == 'monitor' else ''
                print(f'  {uses:>6}  {created}  {proc:<35}  {remote:<35}  {port:<8}  {via}{flag}{orig_tag}')
        else:
            print('[OK] No new allow rules since prior model')
        print()


if __name__ == '__main__':
    main()
