#!/usr/bin/env python3
"""
ls-permissive-analysis.py
Ranks Little Snitch allow rules by permissiveness and flags anomalies.
Run on each security scan after exporting the LS model.

Usage:
  python3 ls-permissive-analysis.py /tmp/ls-current.json
"""

import json
import sys
import re
from pathlib import Path

def permissiveness_score(r: dict) -> int:
    score = 0
    if 'process' not in r:
        score += 40
    remote = r.get('remote', '')
    if remote in ('any', '*'):
        score += 50
    has_remote = any(k in r for k in ('remote-domains', 'remote-hosts', 'remote-addresses'))
    if not has_remote and remote not in ('any', '*', 'local-net', 'bpf'):
        score += 30
    if 'ports' not in r and 'remote-ports' not in r:
        score += 15
    rd = r.get('remote-domains', '')
    if isinstance(rd, str) and len(rd.split('.')) <= 2:
        score += 10
    if isinstance(rd, str) and any(rd.endswith(t) for t in ('.com', '.net', '.io', '.org')):
        score += 5
    if r.get('useCount', 0) > 1000:
        score += 5
    return score


def via_summary(r: dict) -> str:
    via = r.get('via', '')
    if isinstance(via, str) and via.startswith('identifier.SHA256/'):
        return 'SHA256:' + via[18:26] + '... (UNSIGNED/UNKNOWN BINARY)'
    if isinstance(via, str) and via.startswith('identifier.'):
        return via.split('/', 1)[-1] if '/' in via else via
    if not via:
        fht = r.get('factoryHelpText', '')
        m = re.search(r'viaProcessPath: (.+)', fht)
        if m:
            return Path(m.group(1).strip()).name
    return str(via)[:80] if via else ''


def short_process(r: dict) -> str:
    proc = r.get('process', '<ANY PROCESS>')
    if proc.startswith('identifier.APPLE/'):
        return proc.replace('identifier.APPLE/', '')
    if proc.startswith('identifier.'):
        return proc.split('/')[-1] if '/' in proc else proc
    return proc


def main():
    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} <ls-model.json>')
        sys.exit(1)

    path = sys.argv[1]
    d = json.load(open(path))
    rules = d.get('rules', [])

    allow = [r for r in rules if r.get('action') == 'allow' and not r.get('disabled')]
    scored = sorted(allow, key=lambda r: -permissiveness_score(r))

    print(f'LS model: {path}')
    print(f'Total rules: {len(rules)}  |  Allow (active): {len(allow)}')
    print()

    # Anomaly checks
    print('=== ANOMALY CHECKS ===')
    anon_any = [r for r in allow
                if r.get('remote') == 'any'
                and r.get('via','').startswith('identifier.SHA256/')]
    if anon_any:
        print(f'[CRITICAL] {len(anon_any)} allow-any rules via UNSIGNED binary:')
        for r in anon_any:
            print(f'  process={short_process(r)}  via={via_summary(r)}  '
                  f'uses={r.get("useCount",0)}  created={r.get("creationDate","?")[:10]}')
    else:
        print('[OK] No allow-any rules via unsigned binary')

    broad_any = [r for r in allow
                 if r.get('remote') == 'any'
                 and 'process' not in r]
    broad_any_non_icmp = [r for r in broad_any if r.get('protocol') not in ('icmp',)]
    if broad_any_non_icmp:
        print(f'[WARN] {len(broad_any_non_icmp)} allow-any rules with no process restriction (non-ICMP):')
        for r in broad_any_non_icmp:
            print(f'  remote={r.get("remote","")}  proto={r.get("protocol","any")}  '
                  f'origin={r.get("origin","")}')
    else:
        print('[OK] No non-ICMP any-process allow-any rules')

    print()
    print('=== TOP 30 MOST PERMISSIVE ALLOW RULES ===')
    print(f'{"#":>2}  {"Score":>5}  {"Created":>10}  {"Uses":>6}  {"Process":<35}  {"Remote":<30}  {"Via"}')
    print('-' * 130)
    for i, r in enumerate(scored[:30], 1):
        score = permissiveness_score(r)
        proc = short_process(r)[:34]
        remote = (r.get('remote') or r.get('remote-domains') or
                  r.get('remote-hosts') or r.get('remote-addresses') or '')
        if isinstance(remote, list):
            remote = ','.join(str(x) for x in remote)
        remote = str(remote)[:29]
        via = via_summary(r)[:40]
        use = r.get('useCount', 0)
        created = r.get('creationDate', '?')[:10]
        flag = ' !!!' if 'UNSIGNED' in via_summary(r) else ''
        print(f'{i:>2}  {score:>5}  {created}  {use:>6}  {proc:<35}  {remote:<30}  {via}{flag}')


if __name__ == '__main__':
    main()
