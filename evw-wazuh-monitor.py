#!/usr/bin/env python3
"""
evw-wazuh-monitor.py — feed Wazuh agent log events into the evw security
system's existing alert pipelines. Must run as root (wazuh logs are root-only).

Sources:
  /Library/Ossec/logs/alerts/alerts.json — wazuh alert stream (FIM, log
      analysis, rootcheck, SCA), one JSON object per line
  /Library/Ossec/logs/ossec.log — agent lifecycle + manager connection events

Sinks (same conventions as the other evw monitors):
  ~/Library/Logs/mac-sentinel-alert-feed.log — live display feed (one compact
      JSON line per event; the sentinel display terminal colorizes by
      "severity": "CRITICAL"|"WARNING"|"INFO")
  /private/var/log/evw-wazuh-alerts.log — full forensic copy of every alert
  /var/db/evw-security-system/alerts/<id>.json — alert-center queue
      (CRITICAL/WARNING only; CRITICAL persists until acknowledged)

Severity: wazuh rule level >=12 CRITICAL, 7-11 WARNING, else INFO.
Groups containing 'rootkit'/'recon' floor at WARNING (>=10 -> CRITICAL).
Repeat events for the same rule+location are suppressed for DEDUP_WINDOW
seconds (forensic log always gets everything).
"""

import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error_guard.py)
try:
    import pathlib as _pathlib, sys as _sys
    _d = _pathlib.Path(__file__).resolve().parent
    for _ in range(6):
        _lib = _d / "lib" / "error_guard.py"
        if _lib.exists():
            # As root, only trust a root-owned lib: a user-writable ancestor
            # dir (e.g. Intel Homebrew's /usr/local) could plant one.
            if os.geteuid() != 0 or _lib.stat().st_uid == 0:
                _sys.path.insert(0, str(_d / "lib"))
                break
        _d = _d.parent
    from error_guard import guard_run, guarded, SKIP, throw, GuardError
except ImportError:
    SKIP = object()
    def guard_run(_l, fn, *a, **kw): return fn(*a, **kw)
    def guarded(_l=None):
        def deco(fn): return fn
        return deco
    class GuardError(RuntimeError): pass
    def throw(msg): raise GuardError(str(msg))

# KeepAlive daemon: never let the guard exit the process — trip = log + skip
os.environ.setdefault('EVW_GUARD_POLICY', 'continue')

os.umask(0o077)

ALERTS_JSON = '/Library/Ossec/logs/alerts/alerts.json'
OSSEC_LOG   = '/Library/Ossec/logs/ossec.log'
FEED        = '/Users/evw/Library/Logs/mac-sentinel-alert-feed.log'
FORENSIC    = '/private/var/log/evw-wazuh-alerts.log'
MON_LOG     = '/private/var/log/evw-wazuh-monitor.log'
ALERTS_DIR  = '/var/db/evw-security-system/alerts'

LEVEL_CRITICAL = 12
LEVEL_WARNING  = 7
DEDUP_WINDOW   = 300      # seconds, same rule+location
CONN_DEDUP     = 1800     # seconds, manager (un)reachable repeats

_seen = {}                # dedup key -> epoch
_lock = threading.Lock()


def ts() -> str:
    return datetime.now().isoformat(timespec='seconds')


def mlog(msg: str) -> None:
    try:
        with open(MON_LOG, 'a') as f:
            f.write(f'[{ts()}] {msg}\n')
    except Exception:
        pass


def dedup_ok(key: str, window: int) -> bool:
    now = time.time()
    with _lock:
        last = _seen.get(key, 0)
        if now - last < window:
            return False
        _seen[key] = now
        if len(_seen) > 10000:  # prune
            cutoff = now - 24 * 3600
            for k in [k for k, v in _seen.items() if v < cutoff]:
                del _seen[k]
        return True


def classify(level: int, groups) -> str:
    gl = ' '.join(groups).lower() if groups else ''
    if level >= LEVEL_CRITICAL or (level >= 10 and 'rootkit' in gl):
        return 'CRITICAL'
    if level >= LEVEL_WARNING or 'rootkit' in gl or 'recon' in gl:
        return 'WARNING'
    return 'INFO'


def feed_write(severity: str, data: dict) -> None:
    line = json.dumps({
        'ts_human': datetime.now().strftime('%A, %B %d, %Y %I:%M:%S %p %Z'),
        'severity': severity,
        'data': data,
    }, separators=(', ', ': '))
    with open(FEED, 'a') as f:   # feed is root:staff 644 — display reads it
        f.write(line + '\n')
    try:
        os.chmod(FEED, 0o644)    # umask is 077; keep the feed user-readable
    except Exception:
        pass


def _slug(s: str) -> str:
    return ''.join(c if c.isalnum() else '-' for c in s.lower()).strip('-')[:48]


def queue_alert(severity: str, title: str, body: str, persist: bool) -> None:
    """alert-center queue — same schema as evw-security-system.alert()."""
    if not os.path.isdir(ALERTS_DIR):
        return
    base = '{}-wazuh-{}'.format(time.strftime('%Y%m%d-%H%M%S'), _slug(title))
    aid, n = base, 1
    while os.path.exists(os.path.join(ALERTS_DIR, aid + '.json')):
        n += 1
        aid = '{}-{}'.format(base, n)
    doc = {'id': aid, 'ts': int(time.time()), 'severity': severity,
           'title': title[:80], 'body': body, 'source': 'wazuh',
           'persist': persist}
    tmp = os.path.join(ALERTS_DIR, '.' + aid + '.tmp')
    with open(tmp, 'w') as f:
        json.dump(doc, f, indent=2)
    os.replace(tmp, os.path.join(ALERTS_DIR, aid + '.json'))


def forensic(obj) -> None:
    with open(FORENSIC, 'a') as f:
        f.write(json.dumps(obj) + '\n')


def handle_wazuh_alert(alert: dict) -> None:
    rule = alert.get('rule', {}) or {}
    level = int(rule.get('level', 0) or 0)
    groups = rule.get('groups', []) or []
    rid = rule.get('id', '?')
    desc = rule.get('description', '')
    location = alert.get('location', '')
    sev = classify(level, groups)

    guard_run('forensic', forensic, alert)  # everything, always

    if not dedup_ok(f'wazuh:{rid}:{location}', DEDUP_WINDOW):
        return

    data = {'event': 'WAZUH_ALERT', 'rule_id': rid, 'level': level,
            'severity': sev, 'description': desc, 'groups': groups,
            'location': location, 'agent': (alert.get('agent') or {}).get('name', '')}
    for k in ('srcip', 'dstuser', 'path', 'file'):
        v = (alert.get('data') or {}).get(k) or (alert.get('syscheck') or {}).get(k)
        if v:
            data[k] = v
    guard_run('feed', feed_write, sev, data)

    if sev in ('CRITICAL', 'WARNING'):
        body = 'rule {} level {} — {}\ngroups: {}\nlocation: {}'.format(
            rid, level, desc, ', '.join(groups), location)
        guard_run('queue', queue_alert, sev,
                  'wazuh: {}'.format(desc or 'alert'), body,
                  sev == 'CRITICAL')


def handle_ossec_line(line: str) -> None:
    if 'Connected to server' in line:
        ev, sev, key = 'WAZUH_MANAGER_CONNECTED', 'INFO', 'conn'
    elif any(s in line for s in ('Unable to connect', 'Could not resolve',
                                 'Connection refused')):
        ev, sev, key = 'WAZUH_MANAGER_UNREACHABLE', 'WARNING', 'unreach'
    elif 'wazuh-agentd' in line and 'shutdown' in line.lower():
        ev, sev, key = 'WAZUH_AGENT_STOPPED', 'WARNING', 'stop'
    else:
        return
    if dedup_ok(f'ossec:{key}', CONN_DEDUP):
        guard_run('feed', feed_write, sev,
                  {'event': ev, 'line': line.strip()[:200]})


def tail_thread(path: str, handler, name: str, stop: threading.Event) -> None:
    while not stop.is_set():
        if not os.path.isfile(path):
            mlog(f'[{name}] {path} absent — retry in 60s')
            stop.wait(60)
            continue
        proc = None
        try:
            proc = subprocess.Popen(['/usr/bin/tail', '-n', '0', '-F', path],
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    text=True)
            mlog(f'[{name}] tailing {path} pid={proc.pid}')
            for line in proc.stdout:
                if stop.is_set():
                    break
                line = line.rstrip('\n')
                if not line:
                    continue
                try:
                    if path.endswith('.json'):
                        guard_run('parse-alert', handle_wazuh_alert, json.loads(line))
                    else:
                        guard_run('parse-log', handle_ossec_line, line)
                except Exception as e:
                    mlog(f'[{name}] line error: {e}')
        except Exception as e:
            mlog(f'[{name}] error: {e}')
        finally:
            if proc:
                try:
                    proc.terminate()
                except Exception:
                    pass
        mlog(f'[{name}] tail exited — restart in 5s')
        stop.wait(5)


def run() -> int:
    mlog('=== evw-wazuh-monitor started ===')
    stop = threading.Event()
    threads = [
        threading.Thread(target=tail_thread,
                         args=(ALERTS_JSON, handle_wazuh_alert, 'alerts', stop),
                         daemon=True),
        threading.Thread(target=tail_thread,
                         args=(OSSEC_LOG, handle_ossec_line, 'ossec', stop),
                         daemon=True),
    ]
    for t in threads:
        t.start()
    try:
        while True:
            time.sleep(10)
            for t in threads:
                if not t.is_alive():
                    mlog('thread died — restarting monitor threads')
                    return run()  # fresh threads; guard breaker caps churn
    except KeyboardInterrupt:
        stop.set()
    return 0


if __name__ == '__main__':
    if os.geteuid() != 0:
        print('evw-wazuh-monitor must run as root', file=sys.stderr)
        sys.exit(1)
    sys.exit(run())
