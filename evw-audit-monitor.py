#!/usr/bin/env python3
"""
evw-audit-monitor.py
Real-time exec/URL monitor. Must run as root.

Primary source: unified log stream (com.apple.launchservices at debug level,
com.apple.security.tccd, com.apple.xpc). Captures URL opens via LaunchServices
without depending on auditd.

Secondary source (when available): BSM auditpipe via praudit. Gives full exec
argv for all processes. Activated only if /dev/auditpipe produces data.
"""

import subprocess
import sys
import os
import signal
import threading
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

LOG_FILE   = '/private/var/log/evw-audit-monitor.log'
ALERT_FILE = '/private/var/log/evw-audit-alerts.log'

# Checked against exec argv tokens (BSM path) and unified log messages (log path)
WATCH_PATTERNS = [
    'https://',
    'http://',
    'whatsapp',
    'noschg',
    'nouchg',
    'disabled.501.plist',
    'PlistBuddy',
    'launchctl enable',
    'launchctl disable',
    'enable gui/501',
    'disable gui/501',
    'osascript',
    '.env',
    'Keychain',
    '.ssh/',
    'id_rsa',
    'id_ed25519',
]

# Unified log predicates — covers URL delivery and TCC permission grants
LOG_PREDICATES = ' OR '.join([
    'subsystem == "com.apple.launchservices"',
    'subsystem == "com.apple.security.tccd"',
    '(subsystem == "com.apple.xpc" AND category == "activity")',
])


def ts() -> str:
    return datetime.now().isoformat(timespec='seconds')


def alert(log_f, alert_f, source: str, pattern: str, context: str):
    now = ts()
    log_f.write(f'[{now}] ALERT [{source}] [{pattern!r}]\n')
    log_f.flush()
    alert_f.write(
        f'[{now}] ALERT source={source} pattern={pattern!r}\n'
        f'{context[:3000]}\n---\n'
    )
    alert_f.flush()


def watch_unified_log(log_f, alert_f, stop_event):
    """Stream unified log for LaunchServices/TCC events."""
    cmd = [
        '/usr/bin/log', 'stream',
        '--predicate', LOG_PREDICATES,
        '--style', 'compact',
        '--color', 'none',
    ]
    try:
        proc = guard_run(
            'log-stream', subprocess.Popen,
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, bufsize=1,
        )
        if proc is None or proc is SKIP:
            return
        log_f.write(f'[{ts()}] [LOG-STREAM] started pid={proc.pid}\n')
        log_f.flush()

        for raw in proc.stdout:
            if stop_event.is_set():
                proc.terminate()
                break
            line = raw.rstrip('\n')
            line_lower = line.lower()
            for pattern in WATCH_PATTERNS:
                if pattern.lower() in line_lower:
                    guard_run('log-alert', alert,
                              log_f, alert_f, 'unified-log', pattern, line)
                    break
    except Exception as e:
        log_f.write(f'[{ts()}] [LOG-STREAM] error: {e}\n')
        log_f.flush()


def watch_bsm(log_f, alert_f, stop_event):
    """Stream BSM audit pipe via praudit. Requires auditd running."""
    pipe = '/dev/auditpipe'
    if not os.path.exists(pipe):
        log_f.write(f'[{ts()}] [BSM] /dev/auditpipe absent — skipping\n')
        log_f.flush()
        return

    cmd = ['/usr/sbin/praudit', pipe]
    try:
        proc = guard_run(
            'bsm-praudit', subprocess.Popen,
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, bufsize=1,
        )
        if proc is None or proc is SKIP:
            return

        record:    list[str] = []
        exec_args: list[str] = []
        in_record: bool      = False
        got_data = False

        for raw in proc.stdout:
            if stop_event.is_set():
                proc.terminate()
                break

            if not got_data:
                got_data = True
                log_f.write(f'[{ts()}] [BSM] auditpipe active — streaming\n')
                log_f.flush()

            line = raw.rstrip('\n')

            if line.startswith('header,'):
                record    = [line]
                exec_args = []
                in_record = True
            elif in_record:
                record.append(line)
                if line.startswith('exec arg,'):
                    exec_args.append(line[len('exec arg,'):])
                elif line.startswith('trailer,'):
                    in_record = False
                    if exec_args:
                        combined_lower = ' '.join(exec_args).lower()
                        for pattern in WATCH_PATTERNS:
                            if pattern.lower() in combined_lower:
                                guard_run('bsm-alert', alert,
                                          log_f, alert_f, 'bsm',
                                          pattern, '\n'.join(record[:100]))
                                break
                    record    = []
                    exec_args = []

        if not got_data:
            log_f.write(f'[{ts()}] [BSM] praudit exited with no data '
                        f'— auditd not running\n')
            log_f.flush()

    except Exception as e:
        log_f.write(f'[{ts()}] [BSM] error: {e}\n')
        log_f.flush()


def run():
    os.makedirs('/private/var/log', exist_ok=True)

    with open(LOG_FILE, 'a', buffering=1) as log_f, \
         open(ALERT_FILE, 'a', buffering=1) as alert_f:

        # Logs contain URLs and credential-path context — force root-only,
        # fixing perms even if the files pre-existed world-readable.
        for _path in (LOG_FILE, ALERT_FILE):
            try:
                os.chmod(_path, 0o600)
            except OSError as e:
                log_f.write(f'[{ts()}] [START] WARN: chmod 600 {_path}: {e}\n')

        log_f.write(f'[{ts()}] [START] evw-audit-monitor pid={os.getpid()}\n')

        stop_event = threading.Event()

        def _shutdown(sig, _frame):
            log_f.write(f'[{ts()}] [STOP] signal {sig}\n')
            stop_event.set()
            sys.exit(0)

        signal.signal(signal.SIGTERM, _shutdown)
        signal.signal(signal.SIGINT,  _shutdown)

        # Unified log runs in a thread; BSM runs in main thread
        log_thread = threading.Thread(
            target=watch_unified_log,
            args=(log_f, alert_f, stop_event),
            daemon=True,
        )
        log_thread.start()

        # BSM: blocks in main thread (exits quickly if auditd isn't running)
        watch_bsm(log_f, alert_f, stop_event)

        # If BSM exited (auditd not running), keep process alive for log stream
        log_f.write(f'[{ts()}] [BSM] thread ended — unified-log continues\n')
        log_thread.join()


if __name__ == '__main__':
    run()
