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
    'osascript',
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
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, bufsize=1,
        )
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
                    alert(log_f, alert_f, 'unified-log', pattern, line)
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
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, bufsize=1,
        )

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
                                alert(log_f, alert_f, 'bsm',
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
