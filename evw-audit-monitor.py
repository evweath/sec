#!/usr/bin/env python3
"""
evw-audit-monitor.py
Real-time BSM audit pipe monitor. Must run as root.
Reads from /dev/auditpipe via praudit, alerts on suspicious exec arguments.
"""

import subprocess
import sys
import os
import signal
from datetime import datetime

LOG_FILE   = '/private/var/log/evw-audit-monitor.log'
ALERT_FILE = '/private/var/log/evw-audit-alerts.log'

# Patterns checked against all exec arg tokens within a single BSM record.
# One alert per record (first match wins) to avoid log spam.
WATCH_PATTERNS = [
    # URL opens via /usr/bin/open — primary target (catches LaunchServices URL delivery)
    'https://',
    'http://',
    'whatsapp',
    # System immutability tampering
    'noschg',
    'nouchg',
    # Plist/launchd config tampering
    'disabled.501.plist',
    'PlistBuddy',
    'launchctl enable',
    'launchctl disable',
    # Script-based automation
    'osascript',
    # Adversarial credential access
    'Keychain',
    '.ssh/',
    'id_rsa',
    'id_ed25519',
]


def ts() -> str:
    return datetime.now().isoformat(timespec='seconds')


def run():
    os.makedirs('/private/var/log', exist_ok=True)

    with open(LOG_FILE, 'a', buffering=1) as log_f, \
         open(ALERT_FILE, 'a', buffering=1) as alert_f:

        log_f.write(f'[{ts()}] [START] evw-audit-monitor pid={os.getpid()}\n')

        proc = subprocess.Popen(
            ['/usr/sbin/praudit', '/dev/auditpipe'],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )

        def _shutdown(sig, _frame):
            log_f.write(f'[{ts()}] [STOP] signal {sig}\n')
            proc.terminate()
            sys.exit(0)

        signal.signal(signal.SIGTERM, _shutdown)
        signal.signal(signal.SIGINT,  _shutdown)

        record:    list[str] = []
        exec_args: list[str] = []
        in_record: bool      = False

        for raw in proc.stdout:
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
                                now = ts()
                                log_f.write(
                                    f'[{now}] ALERT [{pattern!r}] '
                                    f'args={exec_args}\n'
                                )
                                log_f.flush()
                                alert_f.write(
                                    f'[{now}] ALERT pattern={pattern!r}\n'
                                    f'exec_args: {exec_args}\n'
                                    + '\n'.join(record[:200]) + '\n---\n'
                                )
                                alert_f.flush()
                                break

                    record    = []
                    exec_args = []


if __name__ == '__main__':
    run()
