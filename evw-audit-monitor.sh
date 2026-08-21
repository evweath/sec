#!/bin/bash
# evw-audit-monitor.sh
# BSM audit stream monitor — alerts on process executions matching suspicious patterns.
# Reads from /dev/auditpipe (requires root). Runs as a LaunchDaemon.
#
# Alerts on: open https://, launchctl enable/disable, chflags noschg/nouchg,
#            PlistBuddy writes, disabled.501.plist access, kill commands.

LOG=/private/var/log/evw-audit-monitor.log
ALERT=/private/var/log/evw-audit-alerts.log

exec 2>>"$LOG"
echo "$(date -Iseconds)   [START] evw-audit-monitor pid=$$" >> "$LOG"

# Stream the audit pipe through the Python parser.
# The parser must come from a file, not stdin: stdin belongs to the praudit
# pipe (a heredoc on stdin would silently replace it and the pipe is lost).
PARSER=$(mktemp -t evw-audit-monitor)
trap 'rm -f "$PARSER"' EXIT
cat > "$PARSER" << 'PYEOF'
import sys, os
from datetime import datetime

LOG_FILE   = sys.argv[1]
ALERT_FILE = sys.argv[2]

# Patterns that trigger an alert (checked against exec arg tokens)
WATCH = [
    # URL opens — the primary target
    'https://',
    'http://',
    'whatsapp',
    # Plist/immutability tampering
    'disabled.501.plist',
    'noschg',
    'nouchg',
    'PlistBuddy',
    # launchd service enable/disable
    'enable gui/501',
    'disable gui/501',
    # Suspicious process commands
    'launchctl enable',
    'launchctl disable',
    'osascript',
    # Credential files
    '.env',
    'Keychain',
]

def ts():
    return datetime.now().isoformat(timespec='seconds')

log_f   = open(LOG_FILE,   'a', buffering=1)
alert_f = open(ALERT_FILE, 'a', buffering=1)

record    = []   # accumulate lines of current record
exec_args = []   # exec arg tokens within current record
in_record = False

for raw in sys.stdin:
    line = raw.rstrip('\n')

    # Record start: "header,..." token
    if line.startswith('header,'):
        record    = [line]
        exec_args = []
        in_record = True

    elif in_record:
        record.append(line)

        # Capture exec arg tokens
        if line.startswith('exec arg,'):
            exec_args.append(line[len('exec arg,'):])

        # Record end: "trailer,..." token
        if line.startswith('trailer,'):
            in_record = False

            # Only inspect records that have exec arguments
            if exec_args:
                combined = ' '.join(exec_args)
                combined_lower = combined.lower()

                for pattern in WATCH:
                    if pattern.lower() in combined_lower:
                        now = ts()
                        msg = f'[{now}] ALERT [{pattern!r}] args={exec_args}\n'
                        log_f.write(msg)
                        log_f.flush()
                        full = '\n'.join(record)
                        alert_f.write(f'[{now}] ALERT pattern={pattern!r}\n')
                        alert_f.write(f'exec_args: {exec_args}\n')
                        alert_f.write(full[:4000] + '\n---\n')
                        alert_f.flush()
                        break  # one alert per record

            record    = []
            exec_args = []
PYEOF

/usr/sbin/praudit /dev/auditpipe 2>/dev/null | /usr/bin/python3 -u "$PARSER" "$LOG" "$ALERT"
