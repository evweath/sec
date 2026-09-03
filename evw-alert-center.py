#!/usr/bin/env python3
# evw-alert-center.py — user-space alert display daemon (gui/501 LaunchAgent
# com.evw.alert-center, KeepAlive). Polls /var/db/evw-security-system/alerts
# every 10 s and makes sure security alerts are actually seen:
#
#   persist=true CRITICAL/WARNING -> Acknowledge dialog that RE-APPEARS every
#       alerts.repost_seconds (default 60) until the user clicks Acknowledge
#       or the alert is alerts.persist_minutes old (default 30). macOS cannot
#       truly prevent dismissing a dialog, so this re-post loop is the
#       faithful equivalent of "pop-ups must not be closable for 30 minutes".
#   persist=false or INFO         -> one display notification, .shown marker.
#   older than persist_minutes    -> .expired marker, stop reposting (the
#       alert file stays in alerts/ for the record).
#
# Alert JSON: {"id","ts","severity","title","body","source","persist"}
# Markers in ack/ (mode 1777): <id>.ack / <id>.shown / <id>.expired (ISO ts).
# Config: STATE_DIR/security-system.json -> alerts.persist_minutes,
#   alerts.repost_seconds (re-read every poll; defaults 30/60 if unreadable).
# Log: /Users/evw/Library/Logs/evw-alert-center.log — launchd also redirects
#   stdout there; log() echoes to stdout only on a TTY or with --once, so
#   lines never double up.
#
#   --once   single pass, NO dialogs/notifications: log what WOULD display
#            (headless testing; .shown is not consumed). Expiry bookkeeping
#            still happens for real.

import json
import os
import subprocess
import sys
import time
from datetime import datetime

STATE_DIR = "/var/db/evw-security-system"
ALERTS_DIR = os.path.join(STATE_DIR, "alerts")
ACK_DIR = os.path.join(STATE_DIR, "ack")
CONFIG_PATH = os.path.join(STATE_DIR, "security-system.json")
LOG_PATH = "/Users/evw/Library/Logs/evw-alert-center.log"
POLL_SECONDS = 10
GIVE_UP_SECONDS = 120          # dialog auto-dismiss (counts as NOT acknowledged)
DIALOG_BODY_MAX = 1200
NOTIFY_BODY_MAX = 250
SEV_RANK = {"CRITICAL": 0, "WARNING": 1}

ONCE = "--once" in sys.argv
_next_post = {}                # alert id -> epoch when it may re-post
_logged_bad = set()            # one-time log dedupe (bad files / bad ts)


def log(msg):
    line = "[{}] {}".format(datetime.now().isoformat(timespec="seconds"), msg)
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass
    if ONCE or sys.stdout.isatty():
        print(line, flush=True)


def esc(s):
    # AppleScript string-literal escaping: backslash first, then double-quote
    # (a body like  foo\"...  would otherwise break out of the literal).
    return str(s).replace("\\", "\\\\").replace('"', '\\"')


def safe_id(aid):
    # id becomes a filename in ack/ — strip anything path-unsafe
    s = "".join(c if (c.isalnum() or c in "._-") else "_" for c in str(aid))
    return s or "alert"


def marker_path(aid, suffix):
    return os.path.join(ACK_DIR, safe_id(aid) + suffix)


def has_marker(aid, suffix):
    return os.path.exists(marker_path(aid, suffix))


def write_marker(aid, suffix, note):
    path = marker_path(aid, suffix)
    line = datetime.now().isoformat(timespec="seconds")
    if note:
        line += " " + note
    try:
        with open(path, "w") as f:
            f.write(line + "\n")
    except OSError as e:
        log("MARKER-FAILED {}: {}".format(path, e))


def parse_ts(value, aid):
    # alert ts: ISO string (Z / offset / naive=local) or epoch seconds;
    # unparseable -> treat as new so the alert still gets shown
    try:
        if isinstance(value, (int, float)):
            return float(value)
        s = str(value).strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s).timestamp()
    except (ValueError, TypeError, OverflowError):
        key = "ts:" + str(aid)
        if key not in _logged_bad:
            _logged_bad.add(key)
            log("TS-UNPARSEABLE id={} ts={!r} — treating as new".format(aid, value))
        return time.time()


def load_config():
    try:
        cfg = json.load(open(CONFIG_PATH))
        alerts = cfg.get("alerts", {})
        persist = float(alerts.get("persist_minutes", 30))
        repost = float(alerts.get("repost_seconds", 60))
        return max(persist, 0.5) * 60.0, max(repost, 5.0)
    except (OSError, ValueError, TypeError, AttributeError):
        return 30 * 60.0, 60.0


def load_alerts():
    out = []
    try:
        names = sorted(os.listdir(ALERTS_DIR))
    except OSError:
        return out
    for name in names:
        if not name.endswith(".json"):
            continue
        full = os.path.join(ALERTS_DIR, name)
        try:
            a = json.load(open(full))
            if isinstance(a, dict) and a.get("id") is not None:
                out.append(a)
        except (OSError, ValueError):
            if full not in _logged_bad:
                _logged_bad.add(full)
                log("ALERT-UNREADABLE {}".format(full))
    return out


def show_dialog(a):
    title = str(a.get("title", "security alert"))
    body = str(a.get("body", ""))[:DIALOG_BODY_MAX]
    sev = str(a.get("severity", "WARNING")).upper()
    script = ('display dialog "{}" with title "evw security — {}" '
              'buttons {{"Acknowledge"}} default button 1 with icon caution '
              'giving up after {}').format(
                  esc(title) + "\n\n" + esc(body), esc(sev), GIVE_UP_SECONDS)
    try:
        p = subprocess.run(["osascript", "-e", script], capture_output=True,
                           text=True, timeout=GIVE_UP_SECONDS + 45)
        out = p.stdout or ""
        # a gave-up dialog still reports the default button, with gave up:true
        return (p.returncode == 0 and "button returned:Acknowledge" in out
                and "gave up:true" not in out)
    except (subprocess.TimeoutExpired, OSError) as e:
        log("DIALOG-ERROR id={}: {}".format(a.get("id"), e))
        return False


def show_notification(a):
    title = str(a.get("title", "security alert"))
    body = str(a.get("body", ""))[:NOTIFY_BODY_MAX]
    script = 'display notification "{}" with title "{}"'.format(
        esc(body), esc(title))
    try:
        subprocess.run(["osascript", "-e", script], capture_output=True,
                       timeout=15)
    except (subprocess.TimeoutExpired, OSError) as e:
        log("NOTIFY-ERROR id={}: {}".format(a.get("id"), e))


def process_alerts():
    persist_sec, repost_sec = load_config()
    now = time.time()
    due = []
    for a in load_alerts():
        try:
            aid = str(a.get("id"))
            sev = str(a.get("severity", "INFO")).upper()
            persist = bool(a.get("persist"))
            if has_marker(aid, ".ack"):
                continue
            age = now - parse_ts(a.get("ts", ""), aid)
            if age > persist_sec:
                if not has_marker(aid, ".expired"):
                    write_marker(aid, ".expired", "expired unacknowledged")
                    log("EXPIRED id={} severity={} age={}m title={!r}".format(
                        aid, sev, int(age / 60), a.get("title")))
                continue
            if has_marker(aid, ".expired"):
                continue
            if persist and sev in SEV_RANK:
                if now >= _next_post.get(aid, 0):
                    due.append((aid, sev, a))
            else:
                if has_marker(aid, ".shown"):
                    continue
                if ONCE:
                    log("WOULD-NOTIFY id={} severity={} title={!r}".format(
                        aid, sev, a.get("title")))
                else:
                    show_notification(a)
                    write_marker(aid, ".shown", "notification posted")
                    log("NOTIFY id={} severity={} title={!r}".format(
                        aid, sev, a.get("title")))
        except Exception as e:
            log("ALERT-ERROR {}: {!r}".format(a.get("id"), e))

    # one dialog at a time, CRITICAL before WARNING, oldest first
    due.sort(key=lambda t: (SEV_RANK[t[1]], str(t[2].get("ts", ""))))
    for aid, sev, a in due:
        if ONCE:
            log("WOULD-DIALOG id={} severity={} title={!r}".format(
                aid, sev, a.get("title")))
            continue
        log("DISPLAY id={} severity={} title={!r}".format(
            aid, sev, a.get("title")))
        if show_dialog(a):
            write_marker(aid, ".ack", "acknowledged via dialog")
            _next_post.pop(aid, None)
            log("ACK id={} title={!r}".format(aid, a.get("title")))
        else:
            _next_post[aid] = time.time() + repost_sec
            log("DISMISSED id={} — repost in {}s".format(aid, int(repost_sec)))


def main():
    try:
        os.makedirs(ACK_DIR, exist_ok=True)
    except OSError:
        pass
    persist_sec, repost_sec = load_config()
    log("START evw-alert-center once={} persist={}m repost={}s alerts={}".format(
        ONCE, int(persist_sec / 60), int(repost_sec), ALERTS_DIR))
    if ONCE:
        process_alerts()
        log("DONE (once)")
        return
    while True:
        try:
            process_alerts()
        except Exception as e:
            log("POLL-ERROR {!r}".format(e))
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
