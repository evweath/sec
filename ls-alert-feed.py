#!/usr/bin/env python3
"""ls-alert-feed.py — capture every Little Snitch connection-alert ("pop-up query")
to a readable, persistent log.

Wraps `littlesnitch log` (the data behind LS's pop-up windows: which process
asked to talk to which host:port, and what answer/rule resulted). The literal
pop-up window is not scriptable, but everything it shows is in this stream.

Output:
  - every raw event appended as JSON lines to the JSONL path (full fidelity)
  - alert-relevant events printed to stdout as readable one-liners

Usage:
  sudo python3 ls-alert-feed.py                # live stream (Ctrl+C to stop)
  sudo python3 ls-alert-feed.py --last 2h      # replay the last 2 hours, then exit
  sudo python3 ls-alert-feed.py --out /path/alerts.jsonl

Requires root because `littlesnitch` must run as root.
Python 3.9+, stdlib only.
"""
import argparse
import glob
import json
import os
import re
import subprocess
import sys
import time

LS_CLI = "/Applications/Little Snitch.app/Contents/Components/littlesnitch"
_sec_dir = os.path.expanduser("~/dev/security")
DEFAULT_OUT = os.path.join(_sec_dir if os.path.isdir(_sec_dir) else "/tmp",
                           "ls-alerts.jsonl")
MAX_BYTES = 50 * 1024 * 1024  # rotate JSONL at 50 MB
KEEP_ARCHIVES = 10


def rotate_if_needed(out_path: str, handle) -> object:
    """Rotate out_path when it exceeds MAX_BYTES; prune old archives.
    Returns the (possibly new) open append handle."""
    try:
        if os.path.getsize(out_path) < MAX_BYTES:
            return handle
    except OSError:
        return handle
    handle.close()
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    archive = out_path[:-len(".jsonl")] + "-%s.jsonl" % stamp
    os.replace(out_path, archive)
    archives = sorted(glob.glob(out_path[:-len(".jsonl")] + "-*.jsonl"))
    for old in archives[:-KEEP_ARCHIVES]:
        try:
            os.unlink(old)
        except OSError:
            pass
    return open(out_path, "a")

# A line is "alert-relevant" if it mentions a connection being
# asked about / answered. Broad on purpose — the JSONL keeps everything anyway.
ALERTISH = re.compile(
    r"alert|allow|deny|connection|rule|ask", re.IGNORECASE)


def readable(rec: dict) -> str:
    """Best-effort one-line summary of a Little Snitch log record."""
    # Field names vary between LS versions; probe the common ones.
    def first(*keys):
        for k in keys:
            v = rec.get(k)
            if isinstance(v, str) and v:
                return v
            if isinstance(v, dict):
                for sub in ("identifier", "path", "name"):
                    if v.get(sub):
                        return str(v[sub])
        return ""
    proc = first("process", "processPath", "sender", "responsibleProcess")
    host = first("remoteHostName", "remote-hosts", "hostname", "server", "remoteAddress")
    port = rec.get("port") or rec.get("remotePort") or ""
    action = first("action", "event", "eventType", "decision")
    msg = rec.get("eventMessage") or rec.get("message") or ""
    parts = [p for p in (proc, "->", host + (":" + str(port) if port else ""),
             action, msg[:120]) if p]
    return " ".join(str(p) for p in parts) or json.dumps(rec)[:200]


def run(last: str, out_path: str) -> int:
    cmd = [LS_CLI, "log", "-j", "-a"]
    if last:
        cmd += ["-l", last]
    else:
        cmd += ["-s"]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True,
                                errors="replace", bufsize=1)
    except PermissionError:
        print("error: could not execute littlesnitch — run with sudo", file=sys.stderr)
        return 1
    assert proc.stdout is not None
    n_total = n_alerts = 0
    out = rotate_if_needed(out_path, open(out_path, "a"))
    try:
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            n_total += 1
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                rec = {"eventMessage": line}
            out.write(json.dumps({"ts": time.time(), "ls": rec}) + "\n")
            if n_total % 1000 == 0:
                out.flush()
                out = rotate_if_needed(out_path, out)
            blob = json.dumps(rec)
            if ALERTISH.search(blob):
                n_alerts += 1
                print("[%s] %s" % (time.strftime("%H:%M:%S"), readable(rec)),
                      flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        out.close()
        proc.terminate()
    print("\n%d events captured (%d alert-relevant) -> %s"
          % (n_total, n_alerts, out_path), file=sys.stderr)
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--last", metavar="TIME",
                   help="replay history instead of streaming, e.g. 30m, 2h, 1d")
    p.add_argument("--out", default=DEFAULT_OUT,
                   help="JSONL output path (default: %(default)s)")
    args = p.parse_args()
    print("writing raw events to %s" % args.out, file=sys.stderr)
    return run(args.last, args.out)


if __name__ == "__main__":
    sys.exit(main())
