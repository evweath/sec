#!/usr/bin/env python3
# ls-leak-scan.py — search captured LS connection data for security leaks.
#
# Three checks, per request:
#   1. destination name   — raw-IP destinations, no-PTR hosts, dynamic-DNS /
#                           exfil-friendly patterns, first-seen-today domains
#   2. traffic volume     — heavy uploads to destinations not in the known-good
#                           allow set (uses `littlesnitch log-traffic` export)
#   3. unknown process    — unsigned-looking paths, /tmp|/var/folders binaries,
#                           deleted-from-disk processes, odd via-chains
#
#   python3 ls-leak-scan.py                 # scan the alert feed (+enrich cache)
#   sudo python3 ls-leak-scan.py --export-traffic 24h
#        # also export the last 24h of traffic stats to ls-traffic.jsonl (root)
#   python3 ls-leak-scan.py --traffic ls-traffic.jsonl  # include volume analysis
#
# Reports: ~/dev/security/scan-YYYY-MM-DD/ls-leak-scan-HHMMSS.md
# Read-only against Little Snitch; only --export-traffic needs root.
# Python 3.9+, stdlib only.
import argparse
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
from collections import defaultdict

SEC_DIR = os.path.dirname(os.path.abspath(__file__))
FEED = os.environ.get("LS_ALERT_FEED", "/var/db/evw-ls-alerts/ls-alerts.jsonl")
FEED_FALLBACK = os.path.join(SEC_DIR, "ls-alerts.jsonl")
ENRICH_DB = os.path.join(SEC_DIR, "ls-enrich.db")
TRAFFIC = os.path.join(SEC_DIR, "ls-traffic.jsonl")
KNOWN_GOOD = os.path.join(SEC_DIR, "ls-policy.json")
LS_CLI = "/Applications/Little Snitch.app/Contents/Components/littlesnitch"

IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
PRIVATE = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|0\.)")
# Destination-name patterns worth a human look (extend as you learn):
SUSPICIOUS_NAME = re.compile(
    r"(duckdns|no-ip|noip|dyndns|ddns|hopto|zapto|serveftp|ngrok|trycloudflare|"
    r"pastebin|telegram|t\.me|discordapp|discord\.com/api|onion|"
    r"\.ru$|\.cn$|\.tk$|\.ml$|\.ga$|\.cf$|\.gq$)", re.IGNORECASE)
# Processes are suspicious if their path looks like this:
SUSPICIOUS_PROC_PATH = re.compile(
    r"^(/tmp/|/var/folders/|/private/tmp/|/dev/)|/\.[^/]+/[^\s]*$", re.IGNORECASE)
TRUSTED_PROC_PREFIXES = (
    "/System/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/sbin/", "/bin/",
    "/opt/homebrew/", "/Applications/", "/Library/",
)
UPLOAD_FLAG_BYTES = 100 * 1024 * 1024  # 100 MB to one non-allowlisted destination


def load_feed_paths():
    path = FEED if os.path.exists(FEED) else FEED_FALLBACK
    return path if os.path.exists(path) else None


def iter_feed_events():
    path = load_feed_paths()
    if not path:
        return
    with open(path, errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def event_fields(ev):
    """Best-effort extraction from an ls-alert-feed record."""
    rec = ev.get("ls", ev)
    proc = (rec.get("processPath") or rec.get("process")
            or rec.get("sender") or "")
    if isinstance(proc, dict):
        proc = proc.get("path") or proc.get("identifier") or ""
    host = (rec.get("remoteHostName") or rec.get("hostname") or rec.get("server")
            or rec.get("remoteAddress") or "")
    if isinstance(host, dict):
        host = host.get("name") or host.get("address") or ""
    port = str(rec.get("port") or rec.get("remotePort") or "")
    m = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", json.dumps(rec))
    ip = m[0] if m else ""
    return str(proc), str(host), port, ip


def known_good_hosts():
    try:
        doc = json.load(open(KNOWN_GOOD))
    except (OSError, json.JSONDecodeError):
        return set()
    hosts = set()
    for r in doc.get("rules", []):
        hs = r.get("remote-hosts") or []
        hosts.update(hs if isinstance(hs, list) else [hs])
    return hosts


def enrich_cache():
    """ip -> (ptr, org) from ls-enrich.db, if present."""
    out = {}
    if os.path.exists(ENRICH_DB):
        try:
            db = sqlite3.connect(ENRICH_DB)
            for ip, ptr, org in db.execute("SELECT ip, ptr, org FROM ip_info"):
                out[ip] = (ptr or "", org or "")
            db.close()
        except sqlite3.Error:
            pass
    return out


def check_destinations(events, enrich, first_seen):
    findings = []
    for proc, host, port, ip, ts in events:
        target = host or ip
        if not target:
            continue
        if ip and PRIVATE.match(ip):
            continue
        reasons = []
        if IPV4.match(target):
            reasons.append("raw-IP destination (no hostname)")
        elif SUSPICIOUS_NAME.search(target):
            reasons.append("destination name matches suspicious pattern")
        if ip and ip in enrich and not enrich[ip][0] and IPV4.match(target):
            reasons.append("no PTR record")
        key = host or ip
        if key and first_seen.get(key) == today():
            reasons.append("first seen today")
        if reasons:
            org = enrich.get(ip, ("", ""))[1] if ip else ""
            findings.append((proc, target, port, "; ".join(reasons), org))
    return findings


def check_processes(events):
    findings = []
    seen = set()
    for proc, host, port, ip, ts in events:
        if not proc or proc in seen:
            continue
        seen.add(proc)
        reasons = []
        if SUSPICIOUS_PROC_PATH.search(proc):
            reasons.append("runs from a temp/hidden path")
        if proc.startswith("/") and not os.path.exists(proc):
            reasons.append("binary no longer exists on disk")
        if proc.startswith("/") and not proc.startswith(TRUSTED_PROC_PREFIXES):
            reasons.append("outside trusted install prefixes")
        if reasons:
            findings.append((proc, host or ip, "; ".join(reasons)))
    return findings


def check_traffic(path, allow_hosts):
    """Parse a log-traffic export (JSONL or best-effort text) for heavy uploads."""
    findings, unparsed = [], 0
    if not path or not os.path.exists(path):
        return findings, unparsed
    volumes = defaultdict(int)
    with open(path, errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            proc = host = ""
            sent = 0
            try:
                d = json.loads(line)
                d = d.get("ls", d)
                proc = str(d.get("process") or d.get("processPath") or "")
                host = str(d.get("remoteHostName") or d.get("hostname")
                             or d.get("remoteAddress") or "")
                sent = int(d.get("bytesSent") or d.get("sent") or 0)
            except (json.JSONDecodeError, ValueError):
                m = re.search(r"(\S+).*?(\d+(?:\.\d+)?)\s*(MB|MiB|GB|GiB)\s*(sent|upload|out)",
                              line, re.IGNORECASE)
                if m:
                    proc = m.group(1)
                    mult = 10 ** 6 if m.group(3).lower().startswith("m") else 10 ** 9
                    sent = int(float(m.group(2)) * mult)
                    hm = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|[a-z0-9.-]+\.[a-z]{2,}", line)
                    host = hm.group(0) if hm else ""
                else:
                    unparsed += 1
                    continue
            if host and not PRIVATE.match(host):
                volumes[(proc, host)] += sent
    for (proc, host), sent in sorted(volumes.items(), key=lambda kv: -kv[1]):
        if sent >= UPLOAD_FLAG_BYTES and host not in allow_hosts:
            findings.append((proc, host, "%.1f MB uploaded" % (sent / 1e6)))
    return findings, unparsed


def today():
    return time.strftime("%F")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--export-traffic", metavar="SPAN",
                    help="export traffic stats for SPAN (e.g. 24h) via littlesnitch (root)")
    ap.add_argument("--traffic", metavar="FILE", default=None,
                    help="traffic export to analyze (default: %s)" % TRAFFIC)
    args = ap.parse_args()

    if args.export_traffic:
        if os.geteuid() != 0:
            ap.error("--export-traffic needs root (sudo)")
        end = time.strftime("%F %T")
        begin = time.strftime("%F %T", time.localtime(
            time.time() - span_seconds(args.export_traffic)))
        with open(TRAFFIC, "a") as out:
            subprocess.run([LS_CLI, "log-traffic", "-b", begin, "-e", end],
                           stdout=out, check=False)
        print("traffic appended to %s" % TRAFFIC)

    events = []
    seen_pair = set()
    for ev in iter_feed_events() or []:
        proc, host, port, ip = event_fields(ev)
        ts = time.strftime("%F", time.localtime(ev.get("ts", time.time())))
        key = (proc, host, port)
        if key in seen_pair:
            continue
        seen_pair.add(key)
        events.append((proc, host, port, ip, ts))

    first_seen = {}
    for proc, host, port, ip, ts in events:
        key = host or ip
        if key and key not in first_seen:
            first_seen[key] = ts

    enrich = enrich_cache()
    allow_hosts = known_good_hosts()
    traffic_path = args.traffic or TRAFFIC

    dest_findings = check_destinations(events, enrich, first_seen)
    proc_findings = check_processes(events)
    vol_findings, unparsed = check_traffic(traffic_path, allow_hosts)

    stamp = time.strftime("%H%M%S")
    scan_dir = os.path.join(SEC_DIR, "scan-" + today())
    os.makedirs(scan_dir, exist_ok=True)
    report = os.path.join(scan_dir, "ls-leak-scan-%s.md" % stamp)

    L = ["# LS leak scan — %s" % time.strftime("%F %T"), ""]
    L.append("feed events (unique proc/host/port): %d" % len(events))
    L.append("enriched IPs on cache: %d | known-good policy hosts: %d" % (len(enrich), len(allow_hosts)))
    L.append("")
    L.append("## 1. Suspicious destinations (%d)" % len(dest_findings))
    for proc, target, port, why, org in dest_findings[:100]:
        L.append("- `%s` → **%s**:%s — %s%s" % (proc or "(unknown proc)", target, port or "?",
                 why, (" (org: %s)" % org) if org else ""))
    if not dest_findings:
        L.append("- none")
    L.append("")
    L.append("## 2. Heavy uploads to non-allowlisted destinations (%d)" % len(vol_findings))
    for proc, host, what in vol_findings[:50]:
        L.append("- `%s` → **%s** — %s" % (proc, host, what))
    if not vol_findings:
        L.append("- none%s" % ("" if os.path.exists(traffic_path)
                 else " (no traffic export — run: sudo %s --export-traffic 24h)" % sys.argv[0]))
    if unparsed:
        L.append("- note: %d traffic lines unparsed (log-traffic format variant)" % unparsed)
    L.append("")
    L.append("## 3. Unknown / suspicious processes (%d)" % len(proc_findings))
    for proc, dest, why in proc_findings[:50]:
        L.append("- `%s` → %s — %s" % (proc, dest or "?", why))
    if not proc_findings:
        L.append("- none")
    L.append("")
    text = "\n".join(L)
    with open(report, "w") as f:
        f.write(text)
    print(text)
    print("report: %s" % report, file=sys.stderr)
    return 0


def span_seconds(span):
    m = re.match(r"^(\d+)\s*([mhd])$", span.strip())
    if not m:
        raise SystemExit("span must look like 30m / 12h / 7d")
    n, unit = int(m.group(1)), m.group(2)
    return n * {"m": 60, "h": 3600, "d": 86400}[unit]


if __name__ == "__main__":
    sys.exit(main())
