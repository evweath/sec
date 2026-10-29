#!/usr/bin/env python3
# ls-enrich.py — enrich IPs seen in the LS alert feed with PTR + RDAP ownership.
#
# Reads new events from the ls-alert-feed JSONL (tracks its byte offset, so it
# only processes new events), and for each unique remote IP looks up:
#   PTR  via dig -x (hostname evidence)
#   RDAP via https://rdap.arin.net/registry/ip/<ip> (org, netblock, ASN-ish)
# Results are cached in ls-enrich.db (sqlite, 30-day TTL) and appended to
# ls-enrich.jsonl for auditing. Read-only: touches nothing in Little Snitch.
#
#   python3 ls-enrich.py                 # process new feed events
#   python3 ls-enrich.py 1.2.3.4 8.8.8.8 # ad-hoc lookup (bypasses feed)
#
# No root needed. Python 3.9+, stdlib only.
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
import urllib.request

SEC_DIR = os.path.dirname(os.path.abspath(__file__))
FEED = os.environ.get("LS_ALERT_FEED", "/var/db/evw-ls-alerts/ls-alerts.jsonl")
FEED_FALLBACK = os.path.join(SEC_DIR, "ls-alerts.jsonl")
DB = os.path.join(SEC_DIR, "ls-enrich.db")
AUDIT = os.path.join(SEC_DIR, "ls-enrich.jsonl")
OFFSET_FILE = os.path.join(SEC_DIR, ".ls-enrich.offset")
TTL = 30 * 86400
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PRIVATE = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|0\.)")


def db_connect():
    db = sqlite3.connect(DB)
    db.execute("""CREATE TABLE IF NOT EXISTS ip_info(
        ip TEXT PRIMARY KEY, ptr TEXT, org TEXT, netname TEXT, asn TEXT,
        country TEXT, fetched_at REAL, error TEXT)""")
    return db


def ptr_lookup(ip):
    try:
        r = subprocess.run(["dig", "+short", "+time=3", "+tries=1", "-x", ip],
                           capture_output=True, text=True, timeout=6)
        names = [l.strip().rstrip(".") for l in r.stdout.splitlines() if l.strip()]
        return names[0] if names else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def rdap_lookup(ip):
    url = "https://rdap.arin.net/registry/ip/%s" % ip
    try:
        with urllib.request.urlopen(url, timeout=8) as resp:
            d = json.load(resp)
    except Exception as e:
        return {"error": "%s: %s" % (type(e).__name__, e)}
    org = d.get("name") or ""
    # entities often carry the real operator org
    for ent in d.get("entities") or []:
        v = ent.get("vcardArray")
        if v and len(v) > 1:
            for item in v[1]:
                if item[0] == "fn":
                    org = item[3] or org
                    break
        if ent.get("handle") and not d.get("name"):
            org = ent["handle"]
    asn = ""
    for ps in d.get("arin_originas0_autnums") or []:
        asn = "AS%s" % ps
        break
    return {"org": org, "netname": d.get("handle") or "",
            "asn": asn, "country": d.get("country") or ""}


def enrich(ip, db, force=False):
    row = db.execute("SELECT ptr,org,netname,asn,country,fetched_at,error FROM ip_info WHERE ip=?",
                     (ip,)).fetchone()
    if row and not force:
        ttl = 3600 if row[6] else TTL  # retry transient failures after 1h
        if time.time() - row[5] < ttl:
            return dict(zip(("ptr", "org", "netname", "asn", "country", "cached"), list(row[:6]) + [True]))
    info = {"ip": ip, "ptr": ptr_lookup(ip)}
    info.update(rdap_lookup(ip))
    db.execute("""INSERT OR REPLACE INTO ip_info
                  (ip,ptr,org,netname,asn,country,fetched_at,error)
                  VALUES (?,?,?,?,?,?,?,?)""",
               (ip, info.get("ptr"), info.get("org"), info.get("netname"),
                info.get("asn"), info.get("country"), time.time(), info.get("error")))
    db.commit()
    with open(AUDIT, "a") as f:
        f.write(json.dumps(info) + "\n")
    time.sleep(1.0)  # RDAP politeness
    return info


def feed_ips():
    """Yield unique new IPs from the feed since the last run (offset-tracked)."""
    path = FEED if os.path.exists(FEED) else FEED_FALLBACK
    if not os.path.exists(path):
        return
    offset = 0
    if os.path.exists(OFFSET_FILE):
        try:
            offset = int(open(OFFSET_FILE).read().strip())
        except ValueError:
            offset = 0
        if os.path.getsize(path) < offset:
            offset = 0  # feed rotated
    seen = set()
    with open(path) as f:
        f.seek(offset)
        for line in f:
            for ip in IPV4.findall(line):
                if not PRIVATE.match(ip) and ip not in seen:
                    seen.add(ip)
                    yield ip
        new_offset = f.tell()
    with open(OFFSET_FILE, "w") as f:
        f.write(str(new_offset))


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    db = db_connect()
    if args:
        for ip in args:
            print(json.dumps(enrich(ip, db, force=True)))
        return 0
    n = 0
    for ip in feed_ips():
        info = enrich(ip, db)
        n += 1
        print("%-16s ptr=%-40s org=%s %s" % (
            ip, info.get("ptr") or "-", info.get("org") or "-", info.get("asn") or ""))
    print("enriched %d new IP(s)" % n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
