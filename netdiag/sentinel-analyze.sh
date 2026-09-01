#!/bin/bash
# netdiag/sentinel-analyze.sh — condense all mac-sentinel logs into one reviewable report.
set -uo pipefail
OUT=/Users/evw/dev/fix/netdiag/logs/sentinel-analysis.txt
echo "=== sentinel-analyze $(date) ==="
[ "$(id -u)" -ne 0 ] && { echo "ERROR: must be root"; exit 1; }

/usr/bin/python3 - << 'PYEOF'
import json, os, glob
from collections import Counter, defaultdict

LOGD = "/var/log/mac-sentinel"
OUT = "/Users/evw/dev/fix/netdiag/logs/sentinel-analysis.txt"

def read_jsonl(name, cap=200000):
    path = os.path.join(LOGD, name)
    if not os.path.exists(path):
        return []
    lines = open(path, errors="replace").readlines()[-cap:]
    out = []
    for l in lines:
        try: out.append(json.loads(l))
        except Exception: pass
    return out

rep = []
rep.append("SENTINEL LOG ANALYSIS — adjudicate every entry\n")

# ── A. outbound connections: proc -> ip/port with intel ─────────────────────
conns = read_jsonl("network_connections.jsonl")
bykey = {}
for e in conns:
    d = e.get("data", {})
    key = (d.get("process","?"), d.get("remote_ip","?"), d.get("remote_port","?"))
    intel = d.get("ip_intel") or {}
    bykey[key] = (bykey.get(key, (0, intel))[0] + 1, intel or bykey.get(key, (0, intel))[1])
rep.append("## A. OUTBOUND CONNECTIONS (process -> ip:port, count, owner/country/fcrdns)")
for (proc, ip, port), (cnt, intel) in sorted(bykey.items(), key=lambda kv: (kv[0][0], -kv[1][0])):
    rep.append("  {:<28} -> {}:{}  x{}  org={} country={} ptr={} fcrdns={}".format(
        proc[:28], ip, port, cnt,
        (intel.get("org") or intel.get("net_name") or intel.get("kind","?"))[:40],
        intel.get("country","?"), str(intel.get("ptr","?"))[:30], intel.get("fcrdns_ok","?")))
rep.append("")

# ── B. root processes detected ───────────────────────────────────────────────
roots = read_jsonl("credential_transitions.jsonl")
rp = Counter(); rpd = {}
for e in roots:
    d = e.get("data", {})
    if d.get("event") == "ROOT_PROCESS_DETECTED":
        k = (d.get("process","?"), d.get("exe","?"))
        rp[k] += 1; rpd[k] = d.get("cmdline","?")
rep.append("## B. ROOT_PROCESS_DETECTED (name, exe, count, cmdline)")
for (name, exe), cnt in rp.most_common():
    rep.append("  {:<30} {:<50} x{}  {}".format(name[:30], exe[:50], cnt, str(rpd[(name,exe)])[:60]))
rep.append("")

# ── C. sudo / auth events ────────────────────────────────────────────────────
rep.append("## C. SUDO/AUTH EVENTS")
for e in roots:
    d = e.get("data", {})
    if d.get("event","").startswith(("SUDO","AUTH","FAILED","SSH","NEW_USER")):
        rep.append("  {} {} {}".format(e.get("ts_human","")[:35], d.get("event"), str(d.get("raw_line",""))[:120]))
rep.append("")

# ── D. file changes in watched paths ─────────────────────────────────────────
fcs = read_jsonl("file_changes.jsonl")
fc = Counter()
for e in fcs:
    d = e.get("data", {})
    if d.get("event","").startswith(("FILE_CHANGED","FILE_DELETED","BASELINE")):
        fc[(d.get("event"), d.get("path","?"))] += 1
rep.append("## D. WATCHED FILE CHANGES")
for (ev, path), cnt in fc.most_common(40):
    rep.append("  {:<15} {:<70} x{}".format(ev, path[:70], cnt))
rep.append("")

# ── E. canary tripwires (ANY entry = investigate) ────────────────────────────
can = read_jsonl("cache_validation.jsonl")
rep.append("## E. CANARY TRIPWIRES (expect NONE)")
for e in can[-20:]:
    rep.append("  " + json.dumps(e.get("data",{}))[:200])
if not can: rep.append("  (none)")
rep.append("")

# ── F. USB / hardware events ─────────────────────────────────────────────────
usb = read_jsonl("hardware_devices.jsonl")
rep.append("## F. USB/HARDWARE EVENTS")
seen = set()
for e in usb:
    d = e.get("data", {})
    k = json.dumps(d, sort_keys=True)[:150]
    if k not in seen:
        seen.add(k); rep.append("  {} {}".format(e.get("ts_human","")[:35], k))
if not usb: rep.append("  (none)")
rep.append("")

# ── G. self-integrity ────────────────────────────────────────────────────────
integ = read_jsonl("self_integrity.jsonl")
rep.append("## G. SELF-INTEGRITY (DAEMON_SCRIPT_TAMPERED = alarm)")
for e in integ[-15:]:
    rep.append("  {} {}".format(e.get("ts_human","")[:35], json.dumps(e.get("data",{}))[:150]))
rep.append("")

# ── H. anomaly / correlated threats ──────────────────────────────────────────
anom = read_jsonl("anomaly_scores.jsonl")
rep.append("## H. CORRELATED ANOMALIES (expect none)")
for e in anom[-10:]:
    rep.append("  " + json.dumps(e.get("data",{}))[:200])
if not anom: rep.append("  (none)")
rep.append("")

# ── I. conn-guard actions ────────────────────────────────────────────────────
aa = read_jsonl("auto-actions.jsonl")
acts = Counter(e.get("action","?") for e in aa)
rep.append("## I. CONN-GUARD ACTIONS: " + dict(acts).__str__())
for e in aa:
    if e.get("action") in ("KILL+BLOCK", "ALERT-DNS-HIJACK-SUSPECT"):
        rep.append("  " + json.dumps(e)[:250])
rep.append("")

# ── J. daemon errors ─────────────────────────────────────────────────────────
rep.append("## J. daemon.log (last 8 lines)")
try:
    rep += ["  " + l.rstrip()[:150] for l in open(os.path.join(LOGD,"daemon.log"), errors="replace").readlines()[-8:]]
except Exception as ex:
    rep.append(f"  (unreadable: {ex})")

open(OUT, "w").write("\n".join(rep) + "\n")
print("wrote", OUT, "entries:", len(rep))
PYEOF

chown evw:staff /Users/evw/dev/fix/netdiag/logs/sentinel-analysis.txt
echo "=== sentinel-analyze done ==="
