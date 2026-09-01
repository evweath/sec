#!/usr/bin/env python3
# evw-auto-conn-guard.py — [AUTO-EVW] automated suspicious-connection guard.
#
# Detections (requested 2026-09-01, netdiag review):
#   D1  hardcoded-IP connections: global IP with no PTR on a non-standard port
#       (true "no recent DNS answer" correlation needs an Endpoint Security
#       entitlement — this is the honest proxy)
#   D2  DNS cross-validation: system resolver vs 1.1.1.1/8.8.8.8 answers;
#       fully DISJOINT answer sets = possible DNS hijack (ALERT-ONLY: CDNs
#       legitimately return different answers; disjoint is the red flag)
#   D3  FCrDNS failure: PTR exists but does not resolve back to the same IP
#   D4  long-lived outbound connections from non-browser/non-system processes
#   D5  TLS anomaly (active 2s probe, only when already suspicious):
#       TLS on odd ports, or plaintext on 443
#
# Auto-response — ONLY when score >= ACT_THRESHOLD and target NOT protected:
#   - SIGKILL the connecting PID (comm name re-verified immediately before kill)
#   - pf block of the IP via table <auto_evw_block>, BLOCK_TTL seconds
#     (NOT permanent — janitor expires it; re-applied on restart if unexpired)
#   - queue a Little Snitch deny rule (synced by evw-auto-ls-sync.sh once LS
#     CLI access is enabled: Little Snitch > Settings > Security >
#     Command Line Tool Access). LS model restore is debounced >= 10 min.
#
# Protections (never killed/blocked): RFC1918/loopback/link-local/reserved,
# default gateway, system DNS servers, TRUSTED_IPS, Apple 17.0.0.0/8,
# api.moonshot.cn (Kimi CLI lifeline), SAFE_PROCS (browsers + core system +
# python so the guard never kills itself).
#
# AUDIT / UNDO: every action tagged action_id=auto-<epoch>-<n>, appended to
#   /var/log/mac-sentinel/auto-actions.jsonl  (machine) and
#   /var/log/mac-sentinel/AUTO-ACTIONS.md     (human, one line each)
# Undo any action:  sudo evw-auto-undo.sh <action_id>
# Flush all blocks: sudo evw-auto-undo.sh all-blocks
# Disable guard:    sudo launchctl bootout system/com.evw.auto-conn-guard

import json
import os
import socket
import ssl
import subprocess
import sys
import time
from datetime import datetime

sys.path.insert(0, "/usr/local/lib/mac-sentinel")
try:
    from ip_intel import enrich_ip, classify
except Exception:
    def enrich_ip(ip): return {}
    def classify(ip): return "global" if ":" in ip or "." in ip else "invalid"

SCAN_SECS       = 30
DNSCHECK_SECS   = 300
BLOCK_TTL       = 3600          # auto-blocks expire after 1h unless user promotes
ACT_THRESHOLD   = 5             # score needed for auto kill+block
LONG_LIVED_SECS = 3600
LS_SYNC_DEBOUNCE = 600          # LS model restore at most every 10 min

LOG_DIR   = "/var/log/mac-sentinel"
JSONL     = os.path.join(LOG_DIR, "auto-actions.jsonl")
HUMAN     = os.path.join(LOG_DIR, "AUTO-ACTIONS.md")
STATE     = os.path.join(LOG_DIR, "auto-block-state.json")
LS_QUEUE  = os.path.join(LOG_DIR, "ls-rule-queue.json")
LS_SYNC   = "/usr/local/bin/evw-auto-ls-sync.sh"

TRUSTED_IPS = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4",
               "9.9.9.9", "149.112.112.112"}
STANDARD_PORTS  = {22, 25, 53, 80, 143, 443, 465, 587, 853, 993, 995}
TLS_OK_PORTS    = {443, 853, 993, 995, 465}
SUSPICIOUS_PORTS = {23, 512, 513, 514, 1080, 3128, 4444, 6666, 6667,
                    6668, 6669, 8888, 1337, 31337, 135, 137, 138, 139, 445}
SAFE_PROCS = {   # never auto-killed (user-facing / core system / self)
    "Safari", "Brave Browser", "firefox", "Google Chrome", "Arc", "Opera",
    "mDNSResponder", "nsurlsessiond", "nsurlstoraged", "airportd", "configd",
    "Little Snitch", "Little Snitch Agent", "Little Snitch Network Monitor",
    "kernel_task", "launchd", "UserEventAgent", "cfprefsd", "distnoted",
    "python3", "Python",
}
DNSCHECK_DOMAINS = ["apple.com", "icloud.com", "github.com",
                    "api.moonshot.cn", "cloudflare.com"]

_first_seen = {}
_probed     = set()
_counter    = [0]
_last_ls_sync = [0.0]


def log_action(rec: dict):
    rec["ts"] = datetime.utcnow().isoformat() + "Z"
    rec.setdefault("auto", True)
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        with open(JSONL, "a") as f:
            f.write(json.dumps(rec, default=str) + "\n")
        with open(HUMAN, "a") as f:
            f.write("{} [{}] {} score={} ip={} port={} proc={} pid={} reasons={} undo={}\n".format(
                rec["ts"], rec.get("action_id", "-"), rec.get("action", "?"),
                rec.get("score", "-"), rec.get("ip", "-"), rec.get("port", "-"),
                rec.get("proc", "-"), rec.get("pid", "-"),
                ",".join(rec.get("reasons", [])),
                rec.get("undo", "-")))
    except Exception:
        pass


def _run(cmd, timeout=5):
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout).stdout
    except Exception:
        return ""


def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, obj):
    try:
        with open(path + ".tmp", "w") as f:
            json.dump(obj, f, indent=1)
        os.replace(path + ".tmp", path)
    except Exception:
        pass


def never_block_ips():
    """Runtime-refreshed protection set: gateway + live DNS + moonshot + trusted."""
    out = set(TRUSTED_IPS)
    for line in _run(["route", "-n", "get", "default"]).splitlines():
        if "gateway:" in line:
            out.add(line.split()[-1])
    for line in _run(["scutil", "--dns"]).splitlines():
        if "nameserver[" in line:
            out.add(line.split(":")[-1].strip())
    ans = _run(["dig", "+time=1", "+tries=1", "+short", "api.moonshot.cn", "@1.1.1.1"], 3)
    out.update(l.strip() for l in ans.splitlines() if l.strip())
    return out


def is_protected_ip(ip, never):
    if ip in never or classify(ip) != "global":
        return True
    if ip.startswith("17."):          # Apple 17.0.0.0/8
        return True
    return False


def tls_probe(ip, port, timeout=2):
    """Active bounded probe: 'tls' | 'plain' | 'unknown'. CERT_NONE on purpose —
    we test the PROTOCOL, not certificate trust (a bad cert is still TLS)."""
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except Exception:
        return "unknown"
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(sock, server_hostname=ip)
        s.close()
        return "tls"
    except ssl.SSLError:
        try:
            sock.close()
        except Exception:
            pass
        return "plain"
    except Exception:
        return "unknown"


def score_conn(ip, port, proc, age, intel):
    s, reasons = 0, []
    if port in SUSPICIOUS_PORTS:
        s += 3; reasons.append("suspicious-port")
    ptr = intel.get("ptr", "")
    if not ptr or ptr == "none":
        if port not in STANDARD_PORTS:
            s += 2; reasons.append("D1-no-ptr-odd-port")
        else:
            s += 1; reasons.append("D1-no-ptr")
    elif intel.get("fcrdns_ok") is False:
        s += 1; reasons.append("D3-fcrdns-fail")
    if port not in STANDARD_PORTS:
        s += 2; reasons.append("odd-port")
    if age > LONG_LIVED_SECS and proc not in SAFE_PROCS:
        s += 2; reasons.append("D4-long-lived-nonbrowser")
    return s, reasons


def d5_probe(ip, port, score, reasons):
    """D5: TLS anomaly — only probe when already suspicious, once per conn."""
    key = "{}:{}".format(ip, port)
    if score < 2 or key in _probed:
        return score, reasons
    _probed.add(key)
    if len(_probed) > 5000:
        _probed.clear()
    proto = tls_probe(ip, port)
    if proto == "tls" and port not in TLS_OK_PORTS:
        score += 2; reasons.append("D5-tls-odd-port")
    elif proto == "plain" and port == 443:
        score += 2; reasons.append("D5-plain-on-443")
    return score, reasons


def next_aid():
    _counter[0] += 1
    return "auto-{}-{}".format(int(time.time()), _counter[0])


def queue_ls_rule(aid, ip, reasons):
    q = load_json(LS_QUEUE, [])
    q.append({"action_id": aid, "ip": ip, "reasons": reasons,
              "ts": int(time.time()), "status": "queued"})
    save_json(LS_QUEUE, q)
    if time.time() - _last_ls_sync[0] > LS_SYNC_DEBOUNCE and os.path.exists(LS_SYNC):
        _last_ls_sync[0] = time.time()
        r = subprocess.run(["/bin/bash", LS_SYNC], capture_output=True, text=True)
        return "sync-attempted-rc{}".format(r.returncode)
    return "queued"


def act(ip, port, pid, proc, score, reasons, never):
    aid = next_aid()
    undo = "sudo evw-auto-undo.sh {}".format(aid)
    if is_protected_ip(ip, never) or proc in SAFE_PROCS:
        log_action({"action_id": aid, "action": "SKIPPED-PROTECTED", "ip": ip,
                    "port": port, "pid": pid, "proc": proc, "score": score,
                    "reasons": reasons})
        return

    killed = False
    # Re-verify PID still runs the same process (PID-reuse guard, mirrors
    # binding-monitor.sh) immediately before killing.
    comm = _run(["ps", "-p", str(pid), "-o", "comm="]).strip()
    if comm and os.path.basename(comm).startswith(proc[:15]):
        killed = subprocess.run(["kill", "-9", str(pid)],
                                capture_output=True).returncode == 0
    add = subprocess.run(["pfctl", "-a", "com.ew.autoblock", "-t", "auto_evw_block", "-T", "add", ip],
                         capture_output=True, text=True)
    blocked = add.returncode == 0 or "1/1 addresses added" in (add.stderr or "")
    ls_rule = queue_ls_rule(aid, ip, reasons)

    st = load_json(STATE, {})
    st[ip] = {"action_id": aid, "ts": int(time.time()), "score": score,
              "reasons": reasons, "undone": False}
    save_json(STATE, st)
    log_action({"action_id": aid, "action": "KILL+BLOCK", "ip": ip,
                "port": port, "pid": pid, "proc": proc, "score": score,
                "reasons": reasons, "killed": killed, "blocked": blocked,
                "ls_rule": ls_rule, "block_expires": int(time.time()) + BLOCK_TTL,
                "undo": undo})
    subprocess.run(["osascript", "-e",
        'display notification "KILLED {} (pid {}) + blocked {} (1h) — undo: {}" '
        'with title "[AUTO-EVW] conn-guard" sound name "Basso"'.format(
            proc, pid, ip, undo)], capture_output=True)


def janitor():
    """Expire TTL'd blocks; log each expiry for the audit trail."""
    st, now = load_json(STATE, {}), int(time.time())
    dirty = False
    for ip, e in list(st.items()):
        if e.get("undone"):
            continue
        if now - e.get("ts", 0) > BLOCK_TTL:
            subprocess.run(["pfctl", "-a", "com.ew.autoblock", "-t", "auto_evw_block", "-T", "delete", ip],
                           capture_output=True)
            e["undone"], e["undone_ts"], dirty = True, now, True
            log_action({"action_id": e.get("action_id"), "action": "BLOCK-EXPIRED",
                        "ip": ip, "reasons": e.get("reasons", [])})
    if dirty:
        save_json(STATE, st)


def restore_unexpired():
    """After reboot/restart the pf table is empty — re-apply live blocks."""
    st, now = load_json(STATE, {}), int(time.time())
    for ip, e in st.items():
        if not e.get("undone") and now - e.get("ts", 0) <= BLOCK_TTL:
            subprocess.run(["pfctl", "-a", "com.ew.autoblock", "-t", "auto_evw_block", "-T", "add", ip],
                           capture_output=True)


def scan_connections(never):
    out = _run(["lsof", "-i", "-n", "-P", "-F", "pncPTifu"], 10)
    current, now = {}, int(time.time())
    for line in out.splitlines():
        if not line:
            continue
        code, val = line[0], line[1:]
        if code == "p":
            current = {"pid": int(val) if val.isdigit() else None}
        elif code == "c":
            current["cmd"] = val
        elif code == "n" and "->" in val:
            remote = val.split("->", 1)[1]
            if remote.startswith("[") or ":" not in remote:
                continue
            ip, ps = remote.rsplit(":", 1)
            if not ps.isdigit():
                continue
            port = int(ps)
            if is_protected_ip(ip, never):
                continue
            key = "{}:{}:{}".format(ip, port, current.get("pid"))
            _first_seen.setdefault(key, now)
            age = now - _first_seen[key]
            intel = enrich_ip(ip)
            score, reasons = score_conn(ip, port, current.get("cmd", "?"), age, intel)
            score, reasons = d5_probe(ip, port, score, reasons)
            if score >= ACT_THRESHOLD:
                org = intel.get("org") or intel.get("net_name") or "?"
                act(ip, port, current.get("pid"), current.get("cmd", "?"),
                    score, (reasons + ["org=" + str(org)])[:6], never)
            elif score >= 3:
                log_action({"action_id": next_aid(), "action": "ALERT-ONLY",
                            "ip": ip, "port": port, "pid": current.get("pid"),
                            "proc": current.get("cmd", "?"), "score": score,
                            "reasons": reasons, "intel": intel})
    for k in list(_first_seen):
        if now - _first_seen[k] > LONG_LIVED_SECS * 2:
            del _first_seen[k]


def dns_crosscheck():
    """D2: disjoint system-vs-public answer sets = hijack suspect. Alert-only."""
    for d in DNSCHECK_DOMAINS:
        sys_ans = set()
        for line in _run(["dscacheutil", "-q", "host", "-a", "name", d], 5).splitlines():
            if "ip_address:" in line:
                sys_ans.add(line.split()[-1])
        pub = set()
        for ns in ("1.1.1.1", "8.8.8.8"):
            for line in _run(["dig", "+time=1", "+tries=1", "+short", d, "@" + ns], 4).splitlines():
                if line and line[0].isdigit():
                    pub.add(line.strip())
        if sys_ans and pub and sys_ans.isdisjoint(pub):
            log_action({"action_id": next_aid(), "action": "ALERT-DNS-HIJACK-SUSPECT",
                        "domain": d, "sys_answers": sorted(sys_ans),
                        "public_answers": sorted(pub),
                        "reasons": ["D2-dns-disjoint"], "auto_block": False,
                        "note": "verify manually: dig {} vs dig @1.1.1.1 {}".format(d, d)})
            subprocess.run(["osascript", "-e",
                'display notification "DNS answers for {} are DISJOINT from public resolvers — possible hijack. See AUTO-ACTIONS.md" '
                'with title "[AUTO-EVW] DNS alert" sound name "Basso"'.format(d)],
                capture_output=True)


def main():
    os.makedirs(LOG_DIR, exist_ok=True)
    log_action({"action_id": next_aid(), "action": "GUARD_START",
                "pid": os.getpid(), "threshold": ACT_THRESHOLD,
                "block_ttl": BLOCK_TTL, "version": "2026-09-01.2"})
    restore_unexpired()
    last_dns, last_jan = 0.0, 0.0
    while True:
        never = never_block_ips()
        try:
            scan_connections(never)
        except Exception as e:
            log_action({"action_id": next_aid(), "action": "SCAN-ERROR",
                        "note": str(e)[:200]})
        now = time.time()
        if now - last_dns > DNSCHECK_SECS:
            last_dns = now
            try:
                dns_crosscheck()
            except Exception:
                pass
        if now - last_jan > 300:
            last_jan = now
            janitor()
        time.sleep(SCAN_SECS)


if __name__ == "__main__":
    main()
