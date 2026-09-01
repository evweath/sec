#!/usr/bin/env python3
"""ip_intel.py — IP ownership enrichment for mac-sentinel connection logs.

For every remote IP (v4 or v6): classification (private/loopback/global),
PTR record, RDAP allocation owner (org name / net name / country / CIDR),
and a forward-confirmed-reverse-DNS check. Results cached on disk so repeat
sightings cost zero network calls.

Note: RDAP is an outbound HTTPS call from this (root) process — if Little
Snitch blocks it, the log entry will show rdap_error instead of failing.
"""

import ipaddress
import json
import os
import subprocess
import threading
import time
import urllib.request

CACHE_PATH = "/var/log/mac-sentinel/ip-intel-cache.json"
_RDAP = "https://rdap.arin.net/registry/ip/"   # ARIN redirects to the right RIR
_HTTP_TIMEOUT = 4
_cache = {}
_cache_lock = threading.Lock()
_cache_loaded = False


def _load_cache():
    global _cache_loaded
    if _cache_loaded:
        return
    try:
        with open(CACHE_PATH) as f:
            _cache.update(json.load(f))
    except Exception:
        pass
    _cache_loaded = True


def _save_cache():
    try:
        os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
        tmp = CACHE_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump(_cache, f)
        os.replace(tmp, CACHE_PATH)
    except Exception:
        pass


def classify(ip: str) -> str:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if a.is_loopback:
        return "loopback"
    if a.is_private:
        return "private-lan"
    if a.is_link_local:
        return "link-local"
    if a.is_multicast:
        return "multicast"
    if a.is_reserved or a.is_unspecified:
        return "reserved"
    return "global"


def ptr_lookup(ip: str) -> str:
    try:
        r = subprocess.run(
            ["dig", "+time=1", "+tries=1", "+short", "-x", ip],
            capture_output=True, text=True, timeout=3)
        name = r.stdout.strip().splitlines()
        return name[0].rstrip(".") if name and name[0] else ""
    except Exception:
        return ""


def fcrdns_ok(ip: str, ptr: str) -> bool:
    """Forward-confirmed rDNS: PTR name must resolve back to the same IP.
    Mismatch = classic cheap-VPS / faked-host signal."""
    if not ptr:
        return False
    try:
        r = subprocess.run(
            ["dig", "+time=1", "+tries=1", "+short", "A", ptr],
            capture_output=True, text=True, timeout=3)
        answers = [l.strip() for l in r.stdout.splitlines()]
        return ip in answers
    except Exception:
        return False


def rdap_lookup(ip: str) -> dict:
    try:
        req = urllib.request.Request(
            _RDAP + ip, headers={"User-Agent": "mac-sentinel/3.1"})
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        out = {
            "net_name": data.get("name") or "",
            "handle":   data.get("handle") or "",
            "country":  data.get("country") or "",
            "cidr":     "",
            "org":      "",
        }
        for c in data.get("cidr0_cidrs", []) or []:
            v4, v6 = c.get("v4prefix"), c.get("v6prefix")
            pref = v4 or v6
            if pref:
                out["cidr"] = f"{pref}/{c.get('length', '')}"
                break
        for ent in data.get("entities", []) or []:
            try:
                for field in ent["vcardArray"][1]:
                    if field[0] == "fn":
                        out["org"] = field[3]
                        raise StopIteration
            except StopIteration:
                break
            except Exception:
                continue
        return out
    except Exception as e:
        return {"rdap_error": f"{type(e).__name__}: {e}"[:200]}


def enrich_ip(ip: str) -> dict:
    """Full enrichment for a remote IP. Cached; zero network calls on repeats."""
    kind = classify(ip)
    if kind != "global":
        return {"kind": kind}

    with _cache_lock:
        _load_cache()
        if ip in _cache:
            return _cache[ip]

    intel = {"kind": kind}
    ptr = ptr_lookup(ip)
    intel["ptr"] = ptr or "none"
    intel["fcrdns_ok"] = fcrdns_ok(ip, ptr) if ptr else False
    intel.update(rdap_lookup(ip))
    intel["enriched_ts"] = int(time.time())

    with _cache_lock:
        _cache[ip] = intel
        _save_cache()
    return intel


if __name__ == "__main__":
    import sys
    for target in sys.argv[1:] or ["1.1.1.1"]:
        print(json.dumps({target: enrich_ip(target)}, indent=2))
