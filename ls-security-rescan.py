#!/usr/bin/env python3
"""ls-security-rescan.py — security rescan of a Little Snitch model export.

Usage: python3 ls-security-rescan.py <input-model.json> <output-model.json> [--report FILE]

Requested scan 2026-09-03: "rescan all LS rules for security issues and deny
any rules that are security risks."

Operations (deny / factory / protected rules are never touched):
  1. DENY-ADD  global deny rules (any process, remote-domains, direction both)
               for confirmed tracker domains — ByteDance/Volcengine telemetry
               SDKs (gator/apmplus/tab) and the queniuck.com CNAME-cloaking
               tracker. Same rule shape as the existing api.whatsapp.com deny.
  2. DELETE    allow rules referencing those domains — a process+host allow
               would beat a domain-only global deny on specificity, so the
               allows must go for the deny to be effective (watchdog idiom:
               "allow rule for a blocked domain").
  3. DELETE    suggestion rules with remote "any" (expired alertTimeout
               blanket allows — e.g. Brave -> any:443 — one click from a hole).
  4. DELETE    monitor-origin allow rules with useCount 0 (auto-approved,
               never used — posture target: 0 monitor-origin allows).
  5. DELETE    allow rules whose process/via path no longer exists on disk
               (stale — e.g. /opt/homebrew/Cellar/node/*/bin/node rules).
  6. TIGHTEN   allow rules with a specific remote-hosts target but no port
               restriction to tcp:443 (same rule as evw-ls-watchdog).

Every change is logged to the report file (default stdout summary only).
Python 3.9 compatible. Read-only except for the output/report files.
"""
import json, os, sys, datetime, re

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error_guard.py)
try:
    import pathlib as _pathlib, sys as _sys
    _d = _pathlib.Path(__file__).resolve().parent
    for _ in range(6):
        if (_d / "lib" / "error_guard.py").exists():
            _sys.path.insert(0, str(_d / "lib"))
            break
        _d = _d.parent
    from error_guard import guard_run, guarded, SKIP, throw, GuardError
except ImportError:
    SKIP = object()
    def guard_run(_l, fn, *a, **kw): return fn(*a, **kw)
    def guarded(_l=None):
        def deco(fn): return fn
        return deco
    class GuardError(RuntimeError): pass
    def throw(msg): raise GuardError(str(msg))

REPORT_LINES = []

def report(msg):
    REPORT_LINES.append(msg)

# ── Tracker domains to deny outright (any process). remote-domains matches
#    subdomains by suffix, so this covers gator.volces.com.<hash>.queniuck.com.
TRACKER_DENY = {
    "gator.volces.com":   "ByteDance/Volcengine Gator tracking + anti-bot SDK",
    "apmplus.volces.com": "ByteDance/Volcengine APMPlus telemetry",
    "apmplus.ap-southeast-1.volces.com": "ByteDance/Volcengine APMPlus telemetry (regional endpoint)",
    "tab.volces.com":     "ByteDance/Volcengine DataTester telemetry",
    "queniuck.com":       "CNAME-cloaking tracker (Volcengine alias target)",
}

# ── Blocked-posture domains lost in the 2026-08-31 model rebuild (mirrors
#    evw-ls-watchdog BLOCKED_DOMAINS/BLOCKED_HOSTS — ls-dedup's critical list
#    confirms these denies used to exist).
POSTURE_DENY = {
    "tiktok.com": "blocked posture: TikTok",
    "tiktokcdn-us.com": "blocked posture: TikTok CDN",
    "tiktokv.us": "blocked posture: TikTok",
    "tiktokw.us": "blocked posture: TikTok",
    "ttcdn-us.com": "blocked posture: TikTok CDN",
    "tiktokshops.us": "blocked posture: TikTok shop",
    "bytedance.com": "blocked posture: ByteDance",
    "zohopublic.com": "blocked posture: Zoho tracking",
    "zohocdn.com": "blocked posture: Zoho tracking",
    "salesiq.zoho.com": "blocked posture: Zoho SalesIQ tracker",
    "pagesense-collect.zoho.com": "blocked posture: Zoho PageSense tracker",
    "pagesense-hb-collect.zoho.com": "blocked posture: Zoho PageSense tracker",
}
DENY_DOMAINS = {**TRACKER_DENY, **POSTURE_DENY}

def host_matches_domain(host, domain):
    h = host.strip().lstrip("*.")
    return h == domain or h.endswith("." + domain)

def rule_hits_tracker(r):
    for field in ("remote-hosts", "remote-domains"):
        v = str(r.get(field, ""))
        if not v:
            continue
        for token in re.split(r"[,\s]+", v):
            if token and any(host_matches_domain(token, d) for d in DENY_DOMAINS):
                return True
    return False

def remote_label(r):
    for k in ("remote", "remote-hosts", "remote-domains", "remote-addresses"):
        v = r.get(k)
        if v:
            return str(v)[:60]
    return "any"

def path_missing(ref):
    """True if ref is a plain filesystem path that does not exist.
    identifier.TEAM/bundle refs can't be path-checked -> False."""
    s = str(ref or "")
    if not s.startswith("/"):
        return False
    if "*" in s:  # globbed paths (e.g. Cellar/node/*) — check parent anchor
        anchor = s.split("*")[0].rstrip("/")
        return not os.path.exists(anchor)
    if os.path.exists(s):
        return False
    parts = s.split("/")
    for i, part in enumerate(parts):
        if part.endswith(".app"):
            return not os.path.exists("/".join(parts[: i + 1]))
    return True

def load_model(path):
    with open(path) as f:
        return json.load(f)

def save_model(model, dst):
    with open(dst, "w") as f:
        json.dump(model, f, indent=2, separators=(",", " : "))
        f.write("\n")
    return True

def write_report(path, text):
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(path, "w") as f:
        f.write(text)
    return True

def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(64)
    src, dst = sys.argv[1], sys.argv[2]
    report_file = None
    if "--report" in sys.argv:
        report_file = sys.argv[sys.argv.index("--report") + 1]

    model = guard_run("load-model", load_model, src)
    if model is None or model is SKIP:
        sys.exit(1)
    rules = model.get("rules", [])
    report(f"Input: {len(rules)} rules ({src})")

    now = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    out = []
    n_del_tracker = n_del_sugg = n_del_monitor = n_del_stale = n_tighten = 0

    for r in rules:
        action = r.get("action")
        protected = r.get("protected") or r.get("origin") == "factory"

        # 3. suggestion with remote any -> delete (blanket allow if approved)
        if action == "suggestion" and not protected:
            remote = str(r.get("remote", ""))
            if remote in ("any", "*"):
                n_del_sugg += 1
                report(f"DELETE any-remote suggestion: {r.get('process','any')} -> {remote_label(r)}"
                       f" ports={r.get('ports','any')} origin={r.get('origin')}")
                continue
            out.append(r)
            continue

        if action != "allow" or protected:
            out.append(r)
            continue

        # 2. allow rule for a tracker domain -> delete (deny added below)
        if rule_hits_tracker(r):
            n_del_tracker += 1
            report(f"DELETE tracker allow: {r.get('process')} -> {remote_label(r)}"
                   f" ports={r.get('ports','any')} uses={r.get('useCount',0)}")
            continue

        # 4. monitor-origin, never used -> delete
        if r.get("origin") in ("monitor", "network monitor") and r.get("useCount", 0) == 0:
            n_del_monitor += 1
            report(f"DELETE monitor-unused: {r.get('process')} -> {remote_label(r)}")
            continue

        # 5. stale binary references -> delete
        if path_missing(r.get("process")) or path_missing(r.get("via")):
            n_del_stale += 1
            report(f"DELETE stale-binary: {r.get('process')}"
                   f"{' via ' + str(r.get('via')) if path_missing(r.get('via')) else ''}"
                   f" -> {remote_label(r)}")
            continue

        # 6. specific-host allow without port restriction -> tcp:443
        #    IP-literal rules only with the auto-conn-guard's own on-443
        #    evidence marker (D5-plain-on-443) — anything else could be a
        #    legit non-443 service (DNS/NTP/SSH/…) and must stay any-port
        if ((r.get("remote-hosts") or r.get("remote-domains")
                or (r.get("remote-addresses")
                    and "D5-plain-on-443" in str(r.get("notes", ""))))
                and not r.get("ports")
                and not r.get("disabled")
                and r.get("protocol", "any") not in ("udp", "icmp")):
            r = dict(r)
            r["ports"] = "443"
            r["protocol"] = "tcp"
            r["modificationDate"] = now
            n_tighten += 1
            report(f"TIGHTEN tcp:443: {r.get('process')} -> {remote_label(r)}")
            out.append(r)
            continue

        out.append(r)

    # 1. tracker/posture denies (skip if an equivalent deny already exists)
    n_add = 0
    for domain, why in DENY_DOMAINS.items():
        exists = any(r.get("action") == "deny"
                     and domain in str(r.get("remote-domains", ""))
                     for r in out)
        if exists:
            report(f"SKIP add-deny {domain}: deny already present")
            continue
        out.append({
            "action": "deny",
            "creationDate": now,
            "direction": "both",
            "modificationDate": now,
            "notes": "[AUDIT 2026-09-03] security rescan — " + why,
            "origin": "frontend",
            "process": "any",
            "remote-domains": domain,
        })
        n_add += 1
        report(f"ADD deny-any-process: {domain}  ({why})")

    model["rules"] = out
    if not guard_run("save-model", save_model, model, dst):
        sys.exit(1)

    summary = (f"Done. in={len(rules)} out={len(out)} | +{n_add} tracker denies, "
               f"-{n_del_tracker} tracker allows, -{n_del_sugg} any-remote suggestions, "
               f"-{n_del_monitor} monitor-unused, -{n_del_stale} stale-binary, "
               f"~{n_tighten} tightened to tcp:443")
    report(summary)

    text = "\n".join(REPORT_LINES) + "\n"
    if report_file:
        if not guard_run("write-report", write_report, report_file, text):
            sys.exit(1)
    print(summary)
    print(f"Report: {report_file or '(none)'} — {len(REPORT_LINES)} lines")


if __name__ == "__main__":
    main()
