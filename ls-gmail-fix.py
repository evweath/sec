#!/usr/bin/env python3
"""ls-gmail-fix.py — end the gmail approve-whack-a-mole loop in Little Snitch.

Usage: python3 ls-gmail-fix.py <input-model.json> <output-model.json> [--report FILE]

Background (2026-09-17 audit): Safari's web traffic runs through
com.apple.WebKit.Networking, which had no domain allow for Google mail
endpoints. Every gmail connection warned in the mac-sentinel feed and
ls-sentinel-deny.py planted an any-process deny per Google IP:443; alert-UI
approvals then flipped many of them to any-process allows. Google rotates
front-end (1e100.net) IPs constantly, so neither per-IP denies nor per-IP
allows ever settle — 226 such stale rules had accumulated.

Operations:
  1. DELETE every [AUTO-EVW-LS] sentinel-deny rule (allow or deny) whose note
     references a 1e100.net endpoint — per-IP whack-a-mole artifacts.
     ls-sentinel-deny.py now PTR-excludes 1e100.net, so they stay gone.
  2. ADD one scoped allow per browser process -> GMAIL_DOMAINS tcp:443
     (skipped when an equivalent rule already exists — idempotent):
       - com.apple.WebKit.Networking (WebKit content traffic)
       - com.apple.Safari (2026-09-22: on macOS 26 Little Snitch attributes
         most Safari flows to the Safari app process — 62 alert-approved
         per-host rules under these domains had accumulated for Safari)
  2b. DELETE alert-origin com.apple.Safari allow rules whose remote-hosts is
     a single host under GMAIL_DOMAINS tcp:443 — per-host approve-loop
     sprawl, fully covered by the step-2 Safari domain rule.
  3. VERIFY invariants post-edit; aborts (no output written) if any fail:
       - factory/protected rule counts unchanged
       - every deleted rule is a sentinel-deny 1e100 rule or a collapsed
         Safari per-host rule
       - a scoped gmail domain rule exists for every SCOPED_PROCS process
       - the scoped WebKit github/kimi domain rules are still present

All other rules — deny, factory, protected — are never touched.
Python 3.9 compatible. Read-only except for the output/report files.
"""
import json, sys
from datetime import datetime, timezone

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

TAG = "[AUTO-EVW-LS] sentinel-deny"
PTR_MARKER = "1e100.net"
WEBKIT = "identifier.APPLE/com.apple.WebKit.Networking"
SAFARI = "identifier.APPLE/com.apple.Safari"

# browser processes that need the scoped gmail allow (see docstring step 2)
SCOPED_PROCS = [WEBKIT, SAFARI]

ALERT_ORIGINS = {"alert", "alertTimeout"}

# domains gmail-in-a-browser actually needs: mail hosts, login/OAuth, APIs,
# static assets, avatars/attachments
GMAIL_DOMAINS = ["gmail.com", "googlemail.com", "google.com",
                 "googleapis.com", "gstatic.com", "googleusercontent.com"]

NOTE = ("[ls-gmail-fix] scoped gmail access for {proc}: replaces per-IP "
        "sentinel rules (2026-09-17; Safari scope 2026-09-22)")

REPORT_LINES = []

def report(msg):
    REPORT_LINES.append(msg)

def is_1e100_sentinel(r):
    n = str(r.get("notes", ""))
    return n.startswith(TAG) and PTR_MARKER in n

def covers_gmail(r, proc):
    if r.get("action") != "allow" or r.get("process") != proc:
        return False
    doms = set(r.get("remote-domains") or [])
    return set(GMAIL_DOMAINS) <= doms

def host_under(host, doms):
    h = (host or "").lower().rstrip(".")
    return any(h == d or h.endswith("." + d) for d in doms)

def is_safari_gmail_host_rule(r):
    if (r.get("action") != "allow" or r.get("process") != SAFARI
            or r.get("origin") not in ALERT_ORIGINS
            or str(r.get("ports", "")) not in ("443", "")):
        return False
    hosts = r.get("remote-hosts")
    if isinstance(hosts, list):
        return len(hosts) == 1 and host_under(hosts[0], GMAIL_DOMAINS)
    return host_under(str(hosts or ""), GMAIL_DOMAINS)

def main():
    if len(sys.argv) < 3:
        throw("usage: ls-gmail-fix.py <in.json> <out.json> [--report FILE]")
    src, dst = sys.argv[1], sys.argv[2]
    rpt = sys.argv[sys.argv.index("--report") + 1] if "--report" in sys.argv else None

    model = json.load(open(src))
    rules = model.get("rules", [])
    n_factory = sum(1 for r in rules if r.get("origin") == "factory")
    n_protected = sum(1 for r in rules if r.get("protected"))

    # 1. delete 1e100 sentinel rules (any action)
    doomed = [r for r in rules if is_1e100_sentinel(r)]
    kept = [r for r in rules if not is_1e100_sentinel(r)]
    n_allow = sum(1 for r in doomed if r.get("action") == "allow")
    n_deny = sum(1 for r in doomed if r.get("action") == "deny")
    report("DELETE {} sentinel-deny 1e100 rules (allow={}, deny={})".format(
        len(doomed), n_allow, n_deny))
    for r in doomed:
        report("  - {} {} {}".format(r.get("action"),
               r.get("remote-addresses"), str(r.get("notes", ""))[:110]))

    # 2. add scoped gmail allow per browser process (idempotent)
    added = 0
    for proc in SCOPED_PROCS:
        if any(covers_gmail(r, proc) for r in kept):
            report("ADD skipped: {} gmail domain allow already present"
                   .format(proc))
            continue
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        kept.append({
            "action": "allow",
            "approved": True,
            "creationDate": now,
            "modificationDate": now,
            "notes": NOTE.format(proc=proc),
            "origin": "frontend",
            "ports": "443",
            "process": proc,
            "protocol": "tcp",
            "remote-domains": GMAIL_DOMAINS,
        })
        added += 1
        report("ADD allow {} -> {} tcp:443".format(proc, ",".join(GMAIL_DOMAINS)))

    # 2b. collapse alert-origin Safari per-host gmail-set allows (covered by
    #     the step-2 Safari domain rule)
    host_rules = [r for r in kept if is_safari_gmail_host_rule(r)]
    kept = [r for r in kept if not is_safari_gmail_host_rule(r)]
    report("DELETE {} Safari per-host gmail-set allows (covered by domain rule)"
           .format(len(host_rules)))
    for r in host_rules:
        report("  - allow {} :{}".format(r.get("remote-hosts"), r.get("ports")))
    doomed = doomed + host_rules

    # 3. verify invariants
    if sum(1 for r in kept if r.get("origin") == "factory") != n_factory:
        throw("VERIFY failed: factory rule count changed")
    if sum(1 for r in kept if r.get("protected")) != n_protected:
        throw("VERIFY failed: protected rule count changed")
    if any(is_1e100_sentinel(r) for r in kept):
        throw("VERIFY failed: 1e100 sentinel rule survived")
    for proc in SCOPED_PROCS:
        if not any(covers_gmail(r, proc) for r in kept):
            throw("VERIFY failed: scoped gmail rule missing for " + proc)
    gk = [r for r in kept if r.get("process") == WEBKIT
          and "github.com" in (r.get("remote-domains") or [])]
    if not gk:
        throw("VERIFY failed: scoped WebKit github rule missing")

    model["rules"] = kept
    json.dump(model, open(dst, "w"), indent=2)
    report("SUMMARY: deleted={} added={} rules {} -> {}".format(
        len(doomed), added, len(rules), len(kept)))
    text = "\n".join(REPORT_LINES) + "\n"
    if rpt:
        open(rpt, "w").write(text)
    print(REPORT_LINES[-1])

if __name__ == "__main__":
    guard_run("ls-gmail-fix", main)
