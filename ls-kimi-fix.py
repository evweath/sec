#!/usr/bin/env python3
"""ls-kimi-fix.py — end the Kimi CLI (kimi.ai) approve-whack-a-mole loop.

Usage: python3 ls-kimi-fix.py <input-model.json> <output-model.json> [--report FILE]

Background (2026-10-02 incident): the Kimi Code CLI dials api.kimi.ai,
Cloudflare-fronted on rotating edge IPs (104.18.16.0/24 + 2606:4700::/32).
On 2026-09-03 mac-sentinel warned a com.apple.WebKit.Networking flow to
104.18.16.93:443 (user browsing kimi.ai) and ls-sentinel-deny.py planted an
ANY-PROCESS deny for that IP. Whenever DNS rotation hands the CLI that edge
IP (A or its 2606:4700::6812:105d/115d twins), Little Snitch silently denies
it — the CLI breaks, recovers on the next rotation, breaks again. The CLI's
existing allows are per-host Terminal/iTerm2 via-kimi rules for the OLD
endpoints (api.kimi.com, api.moonshot.ai, cdn.kimi.com, code.kimi.com); no
rule covers *.kimi.ai, and no rule covers the CLI when it runs detached
under tmux (responsible process = kimi itself, not a terminal).

Operations:
  1. RESOLVE the live IPs of the kimi endpoint family (plus a static seed
     set of observed edge IPs) and DELETE every [AUTO-EVW-LS] sentinel-deny
     rule whose remote-addresses are a subset of that set — shared-CDN
     per-IP whack-a-mole artifacts. ls-sentinel-deny.py now org-excludes
     Cloudflare for browser processes, so they stay gone.
  2. ADD one scoped allow per CLI process shape -> KIMI_DOMAINS tcp:443
     (skipped when an equivalent rule already exists — idempotent):
       - identifier.2J9472RW75/kimi            (direct; tmux/detached)
       - com.apple.Terminal via kimi           (matches existing rule family)
       - com.googlecode.iterm2 via kimi        (matches existing rule family)
     Process-scoped domain allows outrank the any-process per-IP denies, so
     future Cloudflare rotation can no longer break the CLI.
  2b. ADD per-host allows for the four kimi.com endpoints the via-rules
     already cover (api/cdn/code/auth) to the DIRECT kimi shape only. The
     whole kimi.com domain is deliberately NOT allowed: the any-process
     [AUDIT 2026-09-02] deny on telemetry-logs.kimi.com must keep matching
     the CLI.
  3. VERIFY invariants post-edit; aborts (no output written) if any fail:
       - factory/protected rule counts unchanged
       - every deleted rule is a sentinel-deny artifact inside the kimi IP set
       - a scoped kimi domain rule exists for every CLI process shape
       - the telemetry-logs.kimi.com any-process deny is still present

Undo: restore-model the ORIGINAL input model (kept untouched by design).
All other rules — deny, factory, protected — are never touched.
Python 3.9 compatible. Read-only except for the output/report files.
"""
import json, socket, sys
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
    from error_guard import guard_run, guard_main, guarded, SKIP, throw, GuardError
except ImportError:
    SKIP = object()
    def guard_run(_l, fn, *a, **kw): return fn(*a, **kw)
    def guard_main(_l, fn, *a, **kw): return fn(*a, **kw)
    def guarded(_l=None):
        def deco(fn): return fn
        return deco
    class GuardError(RuntimeError): pass
    def throw(msg): raise GuardError(str(msg))

TAG = "[AUTO-EVW-LS] sentinel-deny"
KIMI = "identifier.2J9472RW75/kimi"
TERMINAL = "identifier.APPLE/com.apple.Terminal"
ITERM2 = "identifier.H7V7XYVQ7D/com.googlecode.iterm2"

# (process, via) shapes the CLI's connections are attributed under
SHAPES = [(KIMI, None), (TERMINAL, KIMI), (ITERM2, KIMI)]

# whole domains safe to allow for the CLI: no deny rule exists beneath them
KIMI_DOMAINS = ["kimi.ai", "moonshot.ai", "moonshot.cn"]

# legacy endpoints, added per-host to the direct shape only — never the whole
# kimi.com domain (telemetry-logs.kimi.com any-process deny must keep biting)
KIMI_HOSTS_DIRECT = ["api.kimi.com", "cdn.kimi.com", "code.kimi.com",
                     "auth.kimi.com"]

TELEMETRY_DENY_DOMAIN = "telemetry-logs.kimi.com"

# domains resolved live to catch the current edge IPs of the family
RESOLVE_DOMAINS = (KIMI_DOMAINS + KIMI_HOSTS_DIRECT +
                   ["api.kimi.ai", "auth.kimi.ai", "platform.kimi.ai",
                    "www.kimi.ai", "notilo.kimi.ai", "statics.kimi.ai",
                    "api.moonshot.ai", "api.moonshot.cn"])

# observed kimi.ai edge IPs (sentinel-analysis + live connections 2026-10-02)
SEED_IPS = {"104.18.16.93", "104.18.17.93", "104.18.28.136", "101.47.6.99",
            "2606:4700::6812:1c88", "2606:4700::6812:105d",
            "2606:4700::6812:115d"}

NOTE = ("[ls-kimi-fix] scoped Kimi CLI access for {shape}: replaces per-IP "
        "sentinel artifacts on shared Cloudflare edges (2026-10-02)")

REPORT_LINES = []

def report(msg):
    REPORT_LINES.append(msg)

def as_list(v):
    if v is None:
        return []
    return list(v) if isinstance(v, list) else [v]

def resolve_ips():
    ips = set(SEED_IPS)
    for d in RESOLVE_DOMAINS:
        try:
            for fam, _, _, _, sa in socket.getaddrinfo(d, 443):
                if fam in (socket.AF_INET, socket.AF_INET6):
                    ips.add(sa[0])
        except socket.gaierror:
            report("RESOLVE failed (skipped): " + d)
    return ips

def is_kimi_sentinel(r, kimi_ips):
    if not str(r.get("notes", "")).startswith(TAG):
        return False
    addrs = set(as_list(r.get("remote-addresses")))
    return bool(addrs) and addrs <= kimi_ips

def shape_match(r, proc, via):
    if r.get("process") != proc:
        return False
    return (r.get("via") or None) == via

def covers_domains(r, proc, via):
    if r.get("action") != "allow" or not shape_match(r, proc, via):
        return False
    return set(KIMI_DOMAINS) <= set(as_list(r.get("remote-domains")))

def covers_host(r, proc, host):
    if r.get("action") != "allow" or not shape_match(r, proc, None):
        return False
    return host in as_list(r.get("remote-hosts"))

def is_any_proc_telemetry_deny(r):
    if r.get("action") != "deny":
        return False
    if str(r.get("process", "any")) != "any":
        return False
    return TELEMETRY_DENY_DOMAIN in as_list(r.get("remote-domains"))

def main():
    if len(sys.argv) < 3:
        throw("usage: ls-kimi-fix.py <in.json> <out.json> [--report FILE]")
    src, dst = sys.argv[1], sys.argv[2]
    rpt = sys.argv[sys.argv.index("--report") + 1] if "--report" in sys.argv else None

    model = json.load(open(src))
    rules = model.get("rules", [])
    n_factory = sum(1 for r in rules if r.get("origin") == "factory")
    n_protected = sum(1 for r in rules if r.get("protected"))

    # 1. delete sentinel-deny artifacts on kimi edge IPs
    kimi_ips = resolve_ips()
    report("RESOLVE kimi endpoint family -> {} IPs".format(len(kimi_ips)))
    doomed = [r for r in rules if is_kimi_sentinel(r, kimi_ips)]
    kept = [r for r in rules if not is_kimi_sentinel(r, kimi_ips)]
    report("DELETE {} sentinel-deny artifacts on kimi edge IPs".format(len(doomed)))
    for r in doomed:
        report("  - {} {} {}".format(r.get("action"),
               r.get("remote-addresses"), str(r.get("notes", ""))[:110]))

    # 2. add scoped domain allow per CLI process shape (idempotent)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    added = 0
    for proc, via in SHAPES:
        shape = proc + (" via " + via if via else "")
        if any(covers_domains(r, proc, via) for r in kept):
            report("ADD skipped: {} kimi domain allow already present".format(shape))
            continue
        rule = {
            "action": "allow",
            "approved": True,
            "creationDate": now,
            "modificationDate": now,
            "notes": NOTE.format(shape=shape),
            "origin": "frontend",
            "ports": "443",
            "process": proc,
            "protocol": "tcp",
            "remote-domains": KIMI_DOMAINS,
        }
        if via:
            rule["via"] = via
        kept.append(rule)
        added += 1
        report("ADD allow {} -> {} tcp:443".format(shape, ",".join(KIMI_DOMAINS)))

    # 2b. per-host legacy endpoints on the direct shape only
    for host in KIMI_HOSTS_DIRECT:
        if any(covers_host(r, KIMI, host) for r in kept):
            report("ADD skipped: kimi -> {} host allow already present".format(host))
            continue
        kept.append({
            "action": "allow",
            "approved": True,
            "creationDate": now,
            "modificationDate": now,
            "notes": NOTE.format(shape=KIMI),
            "origin": "frontend",
            "ports": "443",
            "process": KIMI,
            "protocol": "tcp",
            "remote-hosts": host,
        })
        added += 1
        report("ADD allow {} -> {} tcp:443".format(KIMI, host))

    # 3. verify invariants
    if sum(1 for r in kept if r.get("origin") == "factory") != n_factory:
        throw("VERIFY failed: factory rule count changed")
    if sum(1 for r in kept if r.get("protected")) != n_protected:
        throw("VERIFY failed: protected rule count changed")
    if any(is_kimi_sentinel(r, kimi_ips) for r in kept):
        throw("VERIFY failed: kimi sentinel artifact survived")
    for proc, via in SHAPES:
        if not any(covers_domains(r, proc, via) for r in kept):
            throw("VERIFY failed: scoped kimi rule missing for " + proc)
    if not any(is_any_proc_telemetry_deny(r) for r in kept):
        throw("VERIFY failed: telemetry-logs.kimi.com any-process deny missing")

    model["rules"] = kept
    json.dump(model, open(dst, "w"), indent=2)
    report("SUMMARY: deleted={} added={} rules {} -> {}".format(
        len(doomed), added, len(rules), len(kept)))
    text = "\n".join(REPORT_LINES) + "\n"
    if rpt:
        open(rpt, "w").write(text)
    print(REPORT_LINES[-1])

if __name__ == "__main__":
    guard_main("ls-kimi-fix", main)
