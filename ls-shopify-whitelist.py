#!/usr/bin/env python3
"""ls-shopify-whitelist.py — end the shopify approve-whack-a-mole loop in Little Snitch.

Usage: python3 ls-shopify-whitelist.py <input-model.json> <output-model.json> [--report FILE]

Background (2026-09-18): Shopify's storefront/admin traffic runs through
com.apple.WebKit.Networking. Shopify serves all shops from the same anycast
IPs (23.227.32.0/20, 2620:127:f00::/48), so every new shop/session warned in
the mac-sentinel feed and ls-sentinel-deny.py planted an any-process deny per
IP:443; alert-UI approvals then flipped some to any-process allows — leaving
CONFLICTING allow+deny pairs on the same endpoints (deny wins, shopify breaks
again). 10 such stale rules had accumulated on just 4 IPs.

Operations:
  1. DELETE every [AUTO-EVW-LS] sentinel-deny rule (allow or deny) whose note
     references a Shopify endpoint — per-IP whack-a-mole artifacts.
     ls-sentinel-deny.py now org-excludes "Shopify", so they stay gone.
  1b. DELETE every sentinel-deny rule (allow or deny) whose note carries a
     bc.googleusercontent.com PTR — GCP load-balancer front-end artifacts
     (2026-09-22: admin.shopify.com moved onto GCP LB IP 34.128.177.21 and
     the surviving any-process deny for that IP kept blocking it; these
     front-end IPs are shared by arbitrary sites, like any CDN).
     ls-sentinel-deny.py now excludes (Google LLC, browser processes) via
     EXCLUDED_ORG_PROCS, so they stay gone.
  2. TIGHTEN any [AUTO-EVW] auto-conn-guard IP allow whose note carries the
     guard's own "D5-plain-on-443" evidence (connection observed on 443) to
     tcp:443 — e.g. the 23.227.39.200 Shopify any-port allow.
  3. ADD one scoped allow per browser process -> SHOPIFY_DOMAINS tcp:443
     (skipped when an equivalent rule already exists — idempotent):
       - com.apple.WebKit.Networking (WebKit content traffic)
       - com.brave.Browser (2026-09-21: Brave carries a catch-all
         "deny -> anywhere" rule — per-site-approval posture — and its
         traffic never touches WebKit.Networking, so the WebKit-only allow
         left Shopify dead in Brave. A domain-scoped allow beats the
         process-wide any-address deny; the catch-all stays in place.)
       - com.apple.Safari (2026-09-22: on macOS 26 Little Snitch attributes
         most Safari flows to the Safari app process, not WebKit.Networking —
         43 alert-approved per-host shopify rules had accumulated for Safari)
  4. DELETE alert-origin com.apple.Safari allow rules whose remote-hosts is a
     single host under SHOPIFY_DOMAINS tcp:443 — per-host approve-loop
     sprawl, fully covered by the step-3 Safari domain rule. Non-shopify
     hosts (klaviyo.com, storage.googleapis.com, …) are never touched.
  5. VERIFY invariants post-edit; aborts (no output written) if any fail:
       - factory/protected rule counts unchanged
       - no Shopify or GCP-LB sentinel rule survives
       - a scoped shopify domain rule exists for every SCOPED_PROCS process
       - the scoped WebKit gmail/github domain rules are still present

All other rules — deny (incl. the Brave catch-all), factory, protected,
process-scoped shopify allows (python3, iterm2) — are never touched.
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
ORG_MARKER = "Shopify"
GCP_PTR_MARKER = "bc.googleusercontent.com"
WEBKIT = "identifier.APPLE/com.apple.WebKit.Networking"
BRAVE = "identifier.KL8N8XSYF4/com.brave.Browser"
SAFARI = "identifier.APPLE/com.apple.Safari"

# browser processes that need the scoped shopify allow (see docstring step 3)
SCOPED_PROCS = [WEBKIT, BRAVE, SAFARI]

ALERT_ORIGINS = {"alert", "alertTimeout"}

# domains the shopify workflow in a browser actually needs: admin/storefront,
# shop checkouts, CDN/assets, app services, CLI/backend endpoints, Shop app
SHOPIFY_DOMAINS = ["shopify.com", "myshopify.com", "shopifycdn.com",
                   "shopifysvc.com", "shopifyapps.com", "shopifycloud.com",
                   "shopifyinc.com", "shop.app"]

NOTE = ("[ls-shopify-whitelist] scoped shopify access for {proc}: replaces "
        "per-IP sentinel rules (2026-09-18; Brave scope 2026-09-21)")

REPORT_LINES = []

def report(msg):
    REPORT_LINES.append(msg)

def is_shopify_sentinel(r):
    n = str(r.get("notes", ""))
    return n.startswith(TAG) and ORG_MARKER in n

def is_gcp_lb_sentinel(r):
    n = str(r.get("notes", ""))
    return n.startswith(TAG) and GCP_PTR_MARKER in n

def host_under(host, doms):
    h = (host or "").lower().rstrip(".")
    return any(h == d or h.endswith("." + d) for d in doms)

def is_safari_shopify_host_rule(r):
    if (r.get("action") != "allow" or r.get("process") != SAFARI
            or r.get("origin") not in ALERT_ORIGINS
            or str(r.get("ports", "")) not in ("443", "")):
        return False
    hosts = r.get("remote-hosts")
    if isinstance(hosts, list):
        return len(hosts) == 1 and host_under(hosts[0], SHOPIFY_DOMAINS)
    return host_under(str(hosts or ""), SHOPIFY_DOMAINS)

def covers_shopify(r, proc):
    if r.get("action") != "allow" or r.get("process") != proc:
        return False
    doms = set(r.get("remote-domains") or [])
    return set(SHOPIFY_DOMAINS) <= doms

def main():
    if len(sys.argv) < 3:
        throw("usage: ls-shopify-whitelist.py <in.json> <out.json> [--report FILE]")
    src, dst = sys.argv[1], sys.argv[2]
    rpt = sys.argv[sys.argv.index("--report") + 1] if "--report" in sys.argv else None

    model = json.load(open(src))
    rules = model.get("rules", [])
    n_factory = sum(1 for r in rules if r.get("origin") == "factory")
    n_protected = sum(1 for r in rules if r.get("protected"))

    # 1. delete shopify sentinel rules (any action)
    doomed = [r for r in rules if is_shopify_sentinel(r)]
    kept = [r for r in rules if not is_shopify_sentinel(r)]
    n_allow = sum(1 for r in doomed if r.get("action") == "allow")
    n_deny = sum(1 for r in doomed if r.get("action") == "deny")
    report("DELETE {} sentinel-deny shopify rules (allow={}, deny={})".format(
        len(doomed), n_allow, n_deny))
    for r in doomed:
        report("  - {} {} {}".format(r.get("action"),
               r.get("remote-addresses"), str(r.get("notes", ""))[:110]))

    # 1b. delete GCP load-balancer sentinel rules (any action) — the active
    #     admin.shopify.com block lives here (34.128.177.21 deny+allow pair)
    gcp = [r for r in kept if is_gcp_lb_sentinel(r)]
    kept = [r for r in kept if not is_gcp_lb_sentinel(r)]
    report("DELETE {} sentinel-deny GCP-LB rules (allow={}, deny={})".format(
        len(gcp),
        sum(1 for r in gcp if r.get("action") == "allow"),
        sum(1 for r in gcp if r.get("action") == "deny")))
    for r in gcp:
        report("  - {} {} {}".format(r.get("action"),
               r.get("remote-addresses"), str(r.get("notes", ""))[:110]))
    doomed = doomed + gcp

    # 2. tighten auto-conn-guard IP allows with on-443 evidence -> tcp:443
    #    (guard's own D5 marker proves the connection runs on 443, so the
    #    any-port grant loses nothing — e.g. the 23.227.39.200 Shopify rule)
    n_tighten = 0
    tightened = []
    for r in kept:
        if (r.get("action") == "allow"
                and str(r.get("notes", "")).startswith("[AUTO-EVW] auto-")
                and "D5-plain-on-443" in str(r.get("notes", ""))
                and r.get("remote-addresses")
                and not r.get("ports")
                and not r.get("disabled")):
            r = dict(r)
            r["ports"] = "443"
            r["protocol"] = "tcp"
            r["modificationDate"] = datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ")
            n_tighten += 1
            report("TIGHTEN tcp:443: any -> {} ({})".format(
                r.get("remote-addresses"), str(r.get("notes", ""))[:90]))
        tightened.append(r)
    kept = tightened

    # 3. add scoped shopify allow per browser process (idempotent)
    added = 0
    for proc in SCOPED_PROCS:
        if any(covers_shopify(r, proc) for r in kept):
            report("ADD skipped: {} shopify domain allow already present"
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
            "remote-domains": SHOPIFY_DOMAINS,
        })
        added += 1
        report("ADD allow {} -> {} tcp:443".format(proc, ",".join(SHOPIFY_DOMAINS)))

    # 4. collapse alert-origin Safari per-host shopify allows (covered by
    #    the step-3 Safari domain rule)
    host_rules = [r for r in kept if is_safari_shopify_host_rule(r)]
    kept = [r for r in kept if not is_safari_shopify_host_rule(r)]
    report("DELETE {} Safari per-host shopify allows (covered by domain rule)"
           .format(len(host_rules)))
    for r in host_rules:
        report("  - allow {} :{}".format(r.get("remote-hosts"), r.get("ports")))
    doomed = doomed + host_rules

    # 5. verify invariants
    if sum(1 for r in kept if r.get("origin") == "factory") != n_factory:
        throw("VERIFY failed: factory rule count changed")
    if sum(1 for r in kept if r.get("protected")) != n_protected:
        throw("VERIFY failed: protected rule count changed")
    if any(is_shopify_sentinel(r) for r in kept):
        throw("VERIFY failed: shopify sentinel rule survived")
    if any(is_gcp_lb_sentinel(r) for r in kept):
        throw("VERIFY failed: GCP-LB sentinel rule survived")
    for proc in SCOPED_PROCS:
        if not any(covers_shopify(r, proc) for r in kept):
            throw("VERIFY failed: scoped shopify rule missing for " + proc)
    gm = [r for r in kept if r.get("process") == WEBKIT
          and "gmail.com" in (r.get("remote-domains") or [])]
    if not gm:
        throw("VERIFY failed: scoped WebKit gmail rule missing")
    gk = [r for r in kept if r.get("process") == WEBKIT
          and "github.com" in (r.get("remote-domains") or [])]
    if not gk:
        throw("VERIFY failed: scoped WebKit github rule missing")

    model["rules"] = kept
    json.dump(model, open(dst, "w"), indent=2)
    report("SUMMARY: deleted={} tightened={} added={} rules {} -> {}".format(
        len(doomed), n_tighten, added, len(rules), len(kept)))
    text = "\n".join(REPORT_LINES) + "\n"
    if rpt:
        open(rpt, "w").write(text)
    print(REPORT_LINES[-1])

if __name__ == "__main__":
    guard_run("ls-shopify-whitelist", main)
