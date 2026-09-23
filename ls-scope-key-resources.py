#!/usr/bin/env python3
"""Scope key resources in a Little Snitch rules model ("option 1" hardening).

Replaces unscoped `<ANY PROCESS> -> <literal IP>` allow rules with
process+domain rules pinned to code-signed processes and tcp:443, so the
channels to key resources (GitHub, Kimi/Moonshot) stay open for the tools
that legitimately use them — and for nothing else.

Usage: python3 ls-scope-key-resources.py <input-model.json> <output-model.json> [--report report.txt]

Edits performed:
  1. ADD   process+domain tcp:443 rules for the scoped tool set below
           (skipped where an equivalent rule already exists — idempotent).
  2. DELETE allow rules that match ALL of: no `process` key, has
           `remote-addresses` (literal IPs), not protected, origin != factory.
           Factory/protected any-process rules (loopback, Apple services,
           local-net, ICMP) are never touched.
  3. DELETE deny rules auto-created by ls-sentinel-deny.py for GitHub
           endpoints (tagged "[AUTO-EVW-LS] sentinel-deny") — the sentinel
           re-adds one per GitHub IP and they override the scoped allows;
           GitHub is org-excluded in ls-sentinel-deny.py so they stay gone.
  4. VERIFY invariants post-edit; aborts (no output written) if any fail:
           - deny count drops by exactly the number of sentinel-GitHub denies
           - protected-rule count unchanged
           - guarded daemons still deny-only
           - factory Apple-services rule (factoryID 421) and the protected
             loopback rule still present

Expected re-alerts after apply (one-time, alert mode): `gh` (unsigned
Homebrew binary — intentionally not pre-scoped), itunescloudd/App Store/geod
against CDN IPs, and the long-lived nonbrowser Shopify connection. Answer
with process + domain + port 443, Forever.
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

GITHUB_DOMAINS = ["github.com", "githubusercontent.com", "githubassets.com",
                  "githubcopilot.com", "ghcr.io", "github.dev", "githubapp.com"]
KIMI_DOMAINS = ["moonshot.cn", "kimi.link"]

# (process identifier as LS sees it, domain set, why it belongs)
SCOPED_RULES = [
    ("identifier.APPLE/com.apple.WebKit.Networking", GITHUB_DOMAINS,
     "Safari/WebKit renderer networking — main consumer of the deleted GitHub-IP rules"),
    ("identifier.APPLE/com.apple.Safari", GITHUB_DOMAINS, "Safari app proper"),
    ("identifier.59GAB85EFG/com.apple.git-remote-http", GITHUB_DOMAINS,
     "git clone/push over HTTPS (CLT + Xcode transport, verified code identifier)"),
    ("identifier.APPLE/com.apple.Terminal", GITHUB_DOMAINS,
     "CLI children LS attributes to Terminal (same posture as existing Terminal->moonshot rule)"),
    ("identifier.APPLE/com.apple.curl", GITHUB_DOMAINS,
     "Apple-signed curl — dev/API calls to github (sentinel saw curl->140.82.x repeatedly)"),
    ("identifier.APPLE/com.apple.WebKit.Networking", KIMI_DOMAINS,
     "Kimi web app/CDN — replaces deleted Alibaba-IP rules"),
]

SENTINEL_TAG = "[AUTO-EVW-LS] sentinel-deny"


def is_sentinel_github_deny(r):
    """Deny rules auto-created by ls-sentinel-deny.py for GitHub endpoints.

    These fight the scoped allows above: the sentinel re-adds one per new
    GitHub IP seen in the alert feed, and the IP-specific deny beats the
    domain-scoped allow for any process not covered process-specifically.
    Only sentinel-tagged rules mentioning GitHub are eligible — user- or
    alert-created denies are never touched by this pass.
    """
    return (r.get("action") == "deny"
            and str(r.get("notes", "")).startswith(SENTINEL_TAG)
            and "github" in str(r.get("notes", "")).lower())

GUARDED = ["replayd", "remotemanagementd", "screensharingd", "ardagent", "studentd",
           "sharingd", "identityservicesd", "replicatord", "privatecloudcomputed",
           "wifivelocityd", "searchpartyuseragent"]

NOTE = "[ls-scope-key-resources] option-1 scoping: replaces any-process IP allow (2026-09-15)"
MAX_DELETIONS = 200  # sanity: 34 expected at authoring time


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def is_unscoped_ip_allow(r):
    return (r.get("action") == "allow"
            and "process" not in r
            and r.get("remote-addresses")
            and not r.get("protected")
            and r.get("origin") != "factory")


def domain_rule_covers(r, process, domains):
    return (r.get("action") == "allow"
            and r.get("process") == process
            and r.get("protocol") == "tcp"
            and str(r.get("ports")) == "443"
            and set(domains) <= set(r.get("remote-domains") or []))


def make_rule(process, domains):
    ts = now_iso()
    return {"action": "allow",
            "creationDate": ts,
            "modificationDate": ts,
            "notes": NOTE,
            "origin": "frontend",
            "ports": "443",
            "process": process,
            "protocol": "tcp",
            "remote-domains": list(domains)}


def check_invariants(before, after, removed_denies):
    def counts(rules):
        return (sum(1 for r in rules if r.get("action") == "deny"),
                sum(1 for r in rules if r.get("protected")))
    deny_before, prot_before = counts(before)
    deny_after, prot_after = counts(after)
    if deny_before - deny_after != removed_denies:
        throw(f"invariant violated: deny count moved {deny_before}->{deny_after}, "
              f"expected exactly {removed_denies} removed")
    if prot_before != prot_after:
        throw("invariant violated: protected rule count changed")
    for g in GUARDED:
        allows = [r for r in after if r.get("action") == "allow" and g in json.dumps(r)]
        denies_before = sum(1 for r in before if r.get("action") == "deny" and g in json.dumps(r))
        denies_after = sum(1 for r in after if r.get("action") == "deny" and g in json.dumps(r))
        if allows or denies_after < denies_before:
            throw(f"invariant violated: guarded process {g} allow={len(allows)} "
                  f"deny {denies_before}->{denies_after}")
    if not any(r.get("factoryID") == 421 and r.get("protected") for r in after):
        throw("invariant violated: factory Apple-services rule (421) missing")
    if not any(r.get("protected") and r.get("remote-addresses") == "0.0.0.0, 127.0.0.1, ::0-::1" for r in after):
        throw("invariant violated: protected loopback rule missing")


@guarded("ls-scope-key-resources")
def main():
    argv = sys.argv[1:]
    report_path = None
    if "--report" in argv:
        i = argv.index("--report")
        report_path = argv[i + 1]
        del argv[i:i + 2]
    if len(argv) != 2:
        throw("usage: ls-scope-key-resources.py <in.json> <out.json> [--report path]")
    args = argv

    model = json.load(open(args[0]))
    rules = model.get("rules")
    if not isinstance(rules, list):
        throw("input has no rules list — not an LS model export")
    before = list(rules)

    added, skipped_existing, deleted = [], [], []

    for process, domains, why in SCOPED_RULES:
        if any(domain_rule_covers(r, process, domains) for r in rules):
            skipped_existing.append((process, domains))
            continue
        rules.append(make_rule(process, domains))
        added.append((process, domains, why))

    victims = [r for r in rules if is_unscoped_ip_allow(r)]
    if len(victims) > MAX_DELETIONS:
        throw(f"refusing to delete {len(victims)} rules (cap {MAX_DELETIONS}) — inspect manually")
    gh_denies = [r for r in rules if is_sentinel_github_deny(r)]
    drop = {id(r) for r in victims} | {id(r) for r in gh_denies}
    rules[:] = [r for r in rules if id(r) not in drop]
    deleted = victims

    check_invariants(before, rules, len(gh_denies))

    json.dump(model, open(args[1], "w"), indent=1)

    lines = []
    lines.append("LS SCOPE KEY RESOURCES — option-1 hardening report")
    lines.append(f"input rules : {len(before)}")
    lines.append(f"output rules: {len(rules)}  (+{len(added)} scoped, -{len(deleted)} unscoped IP allows)")
    lines.append("")
    lines.append(f"ADDED process+domain tcp:443 rules ({len(added)}):")
    for process, domains, why in added:
        lines.append(f"  + {process}")
        lines.append(f"      -> {', '.join(domains)}")
        lines.append(f"      ({why})")
    for process, domains in skipped_existing:
        lines.append(f"  = already covered, skipped: {process} -> {', '.join(domains)}")
    lines.append("")
    lines.append(f"DELETED any-process -> literal-IP allow rules ({len(deleted)}):")
    for r in deleted:
        note = (r.get("notes") or "").replace("\n", " ")
        tag = note.split("sentinel-deny: ")[-1][:70] if "sentinel-deny: " in note else note[:70]
        lines.append(f"  - {r.get('remote-addresses')[:44]:46} ports={r.get('ports', 'any'):4} "
                     f"uses={r.get('useCount', 0):7} {tag}")
    lines.append("")
    lines.append(f"DELETED sentinel-created GitHub deny rules ({len(gh_denies)}) "
                 "— these were re-created per GitHub IP by ls-sentinel-deny.py and "
                 "overrode the scoped allows; GitHub is now org-excluded in the sentinel:")
    for r in gh_denies:
        lines.append(f"  - deny any -> {r.get('remote-addresses')}:{r.get('ports', 'any')} "
                     f"uses={r.get('useCount', 0)}")
    lines.append("")
    lines.append("UNTOUCHED (by design): all other deny rules, all protected/factory rules "
                 "(loopback, Apple services umbrella, local-net, ICMP ping, appGroup.macOS), "
                 "and any user/alert-created GitHub denies.")
    lines.append("EXPECTED ONE-TIME RE-ALERTS after apply: gh (unsigned — choose domain "
                 "github.com, tcp 443, Forever), itunescloudd/App Store/geod CDN fetches, "
                 "the long-lived nonbrowser Shopify connection (23.227.39.20), and incidental "
                 "WebKit fetches (Cloudflare/Google/DATACAMP IPs). Answer process+domain+443.")
    report = "\n".join(lines) + "\n"
    if report_path:
        with open(report_path, "w") as f:
            f.write(report)
    print(report)


if __name__ == "__main__":
    main()
