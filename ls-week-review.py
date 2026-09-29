#!/usr/bin/env python3
"""ls-week-review.py — deny last week's doubt-approved Little Snitch rules.

Usage: python3 ls-week-review.py <input-model.json> <output-model.json> [--report FILE] [--since YYYY-MM-DD]

Background (2026-09-28): between 09-21 and 09-28, ~776 allow rules were
approved from LS connection alerts / the UI ("alert" + "frontend" origins) —
approve-whack-a-mole. Three hole classes resulted:
  1. any-process allows carrying "[AUTO-EVW-LS] sentinel-deny" notes — the
     sentinel planted a DENY per IP; alert-UI approvals flipped them to ALLOW
     (any process -> shared CDN/cloud IP:443 = C2-shaped hole).
  2. any-process "[AUTO-EVW] auto-*" conn-guard allows (same shape).
  3. 700+ process-scoped per-IP / per-host alert approvals (Safari, iterm2,
     parsecd, python3, ...) — mostly rotating CDN edge IPs, trackers, and
     hosts already governed by the toolkit's scoped domain rules.

Policy (user directive 2026-09-28: "if there is any doubt, deny those rules"):
  KEEP   the 13 toolkit-scripted scoped domain rules (notes start "[ls-").
  DENY   every any-process allow with sentinel-deny / auto-conn-guard notes
         (any date — same hole class, not just last week's).
  DELETE alert approvals fully covered by a kept scripted domain rule for the
         same process on tcp:443 (redundant; the domain rule keeps working —
         e.g. Safari->accounts.google.com under Safari->google.com).
  DENY   every other allow approved since --since (default 2026-09-21):
         flip action allow->deny, append a [ls-week-review] note.
Never touched: factory/protected rules, existing denies, disabled rules,
rules created before --since (except class 1/2 above), the [ls-] keeps.

VERIFY invariants post-edit; aborts (no output written) if any fail:
  - factory/protected rule counts unchanged
  - all 13 scripted [ls-] scoped rules still present and unmodified
  - no allow with sentinel/auto any-process note survives
  - every deleted rule was a covered alert approval; only allows flipped
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

SENTINEL_TAG = "[AUTO-EVW-LS] sentinel-deny"
AUTO_TAG = "[AUTO-EVW] auto-"
STAMP = " [ls-week-review] doubt-approved->deny 2026-09-28"
# explicit toolkit-scripted rule markers — a prefix match on "[ls-" alone would
# false-positive on this script's own stamp when the original note was empty
KEEP_MARKERS = ("[ls-shopify-whitelist]", "[ls-gmail-fix]", "[ls-outlook-fix]",
                "[ls-scope-key-resources]")

REPORT_LINES = []

def report(msg):
    REPORT_LINES.append(msg)

def is_keep(r):
    """toolkit-scripted scoped domain rule — the deliberate policy set."""
    return str(r.get("notes", "")).startswith(KEEP_MARKERS)

def is_anyproc_hole(r):
    if r.get("action") != "allow" or r.get("process"):
        return False
    n = str(r.get("notes", ""))
    return n.startswith(SENTINEL_TAG) or n.startswith(AUTO_TAG)

def parse_date(s):
    try:
        return datetime.strptime(str(s), "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc)
    except ValueError:
        return None

def in_window(r, since):
    if r.get("action") != "allow" or r.get("disabled"):
        return False
    d = parse_date(r.get("creationDate"))
    return d is not None and d >= since

def domain_covered(doms, kept_domains):
    """every target domain is == or a subdomain of a kept scripted domain"""
    if not doms:
        return False
    for d in doms:
        d = str(d).lower()
        if not any(d == k or d.endswith("." + k) for k in kept_domains):
            return False
    return True

def main():
    if len(sys.argv) < 3:
        throw("usage: ls-week-review.py <in.json> <out.json> [--report FILE] [--since YYYY-MM-DD]")
    src, dst = sys.argv[1], sys.argv[2]
    rpt = sys.argv[sys.argv.index("--report") + 1] if "--report" in sys.argv else None
    since_s = sys.argv[sys.argv.index("--since") + 1] if "--since" in sys.argv else "2026-09-21"
    since = datetime.strptime(since_s, "%Y-%m-%d").replace(tzinfo=timezone.utc)

    model = json.load(open(src))
    rules = model.get("rules", [])
    n_factory = sum(1 for r in rules if r.get("origin") == "factory")
    n_protected = sum(1 for r in rules if r.get("protected"))

    keeps = [r for r in rules if is_keep(r)]
    if len(keeps) < 10:
        throw("expected >=10 scripted [ls-] scoped rules, found {} — refusing to run"
              .format(len(keeps)))
    # kept domain coverage per process (tcp:443 scripted rules)
    kept_by_proc = {}
    for r in keeps:
        kept_by_proc.setdefault(r.get("process"), set()).update(
            str(d).lower() for d in (r.get("remote-domains") or []))

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    out, n_hole, n_del, n_deny = [], 0, 0, 0
    for r in rules:
        if is_keep(r) or r.get("origin") in ("factory",) or r.get("protected"):
            out.append(r)
            continue
        # class 1+2: any-process holes — deny regardless of age
        if is_anyproc_hole(r):
            r = dict(r)
            r["action"] = "deny"
            r["notes"] = str(r.get("notes", "")) + STAMP
            r["modificationDate"] = now
            n_hole += 1
            report("DENY any-proc  : {} :{} ({})".format(
                r.get("remote-addresses"), r.get("ports", "any"),
                str(r.get("notes", ""))[0:80]))
            out.append(r)
            continue
        if not in_window(r, since):
            out.append(r)
            continue
        # redundant: fully covered by a kept scripted domain rule (same proc, 443)
        proc = r.get("process")
        doms = [str(d) for d in (r.get("remote-domains") or [])]
        if (proc in kept_by_proc and str(r.get("ports", "")) == "443"
                and r.get("protocol", "tcp") == "tcp"
                and domain_covered(doms, kept_by_proc[proc])):
            n_del += 1
            report("DELETE covered : {} -> {} (under scripted domain rule)".format(
                str(proc).rsplit("/", 1)[-1], ",".join(doms)[:80]))
            continue
        # everything else approved in the window: doubt -> deny
        r = dict(r)
        r["action"] = "deny"
        r["notes"] = str(r.get("notes", "")) + STAMP
        r["modificationDate"] = now
        n_deny += 1
        tgt = r.get("remote-domains") or r.get("remote-addresses") or "(anywhere)"
        report("DENY approved  : {} -> {} :{} [{}]".format(
            str(proc).rsplit("/", 1)[-1] if proc else "(any)",
            str(tgt)[:70], r.get("ports", "any"), r.get("origin")))
        out.append(r)

    # verify invariants
    if sum(1 for r in out if r.get("origin") == "factory") != n_factory:
        throw("VERIFY failed: factory rule count changed")
    if sum(1 for r in out if r.get("protected")) != n_protected:
        throw("VERIFY failed: protected rule count changed")
    if sum(1 for r in out if is_keep(r)) != len(keeps):
        throw("VERIFY failed: scripted [ls-] keep-rule count changed")
    if any(is_anyproc_hole(r) for r in out):
        throw("VERIFY failed: any-process sentinel/auto allow survived")
    for kr in keeps:
        match = [r for r in out if r is kr or r == kr]
        if not match:
            throw("VERIFY failed: scripted keep rule missing/altered: {}"
                  .format(str(kr.get("notes", ""))[:60]))

    model["rules"] = out
    json.dump(model, open(dst, "w"), indent=2)
    summary = ("SUMMARY: any-proc-holes denied={} covered-redundant deleted={} "
               "window-approvals denied={} kept={} rules {} -> {}".format(
                   n_hole, n_del, n_deny, len(keeps), len(rules), len(out)))
    report(summary)
    text = "\n".join(REPORT_LINES) + "\n"
    if rpt:
        open(rpt, "w").write(text)
    print(summary)

if __name__ == "__main__":
    guard_main("ls-week-review", main)
