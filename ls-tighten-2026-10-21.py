#!/usr/bin/env python3
"""ls-tighten-2026-10-21.py — flip flagged ad-rot Safari allows to deny.

Usage: python3 ls-tighten-2026-10-21.py <input-model.json> <output-model.json> [--report FILE]

Targets the 4 risky-TLD allow rules flagged by ls-domain-audit /
ls-rules-deep-audit on 2026-10-21 (random-label .icu/.tv hosts, Safari-scoped,
alert-origin, tcp:443 — classic alert-fatigue tracker approvals):

    prreqcroab.icu            (uses=18, created 2026-10-02)
    pixel-ssn.prreqcroab.icu  (uses=6,  created 2026-10-02)
    cdn.ravm.tv               (uses=10, created 2026-09-29)
    pt.ispot.tv               (uses=1,  created 2026-09-30)

Plus one repair: removes the three "overrideDueToCodeSignatureIssue"
any-denies created when the 2026-10-20 brew cascade changed binary CDHashes
and Little Snitch auto-created path-override denies for the "new" binaries:

    limactl -> any            (2026-10-21 10:33, 72 blocks — kills ALL colima
                               VM egress incl. the wazuh manager's CTI feeds)
    node -> any               (2026-10-20, 27 blocks — the npm registry lockout)
    iterm2 via gh -> any      (2026-10-21 08:57, 88 blocks — gh blocked from
                               api.github.com after its CDHash changed)

Removing them restores normal per-host rule evaluation; the tracked tooling
(colima/docker, npm, gh) works again, and genuinely suspicious connections
still alert normally.

Action: allow -> deny, in place, preserving every other rule field (same
specificity, so the deny wins where the allow used to). Only rules whose
remote-hosts exactly matches the set are touched. Per the 2026-09-28 user
directive: if there is any doubt, deny.

Python 3.9 compatible. Read-only except for the output/report files.
"""
import json, sys, datetime

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

FLAGGED_HOSTS = {
    "prreqcroab.icu",
    "pixel-ssn.prreqcroab.icu",
    "cdn.ravm.tv",
    "pt.ispot.tv",
}

REPORT_LINES = []

def report(msg):
    REPORT_LINES.append(msg)

def load_model(path):
    with open(path) as f:
        return json.load(f)

def save_model(model, path):
    with open(path, "w") as f:
        json.dump(model, f, indent=2, separators=(",", " : "))
        f.write("\n")
    return True

def write_report(path, text):
    with open(path, "w") as f:
        f.write(text)
    return True

def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    report_file = None
    for i, a in enumerate(sys.argv):
        if a == "--report" and i + 1 < len(sys.argv):
            report_file = sys.argv[i + 1]
    if len(args) < 2:
        throw("usage: ls-tighten-2026-10-21.py <in.json> <out.json> [--report FILE]")
    src, dst = args[0], args[1]

    model = guard_run("load-model", load_model, src)
    if model is None:
        sys.exit(1)
    rules = model.get("rules", [])
    report("Input: %d rules (%s)" % (len(rules), src))

    n_flip = 0
    n_in = len(rules)
    for r in rules:
        if r.get("action") != "allow":
            continue
        if r.get("remote-hosts") not in FLAGGED_HOSTS:
            continue
        r["action"] = "deny"
        r["modificationDate"] = datetime.datetime.now(
            datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        n_flip += 1
        report("FLIP allow->deny: %s -> %s (port=%s uses=%s)" % (
            r.get("process"), r.get("remote-hosts"),
            r.get("ports"), r.get("useCount")))

    missing = FLAGGED_HOSTS - {
        r.get("remote-hosts") for r in rules
        if r.get("remote-hosts") in FLAGGED_HOSTS
    }
    for h in sorted(missing):
        report("NOTE: no rule for %s (already gone?)" % h)

    # Repair: remove the three "overrideDueToCodeSignatureIssue" any-denies the
    # CDHash-change storm produced (2026-10-20/21 — brew relinked binaries, LS
    # saw new code signatures, auto-created path-override denies):
    #   limactl -> any          (blocks ALL colima VM egress incl. wazuh CTI)
    #   node    -> any          (yesterday's npm lockout, 27 blocks)
    #   iterm2 via gh -> any    (gh is blocked from api.github.com, 88 blocks)
    # Removing them restores normal per-host rule evaluation; daily-driver
    # tooling works again and genuinely suspicious connections still re-alert.
    def is_override_overreach(r):
        if r.get("action") != "deny" or not r.get("overrideDueToCodeSignatureIssue"):
            return False
        proc = str(r.get("process", ""))
        via = str(r.get("via", ""))
        return ("limactl" in proc or "Cellar/node" in proc
                or "Cellar/gh" in via)

    n_remove = 0
    kept = []
    for r in rules:
        if is_override_overreach(r):
            n_remove += 1
            report("REMOVE code-signature-override deny: %s%s -> %s (uses=%s)"
                   % (r.get("process"),
                      (" via " + str(r.get("via"))) if r.get("via") else "",
                      r.get("remote"), r.get("useCount")))
            continue
        kept.append(r)
    if n_remove:
        model["rules"] = kept
        rules = kept

    if not guard_run("save-model", save_model, model, dst):
        sys.exit(1)

    summary = "Done. in=%d out=%d | %d allows flipped to deny, %d auto-denies removed" % (
        n_in, len(model.get("rules", [])), n_flip, n_remove)
    report(summary)

    text = "\n".join(REPORT_LINES) + "\n"
    if report_file:
        if not guard_run("write-report", write_report, report_file, text):
            sys.exit(1)
    print(summary)
    print("Report: %s — %d lines" % (report_file or "(none)", len(REPORT_LINES)))

if __name__ == "__main__":
    main()
