#!/usr/bin/env python3
"""ls-tighten-all.py — tighten a Little Snitch model export.

Usage: python3 ls-tighten-all.py <input-model.json> <output-model.json> [--report FILE]

Operations (allow rules only; deny / factory / protected rules are never touched):
  1. ADD    deny-any rules for guarded daemons (apsd, sharingd, replicatord,
            screensharingd) — skipped if the binary is absent or a deny exists
  2. DELETE monitor-origin allow rules with useCount 0 (auto-approved, never used)
  3. DELETE allow rules referencing binaries that no longer exist on disk
            (stale process path or via path)
  4. TIGHTEN port-less browser/Terminal domain allows to tcp:443
  5. SCOPE  any-process OpenTimestamps allows to the ots binary (tcp:443 kept)

Every change is logged to the report file (default stdout summary only).
Python 3.9 compatible. Read-only except for the output/report files.
"""
import json, os, sys, datetime

REPORT_LINES = []

def report(msg):
    REPORT_LINES.append(msg)

# ── Guarded daemons to deny outright (label: candidate paths, first existing wins)
GUARDED_DENY = {
    "apsd": [
        "/System/Library/PrivateFrameworks/ApplePushService.framework/apsd",
        "/System/Library/PrivateFrameworks/ApplePushService.framework/Support/apsd",
        "/usr/libexec/apnsd",  # pre-26 name
    ],
    "sharingd": ["/usr/libexec/sharingd"],
    "replicatord": [
        "/System/Library/PrivateFrameworks/ReplicatorCore.framework/Support/replicatord",
        "/usr/libexec/replicatord",
    ],
    "screensharingd": [
        "/System/Library/CoreServices/RemoteManagement/screensharingd.bundle/Contents/MacOS/screensharingd",
        "/usr/libexec/screensharingd",
    ],
}

# ── Processes eligible for tcp:443 tightening (browsers + Terminal)
BROWSER_TERMINAL_TOKENS = (
    "com.apple.terminal", "/terminal.app/",
    "com.apple.safari", "/safari.app/",
    "com.duckduckgo.macos.browser", "/duckduckgo.app/",
    "com.brave.browser", "/brave browser.app/",
    "com.google.chrome", "/google chrome.app/",
    "org.mozilla.firefox", "/firefox.app/",
    "com.microsoft.edgemac", "/microsoft edge",
    "company.thebrowser", "/arc.app/",
)

# ── OpenTimestamps endpoints to scope to the ots binary
OTS_DOMAINS = ("opentimestamps.org", "eternitywall.com", "catallaxy.com")
OTS_IPS = ("35.168.1.55", "51.158.62.115")
OTS_BIN = "/Users/evw/Library/Python/3.9/bin/ots"


def is_browser_or_terminal(proc):
    p = str(proc or "").lower()
    return any(tok in p for tok in BROWSER_TERMINAL_TOKENS)


def path_missing(ref):
    """True if ref is a plain filesystem path that does not exist.
    identifier.TEAM/bundle refs can't be path-checked -> False."""
    s = str(ref or "")
    if not s.startswith("/"):
        return False
    # strip .app bundle paths down as far as needed — check the literal path,
    # then the .app bundle root (binary names change more often than bundles)
    if os.path.exists(s):
        return False
    parts = s.split("/")
    for i, part in enumerate(parts):
        if part.endswith(".app"):
            return not os.path.exists("/".join(parts[: i + 1]))
    return True


def remote_field(r):
    for k in ("remote-domains", "remote-hosts"):
        if r.get(k):
            return k
    return None


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(64)
    src, dst = sys.argv[1], sys.argv[2]
    report_file = None
    if "--report" in sys.argv:
        report_file = sys.argv[sys.argv.index("--report") + 1]

    with open(src) as f:
        model = json.load(f)
    rules = model.get("rules", [])
    report(f"Input: {len(rules)} rules ({src})")

    now = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    out = []
    n_del_monitor = n_del_stale = n_tighten = n_scope = 0

    # pre-compute existing deny processes so we don't double-add
    deny_procs = {r.get("process") for r in rules if r.get("action") == "deny"}

    for r in rules:
        action = r.get("action")
        protected = r.get("protected") or r.get("origin") == "factory"

        if action != "allow" or protected:
            out.append(r)
            continue

        # 2. monitor-origin, never used -> delete
        if r.get("origin") == "monitor" and r.get("useCount", 0) == 0:
            n_del_monitor += 1
            report(f"DELETE monitor-unused: {r.get('process')} -> "
                   f"{r.get('remote') or r.get('remote-domains') or r.get('remote-hosts') or r.get('remote-addresses')}")
            continue

        # 3. stale binary references -> delete
        if path_missing(r.get("process")) or path_missing(r.get("via")):
            n_del_stale += 1
            report(f"DELETE stale-binary: {r.get('process')}"
                   f"{' via ' + str(r.get('via')) if path_missing(r.get('via')) else ''} -> "
                   f"{r.get('remote') or r.get('remote-domains') or r.get('remote-hosts') or r.get('remote-addresses')}")
            continue

        # 5. OTS any-process -> scope to ots binary
        remote_blob = " ".join(str(r.get(k, "")) for k in ("remote-domains", "remote-hosts", "remote-addresses"))
        if r.get("process") in (None, "any") and (any(d in remote_blob for d in OTS_DOMAINS)
                                                  or any(ip in remote_blob for ip in OTS_IPS)):
            r["process"] = OTS_BIN
            r["ports"] = "443"
            r["protocol"] = "tcp"
            r["modificationDate"] = now
            n_scope += 1
            report(f"SCOPE ots: any -> {OTS_BIN} [{remote_blob.strip()}]")
            out.append(r)
            continue

        # 4. port-less browser/Terminal domain allow -> tcp:443
        if (not r.get("ports")
                and not r.get("disabled")
                and r.get("direction", "outgoing") == "outgoing"
                and remote_field(r)
                and is_browser_or_terminal(r.get("process"))):
            r["ports"] = "443"
            r["protocol"] = "tcp"
            r["modificationDate"] = now
            n_tighten += 1
            report(f"TIGHTEN tcp:443: {r.get('process')} -> {r.get(remote_field(r))}")
            out.append(r)
            continue

        out.append(r)

    # 1. guarded-daemon denies
    n_add = 0
    for name, candidates in GUARDED_DENY.items():
        path = next((p for p in candidates if os.path.exists(p)), None)
        if not path:
            report(f"SKIP add-deny {name}: no binary found at {candidates}")
            continue
        if path in deny_procs:
            report(f"SKIP add-deny {name}: deny rule already present for {path}")
            continue
        rule = {
            "action": "deny",
            "creationDate": now,
            "direction": "both",
            "modificationDate": now,
            "notes": "guarded daemon — added by ls-tighten-all.py",
            "origin": "frontend",
            "process": path,
            "remote": "any",
            "uid": 501,
        }
        out.append(rule)
        deny_procs.add(path)
        n_add += 1
        report(f"ADD deny-any: {path}")

    model["rules"] = out
    with open(dst, "w") as f:
        json.dump(model, f, indent=2, separators=(",", " : "))
        f.write("\n")

    summary = (f"Done. in={len(rules)} out={len(out)} | +{n_add} denies, "
               f"-{n_del_monitor} monitor-unused, -{n_del_stale} stale-binary, "
               f"~{n_tighten} tightened to tcp:443, ~{n_scope} ots-scoped")
    report(summary)

    text = "\n".join(REPORT_LINES) + "\n"
    if report_file:
        os.makedirs(os.path.dirname(report_file), exist_ok=True)
        with open(report_file, "w") as f:
            f.write(text)
    print(summary)
    print(f"Report: {report_file or '(none)'} — {len(REPORT_LINES)} lines")


if __name__ == "__main__":
    main()
