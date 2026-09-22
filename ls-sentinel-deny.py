#!/usr/bin/env python3
# ls-sentinel-deny.py — [AUTO-EVW-LS] build Little Snitch deny rules from the
# mac-sentinel alert feed (NEW_CONNECTION warnings).
#
#   dry run:  python3 ls-sentinel-deny.py model.json --report out.md
#   apply:    python3 ls-sentinel-deny.py model.json --apply --report out.md --undo undo.json
#             (patches model.json in place; restore-model afterwards)
#
# Every warned (remote_ip, port) gets an any-process outgoing deny tagged
# "[AUTO-EVW-LS] sentinel-deny" — except a small evidence-based exclusion set
# whose denial would break the machine's own security controls or this
# administration session (see EXCLUSIONS below; each is listed in the report
# with its reason so it can be promoted manually if desired).
#
# Inbound from those IPs needs no rule: the Application Firewall is in
# block-all mode (State = 2) and pf anchors com.ew.devports / com.ew.autoblock
# already drop unsolicited inbound traffic.
#
# Remote-access daemons in ROOT_PROCESS_DETECTED warnings (remoted,
# mediaremoted, AirPlayXPCHelper) are already covered by the [AUTO-EVW]
# blanket denies of 2026-09-01 and are reaped every 15 s by studentd-guard;
# verified here and reported, not duplicated.

import json
import sys
import time

FEED = "/Users/evw/Library/Logs/mac-sentinel-alert-feed.log"
TAG = "[AUTO-EVW-LS] sentinel-deny"

# process-name prefix -> reason the warned connection is never denied
EXCLUSIONS = [
    ("at.obdev.littlesnitch",
     "Little Snitch's own network extension — denying it disables the firewall "
     "itself; its :443 endpoints are the user's pinned encrypted DNS (dns-guard)"),
    ("mDNSResponder",
     "system name resolution (incl. encrypted DNS) — denying risks a self-inflicted DNS outage"),
    ("timed",
     "NTP clock sync — clock drift breaks TLS/certificate validation"),
    ("kimi",
     "the active administration CLI session in use right now"),
    ("ssh",
     "user's own git remote (git@github.com:evweath/sec.git, fcrdns verified)"),
]

# ip_intel.org substring -> reason endpoints of this org are never denied,
# regardless of process (github connections come from WebKit, curl, gh, git…)
EXCLUDED_ORGS = [
    ("GitHub",
     "user's key dev resource — github domains are allow-scoped to signed "
     "processes on tcp:443 by ls-scope-key-resources.py; sentinel IP denies "
     "were breaking git/curl/WebKit access (2026-09-15 incident)"),
    ("Shopify",
     "user's storefront workflow (admin.shopify.com, *.myshopify.com, shop.app) — "
     "Shopify anycast IPs (23.227.32.0/20, 2620:127:f00::/48) serve all shops, so "
     "per-IP denies caused an approve-whack-a-mole loop that kept breaking active "
     "sessions; allow-scoped to WebKit + Brave by domain on tcp:443 via "
     "ls-shopify-whitelist.py"),
]

# ptr suffix -> reason endpoints with this reverse-DNS are never denied.
# Google front-end IPs (gmail, googleapis, google.com) rotate constantly, so
# per-IP denies there only produced an approve-whack-a-mole loop (226 stale
# rules by 2026-09-17); gmail is allow-scoped to signed processes by domain
# on tcp:443 via ls-gmail-fix.py instead. GCP customer IPs
# (bc.googleusercontent.com) are NOT covered here and still get denied.
EXCLUDED_PTRS = [
    ("1e100.net",
     "Google front-end infrastructure — IPs rotate under the same domains; "
     "scoped domain allows (ls-gmail-fix.py) replace per-IP denies"),
]

# (ip_intel.org substring, process prefix) -> reason this org is never denied
# when reached from this process. Scoped counterpart to EXCLUDED_ORGS: the
# org stays deny-eligible for every other process (telemetry, app phoning),
# only the proven approve-whack-a-mole loop is closed.
EXCLUDED_ORG_PROCS = [
    ("Microsoft",
     "com.apple.WebKit.Networking",
     "Outlook/Office365 web sessions — Microsoft rotates 40.96/40.99/52.96/52.97 "
     "front-end IPs; 198 stale per-IP rules and 71 manual flips by 2026-09-21. "
     "Scoped WebKit+O365-domain tcp:443 allows (ls-outlook-fix.py) replace them"),
    ("Microsoft",
     "com.apple.Safari",
     "same Outlook/Office365 loop — macOS 26 attributes most Safari flows to "
     "the Safari app process; scoped Safari+O365-domain allows cover it"),
    ("Google LLC",
     "com.apple.WebKit.Networking",
     "GCP load-balancer front-ends (bc.googleusercontent.com PTR) serve "
     "arbitrary sites incl. admin.shopify.com (34.128.177.21, blocked 2026-09-22) "
     "— shared-CDN per-IP denies; scoped browser domain allows replace them. "
     "GCP endpoints reached by non-browser processes remain deny-eligible"),
    ("Google LLC",
     "com.apple.Safari",
     "same GCP load-balancer front-end case — Safari-attributed flows"),
]

# applied would degrade system networking in ways the user may not intend;
# reported for a manual decision instead
OPTIONAL = [
    ("networkserviceproxy",
     "iCloud Private Relay / Network Service Proxy infrastructure (Apple/Akamai) — "
     "denying forces traffic off the relay path; review manually"),
]

BLANKET_COVERED = ("com.apple.remoted", "com.apple.mediaremoted",
                   "com.apple.AirPlayXPCHelper")


def excluded(proc):
    for prefix, reason in EXCLUSIONS:
        if proc.startswith(prefix):
            return reason
    return None


def excluded_org(org):
    for sub, reason in EXCLUDED_ORGS:
        if sub.lower() in (org or "").lower():
            return reason
    return None


def excluded_ptr(ptr):
    p = (ptr or "").lower().rstrip(".")
    for suf, reason in EXCLUDED_PTRS:
        if p.endswith(suf):
            return reason
    return None


def excluded_org_proc(org, proc):
    for sub, prefix, reason in EXCLUDED_ORG_PROCS:
        if sub.lower() in (org or "").lower() and proc.startswith(prefix):
            return reason
    return None


def optional(proc):
    for prefix, reason in OPTIONAL:
        if proc.startswith(prefix):
            return reason
    return None


def load_feed(path):
    conns = {}
    for line in open(path):
        line = line.strip()
        if not line:
            continue
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        d = j.get("data", {})
        if d.get("event") != "NEW_CONNECTION":
            continue
        ip, port = d.get("remote_ip"), d.get("remote_port")
        if not ip or not port:
            continue
        intel = d.get("ip_intel") or {}
        conns[(ip, str(port))] = {
            "process": d.get("process", "?"),
            "org": intel.get("org") or "",
            "ptr": intel.get("ptr") or "",
            "ts": j.get("ts_human", "?"),
        }
    return conns


def already_covered(rules, ip, port):
    for r in rules:
        if r.get("action") != "deny":
            continue
        if str(r.get("remote-addresses", "")) != ip:
            continue
        ports = str(r.get("ports", ""))
        if ports in ("", "any", port):
            return True
    return False


def blanket_status(rules):
    found = {b: False for b in BLANKET_COVERED}
    for r in rules:
        if r.get("action") == "deny" and str(r.get("remote", "")) == "any":
            p = str(r.get("process", ""))
            for b in BLANKET_COVERED:
                if p.endswith("/" + b):
                    found[b] = True
    return found


def main():
    path = sys.argv[1]
    apply = "--apply" in sys.argv
    rpt = sys.argv[sys.argv.index("--report") + 1] if "--report" in sys.argv else None
    undo = sys.argv[sys.argv.index("--undo") + 1] if "--undo" in sys.argv else None
    feed = sys.argv[sys.argv.index("--feed") + 1] if "--feed" in sys.argv else FEED

    model = json.load(open(path))
    rules = model.get("rules", [])
    conns = load_feed(feed)

    added, skipped, covered, opt = [], [], [], []
    for (ip, port), info in sorted(conns.items()):
        proc = info["process"]
        reason = excluded(proc)
        if reason:
            skipped.append((proc, ip, port, info, reason))
            continue
        reason = excluded_org(info["org"])
        if reason:
            skipped.append((proc, ip, port, info, reason))
            continue
        reason = excluded_ptr(info["ptr"])
        if reason:
            skipped.append((proc, ip, port, info, reason))
            continue
        reason = excluded_org_proc(info["org"], proc)
        if reason:
            skipped.append((proc, ip, port, info, reason))
            continue
        reason = optional(proc)
        if reason:
            opt.append((proc, ip, port, info, reason))
            continue
        if already_covered(rules, ip, port):
            covered.append((proc, ip, port, info))
            continue
        note = "{}: {} -> {}:{} ({}{}) seen {}".format(
            TAG, proc, ip, port, info["org"],
            " ptr=" + info["ptr"] if info["ptr"] else "", info["ts"])
        added.append({
            "action": "deny", "direction": "outgoing", "process": "any",
            "remote-addresses": ip, "ports": port,
            "origin": "frontend", "approved": True,
            "creationDate": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "notes": note,
        })

    blanket = blanket_status(rules)

    lines = [
        "# [AUTO-EVW-LS] sentinel-deny report",
        "# {}  feed={}  unique warned endpoints={}".format(
            time.strftime("%Y-%m-%d %H:%M:%S"), feed, len(conns)),
        "# ADD={}  ALREADY-COVERED={}  EXCLUDED={}  OPTIONAL(not applied)={}".format(
            len(added), len(covered), len(skipped), len(opt)),
        "", "## ADDED (any-process outgoing deny, ip+port)",
    ]
    for r in added:
        lines.append("- deny any -> {}:{}   [{}]".format(
            r["remote-addresses"], r["ports"], r["notes"]))
    lines += ["", "## ALREADY COVERED by an existing deny (no-op)"]
    for proc, ip, port, info in covered:
        lines.append("- {} -> {}:{} ({})".format(proc, ip, port, info["org"]))
    lines += ["", "## EXCLUDED — security-critical / active workflow (evidence in reason)"]
    for proc, ip, port, info, reason in skipped:
        lines.append("- {} -> {}:{} ({}) — {}".format(proc, ip, port, info["org"], reason))
    lines += ["", "## OPTIONAL — not applied, manual decision required"]
    for proc, ip, port, info, reason in opt:
        lines.append("- {} -> {}:{} ({}) — {}".format(proc, ip, port, info["org"], reason))
    lines += ["", "## ROOT_PROCESS warnings — blanket-deny verification"]
    for b, ok in blanket.items():
        lines.append("- {}: {}".format(b, "deny-any already present" if ok else "MISSING — add manually"))
    lines.append("- kills: studentd-guard reaps these every 15 s; one-shot kills are in the deploy block")
    text = "\n".join(lines) + "\n"

    if rpt:
        open(rpt, "w").write(text)
    else:
        print(text)
    if undo:
        json.dump({"added": added}, open(undo, "w"), indent=2)
    if apply:
        model["rules"] = rules + added
        json.dump(model, open(path, "w"), indent=2)
    print("ADD={} COVERED={} EXCLUDED={} OPTIONAL={} total_rules={}".format(
        len(added), len(covered), len(skipped), len(opt),
        len(rules) + (len(added) if apply else 0)))


if __name__ == "__main__":
    main()
