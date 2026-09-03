#!/usr/bin/env python3
# ls-hole-audit.py — [AUTO-EVW-LS] close Little Snitch security holes.
#
#   dry run:  python3 ls-hole-audit.py model.json --report out.md
#   apply:    python3 ls-hole-audit.py model.json --apply --report out.md --undo undo.json
#             (patches model.json in place; caller does restore-model)
#
# Runs after LS rule changes (see evw-security-system.py job ls-change-watch).
# Three actions:
#   H1  DELETE allow rules from untrusted origins (alert, alertTimeout,
#       monitor, network monitor) with remote "any" — an any-host allow is a
#       gaping hole (precedent: the Safari allow-any-any rule flagged
#       CRITICAL by the daily harden scan 2026-09-02).
#   H2  DELETE untrusted-origin allow rules for sensitive/remote-access
#       processes (replayd, remotemanagement, screensharing, ARDAgent,
#       launchctl, …) — an allow for something the posture blanket-denies is
#       an inverted rule, usually a mis-clicked popup.
#   H3  REPLANT any missing critical deny (mirrors ls-full-analysis.py's
#       CRITICAL table, same substring checks, same process strings as the
#       [AUTO-EVW] rules of 2026-09-01) so a hole deleted by anyone/anything
#       grows back within minutes.
# REVIEW (never auto-deleted): untrusted-origin allows with ports "any" to a
# specific host — listed in the report for a manual decision.
#
# Undo JSON: {"deleted": [...], "replanted": [...]} — re-import to restore.

import json
import sys
import time

UNTRUSTED_ORIGINS = {"alert", "alertTimeout", "monitor", "network monitor"}

SENSITIVE_PROC = ("replayd", "remotemanagement", "privatecloudcomputed",
                  "studentd", "identityservices", "screensharing", "launchctl",
                  "kickstart", "ardagent", "wifivelocityd",
                  "searchpartyuseragent", "symptomsd", "submitdiaginfo",
                  "managedapps")

# (check-name, process-or-None, remote-domains-or-None) — a deny with this
# process (substring match) or remote-domains (substring match) must exist;
# missing ones are replanted with exactly these fields, remote "any",
# direction "both" (the 2026-09-01 [AUTO-EVW] blanket-deny format).
CRITICAL_DENIES = [
    ("replayd", "identifier.APPLE/com.apple.replayd", None),
    ("privatecloudcomputed", "identifier.APPLE/com.apple.privatecloudcomputed", None),
    ("remotemanagementd", "identifier.APPLE/com.apple.remotemanagementd", None),
    ("RemoteManagementAgent", "identifier.APPLE/com.apple.RemoteManagementAgent", None),
    ("kickstart", "/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart", None),
    ("launchctl", "identifier.APPLE/com.apple.xpc.launchctl", None),
    ("studentd", "identifier.APPLE/com.apple.studentd", None),
    ("identityservicesd", "identifier.APPLE/com.apple.identityservicesd", None),
    ("symptomsd", "identifier.APPLE/com.apple.symptomsd", None),
    ("SubmitDiagInfo", "identifier.APPLE/com.apple.SubmitDiagInfo", None),
    ("ScreenSharingSubscriber", "/System/Library/PrivateFrameworks/RemoteManagement.framework/XPCServices/ScreenSharingSubscriber.xpc/Contents/MacOS/ScreenSharingSubscriber", None),
    ("ManagedAppsSubscriber", "/System/Library/PrivateFrameworks/RemoteManagement.framework/XPCServices/ManagedAppsSubscriber.xpc/Contents/MacOS/ManagedAppsSubscriber", None),
    ("datadoghq.com", None, "datadoghq.com"),
    ("found.io", None, "found.io"),
    ("influxdata.com", "identifier.APPLE/com.apple.Terminal", "influxdata.com"),
]


def untrusted(r):
    return (not r.get("protected")) and str(r.get("origin", "")) in UNTRUSTED_ORIGINS


def describe(r):
    return "{} {} -> {} ports={} dir={} origin={}".format(
        r.get("action"), r.get("process", "any"),
        r.get("remote") or r.get("remote-hosts") or r.get("remote-domains")
        or r.get("remote-addresses") or "any",
        r.get("ports", "any"), r.get("direction", "(both)"), r.get("origin", "?"))


def main():
    path = sys.argv[1]
    apply = "--apply" in sys.argv
    rpt = sys.argv[sys.argv.index("--report") + 1] if "--report" in sys.argv else None
    undo = sys.argv[sys.argv.index("--undo") + 1] if "--undo" in sys.argv else None

    model = json.load(open(path))
    rules = model.get("rules", [])

    deleted, review = [], []
    kept = []
    for r in rules:
        proc = str(r.get("process", ""))
        if (r.get("action") == "allow" and untrusted(r)
                and str(r.get("remote", "")) == "any"):
            deleted.append(("H1-allow-any-remote", r))
            continue
        if (r.get("action") == "allow" and untrusted(r)
                and any(s in proc.lower() for s in SENSITIVE_PROC)):
            deleted.append(("H2-allow-sensitive-proc", r))
            continue
        if (r.get("action") == "allow" and untrusted(r)
                and str(r.get("ports", "")) == "any"):
            review.append(r)
        kept.append(r)

    replanted = []
    for name, proc, domain in CRITICAL_DENIES:
        if proc:
            found = any(r.get("action") == "deny" and proc in str(r.get("process", ""))
                        for r in kept)
        else:
            found = any(r.get("action") == "deny" and domain in str(r.get("remote-domains", ""))
                        for r in kept)
        if found:
            continue
        rule = {"action": "deny", "direction": "both", "origin": "frontend",
                "approved": True,
                "creationDate": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "notes": "[AUTO-EVW-LS] hole-audit: replant critical deny " + name}
        if proc:
            rule["process"] = proc
            rule["remote"] = "any"
        else:
            rule["process"] = "any"
            rule["remote-domains"] = domain
        # influxdata is Terminal-scoped per the CRITICAL table
        if name == "influxdata.com":
            rule["process"] = "identifier.APPLE/com.apple.Terminal"
        replanted.append((name, rule))
        kept.append(rule)

    lines = [
        "# [AUTO-EVW-LS] hole-audit report",
        "# {}  rules={}  DELETE={}  REPLANT={}  REVIEW={}".format(
            time.strftime("%Y-%m-%d %H:%M:%S"), len(rules),
            len(deleted), len(replanted), len(review)),
        "", "## DELETED (full copies in undo JSON)",
    ]
    for tag, r in deleted:
        lines.append("- `{}`  {}".format(tag, describe(r)))
    lines += ["", "## REPLANTED critical denies (were missing)"]
    for name, r in replanted:
        lines.append("- {}  ->  {}".format(name, describe(r)))
    lines += ["", "## REVIEW-ONLY (any-port allows, left in place)"]
    for r in review:
        lines.append("- {}".format(describe(r)))
    text = "\n".join(lines) + "\n"

    if rpt:
        open(rpt, "w").write(text)
    else:
        print(text)
    if undo:
        json.dump({"deleted": [r for _, r in deleted],
                   "replanted": [r for _, r in replanted]},
                  open(undo, "w"), indent=2)
    if apply:
        model["rules"] = kept
        json.dump(model, open(path, "w"), indent=2)
    print("DELETE={} REPLANT={} REVIEW={} total_rules={}".format(
        len(deleted), len(replanted), len(review), len(kept)))


if __name__ == "__main__":
    main()
