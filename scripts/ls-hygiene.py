#!/usr/bin/env python3
# ls-hygiene.py — [AUTO-EVW-LS] targeted Little Snitch rule cleanup (2026-09-01).
#
#   dry run:  python3 ls-hygiene.py model.json --report out.md --undo undo.json
#   apply:    python3 ls-hygiene.py model.json --apply --report out.md --undo undo.json
#             (patches model.json in place; ls-hygiene-apply.sh does backup+restore)
#
# Targeted deletions:
#   T1  alert/monitor-origin ALLOW rules to known tracker/ad hosts.
#   T2  alert-origin DENY rules for com.apple.trustd (they disable OCSP
#       revocation checking; deleting RESTORES it). Includes any OCSP
#       responder host (ocsp.*).
#   T3  alert-origin DENY rules for com.apple.configd (ports 67/any) — DHCP risk.
#
# Durable hardening (apply mode): for every tracker host with no surviving
# deny rule, ADD an explicit any-process deny tagged "[AUTO-EVW-LS] auto-deny".
# With a deny in place Little Snitch stops alerting, so the user cannot
# accidentally re-allow the host via alert dialogs (this was happening —
# 9 tracker allows regenerated within 16 min of the first cleanup).
#
# Report-only (untouched): apsd/push denies, Brave denies, inbound mDNS denies.

import json
import sys
import time

TRACKER_HOSTS = {
    "a.klaviyo.com", "fast.a.klaviyo.com", "static.klaviyo.com",
    "static-tracking.klaviyo.com", "static-forms.klaviyo.com",
    "acdn.adnxs.com", "ads.pro-market.net", "bat.bing.com",
}
UNTRUSTED_ORIGINS = {"alert", "alertTimeout", "monitor", "network monitor"}

def tail(r):
    p = str(r.get("process", ""))
    return p.split("/")[-1] if "/" in p else p

def is_ocsp_host(r):
    h = str(r.get("remote-hosts", ""))
    return h.startswith("ocsp.")

def risk_of(r):
    if r.get("protected") or r.get("disabled"):
        return None
    if str(r.get("origin", "")) not in UNTRUSTED_ORIGINS:
        return None
    action = r.get("action")
    proc = tail(r)
    hosts = str(r.get("remote-hosts", ""))
    if action == "allow" and hosts in TRACKER_HOSTS:
        return "T1-tracker-allow"
    if action == "deny" and proc == "com.apple.trustd":
        return "T2-trustd-deny-(OCSP-disabled)"
    if action == "deny" and is_ocsp_host(r):
        return "T2-ocsp-host-deny"
    if action == "deny" and proc == "com.apple.configd":
        return "T3-configd-deny-(DHCP-risk)"
    return None

def describe(r):
    return "{} {} -> {} ports={} dir={} origin={} uses={}".format(
        r.get("action"), tail(r),
        r.get("remote") or r.get("remote-hosts") or r.get("remote-domains")
        or r.get("remote-addresses") or "any",
        r.get("ports", "any"), r.get("direction", "?"),
        r.get("origin", "?"), r.get("useCount", 0))

def main():
    path = sys.argv[1]
    apply = "--apply" in sys.argv
    rpt = sys.argv[sys.argv.index("--report") + 1] if "--report" in sys.argv else None
    undo = sys.argv[sys.argv.index("--undo") + 1] if "--undo" in sys.argv else None

    model = json.load(open(path))
    rules = model.get("rules", [])
    deleted, review, kept = [], [], []

    for r in rules:
        tag = risk_of(r)
        if tag:
            deleted.append((tag, r))
            continue
        if (r.get("action") == "deny" and tail(r) in
                ("com.brave.Browser", "com.apple.apsd", "com.apple.mDNSResponder")
                and not r.get("protected")):
            review.append(r)
        kept.append(r)

    # Durable: plant explicit denies for tracker hosts lacking one.
    existing_deny_hosts = {str(r.get("remote-hosts", "")) for r in kept
                           if r.get("action") == "deny"}
    added = []
    for h in sorted(TRACKER_HOSTS):
        if h not in existing_deny_hosts:
            added.append({
                "action": "deny", "direction": "outgoing", "process": "any",
                "remote-hosts": h, "origin": "frontend", "approved": True,
                "creationDate": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "notes": "[AUTO-EVW-LS] auto-deny tracker (durable; prevents re-allow via alerts)",
            })

    lines = [
        "# [AUTO-EVW-LS] Little Snitch hygiene report",
        "# {}  rules={}  DELETE={}  ADD-DENY={}  review-only={}".format(
            time.strftime("%Y-%m-%d %H:%M:%S"), len(rules),
            len(deleted), len(added), len(review)),
        "", "## DELETED (tagged, full copies in undo JSON)",
    ]
    for tag, r in deleted:
        lines.append("- `{}`  {}".format(tag, describe(r)))
    lines += ["", "## ADDED (durable denies — stops the alert/re-allow loop)"]
    for r in added:
        lines.append("- deny any -> {}".format(r["remote-hosts"]))
    lines += ["", "## REVIEW-ONLY (left in place deliberately)"]
    for r in review:
        lines.append("- {}".format(describe(r)))
    text = "\n".join(lines) + "\n"

    if rpt:
        open(rpt, "w").write(text)
    else:
        print(text)
    if undo:
        json.dump({"deleted": [r for _, r in deleted],
                   "added_deny_hosts": [r["remote-hosts"] for r in added]},
                  open(undo, "w"), indent=2)
    if apply:
        model["rules"] = kept + added
        json.dump(model, open(path, "w"), indent=2)
    print("DELETE={} ADD-DENY={} REVIEW={} kept={}".format(
        len(deleted), len(added), len(review), len(kept) + len(added)))

if __name__ == "__main__":
    main()
