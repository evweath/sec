#!/usr/bin/env python3
# ls-hygiene.py — [AUTO-EVW-LS] targeted Little Snitch rule cleanup (2026-09-01).
#
#   dry run:  python3 ls-hygiene.py model.json --report out.md --undo undo.json
#   apply:    python3 ls-hygiene.py model.json --apply --report out.md --undo undo.json
#             (patches model.json in place; ls-hygiene-apply.sh does backup+restore)
#
# This ruleset was already well-pruned (no any-remote allows outside factory
# rules, no unsigned-binary allows, no inbound allows). Targeted deletions:
#
#   T1  alert/monitor-origin ALLOW rules to known tracker/ad hosts — several
#       contradict the user's own DENY rules for the same host.
#   T2  alert-origin DENY rules for com.apple.trustd — they disabled OCSP
#       certificate-revocation checking (ocsp2.apple.com, 1826 hits). Deleting
#       the deny RESTORES revocation checks = security-improving.
#   T3  alert-origin DENY rules for com.apple.configd (ports 67/any) — can
#       interfere with DHCP renewal; stock behavior restored.
# Report-only (NOT touched): com.brave.Browser any-deny (deliberate?),
# com.apple.apsd any-deny (push off = posture), mDNSResponder inbound denies
# (consistent with lockdown posture).

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

    lines = [
        "# [AUTO-EVW-LS] Little Snitch hygiene report",
        "# {}  rules={}  DELETE={}  review-only={}".format(
            time.strftime("%Y-%m-%d %H:%M:%S"), len(rules), len(deleted), len(review)),
        "", "## DELETED (tagged, full copies in undo JSON)",
    ]
    for tag, r in deleted:
        lines.append("- `{}`  {}".format(tag, describe(r)))
    lines += ["", "## REVIEW-ONLY (left in place deliberately)"]
    for r in review:
        lines.append("- {}".format(describe(r)))
    text = "\n".join(lines) + "\n"

    if rpt:
        open(rpt, "w").write(text)
    else:
        print(text)
    if undo:
        json.dump([r for _, r in deleted], open(undo, "w"), indent=2)
    if apply and deleted:
        model["rules"] = kept
        json.dump(model, open(path, "w"), indent=2)
    print("DELETE={} REVIEW={} kept={}".format(len(deleted), len(review), len(kept)))

if __name__ == "__main__":
    main()
