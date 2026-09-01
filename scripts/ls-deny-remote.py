#!/usr/bin/env python3
# ls-deny-remote.py — [AUTO-EVW] plant blanket any-remote deny rules for macOS
# remote-access daemons (2026-09-01). Identifiers verified via codesign.
#   python3 ls-deny-remote.py model.json --apply --undo undo.json
# ls-deny-remote-apply.sh wraps: export -> backup -> this -> restore -> verify.
import json
import sys
import time

PROCS = [
    "com.apple.studentd",
    "com.apple.remoted",
    "com.apple.RemoteDesktopAgent",       # ARDAgent
    "com.apple.remotemanagementd",
    "com.apple.RemoteManagementAgent",
    "com.apple.AirPlayUIAgent",
    "com.apple.AirPlayXPCHelper",          # also covers AirPlay receiving
    "com.apple.rapportd",
    "com.apple.sharingd",
    "com.apple.identityservicesd",
    "com.apple.nearbyd",
    "com.apple.mediaremoted",
    "com.apple.avconferenced",
    "com.apple.smbd",
    "com.apple.netbiosd",
    "com.apple.screensharing.daemon",
]
# Not present on disk under macOS 26 (verified): universalcontrol,
# PersonalHotspotAgent, AirPlayReceiver — nothing to match against.
NOTES = "[AUTO-EVW] blanket-deny remote-access daemon (2026-09-01)"


def main():
    path = sys.argv[1]
    apply = "--apply" in sys.argv
    undo = sys.argv[sys.argv.index("--undo") + 1] if "--undo" in sys.argv else None

    model = json.load(open(path))
    rules = model.get("rules", [])
    blanket = {str(r.get("process", "")) for r in rules
               if r.get("action") == "deny" and str(r.get("remote", "")) == "any"}

    added, skipped = [], []
    for pid in PROCS:
        if any(pid in p for p in blanket):
            skipped.append(pid)
            continue
        rules.append({
            "action": "deny",
            "process": "identifier.APPLE/" + pid,
            "remote": "any",
            "origin": "frontend",
            "approved": True,
            "creationDate": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "notes": NOTES,
        })
        added.append(pid)

    if undo:
        json.dump({"added": added, "skipped_already_denied": skipped},
                  open(undo, "w"), indent=2)
    if apply and added:
        model["rules"] = rules
        json.dump(model, open(path, "w"), indent=2)
    print("ADDED={} SKIP={} total_rules={}".format(len(added), len(skipped), len(rules)))
    for a in added:
        print("  + deny any-remote:", a)


if __name__ == "__main__":
    main()
