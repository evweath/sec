#!/usr/bin/env python3
# ls-model-diff.py — diff two exported Little Snitch models (rule sets).
#
#   python3 ls-model-diff.py OLD.json NEW.json
#
# Volatile fields (useCount, lastUsed, creation/modification dates,
# factoryHelpText) are ignored so normal traffic doesn't show up as churn;
# everything else — action, process, remote, ports, direction, origin,
# owner, notes — is fingerprinted. Output: added and removed rules.

import json
import sys

VOLATILE = {"useCount", "lastUsed", "modificationDate", "creationDate",
            "factoryHelpText"}


def fingerprint(r):
    return json.dumps({k: v for k, v in r.items() if k not in VOLATILE},
                      sort_keys=True)


def describe(r):
    return "{} {} -> {} ports={} dir={} origin={} notes={}".format(
        r.get("action"), r.get("process", "any"),
        r.get("remote") or r.get("remote-hosts") or r.get("remote-domains")
        or r.get("remote-addresses") or "any",
        r.get("ports", "any"), r.get("direction", "(both?)"),
        r.get("origin", "?"), str(r.get("notes", ""))[:70])


def main():
    old = json.load(open(sys.argv[1])).get("rules", [])
    new = json.load(open(sys.argv[2])).get("rules", [])

    old_by_fp = {fingerprint(r): r for r in old}
    new_by_fp = {fingerprint(r): r for r in new}

    removed = [r for fp, r in old_by_fp.items() if fp not in new_by_fp]
    added = [r for fp, r in new_by_fp.items() if fp not in old_by_fp]

    print("# ls-model-diff  {} -> {}".format(sys.argv[1], sys.argv[2]))
    print("# rules: {} -> {}   ADDED={} REMOVED={}".format(
        len(old), len(new), len(added), len(removed)))
    print("\n## ADDED")
    for r in sorted(added, key=describe):
        print("+", describe(r))
    print("\n## REMOVED")
    for r in sorted(removed, key=describe):
        print("-", describe(r))


if __name__ == "__main__":
    main()
