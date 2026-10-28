#!/usr/bin/env python3
"""Restore the 2026-10-28 Little Snitch rule inversions to deny.

Usage: python3 ls-tighten-2026-10-28.py INPUT.json OUTPUT.json [--report FILE]
"""
import copy
import datetime
import json
import sys

SENTINEL_TAG = "[AUTO-EVW-LS] sentinel-deny"
AUTO_TAG = "[AUTO-EVW] auto-"
STAMP = " [audit-2026-10-28] restored deny"


def any_process(rule):
    return rule.get("process") in (None, "", "any")


def target(rule):
    if rule.get("action") != "allow" or rule.get("disabled"):
        return False
    if not any_process(rule) or rule.get("protected") or rule.get("origin") == "factory":
        return False
    notes = str(rule.get("notes", ""))
    if notes.startswith((SENTINEL_TAG, AUTO_TAG)):
        return True
    return (rule.get("remote-addresses") == "1.2.3.4"
            and "tracker/telemetry domain family" in notes)


def main():
    args = []
    report_path = None
    i = 1
    while i < len(sys.argv):
        if sys.argv[i] == "--report" and i + 1 < len(sys.argv):
            report_path = sys.argv[i + 1]
            i += 2
        else:
            args.append(sys.argv[i])
            i += 1
    if len(args) != 2:
        raise SystemExit("usage: ls-tighten-2026-10-28.py INPUT.json OUTPUT.json [--report FILE]")
    model = json.load(open(args[0]))
    rules = model.get("rules")
    if not isinstance(rules, list):
        raise SystemExit("input has no rules list")
    before = copy.deepcopy(rules)
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    changed = []
    for rule in rules:
        if not target(rule):
            continue
        rule["action"] = "deny"
        rule["modificationDate"] = now
        rule["notes"] = str(rule.get("notes", "")) + STAMP
        changed.append(rule)
    assert len(rules) == len(before)
    for old, new in zip(before, rules):
        if target(old):
            assert old.get("action") == "allow" and new.get("action") == "deny"
            for key in set(old) | set(new):
                if key not in {"action", "modificationDate", "notes"}:
                    assert old.get(key) == new.get(key), (key, old, new)
        else:
            assert old == new, old
    assert not any(target(rule) for rule in rules)
    assert sum(r.get("origin") == "factory" for r in rules) == sum(r.get("origin") == "factory" for r in before)
    assert sum(bool(r.get("protected")) for r in rules) == sum(bool(r.get("protected")) for r in before)
    model["rules"] = rules
    json.dump(model, open(args[1], "w"), indent=2)
    lines = ["Little Snitch tightening 2026-10-28", "CHANGED=%d" % len(changed)]
    for rule in changed:
        lines.append("DENY %s -> %s port=%s uses=%s" % (
            rule.get("process", "any"),
            rule.get("remote-addresses") or rule.get("remote-hosts") or rule.get("remote-domains"),
            rule.get("ports", "any"), rule.get("useCount", 0)))
    text = "\n".join(lines) + "\n"
    if report_path:
        open(report_path, "w").write(text)
    print("CHANGED=%d RULES=%d" % (len(changed), len(rules)))


if __name__ == "__main__":
    main()
