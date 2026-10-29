#!/usr/bin/env python3
# ls-policy-apply.py — reconcile Little Snitch rules with ls-policy.json.
#
#   dry run (default, read-only):
#     python3 ls-policy-apply.py /path/to/ls-model.json
#   apply (needs root; exports live model itself, backs up, patches, restores):
#     sudo python3 ls-policy-apply.py --apply
#
# The reconciler only manages rules whose notes contain "[POLICY]". Manual
# rules and [AUTO-EVW-LS] sentinel rules are never modified or removed.
# Policy rules are keyed by (process, via, remote-host, port, protocol,
# action): a policy entry already covered by an identical live rule is
# skipped; a [POLICY] rule on disk but absent from ls-policy.json is removed.
#
# Python 3.9+, stdlib only.
import argparse
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

SEC_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_POLICY = os.path.join(SEC_DIR, "ls-policy.json")
TAG = "[POLICY]"
LS_CLI = "/Applications/Little Snitch.app/Contents/Components/littlesnitch"


def load_policy(path):
    with open(path) as f:
        doc = json.load(f)
    rules = []
    for entry in doc.get("rules", []):
        hosts = entry.get("remote-hosts") or []
        if isinstance(hosts, str):
            hosts = [hosts]
        ports = entry.get("ports") or []
        ports = [str(ports)] if not isinstance(ports, list) else [str(p) for p in ports]
        for host in hosts:
            for port in ports:
                rules.append({
                    "name": entry["name"],
                    "action": entry["action"],
                    "process": entry["process"],
                    "via": entry.get("via"),
                    "remote-hosts": host,
                    "ports": port,
                    "protocol": entry.get("protocol", "tcp"),
                })
    return rules


def rule_key(r):
    return (r.get("action"), r.get("process"), r.get("via") or "",
            r.get("remote-hosts") or "", str(r.get("ports") or ""),
            r.get("protocol") or "tcp")


def render_rule(pol):
    """Render a policy entry as a Little Snitch model rule (schema copied from
    real model rules; notes carry the [POLICY] namespace tag)."""
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    r = {
        "action": pol["action"],
        "approved": False,
        "creationDate": now,
        "modificationDate": now,
        "notes": "%s %s" % (TAG, pol["name"]),
        "origin": "alert",
        "ports": pol["ports"],
        "process": pol["process"],
        "protocol": pol["protocol"],
        "remote-hosts": pol["remote-hosts"],
        "uid": 501,
    }
    if pol.get("via"):
        r["via"] = pol["via"]
    return r


def reconcile(model, policy_rules):
    """Return (to_add, to_remove, already_ok, report_lines). Pure — no I/O."""
    live = model.get("rules", [])
    live_keys = {rule_key(r) for r in live}
    policy_keys = {rule_key(r) for r in policy_rules}

    to_add = [render_rule(p) for p in policy_rules if rule_key(p) not in live_keys]
    already_ok = [p for p in policy_rules if rule_key(p) in live_keys]
    to_remove = [r for r in live
                 if TAG in (r.get("notes") or "") and rule_key(r) not in policy_keys]

    lines = ["policy entries: %d  |  already covered: %d  |  to add: %d  |  to remove: %d"
             % (len(policy_rules), len(already_ok), len(to_add), len(to_remove))]
    for p in already_ok:
        lines.append("  OK      %-32s %s -> %s:%s" % (
            p["name"], p["process"].split("/")[-1], p["remote-hosts"], p["ports"]))
    for r in to_add:
        lines.append("  ADD     %-32s %s %s -> %s:%s/%s" % (
            r["notes"][len(TAG) + 1:], r["action"], r["process"].split("/")[-1],
            r["remote-hosts"], r["ports"], r["protocol"]))
    for r in to_remove:
        lines.append("  REMOVE  %s -> %s:%s (in model, no longer in policy)"
                     % (r.get("process", "?"), r.get("remote-hosts", "?"), r.get("ports", "?")))
    return to_add, to_remove, already_ok, lines


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("model", nargs="?", help="model JSON (dry-run against this file)")
    ap.add_argument("--policy", default=DEFAULT_POLICY)
    ap.add_argument("--apply", action="store_true",
                    help="export live model, patch, restore (root required)")
    args = ap.parse_args()

    policy_rules = load_policy(args.policy)

    if not args.apply:
        model_path = args.model
        if not model_path:
            ap.error("dry run needs a model file (e.g. scan-YYYY-MM-DD/ls-model.json)")
        model = json.load(open(model_path))
        to_add, to_remove, _, lines = reconcile(model, policy_rules)
        print("DRY RUN — %s" % model_path)
        print("\n".join(lines))
        print("\n(no changes made; use --apply as root to modify the live model)")
        return 0

    # ── apply path ──
    if os.geteuid() != 0:
        ap.error("--apply must run as root (sudo)")
    tmpdir = tempfile.mkdtemp(prefix="ls-policy-")
    live_path = os.path.join(tmpdir, "ls-model-live.json")
    print("exporting live model…")
    subprocess.run([LS_CLI, "export-model", live_path], check=True)

    backup_dir = os.path.join(SEC_DIR, "scan-" + time.strftime("%F"))
    os.makedirs(backup_dir, exist_ok=True)
    backup = os.path.join(backup_dir,
                          "ls-model-pre-policy-%s.json" % time.strftime("%H%M%S"))
    shutil.copy2(live_path, backup)
    print("backup: %s" % backup)

    model = json.load(open(live_path))
    to_add, to_remove, _, lines = reconcile(model, policy_rules)
    print("\n".join(lines))
    if not to_add and not to_remove:
        print("model already matches policy — nothing to do")
        return 0

    remove_ids = {id(r) for r in to_remove}
    model["rules"] = [r for r in model.get("rules", []) if id(r) not in remove_ids] + to_add
    with open(live_path, "w") as f:
        json.dump(model, f, indent=2)
    print("restoring patched model into Little Snitch…")
    subprocess.run([LS_CLI, "restore-model", live_path], check=True)
    print("done. +%d -%d policy rules applied." % (len(to_add), len(to_remove)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
