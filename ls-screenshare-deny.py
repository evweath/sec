#!/usr/bin/env python3
# ls-screenshare-deny.py — [AUTO-EVW-LS] durable BOTH-WAYS Little Snitch deny
# rules for screen-sharing / remote-desktop binaries (2026-09-03).
#
#   dry run:  python3 ls-screenshare-deny.py model.json --report out.md
#   apply:    python3 ls-screenshare-deny.py model.json --apply --report out.md --undo undo.json
#             (patches model.json in place; caller does restore-model)
#
# Identifiers (union, deduped, config order first):
#   --config PATH      JSON config, key screenshare.ls_both_way_deny_identifiers
#                      (default /var/db/evw-security-system/security-system.json,
#                       fallback /Users/evw/dev/security/security-system.json)
#   --ensure IDENT ... extra identifiers, this run only (orchestrator appends
#   --ensure-file PATH identifiers of processes it killed here, one per line)
#
# Identifier form: "APPLE/com.apple.screensharingd" or
# "com.google.ChromeRemoteDesktopHost" -> rule process "identifier.<IDENT>"
# (real-world example: "identifier.APPLE/com.apple.mDNSResponder").
#
# For every identifier with no covering rule, append TWO rules (outgoing +
# incoming), so even if a kill-on-sight process respawns its connectivity
# stays blocked. A rule covers direction D when it has the same process
# string, action deny, remote "any", and a direction that is absent
# (Little Snitch exports both-directions rules with no direction key),
# "both", or D itself. Idempotent: re-running adds nothing (counted as SKIP).
#
# Last stdout line is always:  ADD=<rules appended> SKIP=<identifiers covered>

import json
import sys
import time

STATE_CONFIG = "/var/db/evw-security-system/security-system.json"
REPO_CONFIG = "/Users/evw/dev/security/security-system.json"
TAG = "[AUTO-EVW-LS] screenshare-deny (both-ways; kill-on-sight backstop)"
DIRECTIONS = ("outgoing", "incoming")


def flag_value(argv, flag):
    return argv[argv.index(flag) + 1] if flag in argv else None


def ensure_args(argv):
    # tokens after --ensure up to the next --flag (repeatable)
    out, i = [], 0
    while i < len(argv):
        if argv[i] == "--ensure":
            i += 1
            while i < len(argv) and not argv[i].startswith("--"):
                out.append(argv[i])
                i += 1
        else:
            i += 1
    return out


def load_config_idents(path):
    # None = file unreadable (try fallback); [] = parsed, no identifiers
    try:
        cfg = json.load(open(path))
    except (OSError, ValueError):
        return None
    if not isinstance(cfg, dict):
        return []
    screenshare = cfg.get("screenshare")
    if not isinstance(screenshare, dict):
        return []
    idents = screenshare.get("ls_both_way_deny_identifiers")
    if not isinstance(idents, list):
        return []
    return [str(x) for x in idents]


def covers(rules, process, direction):
    for r in rules:
        if str(r.get("process", "")) != process:
            continue
        if r.get("action") != "deny" or str(r.get("remote", "")) != "any":
            continue
        d = r.get("direction")
        if d is None or d == "both" or d == direction:
            return r
    return None


def describe(r):
    return "{} {} -> {} dir={} origin={} notes={}".format(
        r.get("action"), r.get("process"), r.get("remote", "any"),
        r.get("direction") or "absent(both)", r.get("origin", "?"),
        r.get("notes", ""))


def main():
    argv = sys.argv
    if len(argv) < 2 or argv[1].startswith("--"):
        sys.stderr.write(
            "usage: ls-screenshare-deny.py MODEL.json [--apply] [--report PATH] "
            "[--undo PATH]\n       [--ensure IDENT ...] [--ensure-file PATH] "
            "[--config PATH]\n")
        raise SystemExit(2)

    path = argv[1]
    apply = "--apply" in argv
    rpt = flag_value(argv, "--report")
    undo = flag_value(argv, "--undo")
    cfg_arg = flag_value(argv, "--config")
    ensure_file = flag_value(argv, "--ensure-file")

    # config: explicit --config wins; else state dir, else repo fallback
    cfg_used, cfg_idents = None, None
    for cand in ([cfg_arg] if cfg_arg else [STATE_CONFIG, REPO_CONFIG]):
        cfg_idents = load_config_idents(cand)
        if cfg_idents is not None:
            cfg_used = cand
            break
    if cfg_idents is None:
        cfg_idents = []

    ensure_idents = ensure_args(argv)
    file_note = None
    if ensure_file:
        try:
            for line in open(ensure_file):
                line = line.strip()
                if line and not line.startswith("#"):
                    ensure_idents.append(line)
        except OSError as e:
            file_note = "ensure-file {} unreadable: {}".format(ensure_file, e)

    idents = list(dict.fromkeys(cfg_idents + ensure_idents))

    model = json.load(open(path))
    rules = model.get("rules", [])
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    added, skipped = [], []
    for ident in idents:
        process = "identifier." + ident
        missing, covered_by = [], []
        for d in DIRECTIONS:
            r = covers(rules, process, d)
            if r is None:
                missing.append(d)
            else:
                covered_by.append(r)
        if not missing:
            skipped.append((ident, covered_by[0]))
            continue
        for d in missing:
            added.append({
                "action": "deny", "direction": d, "process": process,
                "remote": "any", "origin": "frontend", "approved": True,
                "creationDate": now, "notes": TAG,
            })

    lines = [
        "# [AUTO-EVW-LS] screenshare-deny (both-ways) report",
        "# {}  model={}  apply={}".format(
            time.strftime("%Y-%m-%d %H:%M:%S"), path, apply),
        "# config={}  identifiers={} (config={} ensure={})".format(
            cfg_used or "(none found — --ensure only)",
            len(idents), len(cfg_idents), len(ensure_idents)),
        "# ADD={} rules  SKIP={} identifiers (already covered)".format(
            len(added), len(skipped)),
    ]
    if file_note:
        lines.append("# WARNING: " + file_note)
    lines += ["", "## ADDED (durable both-ways denies, grouped by identifier)"]
    by_ident = {}
    for r in added:
        by_ident.setdefault(r["process"], []).append(r)
    for process, rs in by_ident.items():
        lines.append("### {}".format(process))
        for r in rs:
            lines.append("- deny {} {} -> any".format(r["direction"], process))
    lines += ["", "## SKIPPED (an existing deny already covers both directions)"]
    for ident, r in skipped:
        lines.append("- identifier.{} — covered by: {}".format(ident, describe(r)))
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
    print("ADD={} SKIP={}".format(len(added), len(skipped)))


if __name__ == "__main__":
    main()
