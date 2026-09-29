#!/usr/bin/env python3
"""process-audit.py — audit every running process and launchd item.

Usage: python3 process-audit.py [--out FILE]   (read-only)

Sections:
  1. RUNNING PROCESSES — every distinct executable on the system, classified:
     apple / application / homebrew / toolkit / dev-other / SUSPECT, with
     codesign status for non-Apple binaries.
  2. LAUNCHD ITEMS — all LaunchAgents/LaunchDaemons (user + system): plist ->
     target binary exists, signature status, and loaded jobs with no plist.
  3. FLAGS — unsigned/ad-hoc/invalid non-Apple code, executables in temp or
     hidden dirs, missing plist targets, unsigned launchd jobs.
"""
import json, os, plistlib, re, subprocess, sys
from collections import defaultdict

SEC = "/Users/evw/dev/security"

def run(cmd, timeout=20):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.stdout + p.stderr
    except Exception:
        return ""

def sig_status(path):
    """codesign verdict for a binary/app path."""
    if not os.path.exists(path):
        return "missing"
    v = run(["codesign", "--verify", "--verbose=2", path], timeout=15)
    if "valid on disk" not in v:
        if "code object is not signed at all" in v:
            return "UNSIGNED"
        return "invalid:" + v.strip().splitlines()[-1][:60] if v.strip() else "invalid"
    out = run(["codesign", "-dv", "--verbose=2", path], timeout=15)
    if "Authority=Apple" in out or "Authority=Software Signing" in out:
        return "apple"
    if "Signature=adhoc" in out:
        return "adhoc"
    m = re.search(r"TeamIdentifier=([A-Z0-9]+)", out)
    if m:
        return "signed:" + m.group(1)
    return "signed"

def classify(path):
    if path.startswith(("/System/", "/usr/libexec", "/usr/bin", "/usr/sbin",
                        "/Library/Apple", "/private/var/db/oahd")):
        return "apple"
    if path.startswith("/Applications/"):
        return "application"
    if path.startswith(("/opt/homebrew", "/usr/local/Cellar", "/usr/local/opt")):
        return "homebrew"
    if path.startswith((SEC, "/usr/local/bin/evw-", "/usr/local/bin/l5-")):
        return "toolkit"
    if "/Library/Developer/" in path or path.startswith(
            ("/Users/evw/.", "/Users/evw/dev", "/Users/evw/Library/Android",
             "/Users/evw/Library/Python")):
        return "dev-other"
    if path.startswith(("/tmp", "/var/tmp", "/private/tmp")):
        return "SUSPECT-tmp"
    if path.startswith("/Users/evw/Library"):
        return "review-lib"
    return "review-other"

def script_or_binary(path):
    with open(path, "rb") as f:
        magic = f.read(4)
    return magic[:2] == b"#!"

def path_exists(path):
    """True/False, or None when the parent dir is root-only (can't tell)."""
    try:
        os.stat(path)
        return True
    except PermissionError:
        return None
    except OSError:
        return False

def main():
    out = []
    def emit(s=""):
        out.append(s)
        print(s)

    # ── 1. running processes ────────────────────────────────────────────────
    ps = run(["ps", "-eo", "pid=,user=,comm="])
    procs = []          # (pid, user, path)
    seen_paths = {}
    for line in ps.splitlines():
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        pid, user, path = parts
        if not path.startswith("/"):
            continue    # kernel tasks / truncated names
        procs.append((pid, user, path))
        seen_paths.setdefault(path, []).append((pid, user))

    emit("# process-audit — running processes")
    emit("distinct executables: %d (from %d processes)" % (len(seen_paths), len(procs)))
    flags = []
    by_class = defaultdict(list)
    for path in sorted(seen_paths):
        cls = classify(path)
        sig = ""
        if cls not in ("apple",):
            ex = path_exists(path)
            if ex is None:
                sig = "root-only"
            elif not ex:
                sig = "MISSING"
            else:
                try:
                    if script_or_binary(path):
                        sig = "script"
                    else:
                        sig = sig_status(path)
                except Exception:
                    sig = "unreadable"
        by_class[cls].append((path, sig, seen_paths[path]))
        if cls.startswith("SUSPECT") or sig == "UNSIGNED" or sig == "MISSING" \
                or sig == "adhoc" or sig.startswith("invalid"):
            flags.append((cls, path, sig, seen_paths[path]))

    for cls in ("apple", "application", "homebrew", "toolkit", "dev-other",
                "review-lib", "review-other", "SUSPECT-tmp"):
        rows = by_class.get(cls)
        if not rows:
            continue
        emit("\n== %s (%d) ==" % (cls, len(rows)))
        for path, sig, owners in rows:
            users = sorted({u for _, u in owners})
            emit("  %-88s %-14s %s" % (path, sig, ",".join(users)))

    # ── 2. launchd items ────────────────────────────────────────────────────
    emit("\n# launchd items")
    dirs = [os.path.expanduser("~/Library/LaunchAgents"),
            "/Library/LaunchAgents", "/Library/LaunchDaemons"]
    seen_targets = {}
    for d in dirs:
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            if not fn.endswith(".plist"):
                continue
            p = os.path.join(d, fn)
            try:
                pl = plistlib.load(open(p, "rb"))
            except Exception:
                flags.append(("launchd", p, "UNREADABLE-PLIST", []))
                emit("  [!!] unreadable plist: %s" % p)
                continue
            label = pl.get("Label", fn)
            prog = pl.get("Program") or (pl.get("ProgramArguments") or [None])[0]
            if not prog:
                continue
            target = prog if prog.startswith("/") else None
            if target is None:
                continue
            seen_targets[label] = target
            status = "ok"
            ex = path_exists(target)
            if ex is False:
                status = "MISSING-TARGET"
                flags.append(("launchd", label, "missing target " + target, []))
            elif ex is None:
                status = "root-only"
            elif not target.startswith(("/System/", "/usr/libexec", "/usr/bin",
                                        "/usr/sbin", "/Library/Apple")):
                try:
                    s = "script" if script_or_binary(target) else sig_status(target)
                except Exception:
                    s = "unreadable"
                status = s
                if s == "UNSIGNED" or s == "adhoc" or s.startswith("invalid"):
                    flags.append(("launchd", label, "%s (%s)" % (s, target), []))
            emit("  [%s] %-44s -> %s (%s)" % (d.split("/Library/")[-1], label, target, status))

    loaded = run(["launchctl", "list"])
    known = set(seen_targets.keys()) | {""}
    emit("\n  loaded jobs without a plist in the standard dirs (apple jobs omitted):")
    for line in loaded.splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        label = parts[2]
        if label.startswith("com.apple.") or label in known:
            continue
        emit("    %s" % label)

    # ── 3. flags ────────────────────────────────────────────────────────────
    emit("\n# FLAGS (%d)" % len(flags))
    for cls, path, sig, owners in flags:
        emit("  [!!] %-14s %-80s %s" % (cls, path, sig))

    if "--out" in sys.argv:
        open(sys.argv[sys.argv.index("--out") + 1], "w").write("\n".join(out) + "\n")

if __name__ == "__main__":
    main()
