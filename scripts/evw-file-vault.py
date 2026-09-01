#!/usr/bin/env python3
# evw-file-vault.py — versioned snapshots of security-critical files.
#
# Every watched file is copied into a versioned vault at baseline and on EVERY
# subsequent change (including deletions — the last version stays in the vault).
# Any change is reversible with:  vault-restore.sh <original-path> [version]
#
# Runs as root LaunchDaemon (com.evw.file-vault, KeepAlive).
# Uses fswatch if installed, else 30s hash polling.
#
# NOTE: watch list mirrors mac-sentinel.py WATCHED_PATHS — keep in sync.
# Vault dir is root-only (700): it can contain copies of sensitive files.

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime

VAULT_DIR = "/var/log/mac-sentinel/file-vault"
LOG_PATH  = "/var/log/mac-sentinel/file_vault.jsonl"
KEEP      = 10          # versions per file
POLL_SECS = 30

WATCHED_PATHS = [
    "/etc/passwd", "/etc/group", "/etc/sudoers", "/etc/sudoers.d",
    "/etc/hosts", "/etc/resolv.conf", "/etc/pf.conf", "/etc/pf.anchors",
    "/etc/ssh/sshd_config", "/etc/ssh/ssh_config", "/etc/pam.d",
    "/Library/LaunchAgents", "/Library/LaunchDaemons",
    "/Users/evw/Library/LaunchAgents",
    "/usr/local/bin", "/usr/local/sbin", "/usr/local/lib",
    "/Users/evw/.ssh", "/Users/evw/.zshrc", "/Users/evw/.bash_profile",
    "/var/cron/tabs", "/etc/cron.d", "/etc/periodic",
]


def log(event: dict):
    event["ts"] = datetime.utcnow().isoformat() + "Z"
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, "a") as f:
            f.write(json.dumps(event, default=str) + "\n")
    except Exception:
        pass


def _hash(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "ERROR"


def _vault_key(path: str) -> str:
    return hashlib.sha1(path.encode()).hexdigest()[:16]


def snapshot(path: str, tag: str):
    try:
        d = os.path.join(VAULT_DIR, _vault_key(path))
        os.makedirs(d, exist_ok=True)
        os.chmod(VAULT_DIR, 0o700)
        dst = os.path.join(d, f"{int(time.time())}-{tag}-{os.path.basename(path)}")
        shutil.copy2(path, dst)
        with open(os.path.join(d, "SOURCE"), "w") as f:
            f.write(path + "\n")
        versions = sorted(v for v in os.listdir(d) if v != "SOURCE")
        for old in versions[:-KEEP]:
            os.remove(os.path.join(d, old))
        return dst
    except Exception as e:
        log({"event": "VAULT_ERROR", "path": path, "error": str(e)})
        return None


def vault_tree(path: str, tag: str):
    if os.path.isfile(path):
        snapshot(path, tag)
    elif os.path.isdir(path):
        try:
            for entry in os.scandir(path):
                if entry.is_file(follow_symlinks=False):
                    snapshot(entry.path, tag)
        except Exception:
            pass


def each_watched_file(fn):
    for p in WATCHED_PATHS:
        if os.path.isfile(p):
            fn(p)
        elif os.path.isdir(p):
            try:
                for entry in os.scandir(p):
                    if entry.is_file(follow_symlinks=False):
                        fn(entry.path)
            except Exception:
                pass


def run_fswatch():
    existing = [p for p in WATCHED_PATHS if os.path.exists(p)]
    if not existing:
        return run_polling()
    cmd = ["fswatch", "-r", "--event-flags", "--format=%p|%f", "-l", "2"] + existing
    while True:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True)
        try:
            for line in proc.stdout:
                path = line.split("|", 1)[0].strip()
                if not path or os.path.isdir(path):
                    continue
                if os.path.exists(path):
                    dst = snapshot(path, "change")
                    log({"event": "CHANGED", "path": path, "vault": dst})
                else:
                    log({"event": "DELETED", "path": path,
                         "vault": "last version retained in vault"})
            proc.wait()
        except Exception:
            time.sleep(5)


def run_polling():
    baseline = {}
    each_watched_file(lambda p: baseline.__setitem__(p, _hash(p)))
    while True:
        time.sleep(POLL_SECS)
        seen = set()
        def check(p):
            seen.add(p)
            h = _hash(p)
            if h != "ERROR" and baseline.get(p) not in (h, None):
                dst = snapshot(p, "change")
                log({"event": "CHANGED", "path": p, "vault": dst, "method": "poll"})
            if h != "ERROR":
                baseline[p] = h
        each_watched_file(check)
        for p in list(baseline):
            if p not in seen and not os.path.exists(p):
                log({"event": "DELETED", "path": p, "method": "poll"})
                del baseline[p]


def main():
    os.makedirs(VAULT_DIR, exist_ok=True)
    os.chmod(VAULT_DIR, 0o700)
    log({"event": "VAULT_START", "pid": os.getpid(),
         "watched": len(WATCHED_PATHS)})
    each_watched_file(lambda p: snapshot(p, "baseline"))
    log({"event": "BASELINE_DONE"})
    if shutil.which("fswatch"):
        run_fswatch()
    else:
        run_polling()


if __name__ == "__main__":
    main()
