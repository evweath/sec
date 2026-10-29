#!/usr/bin/env python3
"""evw-rollback.py — restore files to any committed integrity-store state.

Design: FILE-INTEGRITY-ROLLBACK-PLAN.md §7.

  evw-rollback.py list    [--store S] [--since COMMIT]
  evw-rollback.py restore [--store S] [--since COMMIT]
                          (--paths a,b,c | --file LIST | --all)
                          [--dry-run] [--apply] [--keep-new]
  evw-rollback.py restore --source github [--repo owner/name] [--ref REF]
                          [--repo-root ROOT] (--paths a,b,c | --file LIST)
                          [--dry-run] [--apply]

Defaults: --since HEAD, local integrity store, --dry-run (restore requires
explicit --apply). GitHub restore uses gh and is limited to repository-tracked
files beneath the repo root; it never handles --all.
Useful commits: "seed" (first baseline), "known-good" (last deploy-window /
rollback commit), or any sha from `git -C <store>/tree log`.

After an --apply the store is RE-BASELINED (restored state committed to the
mirror and tagged "known-good"), so the next sweep sees a consistent world.
Restore is itself reversible: every run writes quarantine/<ts>/UNDO.json.

Root required for --apply on system paths. Python 3.9+, stdlib only.
"""
import hashlib
import json
import os
import pwd
import re
import sqlite3
import subprocess
import sys
import time
import urllib.parse

DEFAULT_STORE = "/var/db/evw-integrity"


def owner_home():
    configured = os.environ.get("EVW_OWNER_HOME")
    if configured:
        return os.path.abspath(os.path.expanduser(configured))
    if os.geteuid() != 0:
        return os.path.expanduser("~")
    try:
        r = subprocess.run(["/usr/bin/stat", "-f", "%Su", "/dev/console"],
                           capture_output=True, text=True, timeout=5)
        user = r.stdout.strip()
        if r.returncode == 0 and user and user != "root":
            return pwd.getpwnam(user).pw_dir
    except (KeyError, OSError, subprocess.TimeoutExpired):
        pass
    return os.path.expanduser("~")


HOME = owner_home()
SEC_DIR = os.environ.get("EVW_SECURITY_DIR", os.path.join(HOME, "dev", "security"))


def git(store, *args, binary=False):
    return subprocess.run(["git", "-C", os.path.join(store, "tree")] + list(args),
                          capture_output=True, text=not binary)


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def resolve_commit(store, since):
    r = git(store, "rev-parse", "--verify", since)
    if r.returncode != 0:
        sys.exit("unknown commit: %s" % since)
    return r.stdout.strip()


def tree_files(store, commit):
    out = {}
    r = git(store, "ls-tree", "-r", commit)
    for line in r.stdout.splitlines():
        meta, path = line.split("\t", 1)
        mode, _typ, sha = meta.split()
        out["/" + path] = (mode, sha)
    return out


def blob_bytes(store, commit, path):
    r = git(store, "show", "%s:%s" % (commit, path.lstrip("/")), binary=True)
    if r.returncode != 0:
        raise FileNotFoundError(path)
    return r.stdout


def github_repo(repo_root, configured=None):
    if configured:
        return configured.removesuffix(".git")
    r = subprocess.run(["git", "-C", repo_root, "remote", "get-url", "origin"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError("cannot determine GitHub origin; pass --repo owner/name")
    m = re.search(r"github\.com[:/]([^/]+)/([^/]+?)(?:\.git)?$", r.stdout.strip())
    if not m:
        raise RuntimeError("origin is not a GitHub repository: %s" % r.stdout.strip())
    return "%s/%s" % m.groups()


def repo_relative(path, repo_root):
    root = os.path.realpath(repo_root)
    target = os.path.realpath(path)
    try:
        rel = os.path.relpath(target, root)
    except ValueError:
        raise ValueError("path is outside repository root: %s" % path)
    if rel == ".." or rel.startswith("../"):
        raise ValueError("path is outside repository root: %s" % path)
    return rel


def github_blob(repo, ref, rel):
    endpoint = "repos/%s/contents/%s?%s" % (
        repo, urllib.parse.quote(rel, safe="/"),
        urllib.parse.urlencode({"ref": ref}))
    try:
        r = subprocess.run(["gh", "api", endpoint, "-H",
                            "Accept: application/vnd.github.raw"],
                           capture_output=True)
    except OSError as e:
        raise RuntimeError("gh executable unavailable: %s" % e)
    if r.returncode != 0:
        detail = r.stderr.decode("utf-8", "replace").strip().splitlines()
        raise FileNotFoundError("%s (%s)" % (rel, detail[-1] if detail else "gh api failed"))
    return r.stdout


def github_mode(repo_root, ref, rel):
    r = subprocess.run(["git", "-C", repo_root, "ls-tree", ref, "--", rel],
                       capture_output=True, text=True)
    if r.returncode == 0 and r.stdout.strip():
        return r.stdout.split()[0]
    return "100644"


def index_connect(store):
    db = sqlite3.connect(os.path.join(store, "index.db"))
    db.execute("""CREATE TABLE IF NOT EXISTS files(
        path TEXT PRIMARY KEY, size INT, mtime_ns INT, mode INT,
        uid INT, gid INT, sha256 TEXT, tier TEXT, snap INTEGER)""")
    return db


def live_status(store, commit):
    tfiles = tree_files(store, commit)
    changed, missing = [], []
    for path, (_mode, _sha) in tfiles.items():
        if not os.path.exists(path):
            missing.append(path)
        else:
            try:
                live_blob = open(path, "rb").read()
                if sha256_bytes(live_blob) != sha256_bytes(blob_bytes(store, commit, path)):
                    changed.append(path)
            except (OSError, PermissionError):
                changed.append(path)
    return changed, missing


def index_new_paths(store, commit, db):
    """Tracked in index but absent from the target commit = post-commit arrivals."""
    tfiles = tree_files(store, commit)
    out = []
    for (p,) in db.execute("SELECT path FROM files"):
        if p not in tfiles and os.path.exists(p):
            out.append(p)
    return out


def re_baseline(store, commit, restored, removed, db):
    """Mirror/index/commit the post-rollback state so the next sweep is clean."""
    for entry in restored:
        path = entry["path"]
        mp = os.path.join(store, "tree", path.lstrip("/"))
        if os.path.exists(path):
            os.makedirs(os.path.dirname(mp), exist_ok=True)
            subprocess.run(["cp", "-p", path, mp], check=False)
            st = os.lstat(path)
            db.execute("""INSERT OR REPLACE INTO files
                          (path,size,mtime_ns,mode,uid,gid,sha256,tier,snap)
                          VALUES(?,?,?,?,?,?,?,COALESCE((SELECT tier FROM files WHERE path=?),'A'),1)""",
                       (path, st.st_size, st.st_mtime_ns, st.st_mode & 0o7777,
                        st.st_uid, st.st_gid, entry["restore_sha"], path))
    for path in removed:
        mp = os.path.join(store, "tree", path.lstrip("/"))
        if os.path.exists(mp):
            os.unlink(mp)
        db.execute("DELETE FROM files WHERE path=?", (path,))
    db.commit()
    git(store, "add", "-A")
    r = git(store, "commit", "-q", "--allow-empty",
            "-m", "rollback re-baseline to %.8s (+%d restored, -%d removed)"
                 % (commit, len(restored), len(removed)))
    if r.returncode == 0:
        git(store, "tag", "-f", "known-good")


def do_restore(store, commit, paths, new_paths, apply, keep_new,
               source="local", repo=None, ref="main", repo_root=None):
    ts = time.strftime("%Y%m%d-%H%M%S")
    qdir = os.path.join(store, "quarantine", ts)
    undo, restored, removed, results = [], [], [], []
    db = index_connect(store)
    repo_root = repo_root or SEC_DIR

    def owner_for(path):
        row = db.execute("SELECT uid,gid FROM files WHERE path=?", (path,)).fetchone()
        if row:
            return row
        if os.path.exists(path):
            st = os.lstat(path)
            return st.st_uid, st.st_gid
        if source == "github":
            st = os.lstat(repo_root)
            return st.st_uid, st.st_gid
        if path.startswith(HOME + "/"):
            st = os.lstat(HOME)
            return st.st_uid, st.st_gid
        return 0, 0

    for path in paths:
        entry = {"path": path, "source": source}
        try:
            if source == "github":
                rel = repo_relative(path, repo_root)
                repo_name = github_repo(repo_root, repo)
                blob = github_blob(repo_name, ref, rel)
                gmode = github_mode(repo_root, ref, rel)
                entry.update({"repo": repo_name, "ref": ref, "repo_path": rel})
            else:
                blob = blob_bytes(store, commit, path)
                gmode = tree_files(store, commit).get(path, ("100644", ""))[0]
                entry["commit"] = commit
        except (FileNotFoundError, RuntimeError, ValueError) as e:
            results.append(("SKIP-NOT-AVAILABLE (%s)" % e, path))
            continue
        cur_sha = None
        if os.path.exists(path):
            try:
                cur_sha = sha256_file(path)
            except (OSError, PermissionError):
                pass
        if cur_sha == sha256_bytes(blob):
            results.append(("UNCHANGED", path))
            continue
        entry["current_sha"] = cur_sha
        entry["restore_sha"] = sha256_bytes(blob)
        if not apply:
            results.append(("WOULD-RESTORE-%s" % source.upper(), path))
            undo.append(entry)
            continue
        if os.path.exists(path):
            qp = os.path.join(qdir, path.lstrip("/"))
            os.makedirs(os.path.dirname(qp), exist_ok=True)
            subprocess.run(["cp", "-p", path, qp], check=False)
            entry["quarantined_to"] = qp
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".integrity-tmp"
        with open(tmp, "wb") as f:
            f.write(blob)
        os.chmod(tmp, 0o755 if gmode.endswith("755") else 0o644)
        try:
            uid, gid = owner_for(path)
            os.chown(tmp, uid, gid)
        except (OSError, PermissionError):
            pass
        os.rename(tmp, path)
        ok = sha256_file(path) == entry["restore_sha"]
        if path.endswith(".plist"):
            lint = subprocess.run(["plutil", "-lint", path], capture_output=True)
            ok = ok and lint.returncode == 0
        entry["verified"] = ok
        undo.append(entry)
        restored.append(entry)
        results.append(("RESTORED-%s" % source.upper()
                        if ok else "RESTORED-%s-UNVERIFIED" % source.upper(), path))

    for path in new_paths:
        if keep_new:
            results.append(("KEPT-NEW", path))
            continue
        if not apply:
            results.append(("WOULD-QUARANTINE-NEW", path))
            continue
        qp = os.path.join(qdir, path.lstrip("/"))
        os.makedirs(os.path.dirname(qp), exist_ok=True)
        try:
            os.rename(path, qp)
            removed.append(path)
            undo.append({"path": path, "quarantined_to": qp, "was_new": True})
            results.append(("QUARANTINED-NEW", path))
        except OSError as e:
            results.append(("QUARANTINE-FAILED (%s)" % e, path))

    if apply and (restored or removed):
        os.makedirs(qdir, exist_ok=True)
        with open(os.path.join(qdir, "UNDO.json"), "w") as f:
            json.dump(undo, f, indent=1)
        re_baseline(store, commit, restored, removed, db)
        with open(os.path.join(store, "logs", "events.log"), "a") as f:
            f.write("[%s] rollback to %.8s: %d restored, %d quarantined — undo: %s\n"
                    % (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                       commit, len(restored), len(removed),
                       os.path.join(qdir, "UNDO.json")))
    db.close()
    return results


def main():
    args = sys.argv[1:]
    if len(args) < 1 or args[0] in ("-h", "--help"):
        print(__doc__)
        sys.exit(64)
    action = args[0]
    store = DEFAULT_STORE
    if "--store" in args:
        store = args[args.index("--store") + 1]
    since = "HEAD"
    if "--since" in args:
        since = args[args.index("--since") + 1]
    apply = "--apply" in args
    dry = "--dry-run" in args or not apply
    keep_new = "--keep-new" in args
    source = "github" if "--github" in args else "local"
    if "--source" in args:
        source = args[args.index("--source") + 1]
    if source not in ("local", "github"):
        sys.exit("unknown restore source: %s" % source)
    repo = os.environ.get("EVW_GITHUB_REPO")
    if "--repo" in args:
        repo = args[args.index("--repo") + 1]
    ref = os.environ.get("EVW_GITHUB_REF", "main")
    if "--ref" in args:
        ref = args[args.index("--ref") + 1]
    repo_root = os.environ.get("EVW_REPO_ROOT", SEC_DIR)
    if "--repo-root" in args:
        repo_root = args[args.index("--repo-root") + 1]

    if not os.path.isdir(os.path.join(store, "tree", ".git")):
        sys.exit("no integrity store at %s" % store)
    commit = resolve_commit(store, since)

    if action == "list":
        changed, missing = live_status(store, commit)
        print("commit %s — live differs:" % commit[:8])
        for p in changed:
            print("  CHANGED  %s" % p)
        for p in missing:
            print("  MISSING  %s" % p)
        db = index_connect(store)
        new = index_new_paths(store, commit, db)
        for p in new:
            print("  NEW      %s" % p)
        db.close()
        if not changed and not missing and not new:
            print("  (clean — live filesystem matches committed state)")
        sys.exit(0)

    if action != "restore":
        sys.exit("unknown action: %s" % action)

    paths, new_paths = [], []
    if "--paths" in args:
        paths = [p for p in args[args.index("--paths") + 1].split(",") if p]
    elif "--file" in args:
        with open(args[args.index("--file") + 1]) as f:
            paths = [l.strip() for l in f if l.strip()]
    elif "--all" in args:
        if source == "github":
            sys.exit("GitHub restore is path-scoped; use --paths or --file, not --all")
        changed, missing = live_status(store, commit)
        paths = changed + missing
        db = index_connect(store)
        new_paths = index_new_paths(store, commit, db)
        db.close()
    else:
        sys.exit("restore needs --paths, --file, or --all")

    if dry:
        print("DRY RUN — no filesystem changes (add --apply to execute)")
    results = do_restore(store, commit, paths, new_paths, apply, keep_new,
                         source=source, repo=repo, ref=ref, repo_root=repo_root)
    for status, p in results:
        print("  %-24s %s" % (status, p))
    n = sum(1 for s, _ in results if s.startswith(("RESTORED", "QUARANTINED")))
    print("\n%d restored/quarantined, %d skipped/unchanged (commit %.8s)%s"
          % (n, len(results) - n, commit,
             "" if apply else " — re-run with --apply"))


if __name__ == "__main__":
    main()
