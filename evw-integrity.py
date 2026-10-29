#!/usr/bin/env python3
"""evw-integrity.py — whole-disk file-integrity scanner with content snapshots,
unified diffs, and a self-heal policy engine.

Design: FILE-INTEGRITY-ROLLBACK-PLAN.md (2026-09-03).

Modes:
  init                        create the store (tree/ + git + index.db)
  sweep [--tiers A] [--heal]  stat-walk, hash candidates, snapshot confirmed
                              changes, git-commit, write delta report
  full  [--tiers A,B,C,D,E]   hash every covered file (ground truth)
  verify [--sample 1000]      git fsck + random re-hash sample + store stats
  canary                      write canary token; next sweep+heal must restore it

Store layout (default /var/db/evw-integrity; override with --store for tests):
  tree/        mirror of watched files (git working tree)
  index.db     sqlite: path -> stat + sha256 + tier
  quarantine/  pre-rollback and heal-quarantined copies
  reports/     delta reports (also copied to ~/dev/security/scan-<date>/)
  logs/events.log  append-only event log
  deploy.marker    presence = admin deploy window (auto-approve, no heal)

Python 3.9+, stdlib only. Root required for production paths.
"""
import difflib
import errno
import fcntl
import hashlib
import json
import os
import pwd
import re
import sqlite3
import stat as statmod
import subprocess
import sys
import time

VERSION = "1.2 (2026-10-29)"  # 1.2: tier E — hash-only ~/dev code coverage
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

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error_guard.py)
try:
    import pathlib as _pathlib, sys as _sys
    _d = _pathlib.Path(__file__).resolve().parent
    for _ in range(6):
        if (_d / "lib" / "error_guard.py").exists():
            _sys.path.insert(0, str(_d / "lib"))
            break
        _d = _d.parent
    from error_guard import guard_run, guarded, SKIP, throw, GuardError
except ImportError:
    SKIP = object()
    def guard_run(_l, fn, *a, **kw): return fn(*a, **kw)
    def guarded(_l=None):
        def deco(fn): return fn
        return deco
    class GuardError(RuntimeError): pass
    def throw(msg): raise GuardError(str(msg))

# ── Coverage model ────────────────────────────────────────────────────────────
LS_CONFIG = "/Library/Application Support/Objective Development/Little Snitch"

def default_tiers():
    # Test override: EVW_INTEGRITY_TIERS='{"A": ["/tmp/root/Library/LaunchDaemons"]}'
    env = os.environ.get("EVW_INTEGRITY_TIERS")
    if env:
        return json.loads(env)
    return {
        # Auto-heal scope: persistence + deployed toolkit + core configs only.
        "A": [
            "/usr/local/bin",
            "/Library/LaunchDaemons",
            "/Library/LaunchAgents",
            HOME + "/Library/LaunchAgents",
            "/private/etc",
            LS_CONFIG,
        ],
        # Report-only scope: installed software + toolkit repo + library prefs.
        "B": [
            "/Applications",
            "/opt/homebrew",
            SEC_DIR,
            "/Library/Frameworks",
            "/Library/PrivilegedHelperTools",
        ],
        "C": [
            "/Library",
            HOME + "/Library/Preferences",
        ],
        "D": [
            HOME,
        ],
        # Hash-only scope: ~/dev code trees. Each project's own git repo is the
        # content source of truth (same rationale as SEC_DIR), so tier E records
        # hashes in the index + OTS-stamped reports but never snapshots content
        # and never auto-heals. DEV_EXCLUDE_RE skips dependency/build trees and
        # churning artifacts (venvs, caches, DBs, archives, backups).
        "E": [
            HOME + "/dev",
        ],
    }

EXCLUDE_RE = re.compile(
    r"(^|/)(\.git|\.Trash|Caches|CachedData|Logs?|node_modules|__pycache__|"
    r"\.npm|\.cargo|\.rustup|TrafficLog|ip-address-database|"
    r"CloudDocs/session|Mobile Documents/com~apple~CloudDocs/.*/)(/|$)|"
    r"/private/var/(vm|folders)/|"
    r"\.(DS_Store)$")

# Extra excludes applied only under HOME + "/dev": dependency/build trees and
# churning or bulky artifacts that carry no tamper signal.
DEV = HOME + "/dev"
DEV_EXCLUDE_RE = re.compile(
    r"(^|/)(\.venv|venv|\.tox|\.nox|\.pytest_cache|\.mypy_cache|\.ruff_cache|"
    r"\.ipynb_checkpoints|\.next|\.turbo|dist|build|target|htmlcov|coverage|"
    r"logs?|local-backups|mainbakups|backups|exports|scan_cache)(/|$)|"
    r"\.(db|db-shm|db-wal|sqlite3?|zip|tar|gz|tgz|bz2|xz|dmg|iso|whl|"
    r"pyc|pyo|log)$|\.bak(-.*)?$")

SNAPSHOT_CAP = {"A": 10 * 1024 * 1024, "B": 10 * 1024 * 1024,
                "C": 1 * 1024 * 1024, "D": 1 * 1024 * 1024}

# Tier A auto-heal scope (NOT ~/dev/security — the git working repo is the
# source of truth and must never be auto-reverted; it is report-only).
HEAL_PATHS = tuple(json.loads(os.environ["EVW_INTEGRITY_HEAL"])) \
    if os.environ.get("EVW_INTEGRITY_HEAL") else (
    "/Library/LaunchDaemons",
    "/Library/LaunchAgents",
    HOME + "/Library/LaunchAgents",
    "/usr/local/bin",
    "/private/etc",
)

MASS_CHANGE_THRESHOLD = 500
MARKER_MAX_AGE = 3600  # deploy.marker older than this is stale

# ── Small helpers ─────────────────────────────────────────────────────────────

def log_line(store, msg):
    line = "[%s] %s\n" % (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), msg)
    with open(os.path.join(store, "logs", "events.log"), "a") as f:
        f.write(line)
    return line.rstrip("\n")

def sha256_file(path, _bufsize=1024 * 1024):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(_bufsize)
            if not b:
                break
            h.update(b)
    return h.hexdigest()

def is_probably_text(path, sniff=4096):
    try:
        with open(path, "rb") as f:
            b = f.read(sniff)
        if b.startswith(b"bplist00"):
            return False
        b.decode("utf-8")
        return True
    except (OSError, UnicodeDecodeError):
        return False

def is_plist(path):
    if path.endswith(".plist"):
        return True
    try:
        with open(path, "rb") as f:
            return f.read(8) == b"bplist00"
    except OSError:
        return False

def plist_xml(path):
    try:
        r = subprocess.run(["plutil", "-convert", "xml1", "-o", "-", path],
                           capture_output=True, timeout=30)
        if r.returncode == 0:
            return r.stdout.decode("utf-8", "replace").splitlines()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None

def read_text_lines(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read().splitlines()
    except OSError:
        return None

def tier_of(path, tiers):
    best, best_len = None, -1
    for t, roots in tiers.items():
        for root in roots:
            if path == root or path.startswith(root.rstrip("/") + "/"):
                if len(root) > best_len:
                    best, best_len = t, len(root)
    # first matching tier by longest prefix, but lowest letter wins ties
    return best

def should_snapshot(path, tier, size):
    if tier == "E":
        return False  # hash-only tier — project git repos are the content record
    cap = SNAPSHOT_CAP.get(tier or "D", 1024 * 1024)
    if size > cap:
        return False
    if tier in ("A", "B"):
        return True
    return is_probably_text(path) or is_plist(path)

def mirror_path(store, path):
    return os.path.join(store, "tree", path.lstrip("/"))

def git(store, *args, check=False):
    r = subprocess.run(["git", "-C", os.path.join(store, "tree")] + list(args),
                       capture_output=True, text=True, errors="replace")
    if check and r.returncode != 0:
        throw("git %s failed: %s" % (" ".join(args), r.stderr.strip()[:200]))
    return r

def ots_stamp(store, target):
    ots = None
    for cand in (HOME + "/Library/Python/3.9/bin/ots", "/usr/local/bin/ots",
                 "/opt/homebrew/bin/ots"):
        if os.path.exists(cand):
            ots = cand
            break
    if not ots:
        return False
    r = subprocess.run([ots, "stamp", target], capture_output=True, timeout=300)
    return r.returncode == 0

def notify(title, msg):
    try:
        subprocess.run(["/usr/bin/osascript", "-e",
                        'display notification "%s" with title "%s" sound name "Basso"'
                        % (msg.replace('"', "'"), title.replace('"', "'"))],
                       capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        subprocess.run(["/usr/bin/logger", "-t", "evw-integrity",
                        "%s: %s" % (title, msg)], capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        pass

# ── Index ─────────────────────────────────────────────────────────────────────

def index_connect(store):
    db = sqlite3.connect(os.path.join(store, "index.db"))
    db.execute("""CREATE TABLE IF NOT EXISTS files(
        path TEXT PRIMARY KEY, size INT, mtime_ns INT, mode INT,
        uid INT, gid INT, sha256 TEXT, tier TEXT, snap INTEGER)""")
    db.execute("CREATE INDEX IF NOT EXISTS ix_tier ON files(tier)")
    return db

def index_map(db):
    return {r[0]: r[1:] for r in db.execute(
        "SELECT path,size,mtime_ns,mode,uid,gid,sha256,tier,snap FROM files")}

# ── Modes ─────────────────────────────────────────────────────────────────────

def mode_init(store):
    for sub in ("tree", "quarantine", "reports", "logs"):
        os.makedirs(os.path.join(store, sub), exist_ok=True)
    if not os.path.isdir(os.path.join(store, "tree", ".git")):
        git(store, "init", "-q")
        git(store, "config", "user.name", "evw-integrity")
        git(store, "config", "user.email", "integrity@localhost")
        git(store, "config", "commit.gpgsign", "false")
    index_connect(store).close()
    open(os.path.join(store, "logs", "events.log"), "a").close()
    print(log_line(store, "store initialized at %s" % store))


def walk_tiers(tier_letters, tiers, errors=None):
    """yield (path, tier) for every covered file, excludes applied."""
    seen = set()
    for t in tier_letters:
        for root in tiers.get(t, []):
            if not os.path.isdir(root):
                if errors is not None:
                    errors.append((root, "root missing or unreadable"))
                continue

            def onerror(err):
                if errors is not None:
                    errors.append((getattr(err, "filename", None) or root,
                                   getattr(err, "strerror", None) or str(err)))

            for dirpath, dirnames, filenames in os.walk(root, onerror=onerror):
                in_dev = dirpath == DEV or dirpath.startswith(DEV + "/")
                dirnames[:] = [d for d in dirnames
                               if not EXCLUDE_RE.search(dirpath + "/" + d + "/")
                               and not (in_dev and DEV_EXCLUDE_RE.search(dirpath + "/" + d + "/"))
                               and not os.path.islink(os.path.join(dirpath, d))]
                for name in filenames:
                    p = os.path.join(dirpath, name)
                    if p in seen or EXCLUDE_RE.search(p):
                        continue
                    if in_dev and DEV_EXCLUDE_RE.search(p):
                        continue
                    if os.path.islink(p):
                        continue
                    seen.add(p)
                    yield p, t


def make_diff(store, path, new_content_lines):
    """Unified diff of last-committed vs current content. None if unavailable."""
    import tempfile
    rel = path.lstrip("/")
    in_head = git(store, "cat-file", "-e", "HEAD:" + rel).returncode == 0
    if not is_plist(path) and not is_probably_text(path):
        return "(binary file changed — hash-only, no text diff)"
    if is_plist(path):
        new = plist_xml(path)
        old = []
        if in_head:
            r = git(store, "show", "HEAD:" + rel)
            with tempfile.NamedTemporaryFile(delete=False) as tf:
                tf.write(r.stdout.encode("utf-8", "replace"))
                tmp = tf.name
            old = plist_xml(tmp)
            try:
                os.unlink(tmp)
            except OSError:
                pass
        if old is None or new is None:
            return None
    else:
        old = git(store, "show", "HEAD:" + rel).stdout.splitlines() if in_head else []
        new = new_content_lines
    if new is None:
        return None
    if old == new:
        return "(content identical after normalization)"
    return "\n".join(difflib.unified_diff(old, new,
                     "prev:" + rel, "curr:" + rel, lineterm=""))[:8000]


def deploy_active(store):
    m = os.path.join(store, "deploy.marker")
    if not os.path.exists(m):
        return False
    age = time.time() - os.path.getmtime(m)
    if age > MARKER_MAX_AGE:
        try:
            os.unlink(m)
        except OSError:
            pass
        return False
    return True


def head_blob(store, path):
    """Content of path at HEAD as bytes, or None."""
    r = subprocess.run(["git", "-C", os.path.join(store, "tree"), "show",
                        "HEAD:" + path.lstrip("/")], capture_output=True)
    return r.stdout if r.returncode == 0 else None


def head_mode(store, path):
    r = git(store, "ls-tree", "HEAD", "--", path.lstrip("/"))
    if r.returncode == 0 and r.stdout.strip():
        return r.stdout.split()[0]  # 100644 / 100755
    return "100644"


def bootout_for(path):
    if "/LaunchDaemons/" in path or "/LaunchAgents/" in path:
        label = os.path.basename(path)[:-len(".plist")] if path.endswith(".plist") else ""
        if label:
            for dom in ("system", "gui/501"):
                subprocess.run(["launchctl", "bootout", dom + "/" + label],
                               capture_output=True, timeout=10)


def heal_new(store, path, healed):
    """Quarantine a NEW file appearing in auto-heal scope (never snapshotted)."""
    ts = time.strftime("%Y%m%d-%H%M%S")
    qpath = os.path.join(store, "quarantine", ts, path.lstrip("/"))
    os.makedirs(os.path.dirname(qpath), exist_ok=True)
    try:
        os.rename(path, qpath)
        bootout_for(path)
        msg = "quarantined NEW file in protected scope: %s -> %s" % (path, qpath)
        log_line(store, "HEAL " + msg)
        notify("FS-INTEGRITY ALERT", msg[:180])
        healed.append("HEALED: " + msg)
    except OSError as e:
        healed.append("HEAL FAILED NEW %s: %s" % (path, e))
        log_line(store, "HEAL FAILED NEW %s: %s" % (path, e))


def heal_restore(store, path, old_row, db, healed):
    """Restore a CHANGED or REMOVED protected-scope file from its HEAD blob.

    Restores from the last COMMIT (pre-tamper), never from the live mirror.
    old_row = index tuple (size,mtime_ns,mode,uid,gid,sha256,tier,snap)."""
    blob = head_blob(store, path)
    if blob is None:
        healed.append("HEAL FAILED %s: no committed version to restore from" % path)
        return False
    ts = time.strftime("%Y%m%d-%H%M%S")
    try:
        if os.path.exists(path):
            qpath = os.path.join(store, "quarantine", ts, path.lstrip("/"))
            os.makedirs(os.path.dirname(qpath), exist_ok=True)
            subprocess.run(["cp", "-p", path, qpath], check=False, timeout=30)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".integrity-tmp"
        with open(tmp, "wb") as f:
            f.write(blob)
        os.chmod(tmp, 0o755 if head_mode(store, path).endswith("755") else 0o644)
        try:
            os.chown(tmp, old_row[3], old_row[4])
        except (OSError, PermissionError):
            pass
        os.rename(tmp, path)
        ok = sha256_file(path) == old_row[5]
        st = os.lstat(path)
        db.execute("UPDATE files SET size=?,mtime_ns=?,mode=?,uid=?,gid=? WHERE path=?",
                   (st.st_size, st.st_mtime_ns, statmod.S_IMODE(st.st_mode),
                    st.st_uid, st.st_gid, path))
        db.commit()
        bootout_for(path)
        msg = "restored %s from committed state%s (suspect copy quarantined)" % (
            path, "" if ok else " [VERIFY MISMATCH]")
        log_line(store, "HEAL " + msg)
        notify("FS-INTEGRITY ALERT", msg[:180])
        healed.append("HEALED: " + msg)
        return ok
    except (OSError, subprocess.TimeoutExpired) as e:
        healed.append("HEAL FAILED %s: %s" % (path, e))
        log_line(store, "HEAL FAILED %s: %s" % (path, e))
        return False


def mode_sweep(store, tier_letters, heal, report_path=None, full=False):
    tiers = default_tiers()
    db = index_connect(store)
    old = index_map(db)
    now = {}
    walk_errors = []
    skipped = []
    snapshot_failed = []
    for p, t in walk_tiers(tier_letters, tiers, walk_errors):
        real_t = tier_of(p, tiers) or t
        try:
            st = os.lstat(p)
        except OSError as e:
            skipped.append((p, "%s: %s" % (type(e).__name__, e)))
            continue
        if not statmod.S_ISREG(st.st_mode):
            continue
        now[p] = (st.st_size, st.st_mtime_ns, statmod.S_IMODE(st.st_mode),
                  st.st_uid, st.st_gid, real_t)

    new_paths = [p for p in now if p not in old]
    gone_paths = [p for p in old
                  if p not in now and (not tier_letters or old[p][6] in tier_letters)]
    cand_changed = [p for p in now if p in old
                    and (full or now[p][:5] != tuple(old[p][:5]))]

    deploying = deploy_active(store)
    confirmed_new, confirmed_chg, touched, binary_notes = [], [], [], []
    diffs, digests = {}, {}

    # ── Phase 1: classify against HEAD/index (no mirror or index mutation yet)
    def classify(p, is_new):
        try:
            digest = sha256_file(p)
        except (OSError, PermissionError) as e:
            skipped.append((p, "%s: %s" % (type(e).__name__, e)))
            return
        if not is_new and digest == old[p][5]:
            touched.append(p)
            size, mtime_ns, mode, uid, gid, real_t = now[p]
            db.execute("UPDATE files SET size=?,mtime_ns=?,mode=?,uid=?,gid=? WHERE path=?",
                       (size, mtime_ns, mode, uid, gid, p))
            return
        d = make_diff(store, p, read_text_lines(p))
        if d:
            diffs[p] = d
        digests[p] = digest
        (confirmed_new if is_new else confirmed_chg).append(p)

    for p in cand_changed:
        classify(p, False)
    for p in new_paths:
        classify(p, True)

    total_confirmed = len(confirmed_new) + len(confirmed_chg) + len(gone_paths)
    incident = total_confirmed > MASS_CHANGE_THRESHOLD
    has_head = git(store, "rev-parse", "--verify", "HEAD").returncode == 0

    # ── Phase 2: heal protected scope from HEAD (pre-tamper), BEFORE any
    #    snapshot/commit so tampered content never enters the store
    healed = []
    if heal and not deploying and not incident and has_head:
        for p in list(confirmed_new):
            if p.startswith(HEAL_PATHS):
                heal_new(store, p, healed)
                confirmed_new.remove(p)
                digests.pop(p, None)
        for p in list(confirmed_chg):
            if p.startswith(HEAL_PATHS):
                if heal_restore(store, p, old[p], db, healed):
                    confirmed_chg.remove(p)
                    digests.pop(p, None)
        for p in list(gone_paths):
            if p.startswith(HEAL_PATHS):
                if heal_restore(store, p, old[p], db, healed):
                    gone_paths.remove(p)
    elif heal and not has_head:
        healed.append("note: no committed baseline yet — first sweep is the seed; heal skipped")

    # ── Phase 3: snapshot + index + commit the remaining (observed/approved)
    for p in confirmed_new + confirmed_chg:
        size, mtime_ns, mode, uid, gid, real_t = now[p]
        snap = 1 if should_snapshot(p, real_t, size) else 0
        mp = mirror_path(store, p)
        if snap:
            os.makedirs(os.path.dirname(mp), exist_ok=True)
            try:
                with open(p, "rb") as src, open(mp, "wb") as dst:
                    dst.write(src.read())
            except (OSError, PermissionError) as e:
                snapshot_failed.append((p, "%s: %s" % (type(e).__name__, e)))
                snap = 0
        if not snap:
            binary_notes.append(p)
        db.execute("""INSERT OR REPLACE INTO files
                      (path,size,mtime_ns,mode,uid,gid,sha256,tier,snap)
                      VALUES(?,?,?,?,?,?,?,?,?)""",
                   (p, size, mtime_ns, mode, uid, gid, digests[p], real_t, snap))
    for p in gone_paths:
        mp = mirror_path(store, p)
        if os.path.exists(mp):
            try:
                os.unlink(mp)
            except OSError:
                pass
        db.execute("DELETE FROM files WHERE path=?", (p,))
    db.commit()

    first_commit = not has_head
    if total_confirmed or full or first_commit:
        git(store, "add", "-A")
        msg = "%s %s +%d ~%d -%d%s" % (
            "full" if full else "sweep",
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            len(confirmed_new), len(confirmed_chg), len(gone_paths),
            " [deploy-window]" if deploying else "")
        git(store, "commit", "-q", "-m", msg, "--allow-empty")
        if first_commit:
            git(store, "tag", "-f", "seed")
        if deploying:
            git(store, "tag", "-f", "known-good")
    head = git(store, "rev-parse", "--short", "HEAD").stdout.strip()

    awaiting = [p for p in confirmed_new + confirmed_chg
                if not p.startswith(HEAL_PATHS)]

    # ── report ──
    R = []
    R.append("=" * 72)
    R.append("EVW-INTEGRITY %s — %s" % ("FULL SCAN" if full else "SWEEP",
             time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())))
    R.append("store: %s   tiers: %s   commit: %s" % (store, ",".join(tier_letters), head))
    R.append("tracked: %d files   confirmed: +%d new, ~%d changed, -%d removed, %d touched-only, %d skipped"
             % (len(now), len(confirmed_new), len(confirmed_chg), len(gone_paths),
                len(touched), len(walk_errors) + len(skipped) + len(snapshot_failed)))
    if deploying:
        R.append("DEPLOY WINDOW ACTIVE (deploy.marker) — all changes auto-approved, no heal")
    if incident:
        R.append("!!! INCIDENT: %d changes in one sweep (> %d) — auto-heal frozen, manual review required"
                 % (total_confirmed, MASS_CHANGE_THRESHOLD))
    R.append("")
    if walk_errors or skipped or snapshot_failed:
        R.append("── UNREADABLE / SKIPPED (%d) %s" % (
            len(walk_errors) + len(skipped) + len(snapshot_failed), "─" * 30))
        for p, reason in walk_errors[:500]:
            R.append("  WALK-ERROR      %s — %s" % (p, reason))
        for p, reason in skipped[:500]:
            R.append("  HASH-FAILED     %s — %s" % (p, reason))
        for p, reason in snapshot_failed[:500]:
            R.append("  SNAPSHOT-FAILED %s — %s" % (p, reason))
        if len(walk_errors) + len(skipped) + len(snapshot_failed) > 1500:
            R.append("  … list truncated")
        R.append("")
    if healed:
        R.append("── AUTO-HEALED (protected scope) " + "─" * 32)
        for h in healed:
            R.append("  " + h)
        R.append("")
    for title, group in (("NEW", confirmed_new), ("CHANGED", confirmed_chg),
                         ("REMOVED", gone_paths)):
        if not group:
            continue
        R.append("── %s (%d) %s" % (title, len(group), "─" * 40))
        for p in group[:200]:
            R.append("  %-6s %s" % (title, p))
            if p in diffs:
                R.append("  " + "\n  ".join(diffs[p].splitlines()[:60]))
        if len(group) > 200:
            R.append("  … and %d more" % (len(group) - 200))
        R.append("")
    if binary_notes:
        R.append("── HASH-ONLY (binary/oversize, no snapshot) " + "─" * 20)
        for p in binary_notes[:100]:
            R.append("  " + p)
        R.append("")
    if awaiting:
        R.append("── AWAITING APPROVAL (outside auto-heal scope) " + "─" * 16)
        R.append("  review, then: evw-rollback.py restore --all --dry-run")
        for p in awaiting[:100]:
            R.append("  " + p)
        R.append("")
    text = "\n".join(R) + "\n"

    os.makedirs(os.path.join(store, "reports"), exist_ok=True)
    rname = "fs-integrity-%s.txt" % time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    rpath = report_path or os.path.join(store, "reports", rname)
    with open(rpath, "w") as f:
        f.write(text)
    try:
        scan = os.path.join(SEC_DIR, "scan-" + time.strftime("%Y-%m-%d"))
        os.makedirs(scan, exist_ok=True)
        with open(os.path.join(scan, rname), "w") as f:
            f.write(text)
    except OSError:
        pass
    ots_stamp(store, rpath)
    log_line(store, "%s +%d ~%d -%d touch=%d skipped=%d heal=%d incident=%s commit=%s" % (
        "full" if full else "sweep", len(confirmed_new), len(confirmed_chg),
        len(gone_paths), len(touched),
        len(walk_errors) + len(skipped) + len(snapshot_failed),
        len(healed), incident, head))
    if incident:
        notify("FS-INTEGRITY INCIDENT",
               "%d file changes in one %s — review %s" % (total_confirmed, "scan" if not full else "full scan", rpath))
    print(text)


def mode_verify(store, sample):
    ok = True
    r = git(store, "fsck", "--no-dangling")
    fsck_ok = r.returncode == 0
    print("git fsck: %s" % ("OK" if fsck_ok else "FAIL\n" + r.stderr[:500]))
    ok &= fsck_ok
    db = index_connect(store)
    rows = db.execute("SELECT path,sha256 FROM files ORDER BY RANDOM() LIMIT ?",
                      (sample,)).fetchall()
    bad = 0
    skipped = []
    for p, want in rows:
        try:
            got = sha256_file(p)
        except (OSError, PermissionError) as e:
            skipped.append((p, "%s: %s" % (type(e).__name__, e)))
            continue
        if got != want:
            bad += 1
            print("  MISMATCH: %s" % p)
    for p, reason in skipped:
        print("  SKIPPED: %s — %s" % (p, reason))
    print("sample re-hash: %d/%d clean, %d skipped"
          % (len(rows) - bad - len(skipped), len(rows), len(skipped)))
    ok &= (bad == 0)
    head = git(store, "rev-parse", "--short", "HEAD").stdout.strip()
    n_commits = git(store, "rev-list", "--count", "HEAD").stdout.strip()
    du = subprocess.run(["du", "-sh", store], capture_output=True, text=True).stdout.split()[0]
    print("store: %s   commits: %s   HEAD: %s" % (du, n_commits, head))
    log_line(store, "verify fsck=%s sample=%d bad=%d store=%s" % (fsck_ok, len(rows), bad, du))
    sys.exit(0 if ok else 1)


def mode_canary(store):
    live = "/usr/local/bin/evw-canary"
    token = "canary-%d" % int(time.time())
    # seed mirror + live twin so the next sweep sees a stable tracked file
    mp = mirror_path(store, live)
    os.makedirs(os.path.dirname(mp), exist_ok=True)
    with open(mp, "w") as f:
        f.write(token + "\n")
    git(store, "add", "-A")
    git(store, "commit", "-q", "-m", "canary seed " + token)
    try:
        os.makedirs(os.path.dirname(live), exist_ok=True)
        with open(live, "w") as f:
            f.write(token + "\n")
    except (OSError, PermissionError) as e:
        print("canary: mirror seeded but cannot write live %s: %s" % (live, e))
        print("run with sudo for the full round-trip")
        return
    print("canary seeded: %s -> %s" % (token, live))
    print("round-trip test: modify/delete %s, then the next pulse (sweep --heal)" % live)
    print("must quarantine+restore it. Verify: cat %s | grep %s" % (live, token))


class StoreLock:
    def __init__(self, store, timeout=None):
        self.store = store
        self.timeout = float(timeout if timeout is not None
                             else os.environ.get("EVW_INTEGRITY_LOCK_TIMEOUT", "30"))
        self.handle = None

    def __enter__(self):
        os.makedirs(self.store, exist_ok=True)
        self.handle = open(os.path.join(self.store, "scan.lock"), "a+")
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except OSError as e:
                if e.errno not in (errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK):
                    raise
                if time.monotonic() >= deadline:
                    raise TimeoutError("integrity store is locked by another scan")
                time.sleep(0.2)

    def __exit__(self, _exc_type, _exc, _tb):
        if self.handle:
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
            self.handle.close()
        return False


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        sys.exit(64)
    mode = args[0]
    store = DEFAULT_STORE
    if "--store" in args:
        store = args[args.index("--store") + 1]
    tiers = ["A"]
    if "--tiers" in args:
        tiers = [t.strip() for t in args[args.index("--tiers") + 1].split(",")]
    heal = "--heal" in args
    report = None
    if "--report" in args:
        report = args[args.index("--report") + 1]
    sample = 1000
    if "--sample" in args:
        sample = int(args[args.index("--sample") + 1])

    if mode != "init" and not os.path.isdir(os.path.join(store, "tree", ".git")):
        print("store not initialized: run 'evw-integrity.py init --store %s' first" % store)
        sys.exit(1)

    if mode == "init":
        mode_init(store)
        return
    try:
        with StoreLock(store):
            if mode == "sweep":
                mode_sweep(store, tiers, heal, report, full=False)
            elif mode == "full":
                mode_sweep(store, tiers, heal, report, full=True)
            elif mode == "verify":
                mode_verify(store, sample)
            elif mode == "canary":
                mode_canary(store)
            else:
                print("unknown mode: %s" % mode)
                sys.exit(64)
    except TimeoutError as e:
        print("%s (try again after the active scan exits)" % e, file=sys.stderr)
        sys.exit(75)


if __name__ == "__main__":
    main()
