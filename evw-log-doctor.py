#!/usr/bin/env python3
"""evw-log-doctor.py — security-log abnormality detector + auto-remediator.

Runs as part of every evw-security-audit.sh scan (user or root mode).

Detects (new content only — per-file cursor kept between scans):
  * Python tracebacks in any evw-* error log
  * the same error signature recurring >= SIG_ALERT times in the new window
    (the 2026-10-20/21 failure classes: integrity UnicodeDecodeError crash-loop,
    ls-watchdog guard_run rc=2 spam — both invisible until someone read the logs)
  * err-log growth storms (> STORM_BYTES since the last scan)

Auto-remediates (root mode only; user mode reports "would-fix"):
  * ROTATE   any err log larger than ROTATE_BYTES (mv to .1)
  * RESTART  the LaunchDaemon mapped to a log with a recurring signature
             (>= SIG_RESTART hits), at most once per signature per 24 h
             (launchctl kickstart -k) — clears wedged operational state
  * ESCALATE when a signature persists AFTER a restart, or on a traceback
             storm: post a CRITICAL alert via the alert-center contract
             (/var/db/evw-security-system/alerts/<id>.json) so a human fixes
             the underlying code — code bugs are surfaced, never auto-patched

Output: <scan-dir>/log-doctor-report.txt + one stdout summary line:
  log-doctor: files=N new-lines=M abnormalities=K actions=R alerts=A

State: logs/.log-doctor-state.json (per-file inode+offset cursor, restart
history). First run scans only the tail (TAIL_FIRST_RUN lines) of each log —
no cursor, no history flood.

Python 3.9 compatible, stdlib only.
"""
import glob, json, os, re, sys, time

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

SEC = "/Users/evw/dev/security"
ALERTS_DIR = "/var/db/evw-security-system/alerts"
STATE_DEFAULT = os.path.join(SEC, "logs", ".log-doctor-state.json")

SIG_ALERT = 3          # same normalized signature this many times = abnormal
SIG_RESTART = 10       # this many times = restart the owning daemon
STORM_BYTES = 1048576  # err-log growth between scans = storm
ROTATE_BYTES = 2097152 # rotate err logs past this (matches ls-watchdog idiom)
RESTART_COOLDOWN = 86400
TAIL_FIRST_RUN = 200

ERR_PAT = re.compile(r"error|traceback|failed|denied|crash(?!-)", re.I)
TS_PAT = re.compile(
    r"(\[?\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?([+-]\d{2}:?\d{2}|Z)?\]?|"
    r"\[\d{2}:\d{2}:\d{2}\])")
HEX_PAT = re.compile(r"\b[0-9a-f]{8,}\b", re.I)
NUM_PAT = re.compile(r"\b\d+\b")
TMP_PAT = re.compile(r"(/var/tmp/|/tmp/)[\w.-]+")
PYV_PAT = re.compile(r"python3\.\d+|Python/3\.\d+")


def norm_sig(line):
    s = TS_PAT.sub("", line)
    s = TMP_PAT.sub("<TMP>", s)
    s = HEX_PAT.sub("<HEX>", s)
    s = PYV_PAT.sub("python3.x", s)
    s = NUM_PAT.sub("#", s)
    return s.strip()[:160]


def label_for(logpath):
    """Map /var/log/evw-ls-watchdog-err.log -> launchd label, if a plist exists."""
    base = os.path.basename(logpath)
    base = re.sub(r"\.log$", "", base)
    base = re.sub(r"-(err|stdout|stderr)$", "", base)
    base = re.sub(r"^evw-", "", base)
    for cand in ("com.evw.%s" % base, "com.ew.%s" % base, "local.%s" % base):
        if os.path.exists("/Library/LaunchDaemons/%s.plist" % cand):
            return cand
    return None


def load_state(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"offsets": {}, "restarts": {}}


def save_state(path, state):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=1)
    os.replace(tmp, path)
    if os.geteuid() == 0:
        try:
            os.chmod(path, 0o666)  # shared root/user runs (audit stamp idiom)
        except OSError:
            pass


def read_new(path, st_offsets):
    """Return (new_lines, growth_bytes, rotated) respecting the cursor."""
    try:
        st = os.stat(path)
    except OSError:
        return [], 0, False
    inode, size = st.st_ino, st.st_size
    cur = st_offsets.get(path)
    off = 0
    rotated = False
    if cur and cur[0] == inode and cur[1] <= size:
        off = cur[1]
    elif cur:
        rotated = True  # inode changed or shrank: log rotated under us
    lines = []
    try:
        with open(path, "r", errors="replace") as f:
            if off == 0 and size > 0:
                # first sight of this file (or rotation): tail only
                f.seek(0)
                lines = f.read().splitlines()[-TAIL_FIRST_RUN:]
            else:
                f.seek(off)
                lines = f.read().splitlines()
    except OSError:
        # root-only log in user mode — root scans cover it; leave cursor unset
        return [], 0, False
    st_offsets[path] = [inode, size]
    growth = max(0, size - off) if not rotated else size
    return lines, growth, rotated


def post_alert(severity, title, body):
    os.makedirs(ALERTS_DIR, exist_ok=True)
    aid = "logdoctor-%d" % int(time.time())
    doc = {"id": aid, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "severity": severity, "title": title[:80], "body": body,
           "source": "log-doctor", "persist": True}
    tmp = os.path.join(ALERTS_DIR, ".%s.tmp" % aid)
    with open(tmp, "w") as f:
        json.dump(doc, f)
    os.replace(tmp, os.path.join(ALERTS_DIR, "%s.json" % aid))
    try:
        os.chmod(os.path.join(ALERTS_DIR, "%s.json" % aid), 0o644)
    except OSError:
        pass  # alert-center (user evw) must be able to read it
    return aid


def kickstart(label):
    import subprocess
    r = subprocess.run(["/bin/launchctl", "kickstart", "-k", "system/%s" % label],
                       capture_output=True, text=True)
    return r.returncode == 0, (r.stderr or "").strip()


def rotate(path):
    os.replace(path, path + ".1")
    return path + ".1"


def main():
    args = sys.argv[1:]
    scan_dir = "."
    root = "--root" in args
    state_path = STATE_DEFAULT
    if "--scan-dir" in args:
        scan_dir = args[args.index("--scan-dir") + 1]
    if "--state" in args:
        state_path = args[args.index("--state") + 1]
    report_path = os.path.join(scan_dir, "log-doctor-report.txt")

    state = load_state(state_path)
    offsets = state["offsets"]
    restarts = state["restarts"]
    now = time.time()

    targets = sorted(set(
        glob.glob("/var/log/evw-*-err.log") +
        glob.glob("/var/log/evw-*.log") +
        glob.glob(os.path.join(SEC, "logs", "*-err.log")) +
        glob.glob(os.path.join(SEC, "logs", "*-stderr.log"))))

    R = []
    n_files = n_lines = n_abn = n_act = n_alert = 0
    R.append("# log-doctor report — %s  mode=%s" % (
        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "root" if root else "user"))
    R.append("")

    for path in targets:
        n_files += 1
        base = os.path.basename(path)
        is_errlog = base.endswith(("-err.log", "-stderr.log"))
        lines, growth, rotated = read_new(path, offsets)
        if not lines and growth == 0:
            continue
        n_lines += len(lines)

        # candidate error lines: err logs are error-only by definition;
        # main .log files are filtered to error-ish lines
        cand = lines if is_errlog else [l for l in lines if ERR_PAT.search(l)]
        tracebacks = sum(1 for l in lines if "Traceback (most recent call last)" in l)

        sigs = {}
        exemplar = {}
        for l in cand:
            s = norm_sig(l)
            if not s:
                continue
            sigs[s] = sigs.get(s, 0) + 1
            exemplar.setdefault(s, l.strip()[:200])

        abnormalities = []
        if tracebacks:
            abnormalities.append(("tracebacks x%d" % tracebacks, SIG_RESTART))
        for s, c in sorted(sigs.items(), key=lambda kv: -kv[1]):
            if c >= SIG_ALERT:
                abnormalities.append(("%s  x%d" % (s, c), c))
        storm = is_errlog and growth > STORM_BYTES

        if not abnormalities and not storm:
            continue

        # ── this log has a problem ──
        n_abn += 1
        R.append("## %s" % path)
        R.append("   new-lines=%d growth=%dB rotated=%s" % (len(lines), growth, rotated))
        label = label_for(path)

        if storm:
            R.append("   STORM: err-log grew %d bytes since last scan" % growth)

        worst_persistent = None
        for desc, c in abnormalities[:8]:
            R.append("   ABNORMAL: %s" % desc)
            sig_key = "%s|%s" % (label or path, desc[:80])
            last_restart = restarts.get(sig_key, 0)

            if root and label and c >= SIG_RESTART:
                if now - last_restart > RESTART_COOLDOWN:
                    ok, err = kickstart(label)
                    restarts[sig_key] = now
                    n_act += 1
                    R.append("   ACTION: restart %s -> %s" % (label, "OK" if ok else "FAILED %s" % err))
                else:
                    worst_persistent = desc
                    R.append("   PERSISTENT: already restarted %.1fh ago — escalating"
                             % ((now - last_restart) / 3600.0))
            elif not root and label and c >= SIG_RESTART:
                R.append("   would-fix (root only): restart %s" % label)

        # rotate oversized err logs (root only)
        if root and is_errlog:
            try:
                if os.path.getsize(path) > ROTATE_BYTES:
                    dst = rotate(path)
                    offsets.pop(path, None)
                    n_act += 1
                    R.append("   ACTION: rotated -> %s" % dst)
            except OSError as e:
                R.append("   rotate failed: %r" % e)
        elif not root and is_errlog:
            try:
                if os.path.getsize(path) > ROTATE_BYTES:
                    R.append("   would-fix (root only): rotate (>2MB)")
            except OSError:
                pass

        # escalate persistent / traceback storms via alert-center (root only)
        if root and (worst_persistent or tracebacks >= 5):
            why = worst_persistent or ("tracebacks x%d" % tracebacks)
            ex = exemplar.get(worst_persistent.split("  x")[0], "") if worst_persistent else ""
            aid = guard_run("alert", post_alert, "CRITICAL",
                            "log-doctor: recurring failure in %s" % (label or base),
                            "%s\nlog: %s\nexample: %s\n"
                            "Restart already attempted or code-level bug — human fix required."
                            % (why, path, ex))
            if aid and aid is not SKIP:
                n_alert += 1
                R.append("   ALERT posted: %s" % aid)
        elif not root and (worst_persistent or tracebacks >= 5):
            R.append("   would-alert (root only): CRITICAL recurring failure")
        R.append("")

    if n_abn == 0:
        R.append("no abnormalities in %d logs (%d new lines scanned)" % (n_files, n_lines))

    guard_run("save-state", save_state, state_path, state)
    guard_run("write-report", lambda: open(report_path, "w").write("\n".join(R) + "\n"))

    print("log-doctor: files=%d new-lines=%d abnormalities=%d actions=%d alerts=%d"
          % (n_files, n_lines, n_abn, n_act, n_alert))


if __name__ == "__main__":
    main()
