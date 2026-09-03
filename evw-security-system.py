#!/usr/bin/env python3
# evw-security-system.py — self-healing security orchestrator for the evw
# workstation (macOS 26 Tahoe). Runs as root LaunchDaemon
# com.evw.security-system (KeepAlive), tick every 15 s.
#
#   daemon:   /usr/bin/python3 /usr/local/bin/evw-security-system.py
#   test:     python3 evw-security-system.py --once          # every enabled job once
#             python3 evw-security-system.py --job crash-watch
#             python3 evw-security-system.py --dry-run       # scheduling only, no side effects
#   SIGHUP reloads the installed config.
#
# Jobs: guards-check (restart dead guard daemons/agents), screenshare-scan
# (kill-on-sight remote-access processes, TCC screen-capture grants, VNC/RDP
# listeners; feed Little Snitch denies), sentinel-deny-sync (auto-close
# mac-sentinel warned endpoints in Little Snitch), crash-watch (panic/jetsam
# post-mortems), health-score (uptime/connectivity telemetry JSONL),
# audit-alerts-digest (make root-only security logs readable to evw),
# weekly-review (self-improvement report; north star = uptime + connectivity).
#
# Scheduling survives sleep/boot/downtime: interval jobs fire when
# now - last_run >= interval, so overdue jobs run immediately at startup.
# State (last_run/last_success/consec_failures/cursors per job) is persisted
# atomically (tmp + rename) after EVERY job so no work is missed or repeated.
# A circuit breaker disables a job after N consecutive failures, alerts, and
# auto re-enables it after a cooldown. One job's failure never kills the loop.
#
# Paths (production, root):
#   /var/db/evw-security-system/    state.json, security-system.json (installed
#                                   config — READ THIS ONE, never the repo copy),
#                                   health.jsonl, alerts/, ack/ (1777),
#                                   screenshare-deny-queue.txt
#   /var/log/evw-security-system.log  one line per event: ISO8601 [job] message
# When run non-root (testing) the state dir falls back to
# ~/Library/Caches/evw-security-system and the log to SEC/logs/; root-only
# steps log "SKIP (not root)" instead of crashing.
#
# Sibling contracts (do not change without coordinating):
#   alert-center (gui agent): reads alerts/<id>.json {"id","ts","severity"
#     (CRITICAL|WARNING|INFO),"title" (<=80 chars),"body","source","persist"};
#     acknowledges by writing ack/<id>. persist=true alerts are re-posted by
#     the alert center until acked or alerts.persist_minutes old.
#   ls-screenshare-deny.py (/usr/local/bin): CLI
#     <model.json> --apply --ensure-file <queue> --report <md> --undo <json>;
#     prints "ADD=n ...". Queue file format written by this daemon, one entry
#     per line:  "<codesign-identifier>\t<executable-path>"  ("-" when the
#     identifier could not be resolved); deduped on the pair.
#   evw-security-system-setup.sh: installs the root-owned config copy, the
#     LaunchDaemon plist, and creates /var/db/evw-security-system with modes
#     (dir 0755, state.json 0600, alerts/ 0755, ack/ 1777). This daemon
#     best-effort creates anything missing but does not enforce modes.
#
# Safety invariants: never reboot, never kill pid 0/1, never kill our own
# tooling (/usr/local/bin/evw-*, /Users/evw/dev/security/*), never kill
# TCC-allowlisted (com.apple.*) clients, kills rate-limited by
# self_protection.max_kills_per_minute.
#
# Requires only /usr/bin/python3 (CLT Python 3.9): stdlib only, no match,
# no PEP 604 unions outside annotations.

from __future__ import annotations

import argparse
import glob
import grp
import hashlib
import json
import os
import pwd
import re
import signal
import subprocess
import sys
import tempfile
import time
import traceback
from datetime import datetime, timedelta

SEC = "/Users/evw/dev/security"
STATE_DIR = "/var/db/evw-security-system"
LOG_PATH = "/var/log/evw-security-system.log"
REPO_CONFIG = os.path.join(SEC, "security-system.json")
SETUP_HINT = "run sudo bash ~/dev/security/evw-security-system-setup.sh to apply"
SENTINEL_FEED = "/Users/evw/Library/Logs/mac-sentinel-alert-feed.log"
LS_BIN = "/Applications/Little Snitch.app/Contents/Components/littlesnitch"
LS_SENTINEL_DENY = os.path.join(SEC, "ls-sentinel-deny.py")
LS_SCREENSHARE_DENY = "/usr/local/bin/ls-screenshare-deny.py"
DIAG_DIR = "/Library/Logs/DiagnosticReports"
NETDIAG_LOG = os.path.join(SEC, "netdiag/logs/monitor.log")
TCC_DB = "/Library/Application Support/com.apple.TCC/TCC.db"
PY = "/usr/bin/python3"
TICK_SECONDS = 15
PAGE_SIZE_DEFAULT = 16384
CONFIG_DRIFT_TITLE = "config drift: repo master differs from installed config"

# Paths that must never be killed no matter what a watchlist says.
OWN_TOOLING_PREFIXES = ("/usr/local/bin/evw-", SEC + "/")

SYSTEM_PID_REQUIRED = [
    "com.evw.plist-monitor", "com.evw.replayd-guard", "com.evw.audit-monitor",
    "com.evw.studentd-guard", "com.evw.mac-sentinel", "com.evw.auto-conn-guard",
    "com.evw.file-vault", "com.evw.ls-hygiene-guard", "com.ew.file-sentinel",
]
# Interval/one-shot jobs run and EXIT by design — a missing PID is normal;
# they only need to stay registered with launchd.
SYSTEM_LOADED_ONLY = ["com.ew.pf-devports", "com.ew.lockdown", "local.security.harden",
                      "com.evw.dns-guard", "com.ew.binding-monitor",
                      "com.evw.security-audit"]
GUI_PID_REQUIRED = ["com.evw.alert-center"]
GUI_LOADED_ONLY = ["com.evw.sentinel-alert-term", "com.ew.config-sentinel",
                   "com.evw.security-audit-login"]

DIGEST_SOURCES = [
    "/var/log/evw-audit-alerts.log",
    "/var/log/evw-audit-monitor.log",
    "/var/log/evw-security-audit.log",
    "/var/log/evw-plist-monitor.log",
]

WEEKDAYS = {"monday": 0, "tuesday": 1, "wednesday": 2, "thursday": 3,
            "friday": 4, "saturday": 5, "sunday": 6}

# ---------------------------------------------------------------------------
# runtime context (config, state, paths that may fall back when non-root)
# ---------------------------------------------------------------------------


class Ctx:
    def __init__(self) -> None:
        self.is_root = os.geteuid() == 0
        self.dry_run = False
        self.state_dir = self._pick_state_dir()
        self.alerts_dir = os.path.join(self.state_dir, "alerts")
        self.state_path = os.path.join(self.state_dir, "state.json")
        self.installed_config = os.path.join(self.state_dir, "security-system.json")
        self.queue_path = os.path.join(self.state_dir, "screenshare-deny-queue.txt")
        self.health_path = os.path.join(self.state_dir, "health.jsonl")
        self.log_path = self._pick_log_path()
        self.config = {}
        self.config_origin = ""
        self.state = {}
        self.sighup = False

    def _pick_state_dir(self) -> str:
        try:
            os.makedirs(os.path.join(STATE_DIR, "alerts"), exist_ok=True)
            os.makedirs(os.path.join(STATE_DIR, "ack"), exist_ok=True)
            if self.is_root:
                os.chmod(os.path.join(STATE_DIR, "ack"), 0o1777)
            return STATE_DIR
        except OSError:
            fb = os.path.expanduser("~/Library/Caches/evw-security-system")
            os.makedirs(os.path.join(fb, "alerts"), exist_ok=True)
            os.makedirs(os.path.join(fb, "ack"), exist_ok=True)
            return fb

    def _pick_log_path(self) -> str:
        try:
            with open(LOG_PATH, "a"):
                pass
            return LOG_PATH
        except OSError:
            return os.path.join(SEC, "logs", "evw-security-system.log")


G = Ctx()


def log(job: str, msg: str) -> None:
    line = "{} [{}] {}".format(
        datetime.now().isoformat(timespec="seconds"), job, msg)
    try:
        with open(G.log_path, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass
    print(line, flush=True)


def run(cmd, timeout=30) -> tuple[int, str, str]:
    """subprocess wrapper that never raises: (rc, stdout, stderr)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", "timeout after {}s".format(timeout)
    except OSError as e:
        return -1, "", str(e)


def skip_not_root(job: str, what: str) -> bool:
    """True when the op needs root and we are not root (logs the SKIP)."""
    if G.is_root:
        return False
    log(job, "SKIP (not root): {}".format(what))
    return True


def skip_perm(job: str, what: str, e: Exception) -> None:
    if isinstance(e, PermissionError) or (isinstance(e, OSError) and not G.is_root):
        log(job, "SKIP (not root): {} ({})".format(what, e))
    else:
        raise e


def atomic_write(path: str, text: str, chown_user: bool = False) -> None:
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    if chown_user:
        chown_evw(path)


def chown_evw(path: str) -> None:
    """Files the root daemon writes under SEC must stay user-accessible."""
    if not G.is_root:
        return
    try:
        os.chown(path, pwd.getpwnam("evw").pw_uid, grp.getgrnam("staff").gr_gid)
    except (KeyError, OSError):
        pass


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# state (atomic tmp+rename after every job)
# ---------------------------------------------------------------------------


def load_state() -> None:
    try:
        with open(G.state_path) as f:
            G.state = json.load(f)
    except FileNotFoundError:
        G.state = {}
    except (json.JSONDecodeError, OSError) as e:
        bad = G.state_path + ".bad-{}".format(int(time.time()))
        try:
            os.replace(G.state_path, bad)
        except OSError:
            pass
        log("state", "state.json unreadable ({}); backed up to {}, starting fresh".format(e, bad))
        G.state = {}
    G.state.setdefault("jobs", {})
    G.state.setdefault("cursors", {})
    G.state.setdefault("flags", {})
    G.state.setdefault("kill_log", [])
    G.state.setdefault("guards", {"up": 0, "total": 0})
    G.state.setdefault("ls_last_restore", 0)


def save_state() -> None:
    try:
        atomic_write(G.state_path, json.dumps(G.state, indent=2, sort_keys=True))
        if G.is_root:
            try:
                os.chmod(G.state_path, 0o600)
            except OSError:
                pass
    except OSError as e:
        log("state", "could not persist state: {}".format(e))


def job_state(name: str) -> dict:
    return G.state["jobs"].setdefault(name, {})


# ---------------------------------------------------------------------------
# config (installed copy wins; repo copy is the dev fallback)
# ---------------------------------------------------------------------------


def load_config() -> None:
    path = G.installed_config if os.path.exists(G.installed_config) else REPO_CONFIG
    with open(path) as f:
        G.config = json.load(f)
    G.config_origin = path


def check_config_drift() -> None:
    """One INFO alert while the repo master and installed config differ."""
    try:
        same = sha256_file(REPO_CONFIG) == sha256_file(G.installed_config)
    except OSError:
        return  # installed copy unreadable/missing — nothing to compare
    flagged = G.state["flags"].get("config_drift_alerted", False)
    if not same and not flagged:
        alert("INFO", CONFIG_DRIFT_TITLE,
              "repo master {} differs from installed {} — {}".format(
                  REPO_CONFIG, G.installed_config, SETUP_HINT),
              "config", persist=False)
        G.state["flags"]["config_drift_alerted"] = True
        save_state()
    elif same and flagged:
        G.state["flags"]["config_drift_alerted"] = False
        save_state()


# ---------------------------------------------------------------------------
# alerts (consumed by the alert-center gui agent — see header contract)
# ---------------------------------------------------------------------------


def _slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s[:40] or "alert"


def alert(severity: str, title: str, body: str, source: str, persist: bool) -> str:
    base = "{}-{}-{}".format(time.strftime("%Y%m%d-%H%M%S"), source, _slug(title))
    aid, n = base, 1
    while os.path.exists(os.path.join(G.alerts_dir, aid + ".json")):
        n += 1
        aid = "{}-{}".format(base, n)
    doc = {"id": aid, "ts": int(time.time()), "severity": severity,
           "title": title[:80], "body": body, "source": source, "persist": persist}
    try:
        atomic_write(os.path.join(G.alerts_dir, aid + ".json"),
                     json.dumps(doc, indent=2))
    except OSError as e:
        log(source, "could not write alert {}: {}".format(aid, e))
    log(source, "ALERT {} {} — {}".format(severity, title[:80], body.splitlines()[0] if body else ""))
    return aid


# ---------------------------------------------------------------------------
# kill budget + safe kill
# ---------------------------------------------------------------------------


def kill_budget_ok() -> bool:
    now = time.time()
    G.state["kill_log"] = [t for t in G.state["kill_log"] if now - t < 60]
    limit = G.config.get("self_protection", {}).get("max_kills_per_minute", 20)
    return len(G.state["kill_log"]) < limit


def own_tooling(path: str) -> bool:
    return any(path.startswith(p) for p in OWN_TOOLING_PREFIXES)


def kill_pid(job: str, pid: int, why: str) -> str:
    """Returns 'killed' | 'skipped' | 'failed'; never raises, never kills 0/1."""
    if pid in (0, 1):
        return "skipped"
    if skip_not_root(job, "kill pid {} ({})".format(pid, why)):
        return "skipped"
    if not kill_budget_ok():
        log(job, "kill budget exhausted (max_kills_per_minute); not killing pid {} ({})".format(pid, why))
        return "skipped"
    try:
        os.kill(pid, signal.SIGKILL)
        G.state["kill_log"].append(time.time())
        log(job, "SIGKILL pid {} ({})".format(pid, why))
        return "killed"
    except ProcessLookupError:
        return "skipped"
    except PermissionError as e:
        log(job, "SKIP (not root): kill pid {} ({})".format(pid, e))
        return "skipped"
    except OSError as e:
        log(job, "kill pid {} failed: {}".format(pid, e))
        return "failed"


def ps_table() -> list[tuple[int, str]]:
    """(pid, executable-path) for every process. comm is the LAST ps column so
    paths containing spaces survive split(None, 1)."""
    rc, out, _ = run(["ps", "-eo", "pid=,comm="])
    if rc != 0:
        return []
    table = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        pid_s, _, path = line.partition(" ")
        try:
            table.append((int(pid_s), path.strip()))
        except ValueError:
            continue
    return table


def rss_sum_mb(procname: str) -> float:
    rc, out, _ = run(["pgrep", "-x", procname])
    if rc != 0 or not out.strip():
        return 0.0
    pids = out.split()
    rc, out, _ = run(["ps", "-o", "rss=", "-p", ",".join(pids)])
    if rc != 0:
        return 0.0
    kb = 0
    for tok in out.split():
        try:
            kb += int(tok)
        except ValueError:
            pass
    return round(kb / 1024.0, 1)


def today_scan_dir() -> str:
    return os.path.join(SEC, time.strftime("scan-%Y-%m-%d"))


def ls_throttle_ok() -> bool:
    interval = G.config.get("self_protection", {}).get("ls_restore_min_interval_seconds", 300)
    return time.time() - G.state.get("ls_last_restore", 0) >= interval


def ls_export_model(job: str) -> str | None:
    if not os.path.exists(LS_BIN):
        log(job, "Little Snitch binary not found at {}; skipping LS step".format(LS_BIN))
        return None
    fd, tmp = tempfile.mkstemp(prefix="evw-ls-model-", suffix=".json")
    os.close(fd)
    rc, _, err = run([LS_BIN, "export-model", tmp], timeout=60)
    if rc != 0:
        log(job, "littlesnitch export-model failed: {}".format(err.strip()[:200]))
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return None
    return tmp


def ls_restore_model(job: str, path: str) -> bool:
    rc, _, err = run([LS_BIN, "restore-model", path], timeout=120)
    if rc != 0:
        log(job, "littlesnitch restore-model failed: {}".format(err.strip()[:200]))
        return False
    G.state["ls_last_restore"] = time.time()
    return True


# ---------------------------------------------------------------------------
# job: guards-check — keep the whole guard stack alive
# ---------------------------------------------------------------------------


def _launchd_pid(domain_label: str) -> tuple[bool, int | None, str]:
    """(loaded, pid, raw output) from launchctl print."""
    rc, out, err = run(["launchctl", "print", domain_label])
    if rc != 0:
        return False, None, out + err
    m = re.search(r"^\s*pid = (\d+)", out, re.M)
    return True, (int(m.group(1)) if m else None), out


def _restart_guard(job: str, domain: str, label: str, kickfail: dict) -> bool:
    """kickstart a dead guard; True when it comes back with a pid."""
    if skip_not_root(job, "kickstart {}/{}".format(domain, label)):
        return False
    rc, _, err = run(["launchctl", "kickstart", "-k", "{}/{}".format(domain, label)])
    if rc != 0:
        log(job, "kickstart {}/{} failed: {}".format(domain, label, err.strip()[:200]))
    time.sleep(1)
    loaded, pid, _ = _launchd_pid("{}/{}".format(domain, label))
    if loaded and pid:
        log(job, "guard {} was down — restarted (pid {})".format(label, pid))
        alert("WARNING", "guard {} was down — restarted".format(label),
              "{} had no running pid; 'launchctl kickstart -k {}/{}' brought it "
              "back (pid {}).".format(label, domain, label, pid),
              job, persist=False)
        kickfail[label] = 0
        return True
    kickfail[label] = kickfail.get(label, 0) + 1
    log(job, "guard {} still down after kickstart (failure {})".format(label, kickfail[label]))
    if kickfail[label] == 3:
        alert("CRITICAL", "guard {} will not stay up".format(label),
              "{} failed to restart {} times in a row via kickstart. "
              "Check its plist and its log under /var/log/.".format(label, kickfail[label]),
              job, persist=True)
    return False


def job_guards_check() -> None:
    job = "guards-check"
    st = job_state(job)
    kickfail = st.setdefault("kick_fail", {})
    restarts = st.setdefault("restarts", {})
    missing_alerts = st.setdefault("missing_alerts", {})

    up = total = 0
    down = []
    for label in SYSTEM_PID_REQUIRED:
        if label == "com.evw.security-system":
            continue
        total += 1
        loaded, pid, _ = _launchd_pid("system/" + label)
        if loaded and pid:
            up += 1
            continue
        down.append(label)
        if _restart_guard(job, "system", label, kickfail):
            up += 1
            restarts[label] = restarts.get(label, 0) + 1

    # one-shots only need to be loaded (they run and exit by design)
    for label in SYSTEM_LOADED_ONLY:
        loaded, _, _ = _launchd_pid("system/" + label)
        if loaded:
            missing_alerts.pop(label, None)
        elif label not in missing_alerts:
            missing_alerts[label] = time.time()
            alert("WARNING", "one-shot guard {} is not loaded".format(label),
                  "launchctl print system/{} reports the service is not loaded. "
                  "It is a boot-time one-shot; bootstrap it from its plist under "
                  "/Library/LaunchDaemons if the plist exists.".format(label),
                  job, persist=False)

    # gui agents: when nobody is logged in the whole gui/501 domain is absent
    gui_results = {}
    for label in GUI_PID_REQUIRED + GUI_LOADED_ONLY:
        gui_results[label] = _launchd_pid("gui/501/" + label)
    if all("Could not find service" in r[2] for r in gui_results.values()):
        log(job, "no gui/501 session (user logged out?) — skipping agent checks")
    else:
        for label in GUI_PID_REQUIRED:
            total += 1
            loaded, pid, out = gui_results[label]
            if loaded and pid:
                up += 1
                continue
            if "Could not find service" in out:
                log(job, "agent {} not in gui/501 domain (logged out?); not counting".format(label))
                total -= 1
                continue
            down.append(label)
            if _restart_guard(job, "gui/501", label, kickfail):
                up += 1
                restarts[label] = restarts.get(label, 0) + 1
        # interval/one-shot agents only need to stay registered (they exit by design)
        for label in GUI_LOADED_ONLY:
            loaded, _, _ = gui_results[label]
            if loaded:
                missing_alerts.pop(label, None)
            elif label not in missing_alerts:
                missing_alerts[label] = time.time()
                alert("WARNING", "gui guard {} is not loaded".format(label),
                      "launchctl print gui/501/{} reports the service is not loaded. "
                      "It is a login one-shot/interval job; bootstrap it from its plist "
                      "under ~/Library/LaunchAgents if the plist exists.".format(label),
                      job, persist=False)

    G.state["guards"] = {"up": up, "total": total, "down": down, "ts": int(time.time())}
    log(job, "guards up {}/{}".format(up, total) + ("; down: " + ", ".join(down) if down else ""))


# ---------------------------------------------------------------------------
# job: screenshare-scan — kill remote-access tooling, close the LS hole behind it
# ---------------------------------------------------------------------------


# SIP-protected Apple territory: binaries here are Apple-shipped, so a
# kill_on_sight match is a NAME COLLISION (e.g. CoreParsec's parsecd vs the
# Parsec remote-desktop app), not a threat — EXCEPT the three Apple
# remote-access daemons the posture explicitly kills (studentd-guard has
# reaped them every 15 s long before this daemon existed).
APPLE_KILL_OK = {"screensharingd", "ardagent", "applevncserver"}
APPLE_SYSTEM_PREFIXES = ("/System/", "/usr/libexec/", "/usr/sbin/", "/usr/bin/",
                         "/sbin/", "/bin/")


def _match_watchlist(path: str, entries) -> str | None:
    """Substring match on the executable path / its basename only — matching
    argv would false-positive on innocent commands (e.g. 'less parsec-notes.txt')."""
    low = path.lower()
    base = os.path.basename(low)
    for entry in entries:
        e = entry.lower()
        if e in base or e in low:
            return entry
    return None


def _codesign_identifier(path: str) -> str:
    rc, out, err = run(["codesign", "-dv", path])
    m = re.search(r"^Identifier=(.+)$", out + err, re.M)
    return m.group(1).strip() if m else "-"


def _queue_deny(job: str, identifier: str, path: str) -> None:
    line = "{}\t{}".format(identifier, path)
    try:
        existing = set()
        if os.path.exists(G.queue_path):
            with open(G.queue_path) as f:
                existing = {l.rstrip("\n") for l in f}
        if line in existing:
            return
        with open(G.queue_path, "a") as f:
            f.write(line + "\n")
        log(job, "queued LS deny: {}".format(line))
    except OSError as e:
        log(job, "could not append to deny queue: {}".format(e))


def _scan_watchlist(job: str, sc: dict, procs) -> None:
    st = job_state(job)
    seen_alert_only = st.setdefault("alert_only_seen", {})
    current_alert_only = {}
    killed = []
    for pid, path in procs:
        if pid in (0, 1) or own_tooling(path):
            continue
        hit = _match_watchlist(path, sc.get("kill_on_sight", []))
        if hit:
            if path.startswith(APPLE_SYSTEM_PREFIXES) and hit.lower() not in APPLE_KILL_OK:
                # Apple system binary with a colliding name — log once, never kill
                noted = st.setdefault("apple_collision_noted", [])
                marker = "{}|{}".format(hit, path)
                if marker not in noted:
                    noted.append(marker)
                    log(job, "kill_on_sight '{}' matched Apple system binary {} — "
                             "name collision, ignored".format(hit, path))
                continue
            result = kill_pid(job, pid, "{} matched kill_on_sight '{}' ({})".format(
                os.path.basename(path), hit, path))
            if result == "killed":
                killed.append((pid, path))
                _queue_deny(job, _codesign_identifier(path), path)
            continue
        hit = _match_watchlist(path, sc.get("alert_only", []))
        if hit:
            current_alert_only[str(pid)] = (os.path.basename(path), hit)
    if killed:
        alert("CRITICAL", "killed {} screen-sharing process(es)".format(len(killed)),
              "kill_on_sight matches, SIGKILLed:\n" + "\n".join(
                  "  pid {}  {}".format(pid, path) for pid, path in killed) +
              "\nIdentifiers queued for Little Snitch both-way deny.",
              job, persist=True)
    new_hits = {p: v for p, v in current_alert_only.items() if p not in seen_alert_only}
    if new_hits:
        alert("WARNING", "remote-meeting software running ({} process(es))".format(len(new_hits)),
              "alert_only watchlist matches (left running by policy):\n" + "\n".join(
                  "  pid {}  {} (matched '{}')".format(p, name, hit)
                  for p, (name, hit) in sorted(new_hits.items(), key=lambda kv: int(kv[0]))),
              job, persist=False)
    st["alert_only_seen"] = current_alert_only


def _scan_tcc(job: str, sc: dict, procs) -> None:
    rc, out, err = run(["/usr/bin/sqlite3", TCC_DB,
                        "SELECT client,auth_value FROM access WHERE "
                        "service='kTCCServiceScreenCapture' AND auth_value=2;"])
    if rc != 0:
        if skip_not_root(job, "read TCC.db screen-capture grants"):
            return
        log(job, "TCC query failed ({}): {}".format(rc, err.strip()[:200]))
        return
    st = job_state(job)
    prev_grants = st.setdefault("tcc_grants_seen", [])
    grants, warn = [], []
    prefixes = tuple(sc.get("tcc_allowlist_prefixes", []))
    for line in out.splitlines():
        client = line.split("|")[0].strip()
        if not client or client.startswith(prefixes):
            continue
        grants.append(client)
    for client in grants:
        killed_here = []
        if sc.get("tcc_kill", True):
            targets = []
            if client.startswith("/"):
                targets = [(pid, p) for pid, p in procs if p == client or p.startswith(client)]
            else:
                rc2, out2, _ = run(["mdfind", "kMDItemCFBundleIdentifier == '{}'".format(client)])
                app = next((l for l in out2.splitlines() if l.strip().endswith(".app")), "")
                if app:
                    targets = [(pid, p) for pid, p in procs
                               if p.startswith(app.rstrip("/") + "/")]
            for pid, p in targets:
                if pid in (0, 1) or own_tooling(p):
                    continue
                if kill_pid(job, pid, "holds Screen Capture TCC grant ({})".format(client)) == "killed":
                    killed_here.append("pid {} {}".format(pid, p))
        warn.append((client, killed_here))
    if warn:
        # alert only for grants not present at the previous scan — the kill is
        # the enforcement and repeats every cycle; the alert should not
        new = [w for w in warn if w[0] not in prev_grants]
        if new:
            alert("WARNING", "non-allowlisted Screen Capture TCC grant(s): {}".format(len(new)),
                  "Clients with an active kTCCServiceScreenCapture grant outside "
                  "the allowlist:\n" + "\n".join(
                      "  {}{}".format(c, " — killed: " + "; ".join(k) if k else " — no running process found")
                      for c, k in new) +
                  "\nReview in System Settings > Privacy & Security > Screen Recording.",
                  job, persist=True)
    st["tcc_grants_seen"] = grants


def _scan_listeners(job: str, sc: dict) -> None:
    rc, out, err = run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"], timeout=20)
    if rc != 0 and not out:
        log(job, "lsof failed ({}): {}".format(rc, err.strip()[:200]))
        return
    st = job_state(job)
    alert_cool = st.setdefault("listener_alert_cool", {})
    ports = {int(p) for p in sc.get("ports", [])}
    now = time.time()
    for line in out.splitlines():
        m = re.search(r":(\d+)\s+\(LISTEN\)", line)
        if not m or int(m.group(1)) not in ports:
            continue
        parts = line.split()
        try:
            pid = int(parts[1])
        except (IndexError, ValueError):
            continue
        port = int(m.group(1))
        name = parts[0]
        rc2, out2, _ = run(["ps", "-o", "comm=", "-p", str(pid)])
        ppath = out2.strip()
        key = "{}:{}".format(name, port)
        why = "LISTEN on remote-access port {} ({})".format(port, ppath or name)
        result = "skipped"
        if pid == 1:
            why += " — owned by launchd (socket activation), cannot kill"
        elif own_tooling(ppath):
            why += " — own tooling, not killing"
        else:
            result = kill_pid(job, pid, why)
        # kills enforce every cycle; alerts are cooled so a respawning
        # listener does not flood the alert center
        if now - alert_cool.get(key, 0) >= 600:
            alert_cool[key] = now
            alert("CRITICAL", "remote-access listener :{} ({}) {}".format(
                      port, name, "killed" if result == "killed" else "detected"),
                  "Process {} pid {} had TCP port {} in LISTEN ({}).\n{}".format(
                      name, pid, port, ppath or "path unknown", why),
                  job, persist=True)


def _screenshare_ls_sync(job: str, sc: dict) -> None:
    if not os.path.exists(G.queue_path) or os.path.getsize(G.queue_path) == 0:
        return
    if not ls_throttle_ok():
        log(job, "deny queue non-empty but LS restore throttled; retry next cycle")
        return
    if skip_not_root(job, "Little Snitch screenshare-deny sync"):
        return
    if not os.path.exists(LS_SCREENSHARE_DENY):
        log(job, "{} not installed yet; keeping queue for later".format(LS_SCREENSHARE_DENY))
        return
    model = ls_export_model(job)
    if not model:
        return
    ts = int(time.time())
    report = os.path.join(SEC, "security-system", "reports",
                          "screenshare-deny-{}.md".format(ts))
    undo = os.path.join(G.state_dir, "screenshare-undo-{}.json".format(ts))
    rc, out, err = run([PY, LS_SCREENSHARE_DENY, model, "--apply",
                        "--ensure-file", G.queue_path,
                        "--report", report, "--undo", undo], timeout=120)
    if rc != 0:
        log(job, "ls-screenshare-deny failed ({}): {}".format(rc, (out + err).strip()[:300]))
        try:
            os.unlink(model)
        except OSError:
            pass
        return
    m = re.search(r"ADD=(\d+)", out)
    added = int(m.group(1)) if m else 0
    if added >= 1:
        if ls_restore_model(job, model):
            alert("INFO", "Little Snitch: {} screen-share deny rule(s) added".format(added),
                  "ls-screenshare-deny applied {} both-way deny rule(s) from the "
                  "kill queue and the model was restored.\nreport: {}\nundo: {}".format(
                      added, report, undo), job, persist=False)
    else:
        log(job, "queued identifiers already covered ({}); clearing queue".format(
            out.strip()[:160]))
    try:
        open(G.queue_path, "w").close()
    except OSError:
        pass
    chown_evw(report)
    chown_evw(os.path.dirname(report))
    try:
        os.unlink(model)
    except OSError:
        pass


def job_screenshare_scan() -> None:
    job = "screenshare-scan"
    sc = G.config.get("screenshare", {})
    procs = ps_table()
    if not procs:
        log(job, "ps table empty; skipping cycle")
        return
    _scan_watchlist(job, sc, procs)
    _scan_tcc(job, sc, procs)
    _scan_listeners(job, sc)
    _screenshare_ls_sync(job, sc)


# ---------------------------------------------------------------------------
# job: sentinel-deny-sync — auto-close mac-sentinel warned endpoints in LS
# ---------------------------------------------------------------------------


def job_sentinel_deny_sync() -> None:
    job = "sentinel-deny-sync"
    cursor = G.state["cursors"].get("sentinel_feed", 0)
    try:
        size = os.path.getsize(SENTINEL_FEED)
    except OSError:
        log(job, "sentinel feed {} not present; nothing to sync".format(SENTINEL_FEED))
        return
    if size < cursor:
        log(job, "sentinel feed shrank (rotated?); resetting cursor")
        cursor = 0
    if size == cursor:
        return
    if skip_not_root(job, "Little Snitch sentinel-deny sync"):
        return
    if not os.path.exists(LS_SENTINEL_DENY):
        log(job, "{} missing; cannot sync".format(LS_SENTINEL_DENY))
        return
    model = ls_export_model(job)
    if not model:
        return
    ts = int(time.time())
    report = os.path.join(today_scan_dir(), "ls-sentinel-deny-{}.md".format(ts))
    undo = os.path.join(G.state_dir, "sentinel-undo-{}.json".format(ts))
    rc, out, err = run([PY, LS_SENTINEL_DENY, model, "--apply",
                        "--report", report, "--undo", undo], timeout=120)
    if rc != 0:
        try:
            os.unlink(model)
        except OSError:
            pass
        raise RuntimeError("ls-sentinel-deny failed ({}): {}".format(rc, (out + err).strip()[:300]))
    m = re.search(r"ADD=(\d+)", out)
    added = int(m.group(1)) if m else 0
    if added == 0:
        log(job, "no new endpoints to deny ({})".format(out.strip()[:160]))
        G.state["cursors"]["sentinel_feed"] = size
    elif not ls_throttle_ok():
        # model patched on disk but not restored; leave the cursor behind so
        # the next cycle re-runs the tool and restores once the throttle opens
        log(job, "ADD={} but LS restore throttled; will retry next cycle".format(added))
    elif ls_restore_model(job, model):
        G.state["cursors"]["sentinel_feed"] = size
        alert("INFO", "auto-closed {} sentinel-warned endpoints in Little Snitch".format(added),
              "ls-sentinel-deny added {} any-process outgoing deny rule(s) from the "
              "mac-sentinel alert feed and the model was restored.\n{}\nreport: {}\nundo: {}".format(
                  added, out.strip(), report, undo), job, persist=False)
    chown_evw(report)
    chown_evw(os.path.dirname(report))
    try:
        os.unlink(model)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# job: crash-watch — post-mortems for panics, jetsams, app crashes
# ---------------------------------------------------------------------------


def _parse_diag(text: str) -> tuple[dict, dict]:
    """.ips/.panic files: first line is a one-line JSON header, the rest is
    the body JSON."""
    first, _, rest = text.partition("\n")
    header, body = {}, {}
    try:
        header = json.loads(first)
    except json.JSONDecodeError:
        pass
    try:
        body = json.loads(rest.strip())
    except json.JSONDecodeError:
        pass
    return header, body


def _pages_mb(pages) -> str:
    try:
        return "{:,.0f} MB".format(int(pages) * PAGE_SIZE_DEFAULT / (1024.0 * 1024))
    except (TypeError, ValueError):
        return "?"


def _pages_gb(pages) -> str:
    try:
        return "{:.1f} GB".format(int(pages) * PAGE_SIZE_DEFAULT / (1024.0 ** 3))
    except (TypeError, ValueError):
        return "?"


def _jetsam_same_hour(job: str, ts_str: str) -> str:
    """Name the largest process of a JetsamEvent from the panic's hour."""
    m = re.match(r"(\d{4}-\d{2}-\d{2})[ T](\d{2})", ts_str or "")
    if not m:
        return ""
    prefix = "JetsamEvent-{}-{}".format(m.group(1), m.group(2))
    try:
        names = sorted(n for n in os.listdir(DIAG_DIR)
                       if n.startswith(prefix) and n.endswith(".ips"))
    except OSError:
        return ""
    if not names:
        return ""
    try:
        with open(os.path.join(DIAG_DIR, names[-1]), errors="replace") as f:
            _, body = _parse_diag(f.read())
        largest = body.get("largestProcess")
        if largest:
            return "JetsamEvent {} in the same hour names '{}' as the largest " \
                   "process — the likely memory-pressure driver.".format(names[-1], largest)
    except OSError:
        pass
    return ""


def _remediation_checklist(job: str) -> list[str]:
    items = []
    rc, out, _ = run(["grep", "-c", "MAX_RSS_KB", "/usr/local/bin/evw-plist-monitor.sh"])
    n = out.strip() if rc == 0 else "0"
    items.append("- [{}] fs_usage memory cap present in evw-plist-monitor.sh "
                 "(MAX_RSS_KB occurrences: {})".format("x" if n not in ("0", "") else " ", n))
    cmd = (["sudo", "-u", "evw"] if G.is_root else []) + \
          ["defaults", "read", "com.googlecode.iterm2", "Unlimited Scrollback"]
    rc, out, _ = run(cmd)
    unlim = out.strip().lower() in ("1", "true", "yes")
    items.append("- [{}] iTerm2 unlimited scrollback {} (memory-hoard risk "
                 "when on)".format(" " if unlim else "x",
                                    "ON — disable or cap it" if unlim else "off"))
    big = []
    for p in glob.glob("/var/log/evw-*.log"):
        try:
            if os.path.getsize(p) > 50 * 1024 * 1024:
                big.append("{} ({:.0f} MB)".format(p, os.path.getsize(p) / 1048576.0))
        except OSError:
            pass
    items.append("- [{}] no /var/log/evw-*.log over 50 MB{}".format(
        " " if big else "x",
        " — add newsyslog rotation for: " + ", ".join(big) if big else ""))
    return items


def _panic_report(job: str, name: str, path: str, text: str) -> tuple[str, str]:
    header, body = _parse_diag(text)
    panic_str = (body.get("panicString") or "").splitlines()
    panic_line = panic_str[0] if panic_str else "(panicString unavailable)"
    mem = body.get("memoryStatus") or {}
    pages = mem.get("memoryPages") or {}
    details = mem.get("memoryPressureDetails") or {}

    causes = []
    if "watchdog timeout" in text:
        causes.append("watchdogd (userspace) was starved of CPU for 94+ s — almost "
                      "always severe memory exhaustion (compressor/swap storm) or a "
                      "kernel_task priority inversion; check top consumers and caps")
    if "segments limit (BAD)" in text:
        causes.append("memory compressor hit its segment limit — physical RAM exhausted")
    jetsam_note = _jetsam_same_hour(job, header.get("timestamp") or body.get("date", ""))
    if jetsam_note:
        causes.append(jetsam_note)
    if not causes:
        causes.append("no known cause signature matched — read the panicString and "
                      "the original log manually")
    m = re.search(r"(\d+)\s+swapfiles?", text, re.I)

    lines = [
        "# post-mortem: {}".format(name),
        "",
        "- original: `{}`".format(path),
        "- detected: {}".format(datetime.now().isoformat(timespec="seconds")),
        "- bug_type: {}".format(header.get("bug_type", body.get("bug_type", "?"))),
        "- os: {}".format(header.get("os_version", body.get("build", "?"))),
        "- product: {}".format(body.get("product", "?")),
        "- kernel: {}".format(body.get("kernel", "?")),
        "",
        "## panic",
        "```",
        panic_line,
        "```",
        "",
        "## memory status at panic",
        "- compressor size: {} ({} pages)".format(_pages_gb(mem.get("compressorSize")),
                                                  mem.get("compressorSize", "?")),
        "- free memory: {} ({} pages)".format(_pages_mb(pages.get("free")), pages.get("free", "?")),
        "- active / inactive / wired: {} / {} / {}".format(
            _pages_mb(pages.get("active")), _pages_mb(pages.get("inactive")),
            _pages_mb(pages.get("wired"))),
        "- busyBufferCount: {}".format(mem.get("busyBufferCount", "?")),
        "- memoryPressure: {} (pagesWanted={}, pagesReclaimed={})".format(
            mem.get("memoryPressure", "?"), details.get("pagesWanted", "?"),
            details.get("pagesReclaimed", "?")),
    ]
    if "segments limit (BAD)" in text:
        lines.append("- raw log contains 'segments limit (BAD)' (compressor segment limit)")
    if m:
        lines.append("- swapfiles at panic: {}".format(m.group(1)))
    lines += ["", "## cause hypothesis"]
    lines += ["{}. {}".format(i + 1, c) for i, c in enumerate(causes)]
    lines += ["", "## remediation checklist"] + _remediation_checklist(job)
    lines.append("")
    return "\n".join(lines), causes[0]


def _jetsam_report(name: str, path: str, text: str) -> tuple[str, str]:
    header, body = _parse_diag(text)
    procs = sorted(body.get("processes") or [],
                   key=lambda p: p.get("rpages", 0), reverse=True)[:3]
    lines = [
        "# post-mortem: {}".format(name), "",
        "- original: `{}`".format(path),
        "- detected: {}".format(datetime.now().isoformat(timespec="seconds")),
        "- os: {}".format(header.get("os_version", body.get("build", "?"))),
        "- largestProcess: {}".format(body.get("largestProcess", "?")), "",
        "## top-3 processes by resident pages (16 KB pages)",
    ]
    for p in procs:
        lines.append("- {} (pid {}): {} resident ({:,} rpages)".format(
            p.get("name", "?"), p.get("pid", "?"), _pages_mb(p.get("rpages", 0)),
            p.get("rpages", 0)))
    lines += ["", "macOS jetsam killed processes under memory pressure. If the "
              "largest process repeats across events, cap or restart it. "
              "(rpages is jetsam's own accounting and can far exceed physical "
              "RAM for long-lived processes.)", ""]
    return "\n".join(lines), str(body.get("largestProcess", "?"))


def _generic_report(name: str, path: str, text: str) -> str:
    header, _ = _parse_diag(text)
    return ("# post-mortem: {}\n\n- original: `{}`\n- detected: {}\n"
            "- bug_type: {}\n- os: {}\n- size: {:,} bytes\n\n"
            "Routine diagnostic (app crash / spin / diagnostic dump); no deep "
            "parse — one event of this kind is usually noise, a repeating "
            "pattern is not.\n").format(
                name, path, datetime.now().isoformat(timespec="seconds"),
                header.get("bug_type", "?"), header.get("os_version", "?"), len(text))


def job_crash_watch() -> None:
    job = "crash-watch"
    cursor = G.state["cursors"].get("diagreports_mtime")
    if cursor is None:
        cursor = time.time() - 7 * 86400  # first run: sweep the last 7 days
    try:
        names = os.listdir(DIAG_DIR)
    except PermissionError as e:
        skip_perm(job, "list {}".format(DIAG_DIR), e)
        return
    except OSError as e:
        log(job, "cannot list {}: {}".format(DIAG_DIR, e))
        return

    candidates = []
    for name in names:
        if name.startswith("."):
            continue
        full = os.path.join(DIAG_DIR, name)
        try:
            if not os.path.isfile(full):
                continue
            mtime = os.path.getmtime(full)
        except OSError:
            continue
        if mtime > cursor:
            candidates.append((mtime, name, full))
    candidates.sort()

    new_cursor = cursor
    for mtime, name, full in candidates:
        report_path = os.path.join(today_scan_dir(), "postmortem-{}.md".format(name))
        if os.path.exists(report_path):
            new_cursor = max(new_cursor, mtime)  # already done — mark seen, no repeat
            continue
        if name.endswith(".panic"):
            kind = "panic"
        elif name.startswith("JetsamEvent-") and name.endswith(".ips"):
            kind = "jetsam"
        elif name.endswith(".ips") or name.endswith(".diag") or name.endswith(".spin"):
            kind = "generic"
        else:
            new_cursor = max(new_cursor, mtime)
            continue
        try:
            with open(full, errors="replace") as f:
                text = f.read()
        except PermissionError as e:
            skip_perm(job, "read {}".format(full), e)
            break  # leave cursor behind: retry this and newer files next cycle
        except OSError as e:
            log(job, "cannot read {}: {}".format(full, e))
            break
        if kind == "panic":
            body, cause = _panic_report(job, name, full, text)
            alert("CRITICAL", "kernel panic: {}".format(cause)[:80],
                  "New panic report {}\n\nCause hypothesis: {}\n\n"
                  "Full post-mortem: {}".format(name, cause, report_path),
                  job, persist=True)
        elif kind == "jetsam":
            body, largest = _jetsam_report(name, full, text)
            alert("WARNING", "memory-pressure kill: largest={}".format(largest),
                  "New JetsamEvent {} — largest process '{}'.\n"
                  "Post-mortem: {}".format(name, largest, report_path),
                  job, persist=True)
        else:
            body = _generic_report(name, full, text)
            alert("INFO", "diagnostic report: {}".format(name)[:80],
                  "New {} — one-paragraph post-mortem: {}".format(name, report_path),
                  job, persist=False)
        try:
            atomic_write(report_path, body, chown_user=True)
            # keep the scan dir itself evw-owned so non-root tools can add to it
            chown_evw(os.path.dirname(report_path))
            log(job, "wrote {}".format(report_path))
        except OSError as e:
            log(job, "could not write {}: {}".format(report_path, e))
            break
        new_cursor = max(new_cursor, mtime)
    G.state["cursors"]["diagreports_mtime"] = new_cursor


# ---------------------------------------------------------------------------
# job: health-score — the north-star telemetry line
# ---------------------------------------------------------------------------


def _connectivity() -> int | None:
    try:
        rc, out, _ = run(["/usr/bin/tail", "-1", NETDIAG_LOG])
        if rc != 0 or not out.strip():
            return None
        line = out.strip()
        m = re.search(r"\((\d+)\)", line)
        if not m or time.time() - int(m.group(1)) >= 120:
            return None
        n = re.search(r"net=(\w+)", line)
        if not n:
            return None
        v = n.group(1).lower()
        return 1 if v == "ok" else (0 if v == "fail" else None)
    except OSError:
        return None


def job_health_score() -> None:
    job = "health-score"
    rec = {"ts": int(time.time())}

    rc, out, _ = run(["sysctl", "-n", "kern.boottime"])
    m = re.search(r"sec = (\d+)", out)
    rec["uptime_s"] = int(time.time()) - int(m.group(1)) if m else None
    try:
        rec["load1"] = round(os.getloadavg()[0], 2)
    except OSError:
        rec["load1"] = None

    rc, out, _ = run(["vm_stat"])
    page = PAGE_SIZE_DEFAULT
    pm = re.search(r"page size of (\d+) bytes", out)
    if pm:
        page = int(pm.group(1))
    def _vm(field):
        fm = re.search(r"{}:\s+(\d+)\.".format(re.escape(field)), out)
        return round(int(fm.group(1)) * page / (1024.0 * 1024), 1) if fm else None
    rec["mem_free_mb"] = _vm("Pages free")
    rec["mem_compressor_mb"] = _vm("Pages occupied by compressor")

    rc, out, _ = run(["sysctl", "-n", "vm.swapusage"])
    m = re.search(r"used = ([\d.]+)([MG])", out)
    if m:
        v = float(m.group(1)) * (1024 if m.group(2) == "G" else 1)
        rec["swap_used_mb"] = round(v, 1)
    else:
        rec["swap_used_mb"] = None

    rec["fs_usage_rss_mb"] = rss_sum_mb("fs_usage")
    rec["iterm2_rss_mb"] = rss_sum_mb("iTerm2")
    guards = G.state.get("guards") or {}
    rec["guards_up"] = guards.get("up")
    rec["guards_total"] = guards.get("total")
    rec["connectivity"] = _connectivity()

    try:
        with open(G.health_path, "a") as f:
            f.write(json.dumps(rec) + "\n")
    except OSError as e:
        log(job, "could not append health line: {}".format(e))
        return

    try:
        if os.path.getsize(G.health_path) > 20 * 1024 * 1024:
            cutoff = time.time() - 90 * 86400
            kept = []
            with open(G.health_path) as f:
                for line in f:
                    try:
                        if json.loads(line).get("ts", 0) >= cutoff:
                            kept.append(line)
                    except json.JSONDecodeError:
                        pass
            atomic_write(G.health_path, "".join(kept))
            log(job, "rotated health.jsonl: kept {} lines (last 90 days)".format(len(kept)))
    except OSError:
        pass
    log(job, "uptime={}s load1={} swap={}MB conn={}".format(
        rec["uptime_s"], rec["load1"], rec["swap_used_mb"], rec["connectivity"]))


# ---------------------------------------------------------------------------
# job: audit-alerts-digest — give evw eyes on the root-only security logs
# ---------------------------------------------------------------------------


def job_audit_alerts_digest() -> None:
    job = "audit-alerts-digest"
    digest_dir = os.path.join(SEC, "logs", "digests")
    try:
        os.makedirs(digest_dir, exist_ok=True)
    except OSError as e:
        log(job, "cannot create {}: {}".format(digest_dir, e))
        return
    chown_evw(digest_dir)
    alerts_log = DIGEST_SOURCES[0]

    if not G.state["flags"].get("audit_full_digest_done"):
        try:
            with open(alerts_log, errors="replace") as f:
                data = f.read()
            full_out = os.path.join(digest_dir, "evw-audit-alerts-full.txt")
            atomic_write(full_out, data, chown_user=True)
            G.state["flags"]["audit_full_digest_done"] = True
            G.state["cursors"]["audit_alerts"] = len(data)
            alert("INFO", "full audit-alerts digest ready",
                  "Complete copy of {} ({} bytes) written to {} — the historical "
                  "record is now readable without sudo.".format(alerts_log, len(data), full_out),
                  job, persist=False)
        except PermissionError as e:
            skip_perm(job, "full copy of {}".format(alerts_log), e)
        except OSError as e:
            log(job, "full digest failed: {}".format(e))

    for src in DIGEST_SOURCES:
        dst = os.path.join(digest_dir, os.path.basename(src).replace(".log", "") + "-tail.txt")
        rc, out, err = run(["/usr/bin/tail", "-500", src])
        if rc != 0:
            if not G.is_root and not os.access(src, os.R_OK):
                log(job, "SKIP (not root): tail {}".format(src))
            else:
                log(job, "tail {} failed ({}): {}".format(src, rc, err.strip()[:120]))
            continue
        try:
            atomic_write(dst, out, chown_user=True)
        except OSError as e:
            log(job, "could not write {}: {}".format(dst, e))

    # byte cursor over the alerts log: summarize new CRITICAL|ALERT|DENY lines
    cursor = G.state["cursors"].get("audit_alerts")
    try:
        size = os.path.getsize(alerts_log)
        if cursor is None:
            cursor = size  # no retroactive alert storm; the full copy covers history
        elif size < cursor:
            cursor = 0
        if size > cursor:
            with open(alerts_log, errors="replace") as f:
                f.seek(cursor)
                new = f.read(size - cursor)
            hits = [l for l in new.splitlines()
                    if re.search(r"CRITICAL|ALERT|DENY", l)]
            if hits:
                alert("WARNING", "audit-alerts: {} new CRITICAL/ALERT/DENY line(s)".format(len(hits)),
                      "{} new line(s) matching CRITICAL|ALERT|DENY in {} since last "
                      "digest (first {} shown):\n\n{}".format(
                          len(hits), alerts_log, min(10, len(hits)), "\n".join(hits[:10])),
                      job, persist=False)
            cursor = size
        G.state["cursors"]["audit_alerts"] = cursor
    except PermissionError as e:
        skip_perm(job, "cursor-scan {}".format(alerts_log), e)
    except OSError as e:
        log(job, "cursor scan failed: {}".format(e))


# ---------------------------------------------------------------------------
# job: weekly-review — self-improvement report (uptime + connectivity)
# ---------------------------------------------------------------------------


def _health_week() -> list[dict]:
    recs = []
    cutoff = time.time() - 7 * 86400
    try:
        with open(G.health_path) as f:
            for line in f:
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if r.get("ts", 0) >= cutoff:
                    recs.append(r)
    except OSError:
        pass
    return recs


def _top_rss(n: int) -> list[str]:
    rc, out, _ = run(["ps", "-eo", "rss=,comm="])
    rows = []
    for line in out.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            try:
                rows.append((int(parts[0]), parts[1]))
            except ValueError:
                pass
    rows.sort(reverse=True)
    return ["{} ({:,.0f} MB)".format(p, kb / 1024.0) for kb, p in rows[:n]]


def job_weekly_review() -> None:
    job = "weekly-review"
    recs = _health_week()
    suggestions = []

    # ---- 1. SCORECARD ----
    streaks, cur, best = [], 0, 0
    for r in recs:
        u = r.get("uptime_s")
        if u is None:
            continue
        if u < cur:
            streaks.append(cur)
        cur = u
        best = max(best, u)
    if cur:
        streaks.append(cur)
    longest = max(streaks) if streaks else 0
    current_uptime = recs[-1].get("uptime_s") if recs else None

    conn_samples = [r["connectivity"] for r in recs if r.get("connectivity") is not None]
    conn_pct = (100.0 * sum(conn_samples) / len(conn_samples)) if conn_samples else None
    guard_samples = [(r["guards_up"], r["guards_total"]) for r in recs
                     if r.get("guards_total")]
    guard_pct = (100.0 * sum(u / float(t) for u, t in guard_samples) / len(guard_samples)) \
        if guard_samples else None

    panics = jetsams = None
    try:
        week_ago = time.time() - 7 * 86400
        panics = jetsams = 0
        for n in os.listdir(DIAG_DIR):
            full = os.path.join(DIAG_DIR, n)
            try:
                if os.path.getmtime(full) < week_ago:
                    continue
            except OSError:
                continue
            if n.endswith(".panic"):
                panics += 1
            elif n.startswith("JetsamEvent-") and n.endswith(".ips"):
                jetsams += 1
    except OSError as e:
        skip_perm(job, "count this week's DiagnosticReports", e)

    def _fmt_s(s):
        return "{:.1f} days".format(s / 86400.0) if s is not None else "n/a"

    scorecard = [
        "## 1. SCORECARD — the north star: uptime + connectivity",
        "",
        "- health samples this week: {}".format(len(recs)),
        "- current uptime: {}".format(_fmt_s(current_uptime)),
        "- longest continuous uptime streak this week: {}".format(_fmt_s(longest)),
        "- connectivity ok: {} ({} samples)".format(
            "{:.1f}%".format(conn_pct) if conn_pct is not None else "n/a",
            len(conn_samples)),
        "- guard availability: {} ({} samples)".format(
            "{:.1f}%".format(guard_pct) if guard_pct is not None else "n/a",
            len(guard_samples)),
        "- panics this week: {}".format(panics if panics is not None else "n/a (not root)"),
        "- jetsam events this week: {}".format(jetsams if jetsams is not None else "n/a (not root)"),
        "",
    ]

    # ---- 2. LOG ANALYSIS ----
    logsec = ["## 2. LOG ANALYSIS", "", "### unified log (log stats --last 7d)", ""]
    rc, out, err = None, "", ""
    try:
        rc, out, err = run(["log", "stats", "--last", "7d"], timeout=120)
    except OSError as e:
        rc = -1
        err = str(e)
    if rc == 0:
        m = re.search(r"log messages:.*?\n\s*\[([\d,\s]+)\]", out)
        if m:
            nums = [x.strip() for x in m.group(1).split(",") if x.strip()]
            # columns: default info debug error fault
            if len(nums) == 5:
                logsec.append("- totals: {} default, {} info, {} debug, "
                              "**{} error, {} fault**".format(*nums))
        logsec.append("")
        logsec.append("top-10 processes by event volume (per-sender fault "
                      "breakdown is not exposed by `log stats`; volumes point "
                      "at the noisiest subsystems):")
        logsec.append("")
        procs = re.findall(r"\[\s*[\d,]+ \([^)]+\),\s*[\d,]+ \([^)]+\),\s*[0-9A-F-]+, ([^]]+)\]", out)
        if procs:
            for p in procs[:10]:
                logsec.append("- {}".format(p.strip()))
        else:
            logsec.append("```")
            logsec.extend(out.splitlines()[:30])
            logsec.append("```")
    else:
        logsec.append("`log stats --last 7d` failed or timed out (120 s) — "
                      "tolerated: {}".format((err or "rc={}".format(rc)).strip()[:200]))
    logsec.append("")

    logsec.append("### security log sizes (flag > 50 MB)")
    logsec.append("")
    logsec.append("| log | size MB |")
    logsec.append("|---|---|")
    seen_paths = set()
    for pattern in ("/var/log/evw-*.log", "/var/log/file-sentinel*.log",
                    os.path.join(SEC, "logs", "*.log")):
        for p in sorted(glob.glob(pattern)):
            if p in seen_paths:
                continue
            seen_paths.add(p)
            try:
                stt = os.stat(p)
                mb = stt.st_size / 1048576.0
            except OSError:
                continue
            flag = ""
            if mb > 50:
                flag = " **>50 MB**"
                try:
                    owner = "{}:{}".format(pwd.getpwuid(stt.st_uid).pw_name,
                                           grp.getgrgid(stt.st_gid).gr_name)
                except KeyError:
                    owner = "root:wheel"
                suggestions.append(
                    "- log `{}` is {:.0f} MB — add a newsyslog.d entry, e.g. "
                    "`{}  {}  640  5  51200  *  Z` (rotate at 50 MB, "
                    "keep 5, compress).".format(p, mb, p, owner))
            logsec.append("| {} | {:.1f}{} |".format(p, mb, flag))
    logsec.append("")

    # ---- 3. TUNING SUGGESTIONS (rule engine; every rule cites its data) ----
    swaps = [r["swap_used_mb"] for r in recs if r.get("swap_used_mb") is not None]
    if swaps and sum(swaps) / len(swaps) > 500:
        suggestions.append(
            "- average swap usage this week was {:.0f} MB (>500 MB) — identify and "
            "leash the top memory consumers; current top-3 RSS: {}.".format(
                sum(swaps) / len(swaps), "; ".join(_top_rss(3))))
    fs_max = max((r.get("fs_usage_rss_mb") or 0 for r in recs), default=0)
    if fs_max > 1500:
        suggestions.append(
            "- fs_usage peaked at {:,.0f} MB RSS this week (>1500 MB) — the "
            "MAX_RSS_KB cap in /usr/local/bin/evw-plist-monitor.sh is doing real "
            "work; consider lowering it if fs_usage is not actively needed.".format(fs_max))
    if conn_pct is not None and conn_pct < 99.0:
        worst = []
        rc, out, _ = run(["/usr/bin/grep", "CHANGE", NETDIAG_LOG])
        if rc == 0 and out.strip():
            worst = out.strip().splitlines()[-5:]
        else:
            rc, out, _ = run(["/usr/bin/grep", "net=FAIL", NETDIAG_LOG])
            if rc == 0:
                worst = out.strip().splitlines()[-5:]
        suggestions.append(
            "- connectivity was {:.1f}% (<99%) this week — worst monitor.log "
            "lines:\n```\n{}\n```".format(conn_pct, "\n".join(worst) or "(none found)"))
    if guard_pct is not None and guard_pct < 100.0:
        restarts = job_state("guards-check").get("restarts", {})
        flaky = sorted(restarts.items(), key=lambda kv: -kv[1])[:5]
        suggestions.append(
            "- guard availability was {:.2f}% (<100%) — flaky guards by restart "
            "count: {}.".format(guard_pct, ", ".join(
                "{} ({})".format(k, v) for k, v in flaky) or "none recorded"))
    restarts_in_log = 0
    try:
        cutoff = (datetime.now() - timedelta(days=7)).isoformat(timespec="seconds")
        with open(G.log_path) as f:
            for line in f:
                if "restarted" in line and line[:19] >= cutoff:
                    restarts_in_log += 1
    except OSError:
        pass
    if restarts_in_log > 20:
        suggestions.append(
            "- {} guard restarts were logged in the last 7 days (restart storm) — "
            "investigate why guards keep dying before the restarts mask a real "
            "problem.".format(restarts_in_log))
    rc, out, _ = run(["df", "-h", "/"])
    m = re.search(r"(\d+)%", out.splitlines()[-1] if rc == 0 and out else "")
    if m and int(m.group(1)) >= 85:
        suggestions.append(
            "- disk / is {}% full (<15% free) — clean up: `du -x -d1 -h / | sort -h | "
            "tail`, purge old DiagnosticReports, empty ~/.Trash, review ~/Downloads.".format(
                m.group(1)))
    loads = [r["load1"] for r in recs if r.get("load1") is not None]
    cpus = os.cpu_count() or 1
    if loads and sum(1 for l in loads if l > cpus) / float(len(loads)) > 0.5:
        agents = []
        la_dir = os.path.expanduser("~/Library/LaunchAgents")
        try:
            agents = [n for n in os.listdir(la_dir)
                      if not n.startswith(("com.evw", "com.ew"))]
        except OSError:
            pass
        suggestions.append(
            "- load1 exceeded the CPU count ({}) in >50% of this week's samples — "
            "review login items; non-evw LaunchAgents present: {}.".format(
                cpus, ", ".join(agents) or "none"))

    tuning = ["## 3. TUNING SUGGESTIONS", ""]
    if suggestions:
        tuning += suggestions
    else:
        tuning.append("- none — no rule fired on this week's data")
    tuning.append("")

    text = "\n".join(
        ["# weekly security & performance review — {}".format(time.strftime("%Y-%m-%d")),
         "",
         "generated by evw-security-system (weekly-review); data: health.jsonl "
         "({} samples), unified log, /var/log, netdiag monitor.log".format(len(recs)),
         ""] + scorecard + [""] + logsec + [""] + tuning)

    path = os.path.join(SEC, "security-system", "reports",
                        "weekly-{}.md".format(time.strftime("%Y-%m-%d")))
    atomic_write(path, text, chown_user=True)
    chown_evw(os.path.dirname(path))
    log(job, "wrote {}".format(path))
    alert("INFO", "weekly security & performance review ready",
          "Report: {}\nScorecard: uptime {}, connectivity {}, guard availability "
          "{}. {} tuning suggestion(s).".format(
              path, _fmt_s(current_uptime),
              "{:.1f}%".format(conn_pct) if conn_pct is not None else "n/a",
              "{:.1f}%".format(guard_pct) if guard_pct is not None else "n/a",
              len(suggestions)), job, persist=True)


# ---------------------------------------------------------------------------
# job: ls-change-watch — 3 min after any LS rule change, audit + close holes
# ---------------------------------------------------------------------------

LS_FP_VOLATILE = {"useCount", "lastUsed", "modificationDate", "creationDate",
                  "factoryHelpText"}


def _ls_fingerprint(path: str) -> set:
    """Rule-set fingerprint ignoring volatile fields (same set as ls-model-diff)."""
    try:
        rules = json.load(open(path)).get("rules", [])
    except (OSError, json.JSONDecodeError):
        return set()
    return {json.dumps({k: v for k, v in r.items() if k not in LS_FP_VOLATILE},
                       sort_keys=True) for r in rules}


def job_ls_change_watch() -> None:
    job = "ls-change-watch"
    if skip_not_root(job, "Little Snitch change watch"):
        return
    jcfg = G.config.get("jobs", {}).get(job, {})
    settle = int(jcfg.get("settle_seconds", 180))
    max_settle = int(jcfg.get("max_settle_seconds", 900))
    cur = job_state(job).setdefault("watch", {})

    model = ls_export_model(job)
    if not model:
        return
    fps = _ls_fingerprint(model)
    baseline = set(cur.get("baseline", []))
    now = time.time()

    if not baseline:
        cur["baseline"] = sorted(fps)
        # first run after install: audit once (closes any holes that predate the
        # job — e.g. a critical deny deleted before it existed), then watch
        cur["pending_since"] = now
        cur["pending_until"] = now + settle
        log(job, "baseline recorded: {} rules — initial audit in {}s".format(len(fps), settle))

    if fps != baseline:
        if not cur.get("pending_since"):
            cur["pending_since"] = now
        # rolling 3-min settle: each new change pushes the audit out again
        cur["pending_until"] = now + settle
        log(job, "rules changed (+{}/-{}) — audit in {}s".format(
            len(fps - baseline), len(baseline - fps), settle))

    pending = cur.get("pending_until", 0)
    starved = (cur.get("pending_since")
               and now - cur["pending_since"] >= max_settle)
    if not pending or (now < pending and not starved):
        try:
            os.unlink(model)
        except OSError:
            pass
        return

    log(job, "settle elapsed — auditing {} rules for holes".format(len(fps)))
    ts = time.strftime("%Y%m%d-%H%M%S")
    reports = os.path.join(SEC, "security-system", "reports")
    os.makedirs(reports, exist_ok=True)
    closures = 0
    last_rpt = ""
    for tool, tag in (("/usr/local/bin/ls-hygiene.py", "hygiene"),
                      ("/usr/local/bin/ls-hole-audit.py", "hole-audit")):
        rpt = os.path.join(reports, "ls-{}-{}.md".format(tag, ts))
        undo = os.path.join(G.state_dir, "ls-{}-undo-{}.json".format(tag, ts))
        rc, out, err = run(["/usr/bin/python3", tool, model, "--apply",
                            "--report", rpt, "--undo", undo], timeout=120)
        chown_evw(rpt)
        if rc != 0:
            log(job, "{} failed rc={}: {}".format(tag, rc, (err or out).strip()[:200]))
            continue
        last_rpt = rpt
        m = re.search(r"DELETE=(\d+).*?(?:ADD-DENY|REPLANT)=(\d+)", out)
        if m:
            closures += int(m.group(1)) + int(m.group(2))
        log(job, "{}: {}".format(tag, out.strip().splitlines()[-1] if out.strip() else "?"))

    if closures > 0:
        if ls_restore_model(job, model):
            log(job, "restore-model applied ({} hole closures)".format(closures))
            model = ls_export_model(job) or model   # re-baseline on what's live

    # full analysis for the record + critical-deny verification
    scan = today_scan_dir()
    os.makedirs(scan, exist_ok=True)
    rc, out, err = run(["/usr/bin/python3", os.path.join(SEC, "ls-full-analysis.py"),
                        model], timeout=120)
    analysis = os.path.join(scan, "ls-full-analysis-{}.txt".format(ts))
    atomic_write(analysis, out if rc == 0 else "analysis failed rc={}\n{}".format(rc, err),
                 chown_user=True)
    missing = [l.strip() for l in out.splitlines() if "❌ MISSING" in l] if rc == 0 else []

    cur["baseline"] = sorted(_ls_fingerprint(model))
    cur.pop("pending_since", None)
    cur.pop("pending_until", None)
    if model and os.path.exists(model):
        try:
            os.unlink(model)
        except OSError:
            pass

    if missing:
        alert("WARNING", "LS audit: {} critical denies still missing".format(len(missing)),
              "Hole audit closed {} rule(s) but these critical denies could not be "
              "verified:\n{}\nFull analysis: {}".format(
                  closures, "\n".join(missing[:10]), analysis), job, persist=True)
    elif closures:
        alert("INFO", "LS changed — {} hole(s) auto-closed".format(closures),
              "Little Snitch rules changed; after a 3-min settle the hole audit ran "
              "(hygiene + hole-audit) and the model was restored. "
              "Report: {}".format(last_rpt), job, persist=False)
    else:
        log(job, "audit clean — no holes in changed ruleset")


# ---------------------------------------------------------------------------
# scheduler + job runner (circuit breaker, atomic state after every job)
# ---------------------------------------------------------------------------

JOBS = {
    "guards-check": job_guards_check,
    "screenshare-scan": job_screenshare_scan,
    "sentinel-deny-sync": job_sentinel_deny_sync,
    "ls-change-watch": job_ls_change_watch,
    "crash-watch": job_crash_watch,
    "health-score": job_health_score,
    "audit-alerts-digest": job_audit_alerts_digest,
    "weekly-review": job_weekly_review,
}
JOB_ORDER = ["guards-check", "screenshare-scan", "sentinel-deny-sync",
             "ls-change-watch", "crash-watch", "health-score",
             "audit-alerts-digest", "weekly-review"]
WEEKLY_JOBS = {"weekly-review"}


def weekly_due(name: str, jcfg: dict, st: dict, now: float) -> bool:
    wd = WEEKDAYS.get(str(jcfg.get("weekday", "sunday")).lower())
    t = str(jcfg.get("time", "09:15"))
    try:
        hh, mm = (int(x) for x in t.split(":"))
    except ValueError:
        return False
    d = datetime.fromtimestamp(now)
    if wd is None or d.weekday() != wd:
        return False
    sched = d.replace(hour=hh, minute=mm, second=0, microsecond=0).timestamp()
    return now >= sched and st.get("last_run", 0) < sched


def job_due(name: str, now: float) -> bool:
    jcfg = G.config.get("jobs", {}).get(name, {})
    if not jcfg.get("enabled", False):
        return False
    st = job_state(name)
    if name in WEEKLY_JOBS:
        return weekly_due(name, jcfg, st, now)
    return now - st.get("last_run", 0) >= jcfg.get("interval_seconds", 300)


def run_job(name: str, why: str) -> None:
    st = job_state(name)
    sp = G.config.get("self_protection", {})
    until = st.get("breaker_until", 0)
    if time.time() < until:
        log(name, "circuit breaker open for {} more s; skipped".format(int(until - time.time())))
        return
    if G.dry_run:
        log(name, "DRY-RUN: would run now ({})".format(why))
        return
    log(name, "running ({})".format(why))
    st["last_run"] = time.time()
    try:
        JOBS[name]()
        st["last_success"] = time.time()
        st["consec_failures"] = 0
    except Exception as e:
        st["consec_failures"] = st.get("consec_failures", 0) + 1
        log(name, "FAILED ({} in a row): {}\n{}".format(
            st["consec_failures"], e, traceback.format_exc().strip()[-500:]))
        limit = sp.get("job_failure_breaker", 5)
        if st["consec_failures"] >= limit:
            cooldown = sp.get("breaker_cooldown_seconds", 3600)
            st["breaker_until"] = time.time() + cooldown
            st["consec_failures"] = 0
            alert("CRITICAL", "job {} auto-disabled {}s after {} failures".format(
                      name, cooldown, limit),
                  "Job '{}' failed {} times in a row; circuit breaker opened for "
                  "{}s, then it re-enables itself. Last error:\n{}".format(
                      name, limit, cooldown, e),
                  "self-protection", persist=True)
    save_state()


def daemon_loop() -> None:
    log("main", "evw-security-system starting (pid {}, config from {}, state dir {})".format(
        os.getpid(), G.config_origin, G.state_dir))
    while True:
        if G.sighup:
            G.sighup = False
            try:
                load_config()
                log("main", "SIGHUP: config reloaded from {}".format(G.config_origin))
            except (json.JSONDecodeError, OSError) as e:
                log("main", "SIGHUP: config reload failed, keeping old config: {}".format(e))
        check_config_drift()
        now = time.time()
        for name in JOB_ORDER:
            if job_due(name, now):
                run_job(name, "due: interval elapsed" if name not in WEEKLY_JOBS
                        else "due: weekly schedule reached")
        time.sleep(TICK_SECONDS)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="evw self-healing security orchestrator (LaunchDaemon com.evw.security-system)")
    ap.add_argument("--once", action="store_true",
                    help="run every enabled job one time, then exit")
    ap.add_argument("--job", metavar="NAME",
                    help="run one job one time, then exit")
    ap.add_argument("--dry-run", action="store_true",
                    help="log what would run; execute nothing with side effects")
    args = ap.parse_args()
    G.dry_run = args.dry_run

    try:
        load_config()
    except (json.JSONDecodeError, OSError) as e:
        print("cannot load config: {}".format(e), file=sys.stderr)
        sys.exit(1)
    load_state()
    if G.state_dir != STATE_DIR:
        log("main", "not root: state dir fell back to {} (production: {})".format(
            G.state_dir, STATE_DIR))

    def _hup(signum, frame):
        G.sighup = True
    signal.signal(signal.SIGHUP, _hup)

    if args.job:
        if args.job not in JOBS:
            print("unknown job '{}'; jobs: {}".format(args.job, ", ".join(JOB_ORDER)),
                  file=sys.stderr)
            sys.exit(2)
        run_job(args.job, "manual --job")
        return
    if args.once:
        for name in JOB_ORDER:
            if G.config.get("jobs", {}).get(name, {}).get("enabled", False):
                run_job(name, "manual --once")
            else:
                log(name, "disabled in config; skipped")
        return
    daemon_loop()


if __name__ == "__main__":
    main()
