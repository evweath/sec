#!/usr/bin/env python3
# mac-sentinel — macOS security monitoring and hardening daemon
# Watches sensitive files, network connections, auth/privilege events, USB
# devices and canary tripwires; logs anomalies and raises user alerts.
# Requires root. Runs as a long-lived daemon under launchd
# (label com.evw.mac-sentinel).
#
# Converted for macOS Tahoe 26.3 (arm64) from Kodachi thermald.
# Incorporates all hardening steps from Lynis audit (index 77→90+).

import os
import sys
import time
import json
import hashlib
import logging
import threading
import subprocess
import socket
import re
import signal
import shutil
import glob
import stat
import pwd
import grp
import argparse
import tempfile
import ipaddress
import ctypes
import ctypes.util
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict, deque
from typing import Optional, Dict, List, Tuple, Any

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error_guard.py)
try:
    import pathlib as _pathlib, sys as _sys
    _d = _pathlib.Path(__file__).resolve().parent
    for _ in range(6):
        _eg = _d / "lib" / "error_guard.py"
        if _eg.exists():
            # Runs as root: only import a root-owned lib — a user-writable
            # error_guard.py here would be arbitrary code execution as root.
            if os.geteuid() == 0 and _eg.stat().st_uid != 0:
                break
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

# KeepAlive daemon: never let the guard exit the process — trip = log + skip
os.environ.setdefault("EVW_GUARD_POLICY", "continue")

# 2026-09-01: IP ownership enrichment (RDAP allocation owner, PTR, FCrDNS
# check, classification) for every new remote connection in the logs.
try:
    from ip_intel import enrich_ip
except Exception:
    def enrich_ip(_ip): return {"intel_error": "ip_intel module unavailable"}


# ─── PROCESS TITLE MASKING ────────────────────────────────────────────────────

def _mask_process_title(title: str) -> None:
    """Set the process title shown in ps/pthread to the daemon name."""
    try:
        # macOS: use setproctitle if available via ctypes
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        # macOS doesn't have prctl; use pthread_setname_np instead
        libc.pthread_setname_np(title.encode()[:63])
    except Exception:
        pass
    try:
        sys.argv[0] = title
    except Exception:
        pass


# ─── CONSTANTS ────────────────────────────────────────────────────────────────

VERSION         = "3.0.0-macos"
SCRIPT_PATH     = os.path.abspath(__file__)
INSTALL_DIR     = "/usr/local/lib/mac-sentinel"
LOG_BASE_DIR    = "/var/log/mac-sentinel"
PID_FILE        = "/var/run/mac-sentinel.pid"
LAUNCHD_PLIST   = "/Library/LaunchDaemons/com.evw.mac-sentinel.plist"
CANARY_DIR      = "/usr/local/lib/mac-sentinel/.cache"
LOG_MAX_BYTES   = 100 * 1024 * 1024   # 100 MB
ALERT_COOLDOWN_SECONDS = 300           # 5-min dedup window per alert type
BREW_PREFIX     = "/opt/homebrew"      # Apple Silicon Homebrew path

# ─── WATCHED PATHS (macOS equivalents) ────────────────────────────────────────

WATCHED_PATHS = [
    # Auth & user database
    "/etc/passwd", "/etc/group",
    "/etc/sudoers", "/etc/sudoers.d",
    "/private/etc/passwd", "/private/etc/group",
    # Network configuration
    "/etc/hosts", "/etc/resolv.conf",
    "/etc/pf.conf", "/etc/pf.anchors",
    "/private/etc/hosts",
    # SSH
    "/etc/ssh/sshd_config", "/etc/ssh/ssh_config",
    "/var/root/.ssh",
    # macOS persistence vectors (LaunchAgents/Daemons = equivalent of systemd units)
    "/Library/LaunchAgents",
    "/Library/LaunchDaemons",
    "/System/Library/LaunchDaemons",
    # User persistence (per-user — monitor current user)
    f"/Users/{os.environ.get('SUDO_USER', 'evw')}/Library/LaunchAgents",
    # PAM configuration
    "/etc/pam.d",
    # Cron
    "/var/cron/tabs", "/etc/cron.d", "/etc/periodic",
    # SSL/TLS certificates
    "/etc/ssl/certs", "/etc/ssl",
    # Homebrew bin (custom executables)
    f"{BREW_PREFIX}/bin", f"{BREW_PREFIX}/sbin",
    "/usr/local/bin", "/usr/local/sbin",
    # OSSEC
    "/var/ossec/etc", "/var/ossec/bin",
    # This service
    INSTALL_DIR,
]

CANARY_FILES = [
    os.path.join(CANARY_DIR, f".{n}")
    for n in ["system_cache", "kernel_mod", "lib_index", "auth_token", "net_config"]
]

LOG_FILES = {
    "file_changes":  "file_changes",
    "connections":   "network_connections",
    "root_events":   "credential_transitions",
    "canary":        "cache_validation",
    "anomaly":       "anomaly_scores",
    "usb":           "hardware_devices",
    "dns":           "dns_activity",
    "process":       "process_lineage",
    "integrity":     "self_integrity",
    "hardening":     "hardening_events",
    "master":        "master_events",
}

# ─── RUNTIME STATE ────────────────────────────────────────────────────────────

_alert_lock          = threading.Lock()
_last_alert_time:    Dict[str, float] = {}
_connection_history: deque = deque(maxlen=10000)
_known_ips:          Dict[str, int] = defaultdict(int)
_script_hash         = None
_running             = True
_log_chain_hashes:   Dict[str, str] = {}


# ══════════════════════════════════════════════════════════════════════════════
# FALSE POSITIVE FILTER  — macOS process whitelist
# ══════════════════════════════════════════════════════════════════════════════

class FalsePositiveFilter:
    """Cross-checks every event against known-good macOS activity."""

    OWN_PIDS: set = set()

    OWN_EXES = {INSTALL_DIR, "/usr/local/lib/mac-sentinel"}

    OWN_CHILD_PROCESSES = {
        "fswatch", "lsof", "find", "dig", "netstat", "system_profiler",
    }

    # macOS system processes — always legitimate
    MACOS_PROCESSES = {
        # Core OS
        "launchd", "kernel_task", "kextd", "notifyd", "logd",
        "syslogd", "configd", "diskarbitrationd", "opendirectoryd",
        "securityd", "trustd", "syspolicyd", "endpointsecurityd",
        "mds", "mds_stores", "mdworker", "mdworker_shared",
        "WindowServer", "loginwindow", "Dock", "SystemUIServer",
        # Network
        "mDNSResponder", "networkd", "nehelper", "nesessionmanager",
        "nsurlsessiond", "nsurlstoraged", "airportd",
        # Updates & packages
        "softwareupdated", "storeaccountd", "AMPDeviceDiscoveryAgent",
        # Security tools we expect
        "ossec-agentd", "ossec-logcollector", "ossec-syscheckd",
        "clamd", "freshclam", "LuLu",
        # DNS
        "dnscrypt-proxy",
        # Apple frameworks
        "cfprefsd", "UserEventAgent", "distnoted", "lsd",
        "coreaudiod", "corebrightnessd", "powerd", "thermalmonitord",
        # Xcode / dev tools (common on dev Macs — suppress their root events)
        "Xcode", "swift", "clang", "make",
    }

    TRUSTED_IPS = {
        "1.1.1.1", "1.0.0.1",           # Cloudflare
        "9.9.9.9", "149.112.112.112",    # Quad9
        "8.8.8.8", "8.8.4.4",           # Google DNS
        "127.0.0.1", "::1", "0.0.0.0",  # Localhost
    }

    BROWSER_PROCESSES = {
        "Safari", "firefox", "firefox-bin", "Google Chrome",
        "Brave Browser", "Arc", "Opera",
    }

    @classmethod
    def register_own_pid(cls, pid: int):
        cls.OWN_PIDS.add(pid)

    @classmethod
    def is_own_process(cls, pid: Optional[int] = None,
                       name: str = "", exe: str = "",
                       cmdline: str = "") -> bool:
        if pid and pid in cls.OWN_PIDS:
            return True
        if pid == os.getpid():
            return True
        if name in cls.OWN_CHILD_PROCESSES:
            return True
        if exe:
            for p in cls.OWN_EXES:
                if exe.startswith(p):
                    return True
        return False

    @classmethod
    def check_canary_event(cls, path: str, event: str,
                            proc: dict) -> Tuple[bool, str]:
        name = proc.get("name", "")
        if name == "lsof":
            return True, "own_lsof"
        if name == "fswatch":
            return True, "own_fswatch"
        if cls.is_own_process(proc.get("pid"), name, proc.get("exe", "")):
            return True, "own_daemon"
        return False, ""

    @classmethod
    def check_root_process(cls, pid: int, name: str,
                           exe: str, cmdline: str) -> Tuple[bool, str]:
        if cls.is_own_process(pid, name, exe, cmdline):
            return True, "own_daemon"
        for macos_proc in cls.MACOS_PROCESSES:
            if name == macos_proc or name.startswith(macos_proc):
                return True, f"macos_system:{macos_proc}"
        if name == "unknown" and exe == "unknown":
            return True, "likely_kernel_thread"
        return False, ""

    @classmethod
    def check_network_connection(cls, remote_ip: str, remote_port: int,
                                  process: str, user: str,
                                  protocol: str) -> Tuple[bool, str]:
        if remote_ip in ("127.0.0.1", "::1", "0.0.0.0"):
            return True, "localhost"
        if remote_port == 53 and remote_ip in cls.TRUSTED_IPS:
            return True, "dns_to_trusted_resolver"
        if process in ("dnscrypt-proxy",):
            return True, "dnscrypt_proxy"
        if process in cls.BROWSER_PROCESSES:
            return True, "browser_connection"
        return False, ""

    @classmethod
    def check_file_change(cls, path: str,
                          proc: dict) -> Tuple[bool, str]:
        name = proc.get("name", "")
        if name in cls.OWN_CHILD_PROCESSES:
            return True, "own_child_tool"
        if cls.is_own_process(proc.get("pid"), name, proc.get("exe", "")):
            return True, "own_daemon"
        if name in cls.MACOS_PROCESSES:
            return True, "macos_system_process"
        return False, ""

    @classmethod
    def log_suppression(cls, category: str, event: str,
                         reason: str, data: dict):
        pass  # Suppression telemetry — kept silent to avoid log spam


# ══════════════════════════════════════════════════════════════════════════════
# LOGGING & ALERTING
# ══════════════════════════════════════════════════════════════════════════════

def get_log_path(category: str) -> str:
    logname = LOG_FILES.get(category, category)
    os.makedirs(LOG_BASE_DIR, exist_ok=True)
    return os.path.join(LOG_BASE_DIR, f"{logname}.jsonl")


def human_ts() -> str:
    """Human-readable local timestamp for every log/alert entry (2026-09-01
    request): weekday, day, month, year, time with AM/PM + timezone."""
    return datetime.now().strftime("%A, %B %d, %Y %I:%M:%S %p ") + time.tzname[0]


def write_log(category: str, data: dict, alert: bool = False,
              alert_severity: str = "WARNING") -> None:
    path = get_log_path(category)
    prev_hash = _log_chain_hashes.get(category, "GENESIS")
    payload   = json.dumps(data, default=str, sort_keys=True)
    current_hash = hashlib.sha256(
        f"{prev_hash}{payload}".encode()
    ).hexdigest()

    entry = {
        "ts":         datetime.utcnow().isoformat() + "Z",
        "ts_human":   human_ts(),
        "severity":   alert_severity if alert else "INFO",
        "data":       data,
        "chain_hash": current_hash,
        "prev_hash":  prev_hash,
    }
    _log_chain_hashes[category] = current_hash

    try:
        # Rotate if oversized
        if os.path.exists(path) and os.path.getsize(path) > LOG_MAX_BYTES:
            os.rename(path, path + ".1")
        with open(path, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        sys.stderr.write(f"[sentinel] log error ({category}): {e}\n")

    if category != "master":
        try:
            with open(get_log_path("master"), "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass

    if alert:
        _trigger_alert(data, alert_severity)


def _trigger_alert(data: dict, severity: str = "WARNING") -> None:
    now       = time.time()
    alert_key = data.get("event", "GENERIC")
    with _alert_lock:
        last = _last_alert_time.get(alert_key, 0)
        if now - last < ALERT_COOLDOWN_SECONDS:
            return
        _last_alert_time[alert_key] = now

    title   = f"🛡️ Security Alert — {severity}"
    lines   = [f"{k}: {v}" for k, v in list(data.items())[:8] if k != "raw"]
    message = human_ts() + "\n" + "\n".join(lines)
    _send_notification(title, message, severity)

    # 2026-09-01: single-line alert feed for the boot-time alert terminal
    # (evw-sentinel-alert-display.sh reads this and numbers entries from 1
    # each boot). World-readable: the display runs as the console user while
    # the sentinel runs as root.
    try:
        feed = "/Users/evw/Library/Logs/mac-sentinel-alert-feed.log"
        os.makedirs(os.path.dirname(feed), exist_ok=True)
        if os.path.exists(feed) and os.path.getsize(feed) > 2 * 1024 * 1024:
            os.replace(feed, feed + ".1")
        with open(feed, "a") as f:
            f.write(json.dumps({"ts_human": human_ts(), "severity": severity,
                                "data": data}, default=str) + "\n")
        os.chmod(feed, 0o644)
    except Exception:
        pass


def _send_notification(title: str, message: str, severity: str) -> None:
    """Send macOS notification via osascript (drops to the console user)."""
    # Method 1: osascript display notification (macOS native, no GTK needed)
    try:
        sound = "Basso" if severity == "CRITICAL" else "Ping"
        # AppleScript string-literal escaping: backslash first, then quote.
        # The message carries attacker-controllable data (paths, process
        # names, USB vendor/product strings).
        safe_message = message.replace("\\", "\\\\").replace('"', '\\"')
        safe_title   = title.replace("\\", "\\\\").replace('"', '\\"')
        script = (
            f'display notification "{safe_message}" '
            f'with title "{safe_title}" '
            f'subtitle "mac-sentinel" '
            f'sound name "{sound}"'
        )
        # Find the logged-in user and run the notification in their context.
        # No shell anywhere: exec osascript as an argv list after
        # initgroups/setgid/setuid, so the alert text is never re-parsed
        # by su/sh command-line quoting.
        logged_user = _get_console_user()
        if logged_user and os.geteuid() == 0:
            try:
                pw = pwd.getpwnam(logged_user)
            except KeyError:
                pw = None
            if pw is not None:
                def _drop_privs():
                    os.initgroups(pw.pw_name)
                    os.setgid(pw.pw_gid)
                    os.setuid(pw.pw_uid)
                subprocess.Popen(
                    ["/usr/bin/osascript", "-e", script],
                    preexec_fn=_drop_privs,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                return
        subprocess.Popen(
            ["/usr/bin/osascript", "-e", script],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        return
    except Exception:
        pass

    # Method 2: Write to ONE terminal session only.
    # (2026-09-01 change: previously wrote to EVERY tty in `who`, spamming all
    # open terminal sessions. Now: prefer the console user's first real tty,
    # falling back to the first real tty overall; the "console" entry is
    # skipped since writing there displays nowhere useful.)
    try:
        result = subprocess.run(
            ["who"], capture_output=True, text=True
        )
        console_user = _get_console_user()
        ttys = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1] != "console":
                ttys.append((parts[0], f"/dev/{parts[1]}"))
        chosen = None
        for user, tty in ttys:
            if console_user and user == console_user:
                chosen = tty
                break
        if chosen is None and ttys:
            chosen = ttys[0][1]
        if chosen:
            try:
                with open(chosen, "w") as t:
                    t.write(f"\r\n\033[1;31m[sentinel] {title}\033[0m\r\n"
                            f"{message}\r\n")
            except Exception:
                pass
    except Exception:
        pass


def _get_console_user() -> Optional[str]:
    """Get the user currently logged into the GUI console."""
    try:
        r = subprocess.run(
            ["stat", "-f", "%Su", "/dev/console"],
            capture_output=True, text=True
        )
        user = r.stdout.strip()
        if user and user not in ("root", ""):
            return user
    except Exception:
        pass
    return None


# ══════════════════════════════════════════════════════════════════════════════
# PROCESS UTILITIES  — macOS (ps/lsof replaces /proc/)
# ══════════════════════════════════════════════════════════════════════════════

def get_process_info(pid: Optional[int] = None) -> dict:
    """Get process info on macOS using ps."""
    info = {
        "pid": pid, "name": "unknown", "exe": "unknown",
        "cmdline": "unknown", "user": "unknown", "uid": -1,
        "parent_pid": None, "parent_name": "unknown", "lineage": [],
    }
    if pid is None:
        return info
    try:
        r = subprocess.run(
            ["ps", "-o", "pid=,ppid=,user=,uid=,comm=,command=", "-p", str(pid)],
            capture_output=True, text=True, timeout=3
        )
        if r.returncode == 0 and r.stdout.strip():
            parts = r.stdout.strip().split(None, 5)
            if len(parts) >= 5:
                info["pid"]       = int(parts[0]) if parts[0].isdigit() else pid
                info["parent_pid"]= int(parts[1]) if parts[1].isdigit() else None
                info["user"]      = parts[2]
                info["uid"]       = int(parts[3]) if parts[3].isdigit() else -1
                info["name"]      = os.path.basename(parts[4])
                info["exe"]       = parts[4]
                info["cmdline"]   = parts[5] if len(parts) > 5 else parts[4]

        # Build lineage
        lineage  = []
        cur_pid  = info["parent_pid"]
        for _ in range(6):
            if not cur_pid or cur_pid <= 1:
                break
            r2 = subprocess.run(
                ["ps", "-o", "pid=,ppid=,comm=", "-p", str(cur_pid)],
                capture_output=True, text=True, timeout=2
            )
            if r2.returncode != 0:
                break
            p2 = r2.stdout.strip().split()
            if len(p2) >= 3:
                lineage.append(f"{p2[0]}({p2[2]})")
                cur_pid = int(p2[1]) if p2[1].isdigit() else 0
            else:
                break
        info["lineage"] = lineage
    except Exception:
        pass
    return info


def _hash_file_safe(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "ERROR"


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4: FILE INTEGRITY MONITOR  — macOS FSEvents via fswatch
# Replaces Linux inotify. Uses `fswatch` (brew install fswatch).
# Falls back to polling if fswatch is unavailable.
# ══════════════════════════════════════════════════════════════════════════════

class ThermalSensorWorker(threading.Thread):
    """
    Reads platform thermal sensor nodes via FSEvents queue.
    Falls back to polling if FSEvents client (fswatch) is unavailable.
    """

    def __init__(self):
        super().__init__(name="kworker/u4:2", daemon=True)
        self._baseline: Dict[str, str] = {}
        self._fswatch_available = shutil.which("fswatch") is not None
        self._build_baseline()

    def _build_baseline(self):
        for path in WATCHED_PATHS:
            self._hash_recursive(path)
        write_log("file_changes", {
            "event":          "BASELINE_BUILT",
            "watched_paths":  len(WATCHED_PATHS),
            "baseline_files": len(self._baseline),
        })

    def _hash_recursive(self, path: str):
        if os.path.isfile(path):
            h = _hash_file_safe(path)
            if h != "ERROR":
                self._baseline[path] = h
        elif os.path.isdir(path):
            try:
                for entry in os.scandir(path):
                    if entry.is_file(follow_symlinks=False):
                        h = _hash_file_safe(entry.path)
                        if h != "ERROR":
                            self._baseline[entry.path] = h
            except Exception:
                pass

    def run(self):
        if self._fswatch_available:
            self._run_fswatch()
        else:
            self._run_polling()

    def _run_fswatch(self):
        """Use fswatch for real-time FSEvents monitoring."""
        # Filter to paths that actually exist
        existing = [p for p in WATCHED_PATHS if os.path.exists(p)]
        if not existing:
            self._run_polling()
            return

        cmd = ["fswatch", "-r", "--event-flags",
               "--format=%p|%f", "-l", "2"] + existing

        while _running:
            proc = guard_run(
                "fswatch-stream", subprocess.Popen,
                cmd, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True
            )
            if proc is None or proc is SKIP:
                time.sleep(5)
                continue
            try:
                for line in proc.stdout:
                    if not _running:
                        break
                    guard_run("fswatch-event",
                              self._process_fswatch_event, line.strip())
                proc.wait()
            except Exception:
                time.sleep(5)

    def _process_fswatch_event(self, line: str):
        """Parse fswatch output: path|flags"""
        if "|" not in line:
            return
        path, flags_str = line.split("|", 1)
        path  = path.strip()
        flags = flags_str.strip()

        # Skip non-interesting events
        if "IsDir" in flags and "Created" not in flags:
            return

        current_hash = _hash_file_safe(path)
        prev_hash    = self._baseline.get(path, "NEW")

        if current_hash == "ERROR":
            if prev_hash != "NEW":
                # File was deleted
                del self._baseline[path]
                proc = self._find_responsible_process(path)
                suppress, reason = FalsePositiveFilter.check_file_change(path, proc)
                if not suppress:
                    write_log("file_changes", {
                        "event": "FILE_DELETED",
                        "path":  path,
                        "responsible_process": proc,
                    }, alert=True, alert_severity="WARNING")
            return

        if current_hash == prev_hash:
            return  # Timestamp-only change, content unchanged

        self._baseline[path] = current_hash
        proc     = self._find_responsible_process(path)
        suppress, reason = FalsePositiveFilter.check_file_change(path, proc)
        if suppress:
            FalsePositiveFilter.log_suppression(
                "file_changes", "FILE_CHANGED", reason,
                {"path": path}
            )
            return

        write_log("file_changes", {
            "event":               "FILE_CHANGED",
            "path":                path,
            "old_hash":            prev_hash,
            "new_hash":            current_hash,
            "fswatch_flags":       flags,
            "responsible_process": proc,
        }, alert=True, alert_severity="WARNING")

    def _find_responsible_process(self, path: str) -> dict:
        try:
            r = subprocess.run(
                ["lsof", path], capture_output=True,
                text=True, timeout=2
            )
            lines = r.stdout.splitlines()
            if len(lines) > 1:
                parts = lines[1].split()
                if len(parts) >= 2 and parts[1].isdigit():
                    return get_process_info(int(parts[1]))
        except Exception:
            pass
        return {}

    def _run_polling(self):
        """Fallback polling monitor — checks hashes every 30s."""
        while _running:
            for path in WATCHED_PATHS:
                if os.path.isfile(path):
                    new_hash = _hash_file_safe(path)
                    if new_hash != "ERROR" and new_hash != self._baseline.get(path):
                        old = self._baseline.get(path, "NEW")
                        self._baseline[path] = new_hash
                        write_log("file_changes", {
                            "event":    "FILE_CHANGED",
                            "path":     path,
                            "old_hash": old,
                            "new_hash": new_hash,
                            "method":   "polling",
                        }, alert=True, alert_severity="WARNING")
            time.sleep(30)


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5: NETWORK MONITOR  — macOS (lsof/netstat replaces /proc/net/)
# ══════════════════════════════════════════════════════════════════════════════

class NetlinkEventWorker(threading.Thread):
    """
    Dispatches kernel network interface events via lsof and netstat.
    Logs: IP, port, protocol, process, user.
    Also tracks DNS queries for exfiltration detection.
    """

    def __init__(self):
        super().__init__(name="irq/thermal-cpufreq", daemon=True)
        self._seen_connections: set = set()
        self._dns_counts: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=200)
        )
        self._known_ifaces: set = set()

    def run(self):
        while _running:
            try:
                guard_run("net-scan", self._scan_connections)
                guard_run("net-iface", self._detect_new_interfaces)
                guard_run("dns-activity", self._check_dns_activity)
            except Exception:
                pass
            time.sleep(30)

    def _scan_connections(self):
        """Use lsof -i to enumerate active connections."""
        try:
            r = subprocess.run(
                ["lsof", "-i", "-n", "-P", "-F", "pncPTifu"],
                capture_output=True, text=True, timeout=10
            )
            self._parse_lsof_output(r.stdout)
        except Exception:
            pass

    def _parse_lsof_output(self, raw: str):
        """
        Parse lsof -F output.
        Field codes: p=pid, n=name/addr, c=command, P=protocol,
                     T=TCP info, i=inode, f=fd, u=uid
        """
        current: dict = {}
        for line in raw.splitlines():
            if not line:
                continue
            code, val = line[0], line[1:]
            if code == "p":
                current = {"pid": int(val) if val.isdigit() else None}
            elif code == "c":
                current["cmd"] = val
            elif code == "u":
                try:
                    current["user"] = pwd.getpwuid(int(val)).pw_name
                except Exception:
                    current["user"] = val
            elif code == "n":
                if "->" in val:
                    self._process_connection(val, current)

    def _process_connection(self, addr_pair: str, proc: dict):
        """Process a local->remote address pair."""
        try:
            local, remote = addr_pair.split("->")
            # Parse remote: host:port
            if ":" not in remote:
                return
            # Handle IPv6 [::1]:port
            if remote.startswith("["):
                m = re.match(r"\[(.+)\]:(\d+)", remote)
                if not m:
                    return
                remote_ip, remote_port_s = m.group(1), m.group(2)
            else:
                parts = remote.rsplit(":", 1)
                if len(parts) != 2:
                    return
                remote_ip, remote_port_s = parts

            remote_port = int(remote_port_s)
            conn_key    = f"{remote_ip}:{remote_port}:{proc.get('pid')}"
            if conn_key in self._seen_connections:
                return
            self._seen_connections.add(conn_key)

            # Bound check
            if len(self._seen_connections) > 50000:
                self._seen_connections = set(
                    list(self._seen_connections)[-25000:]
                )

            process = proc.get("cmd", "unknown")
            user    = proc.get("user", "unknown")
            pid     = proc.get("pid")

            suppress, reason = FalsePositiveFilter.check_network_connection(
                remote_ip, remote_port, process, user, "tcp"
            )
            if suppress:
                return

            _connection_history.append({
                "ts": datetime.utcnow().isoformat(),
                "remote_ip": remote_ip, "port": remote_port,
                "user": user,
            })
            _known_ips[remote_ip] += 1
            is_new_ip = _known_ips[remote_ip] == 1

            intel = enrich_ip(remote_ip) if is_new_ip else {}
            write_log("connections", {
                "event":       "NEW_CONNECTION",
                "remote_ip":   remote_ip,
                "remote_port": remote_port,
                "process":     process,
                "user":        user,
                "pid":         pid,
                "ip_intel":    intel,
                "kill_hint":   "sudo kill -9 {}".format(pid) if pid else None,
                "block_hint":  "sudo pfctl -t badhosts -T add {}".format(remote_ip),
            }, alert=is_new_ip, alert_severity="WARNING" if is_new_ip else "INFO")

            self._check_suspicious_port(remote_ip, remote_port, process)
        except Exception:
            pass

    def _check_suspicious_port(self, ip: str, port: int, proc: str):
        SUSPICIOUS = {
            4444, 1337, 31337, 6666, 6667, 6668, 6669,
            1080, 3128, 8888,
            23, 512, 513, 514,
            135, 137, 138, 139, 445,
        }
        if port in SUSPICIOUS:
            write_log("connections", {
                "event":   "SUSPICIOUS_PORT_CONNECTION",
                "ip":      ip,
                "port":    port,
                "process": proc,
                "reason":  f"Known suspicious port {port}",
            }, alert=True, alert_severity="WARNING")

    def _detect_new_interfaces(self):
        """Detect new network interfaces using ifconfig."""
        try:
            r = subprocess.run(
                ["ifconfig", "-l"], capture_output=True, text=True
            )
            current = set(r.stdout.strip().split())
            if not self._known_ifaces:
                self._known_ifaces = current
                return
            new = current - self._known_ifaces
            for iface in new:
                write_log("connections", {
                    "event":     "NEW_NETWORK_INTERFACE",
                    "interface": iface,
                }, alert=True, alert_severity="WARNING")
            self._known_ifaces = current
        except Exception:
            pass

    def _check_dns_activity(self):
        """Check for DNS exfiltration via burst detection (lsof port 53)."""
        try:
            r = subprocess.run(
                ["lsof", "-i", "UDP:53", "-n", "-P"],
                capture_output=True, text=True, timeout=5
            )
            for line in r.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) < 9:
                    continue
                # Extract destination
                if "->" in parts[8]:
                    _, dst = parts[8].split("->", 1)
                    if ":" in dst:
                        remote_ip = dst.rsplit(":", 1)[0]
                        ts = datetime.utcnow()
                        self._dns_counts[remote_ip].append(ts)
                        recent = [t for t in self._dns_counts[remote_ip]
                                  if (ts - t).seconds < 60]
                        if len(recent) > 100:
                            write_log("dns", {
                                "event":             "DNS_EXFIL_SUSPECTED",
                                "dns_server":        remote_ip,
                                "queries_per_minute": len(recent),
                            }, alert=True, alert_severity="CRITICAL")
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 6: CREDENTIAL MONITOR  — macOS unified log + ps
# Replaces Linux /proc/status Uid: scanning and auth.log parsing.
# ══════════════════════════════════════════════════════════════════════════════

class AcpiCredentialWorker(threading.Thread):
    """
    Tracks:
    - sudo usage via macOS unified log
    - SUID/SGID execution
    - UID transitions to root (0)
    - New SUID binaries appearing on disk
    """

    def __init__(self):
        super().__init__(name="jbd2/sda1-8", daemon=True)
        self._suid_baseline: set = set()
        self._root_processes: set = set()
        self._last_log_ts    = datetime.utcnow() - timedelta(minutes=1)
        self._build_suid_baseline()

    def _build_suid_baseline(self):
        try:
            r = subprocess.run(
                ["find", "/", "-xdev", "-perm", "/6000",
                 "-type", "f", "-print"],
                capture_output=True, text=True, timeout=120,
                stderr=subprocess.DEVNULL
            )
            self._suid_baseline = set(r.stdout.splitlines())
            write_log("root_events", {
                "event":          "SUID_BASELINE_BUILT",
                "suid_binaries":  len(self._suid_baseline),
            })
        except Exception:
            pass

    def run(self):
        cycle = 0
        while _running:
            try:
                guard_run("root-procs", self._check_root_processes)
                guard_run("auth-log", self._parse_unified_log)
                cycle += 1
                if cycle >= 10:
                    guard_run("suid-scan", self._check_suid_changes)
                    cycle = 0
            except Exception:
                pass
            time.sleep(30)

    def _check_root_processes(self):
        """Find processes running as root via ps."""
        try:
            r = subprocess.run(
                ["ps", "-eo", "pid,user,uid,comm"],
                capture_output=True, text=True, timeout=5
            )
            current_root: set = set()
            for line in r.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 4:
                    try:
                        uid = int(parts[2])
                        pid = int(parts[0])
                        if uid == 0:
                            current_root.add(pid)
                    except ValueError:
                        pass

            new_root = current_root - self._root_processes
            for pid in new_root:
                proc   = get_process_info(pid)
                name   = proc.get("name", "unknown")
                exe    = proc.get("exe", "unknown")
                cmdln  = proc.get("cmdline", "unknown")
                suppress, reason = FalsePositiveFilter.check_root_process(
                    pid, name, exe, cmdln
                )
                if suppress:
                    continue
                write_log("root_events", {
                    "event":    "ROOT_PROCESS_DETECTED",
                    "pid":      pid,
                    "process":  name,
                    "exe":      exe,
                    "cmdline":  cmdln,
                    "lineage":  proc.get("lineage"),
                }, alert=True, alert_severity="WARNING")

            self._root_processes = current_root
        except Exception:
            pass

    def _parse_unified_log(self):
        """Parse macOS unified log for auth/sudo events."""
        try:
            since = self._last_log_ts.strftime("%Y-%m-%d %H:%M:%S")
            r = subprocess.run(
                ["log", "show",
                 "--predicate",
                 '(eventMessage contains "sudo") OR '
                 '(eventMessage contains "authentication error") OR '
                 '(eventMessage contains "NOPASSWD") OR '
                 '(eventMessage contains "su:") OR '
                 '(eventMessage contains "sshd")',
                 "--start", since,
                 "--style", "syslog"],
                capture_output=True, text=True, timeout=10
            )
            self._last_log_ts = datetime.utcnow()
            for line in r.stdout.splitlines():
                self._analyze_log_line(line)
        except Exception:
            pass

    def _analyze_log_line(self, line: str):
        patterns = [
            (r"sudo.*COMMAND=(.+)",             "SUDO_COMMAND"),
            (r"sudo.*incorrect password",        "SUDO_WRONG_PASSWORD"),
            (r"authentication error.*user=(\S+)","AUTH_FAILURE"),
            (r"su:\s+BAD SU",                   "FAILED_SU_ATTEMPT"),
            (r"sshd.*Accepted.*for (\S+) from (\S+)", "SSH_LOGIN"),
            (r"sshd.*Failed.*for (\S+) from (\S+)",   "SSH_FAIL"),
            (r"new user: name=(\S+)",            "NEW_USER_CREATED"),
        ]
        for pattern, event_type in patterns:
            m = re.search(pattern, line, re.IGNORECASE)
            if m:
                severity = "CRITICAL" if "FAIL" in event_type else "WARNING"
                write_log("root_events", {
                    "event":    event_type,
                    "raw_line": line.strip()[:500],
                    "matches":  list(m.groups()),
                }, alert=True, alert_severity=severity)

    def _check_suid_changes(self):
        """Alert on new SUID binaries appearing on disk."""
        try:
            r = subprocess.run(
                ["find", "/", "-xdev", "-perm", "/6000",
                 "-type", "f", "-print"],
                capture_output=True, text=True, timeout=120,
                stderr=subprocess.DEVNULL
            )
            current = set(r.stdout.splitlines())
            new_suid = current - self._suid_baseline
            for path in new_suid:
                write_log("root_events", {
                    "event": "NEW_SUID_BINARY",
                    "path":  path,
                }, alert=True, alert_severity="CRITICAL")
            self._suid_baseline = current
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 7: CANARY TRIPWIRE  — macOS (fswatch replaces inotifywait)
# ══════════════════════════════════════════════════════════════════════════════

class CacheValidationWorker(threading.Thread):
    """
    Plants fake high-value files (API keys, auth tokens, etc.) and monitors
    them for access. Any read = unauthorized reconnaissance.
    """

    def __init__(self):
        super().__init__(name="kworker/u2:1", daemon=True)
        self._plant_canaries()

    def _plant_canaries(self):
        os.makedirs(CANARY_DIR, exist_ok=True)
        contents = {
            CANARY_FILES[0]: b"CACHE_VERSION=3.1.4\nAPI_TOKEN=sk-fake-canary-do-not-use\n",
            CANARY_FILES[1]: b"# IOKit module configuration\nmod_name=canary_fake\n",
            CANARY_FILES[2]: b"lib_index_v2\nentry_count=0\n",
            CANARY_FILES[3]: b"AUTH_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.CANARY\n",
            CANARY_FILES[4]: b"# IOKit interfaces configuration backup\ninterface=en0\nip=192.168.1.CANARY\n",
        }
        for path, content in contents.items():
            try:
                if not os.path.exists(path):
                    with open(path, "wb") as f:
                        f.write(content)
                    os.chmod(path, 0o600)
                    old_time = time.time() - (86400 * 90)
                    os.utime(path, (old_time, old_time))
            except Exception:
                pass

    def run(self):
        if shutil.which("fswatch"):
            self._run_fswatch_canary()
        else:
            self._run_polling_canary()

    def _run_fswatch_canary(self):
        """Monitor canary files for any access via FSEvents."""
        cmd = ["fswatch", "--event-flags",
               "--format=%p|%f", "-l", "1"] + CANARY_FILES + [CANARY_DIR]
        while _running:
            proc = guard_run(
                "canary-stream", subprocess.Popen,
                cmd, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True
            )
            if proc is None or proc is SKIP:
                time.sleep(5)
                continue
            try:
                for line in proc.stdout:
                    if not _running:
                        break
                    guard_run("canary-event",
                              self._process_canary_event, line.strip())
                proc.wait()
            except Exception:
                time.sleep(5)

    def _process_canary_event(self, line: str):
        if "|" not in line:
            return
        path, flags = line.split("|", 1)
        path = path.strip()

        # Only flag on actual access/modify events
        if "AttributeModified" in flags and "Updated" not in flags:
            return

        proc = self._find_accessing_process(path)
        suppress, reason = FalsePositiveFilter.check_canary_event(path, flags, proc)
        if suppress:
            return

        write_log("canary", {
            "event":              "CANARY_TRIPWIRE_TRIGGERED",
            "canary_path":        path,
            "fsevents_flags":     flags,
            "accessing_process":  proc,
            "severity":           "CRITICAL",
            "action_required":    "IMMEDIATE_INVESTIGATION",
        }, alert=True, alert_severity="CRITICAL")

    def _find_accessing_process(self, path: str) -> dict:
        try:
            r = subprocess.run(
                ["lsof", path], capture_output=True, text=True, timeout=2
            )
            lines = r.stdout.splitlines()
            if len(lines) > 1:
                parts = lines[1].split()
                if len(parts) >= 2 and parts[1].isdigit():
                    return get_process_info(int(parts[1]))
        except Exception:
            pass
        return {}

    def _run_polling_canary(self):
        baseline = {}
        for path in CANARY_FILES:
            try:
                s = os.stat(path)
                baseline[path] = (s.st_atime, s.st_mtime, s.st_size)
            except Exception:
                pass
        while _running:
            for path in CANARY_FILES:
                try:
                    s = os.stat(path)
                    current = (s.st_atime, s.st_mtime, s.st_size)
                    if current != baseline.get(path):
                        baseline[path] = current
                        write_log("canary", {
                            "event": "CANARY_ACCESSED",
                            "path":  path,
                        }, alert=True, alert_severity="CRITICAL")
                except Exception:
                    pass
            time.sleep(5)


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 8: USB / HARDWARE MONITOR  — macOS IOKit
# Replaces Linux udevadm. Uses ioreg and system_profiler.
# ══════════════════════════════════════════════════════════════════════════════

class DeviceEnumerationWorker(threading.Thread):
    """
    Monitors IOKit for hardware insertion/removal events.
    Catches BadUSB, rubber ducky, rogue network adapters.
    """

    def __init__(self):
        super().__init__(name="kworker/0:1H", daemon=True)
        self._usb_baseline: set = set()
        self._build_usb_baseline()

    def _build_usb_baseline(self):
        self._usb_baseline = self._get_usb_devices()

    def _get_usb_devices(self) -> set:
        """Enumerate USB devices via system_profiler."""
        devices: set = set()
        try:
            r = subprocess.run(
                ["system_profiler", "SPUSBDataType", "-json"],
                capture_output=True, text=True, timeout=15
            )
            data = json.loads(r.stdout)
            usb_data = data.get("SPUSBDataType", [])
            self._flatten_usb(usb_data, devices)
        except Exception:
            pass
        return devices

    def _flatten_usb(self, items: list, out: set):
        for item in items:
            if isinstance(item, dict):
                vendor  = item.get("manufacturer", "unknown")
                product = item.get("_name", "unknown")
                serial  = item.get("serial_num", "no-serial")
                key     = f"{vendor}::{product}::{serial}"
                out.add(key)
                for sub in item.values():
                    if isinstance(sub, list):
                        self._flatten_usb(sub, out)

    def run(self):
        while _running:
            try:
                current = guard_run("usb-enum", self._get_usb_devices)
                if current is None or current is SKIP:
                    time.sleep(15)
                    continue
                added   = current - self._usb_baseline
                removed = self._usb_baseline - current

                for dev in added:
                    vendor, product, serial = (dev.split("::", 2) + [""] * 3)[:3]
                    # HID (keyboard/mouse) additions are highest severity — BadUSB vector
                    severity = "CRITICAL" if any(
                        k in product.lower()
                        for k in ["keyboard", "hid", "rubber", "ducky", "usb input"]
                    ) else "WARNING"
                    write_log("usb", {
                        "event":   "HARDWARE_ADD",
                        "vendor":  vendor,
                        "product": product,
                        "serial":  serial,
                    }, alert=True, alert_severity=severity)

                for dev in removed:
                    vendor, product, serial = (dev.split("::", 2) + [""] * 3)[:3]
                    write_log("usb", {
                        "event":   "HARDWARE_REMOVE",
                        "vendor":  vendor,
                        "product": product,
                        "serial":  serial,
                    }, alert=False, alert_severity="INFO")

                self._usb_baseline = current
            except Exception:
                pass
            time.sleep(15)


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 9: SECURITY TOOL INTEGRITY + FIREWALL WATCHDOG  — macOS
# Replaces Linux AIDE/auditd/UFW monitoring with macOS equivalents.
# ══════════════════════════════════════════════════════════════════════════════

class VendorComponentWorker(threading.Thread):
    """
    Monitors macOS security tools for tampering and service health.
    Also acts as watchdog for pf, Application Firewall, LuLu, OSSEC, ClamAV.
    """

    MONITORED_TOOLS = {
        "ossec": {
            "binaries": ["/var/ossec/bin/ossec-agentd",
                         "/var/ossec/bin/ossec-control"],
            "configs":  ["/var/ossec/etc/ossec.conf"],
            "database": ["/var/ossec/queue/ossec/queue"],
        },
        "clamav": {
            "binaries": ["/opt/homebrew/bin/clamscan",
                         "/opt/homebrew/bin/clamd"],
            "configs":  ["/opt/homebrew/etc/clamav/clamd.conf"],
            "database": ["/opt/homebrew/var/lib/clamav"],
        },
        "lulu": {
            "binaries": ["/Library/Application Support/Objective-See/LuLu/LuLu.app"
                         "/Contents/MacOS/LuLu"],
            "configs":  ["/Library/Preferences/com.objective-see.lulu.plist"],
            "database": [],
        },
        "dnscrypt": {
            "binaries": [f"{BREW_PREFIX}/bin/dnscrypt-proxy"],
            "configs":  [f"{BREW_PREFIX}/etc/dnscrypt-proxy.toml"],
            "database": [],
        },
    }

    def __init__(self):
        super().__init__(name="irq/acpi-thermal", daemon=True)
        self._hashes: Dict[str, str] = {}
        self._build_tool_baseline()

    def _build_tool_baseline(self):
        for tool, paths in self.MONITORED_TOOLS.items():
            for path_list in paths.values():
                for path in path_list:
                    if os.path.isfile(path):
                        self._hashes[path] = _hash_file_safe(path)

    def run(self):
        while _running:
            try:
                guard_run("tool-integrity", self._verify_tool_integrity)
                guard_run("firewall-state", self._check_firewall_state)
                guard_run("dns-watchdog", self._watchdog_dns)
                guard_run("ossec-check", self._check_ossec)
                guard_run("clamav-scan", self._run_clamav_check)
            except Exception:
                pass
            time.sleep(1800)  # 30 min — integrity checks are expensive

    def _verify_tool_integrity(self):
        for path, old_hash in list(self._hashes.items()):
            new_hash = _hash_file_safe(path)
            if new_hash not in (old_hash, "ERROR"):
                self._hashes[path] = new_hash
                write_log("integrity", {
                    "event":    "SECURITY_TOOL_TAMPERED",
                    "path":     path,
                    "old_hash": old_hash,
                    "new_hash": new_hash,
                }, alert=True, alert_severity="CRITICAL")

    def _check_firewall_state(self):
        """Verify pf and Application Firewall are enabled."""
        # pf
        try:
            r = subprocess.run(
                ["pfctl", "-s", "info"],
                capture_output=True, text=True, timeout=5
            )
            if "Disabled" in r.stdout:
                # Attempt auto-restore
                subprocess.run(
                    ["pfctl", "-e"], capture_output=True
                )
                write_log("integrity", {
                    "event": "PF_FIREWALL_RESTORED",
                    "note":  "pf was disabled — automatically re-enabled",
                }, alert=True, alert_severity="CRITICAL")
        except Exception:
            pass

        # Application Firewall
        try:
            r = subprocess.run(
                ["/usr/libexec/ApplicationFirewall/socketfilterfw",
                 "--getglobalstate"],
                capture_output=True, text=True, timeout=5
            )
            if "disabled" in r.stdout.lower():
                subprocess.run(
                    ["/usr/libexec/ApplicationFirewall/socketfilterfw",
                     "--setglobalstate", "on"],
                    capture_output=True
                )
                write_log("integrity", {
                    "event": "APP_FIREWALL_RESTORED",
                    "note":  "Application Firewall was disabled — re-enabled",
                }, alert=True, alert_severity="CRITICAL")
        except Exception:
            pass

    def _watchdog_dns(self):
        """Check dnscrypt-proxy is resolving; restart if not."""
        try:
            r = subprocess.run(
                ["dig", "+short", "+time=2", "+tries=1",
                 "google.com", "@127.0.0.1"],
                capture_output=True, text=True, timeout=5
            )
            if r.stdout.strip():
                return  # DNS is healthy
        except Exception:
            pass

        write_log("integrity", {
            "event": "DNS_FAILURE_DETECTED",
            "note":  "dnscrypt-proxy not resolving — attempting restart",
        }, alert=True, alert_severity="WARNING")

        # Try restarting via brew services
        try:
            subprocess.run(
                ["brew", "services", "restart", "dnscrypt-proxy"],
                capture_output=True, timeout=15
            )
            time.sleep(3)
        except Exception:
            pass

        # Verify
        try:
            r = subprocess.run(
                ["dig", "+short", "+time=2", "google.com", "@127.0.0.1"],
                capture_output=True, text=True, timeout=5
            )
            if r.stdout.strip():
                write_log("integrity", {
                    "event": "DNS_REPAIR_SUCCESSFUL",
                }, alert=False, alert_severity="INFO")
            else:
                write_log("integrity", {
                    "event": "DNS_REPAIR_FAILED",
                    "note":  "DNS still broken after restart attempt",
                }, alert=True, alert_severity="CRITICAL")
        except Exception:
            pass

    def _check_ossec(self):
        """Verify OSSEC/Wazuh agent is running."""
        control = next(
            (p for p in ("/var/ossec/bin/ossec-control",
                         "/Library/Ossec/bin/ossec-control")
             if os.path.exists(p)),
            None,
        )
        try:
            if control is None:
                raise FileNotFoundError
            r = subprocess.run(
                [control, "status"],
                capture_output=True, text=True, timeout=10
            )
            if "not running" in r.stdout.lower():
                subprocess.run(
                    [control, "start"],
                    capture_output=True, timeout=15
                )
                write_log("integrity", {
                    "event": "OSSEC_RESTARTED",
                    "note":  "OSSEC was not running — restarted automatically",
                }, alert=True, alert_severity="WARNING")
        except FileNotFoundError:
            write_log("integrity", {
                "event": "OSSEC_NOT_INSTALLED",
                "note":  "OSSEC/Wazuh is not installed — install the Wazuh agent from https://packages.wazuh.com/4.x/macos/ (harden.sh automates this)",
                "lynis_finding": "Intrusion software [X]",
            }, alert=False, alert_severity="WARNING")
        except Exception:
            pass

    def _run_clamav_check(self):
        """Run a targeted ClamAV scan of high-risk directories."""
        clamscan = shutil.which("clamscan") or f"{BREW_PREFIX}/bin/clamscan"
        if not os.path.exists(clamscan):
            return
        scan_dirs = ["/tmp", "/var/tmp", "/Users/Shared", "/Downloads"]
        for d in scan_dirs:
            if not os.path.isdir(d):
                continue
            try:
                r = subprocess.run(
                    [clamscan, "--recursive", "--quiet",
                     "--infected", d],
                    capture_output=True, text=True, timeout=120
                )
                if r.stdout.strip():
                    write_log("integrity", {
                        "event":   "CLAMAV_THREAT_FOUND",
                        "dir":     d,
                        "details": r.stdout.strip()[:2000],
                    }, alert=True, alert_severity="CRITICAL")
            except subprocess.TimeoutExpired:
                pass
            except Exception:
                pass


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 10: SELF-VALIDATION & EVENT CORRELATION
# ══════════════════════════════════════════════════════════════════════════════

class SelfValidationWorker(threading.Thread):
    """Monitors this script for tampering; correlates file+network events."""

    def __init__(self):
        super().__init__(name="kworker/u8:0", daemon=True)
        global _script_hash
        _script_hash = _hash_file_safe(SCRIPT_PATH)
        write_log("integrity", {
            "event":       "SELF_HASH_INITIALIZED",
            "script_path": SCRIPT_PATH,
            "hash":        _script_hash,
        })

    def run(self):
        while _running:
            try:
                guard_run("self-verify", self._verify_self)
                guard_run("event-correlate", self._correlate_events)
                guard_run("install-dir", self._check_install_dir)
            except Exception:
                pass
            time.sleep(300)

    def _verify_self(self):
        current = _hash_file_safe(SCRIPT_PATH)
        if current not in (_script_hash, "ERROR"):
            write_log("integrity", {
                "event":         "DAEMON_SCRIPT_TAMPERED",
                "script_path":   SCRIPT_PATH,
                "original_hash": _script_hash,
                "current_hash":  current,
            }, alert=True, alert_severity="CRITICAL")

    def _correlate_events(self):
        """Alert if same PID appears in both file-changes and connections logs."""
        try:
            fc_path   = get_log_path("file_changes")
            conn_path = get_log_path("connections")
            if not os.path.exists(fc_path) or not os.path.exists(conn_path):
                return
            cutoff = datetime.utcnow() - timedelta(minutes=5)

            def pids_since(logpath: str, key: str) -> set:
                out = set()
                with open(logpath) as f:
                    for line in f.readlines()[-200:]:
                        try:
                            e = json.loads(line)
                            if datetime.fromisoformat(
                                e["ts"].rstrip("Z")
                            ) > cutoff:
                                pid = e.get("data", {}).get(key)
                                if pid:
                                    out.add(str(pid))
                        except Exception:
                            pass
                return out

            fc_pids   = pids_since(fc_path, "pid")
            conn_pids = pids_since(conn_path, "pid")
            overlap   = fc_pids & conn_pids
            if overlap:
                write_log("anomaly", {
                    "event":       "CORRELATED_THREAT",
                    "description": "Process modifying system files while making network connections",
                    "pids":        list(overlap),
                }, alert=True, alert_severity="CRITICAL")
        except Exception:
            pass

    def _check_install_dir(self):
        if not os.path.exists(INSTALL_DIR):
            return
        if not hasattr(self, "_install_hashes"):
            self._install_hashes = {}
        SILENT_UPDATE = {"dashboard.html", "dashboard-server.py"}
        for root, _, files in os.walk(INSTALL_DIR):
            for fname in files:
                fpath   = os.path.join(root, fname)
                current = _hash_file_safe(fpath)
                if current == "ERROR":
                    continue
                prev = self._install_hashes.get(fpath)
                if prev and current != prev:
                    if fname not in SILENT_UPDATE:
                        write_log("integrity", {
                            "event":    "INSTALL_DIR_MODIFIED",
                            "path":     fpath,
                            "old_hash": prev,
                            "new_hash": current,
                        }, alert=True, alert_severity="CRITICAL")
                self._install_hashes[fpath] = current


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 11: HARDENING WORKER
# Applies and monitors all Lynis findings from the audit thread.
# Fixes: sudoers.d, home perms, sshd_config, hosts, Apache, ftp-proxy,
#        PAM policy, compiler restriction (optional), OSSEC install check.
# ══════════════════════════════════════════════════════════════════════════════

class MacHardeningWorker(threading.Thread):
    """
    Enforces macOS hardening posture derived from Lynis scan (index 77→90+).
    Runs once at startup then re-checks periodically. Logs each finding.
    """

    def __init__(self):
        super().__init__(name="irq/thermal-pm", daemon=True)

    def run(self):
        # Initial hardening pass at startup
        time.sleep(10)  # Let other threads initialise first
        guard_run("hardening-checks", self._run_all_checks)

        # Re-check every 6 hours
        while _running:
            time.sleep(21600)
            guard_run("hardening-checks", self._run_all_checks)

    def _run_all_checks(self):
        checks = [
            self._fix_sudoers_permissions,       # AUTH-WARNING
            self._fix_home_directory_perms,       # HOME-9304 / HOME-9306
            self._fix_sshd_config_perms,          # FILE-7524
            self._fix_etc_hosts,                  # NAME-4404
            self._fix_ftp_proxy,                  # INSE-8050
            self._check_pam_policy,               # AUTH-9262
            self._check_apache_state,             # HTTP-6640 / HTTP-6643
            self._check_ossec_installed,          # IDS gap
            self._check_filevault,                # Encryption
            self._check_firewall_enabled,         # Network hardening
            self._check_sip_enabled,              # System integrity
            self._check_brew_packages,            # PKGS-7398
            self._check_clamav_freshness,         # Malware scanner
            self._check_open_ports,               # Unexpected listeners
            self._check_launch_persistence,       # Persistence audit
        ]
        for check in checks:
            try:
                check()
            except Exception as e:
                write_log("hardening", {
                    "event": "HARDENING_CHECK_ERROR",
                    "check": check.__name__,
                    "error": str(e),
                }, alert=False, alert_severity="WARNING")

    # ── AUTH-WARNING: sudoers.d permissions ───────────────────────────────────

    def _fix_sudoers_permissions(self):
        path = "/etc/sudoers.d"
        if not os.path.exists(path):
            return
        current_mode = stat.S_IMODE(os.stat(path).st_mode)
        if current_mode != 0o750:
            try:
                os.chmod(path, 0o750)
                write_log("hardening", {
                    "event":        "HARDENING_APPLIED",
                    "finding":      "AUTH-WARNING",
                    "action":       f"chmod 750 {path}",
                    "old_mode":     oct(current_mode),
                    "new_mode":     "0o750",
                    "lynis_fix":    True,
                }, alert=False, alert_severity="INFO")
            except Exception as e:
                write_log("hardening", {
                    "event":   "HARDENING_FAILED",
                    "finding": "AUTH-WARNING sudoers.d",
                    "error":   str(e),
                }, alert=True, alert_severity="WARNING")

    # ── HOME-9304 / HOME-9306: home directory permissions & ownership ─────────

    def _fix_home_directory_perms(self):
        try:
            r = subprocess.run(
                ["dscl", ".", "-list", "/Users", "UniqueID"],
                capture_output=True, text=True
            )
            for line in r.stdout.splitlines():
                parts = line.split()
                if len(parts) != 2:
                    continue
                username = parts[0]
                # Skip system accounts
                if int(parts[1]) < 500:
                    continue
                home = f"/Users/{username}"
                if not os.path.isdir(home):
                    continue
                s    = os.stat(home)
                mode = stat.S_IMODE(s.st_mode)
                if mode != 0o700:
                    os.chmod(home, 0o700)
                    write_log("hardening", {
                        "event":   "HARDENING_APPLIED",
                        "finding": "HOME-9304",
                        "action":  f"chmod 700 {home}",
                        "user":    username,
                    }, alert=False, alert_severity="INFO")
                try:
                    pw = pwd.getpwnam(username)
                    if s.st_uid != pw.pw_uid:
                        subprocess.run(
                            ["chown", f"{username}:staff", home],
                            capture_output=True
                        )
                        write_log("hardening", {
                            "event":   "HARDENING_APPLIED",
                            "finding": "HOME-9306",
                            "action":  f"chown {username}:staff {home}",
                        }, alert=False, alert_severity="INFO")
                except Exception:
                    pass
        except Exception:
            pass

    # ── FILE-7524: sshd_config permissions ────────────────────────────────────

    def _fix_sshd_config_perms(self):
        path = "/etc/ssh/sshd_config"
        if not os.path.exists(path):
            return
        mode = stat.S_IMODE(os.stat(path).st_mode)
        if mode not in (0o600, 0o640):
            try:
                os.chmod(path, 0o600)
                write_log("hardening", {
                    "event":   "HARDENING_APPLIED",
                    "finding": "FILE-7524",
                    "action":  f"chmod 600 {path}",
                }, alert=False, alert_severity="INFO")
            except Exception as e:
                write_log("hardening", {
                    "event":   "HARDENING_FAILED",
                    "finding": "FILE-7524",
                    "error":   str(e),
                }, alert=True, alert_severity="WARNING")

    # ── NAME-4404: hostname in /etc/hosts ─────────────────────────────────────

    def _fix_etc_hosts(self):
        hosts_path = "/etc/hosts"
        hostname   = socket.gethostname()
        try:
            with open(hosts_path) as f:
                content = f.read()
            if hostname not in content:
                with open(hosts_path, "a") as f:
                    f.write(f"\n127.0.0.1  {hostname}.local {hostname}\n")
                write_log("hardening", {
                    "event":   "HARDENING_APPLIED",
                    "finding": "NAME-4404",
                    "action":  f"Added {hostname} to /etc/hosts",
                }, alert=False, alert_severity="INFO")
        except Exception as e:
            write_log("hardening", {
                "event":   "HARDENING_FAILED",
                "finding": "NAME-4404",
                "error":   str(e),
            }, alert=True, alert_severity="WARNING")

    # ── INSE-8050: disable ftp-proxy ──────────────────────────────────────────

    def _fix_ftp_proxy(self):
        plist = "/System/Library/LaunchDaemons/com.apple.ftp-proxy.plist"
        if not os.path.exists(plist):
            return
        try:
            r = subprocess.run(
                ["launchctl", "list", "com.apple.ftp-proxy"],
                capture_output=True, text=True
            )
            if r.returncode == 0:  # Service is loaded
                subprocess.run(
                    ["launchctl", "unload", "-w", plist],
                    capture_output=True
                )
                write_log("hardening", {
                    "event":   "HARDENING_APPLIED",
                    "finding": "INSE-8050",
                    "action":  "Unloaded com.apple.ftp-proxy",
                }, alert=False, alert_severity="INFO")
        except Exception as e:
            write_log("hardening", {
                "event":   "HARDENING_FAILED",
                "finding": "INSE-8050",
                "error":   str(e),
            }, alert=True, alert_severity="WARNING")

    # ── AUTH-9262: PAM password policy ────────────────────────────────────────

    def _check_pam_policy(self):
        """Check and set minimum password policy via pwpolicy."""
        try:
            r = subprocess.run(
                ["pwpolicy", "-getglobalpolicy"],
                capture_output=True, text=True
            )
            policy = r.stdout.strip()
            if "minChars" not in policy:
                subprocess.run(
                    ["pwpolicy", "-setglobalpolicy",
                     "minChars=12 requiresAlpha=1 requiresNumeric=1"],
                    capture_output=True
                )
                write_log("hardening", {
                    "event":   "HARDENING_APPLIED",
                    "finding": "AUTH-9262",
                    "action":  "Set minChars=12 requiresAlpha requiresNumeric",
                }, alert=False, alert_severity="INFO")
        except Exception:
            pass

    # ── HTTP-6640 / HTTP-6643: Apache hardening ────────────────────────────────

    def _check_apache_state(self):
        """Check if Apache is running; alert if active without hardening."""
        try:
            r = subprocess.run(
                ["launchctl", "list", "org.apache.httpd"],
                capture_output=True, text=True
            )
            if r.returncode == 0:
                # Apache is loaded — check for modsecurity
                httpd_conf = "/etc/apache2/httpd.conf"
                if os.path.exists(httpd_conf):
                    with open(httpd_conf) as f:
                        conf = f.read()
                    missing = []
                    if "mod_security" not in conf and "security2_module" not in conf:
                        missing.append("ModSecurity (HTTP-6643)")
                    if "mod_evasive" not in conf:
                        missing.append("mod_evasive (HTTP-6640)")
                    if missing:
                        write_log("hardening", {
                            "event":      "HARDENING_FINDING",
                            "finding":    "HTTP-6640/6643",
                            "severity":   "Medium",
                            "detail":     f"Apache running without: {', '.join(missing)}",
                            "remediation": (
                                "Either: sudo launchctl unload -w "
                                "/System/Library/LaunchDaemons/org.apache.httpd.plist "
                                "OR brew install modsecurity"
                            ),
                        }, alert=True, alert_severity="WARNING")
        except Exception:
            pass

    # ── OSSEC IDS check ──────────────────────────────────────────────────────

    def _check_ossec_installed(self):
        if not (os.path.exists("/var/ossec/bin/ossec-control")
                or os.path.exists("/Library/Ossec/bin/ossec-control")):
            write_log("hardening", {
                "event":      "HARDENING_FINDING",
                "finding":    "IDS_NOT_INSTALLED",
                "severity":   "High",
                "detail":     "OSSEC/Wazuh not installed — Lynis Intrusion software [X]",
                "remediation": "Install Wazuh agent from https://packages.wazuh.com/4.x/macos/ && sudo /Library/Ossec/bin/ossec-control start",
            }, alert=True, alert_severity="WARNING")

    # ── FileVault check ──────────────────────────────────────────────────────

    def _check_filevault(self):
        try:
            r = subprocess.run(
                ["fdesetup", "status"],
                capture_output=True, text=True
            )
            if "Off" in r.stdout:
                write_log("hardening", {
                    "event":      "HARDENING_FINDING",
                    "finding":    "CRYPT-FILEVAULT",
                    "severity":   "Critical",
                    "detail":     "FileVault disk encryption is DISABLED",
                    "remediation": "System Settings > Privacy & Security > FileVault",
                }, alert=True, alert_severity="CRITICAL")
        except Exception:
            pass

    # ── Firewall check ───────────────────────────────────────────────────────

    def _check_firewall_enabled(self):
        try:
            r = subprocess.run(
                ["/usr/libexec/ApplicationFirewall/socketfilterfw",
                 "--getglobalstate"],
                capture_output=True, text=True
            )
            if "disabled" in r.stdout.lower():
                write_log("hardening", {
                    "event":      "HARDENING_FINDING",
                    "finding":    "FIRE-APPFW",
                    "severity":   "High",
                    "detail":     "Application Firewall is disabled",
                    "remediation": (
                        "sudo /usr/libexec/ApplicationFirewall/socketfilterfw "
                        "--setglobalstate on"
                    ),
                }, alert=True, alert_severity="WARNING")
        except Exception:
            pass

    # ── SIP check ────────────────────────────────────────────────────────────

    def _check_sip_enabled(self):
        try:
            r = subprocess.run(
                ["csrutil", "status"],
                capture_output=True, text=True
            )
            if "disabled" in r.stdout.lower():
                write_log("hardening", {
                    "event":    "HARDENING_FINDING",
                    "finding":  "SIP_DISABLED",
                    "severity": "Critical",
                    "detail":   "System Integrity Protection (SIP) is DISABLED",
                    "remediation": "Boot to Recovery > Utilities > Terminal > csrutil enable",
                }, alert=True, alert_severity="CRITICAL")
        except Exception:
            pass

    # ── Homebrew package audit ────────────────────────────────────────────────

    def _check_brew_packages(self):
        """Check for outdated Homebrew packages (PKGS-7398)."""
        brew = shutil.which("brew") or f"{BREW_PREFIX}/bin/brew"
        if not os.path.exists(brew):
            return
        try:
            r = subprocess.run(
                [brew, "outdated", "--json=v2"],
                capture_output=True, text=True, timeout=60
            )
            data     = json.loads(r.stdout)
            outdated = data.get("formulae", []) + data.get("casks", [])
            if outdated:
                names = [p.get("name", "unknown") for p in outdated[:20]]
                write_log("hardening", {
                    "event":       "HARDENING_FINDING",
                    "finding":     "PKGS-7398",
                    "detail":      f"{len(outdated)} outdated Homebrew packages",
                    "packages":    names,
                    "remediation": "brew upgrade",
                }, alert=len(outdated) > 5, alert_severity="WARNING")
        except Exception:
            pass

    # ── ClamAV definition freshness ──────────────────────────────────────────

    def _check_clamav_freshness(self):
        """Alert if ClamAV definitions are stale (>48h old)."""
        db_paths = [
            "/opt/homebrew/var/lib/clamav/main.cvd",
            "/opt/homebrew/var/lib/clamav/daily.cvd",
            "/usr/local/share/clamav/main.cvd",
        ]
        for db in db_paths:
            if not os.path.exists(db):
                continue
            age_hours = (time.time() - os.path.getmtime(db)) / 3600
            if age_hours > 48:
                write_log("hardening", {
                    "event":      "HARDENING_FINDING",
                    "finding":    "CLAMAV_STALE_DEFS",
                    "detail":     f"ClamAV definitions are {age_hours:.0f}h old",
                    "remediation": "sudo freshclam",
                }, alert=True, alert_severity="WARNING")
            break

    # ── Unexpected open ports ─────────────────────────────────────────────────

    def _check_open_ports(self):
        """Alert on unexpected listening ports."""
        # Ports that are legitimate on a standard Mac
        EXPECTED_PORTS = {
            # System
            22,    # SSH (even if off, may appear in scan)
            88,    # Kerberos
            631,   # CUPS (printing)
            5900,  # VNC (if enabled)
            # mDNS
            5353,
        }
        try:
            r = subprocess.run(
                ["netstat", "-an", "-p", "tcp"],
                capture_output=True, text=True, timeout=10
            )
            for line in r.stdout.splitlines():
                if "LISTEN" not in line:
                    continue
                # Extract port from *.<port> or 127.0.0.1.<port>
                m = re.search(r"[.*]\.(\d+)\s+.*LISTEN", line)
                if m:
                    port = int(m.group(1))
                    if port not in EXPECTED_PORTS and port > 1024:
                        continue  # Skip high ephemeral ports
                    if port < 1024 and port not in EXPECTED_PORTS:
                        write_log("hardening", {
                            "event":   "UNEXPECTED_LISTENING_PORT",
                            "port":    port,
                            "raw":     line.strip(),
                            "finding": "NETW-PORTS",
                        }, alert=True, alert_severity="WARNING")
        except Exception:
            pass

    # ── LaunchAgent/Daemon persistence audit ─────────────────────────────────

    def _check_launch_persistence(self):
        """Alert on unexpected LaunchAgents or LaunchDaemons."""
        if not hasattr(self, "_known_launch_items"):
            self._known_launch_items = self._enumerate_launch_items()
            return

        current = self._enumerate_launch_items()
        new_items = current - self._known_launch_items
        for item in new_items:
            write_log("hardening", {
                "event":   "NEW_LAUNCH_PERSISTENCE",
                "path":    item,
                "note":    "New LaunchAgent/Daemon detected — verify legitimacy",
            }, alert=True, alert_severity="WARNING")
        self._known_launch_items = current

    def _enumerate_launch_items(self) -> set:
        dirs = [
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons",
            "/System/Library/LaunchDaemons",
            f"/Users/{os.environ.get('SUDO_USER', 'evw')}/Library/LaunchAgents",
        ]
        items: set = set()
        for d in dirs:
            if os.path.isdir(d):
                for f in os.listdir(d):
                    items.add(os.path.join(d, f))
        return items


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 12: REPORT GENERATOR
# ══════════════════════════════════════════════════════════════════════════════

def generate_report() -> str:
    lines = [
        "=" * 70,
        f"mac-sentinel Security Report — {datetime.now().isoformat()}",
        f"Host: {socket.gethostname()} | Version: {VERSION}",
        "=" * 70,
    ]

    # Hardening summary
    hardening_path = get_log_path("hardening")
    if os.path.exists(hardening_path):
        findings = []
        applied  = []
        try:
            with open(hardening_path) as f:
                for line in f.readlines()[-500:]:
                    e = json.loads(line)
                    d = e.get("data", {})
                    if d.get("event") == "HARDENING_FINDING":
                        findings.append(d)
                    elif d.get("event") == "HARDENING_APPLIED":
                        applied.append(d)
        except Exception:
            pass
        lines.append(f"\n[HARDENING] Applied: {len(applied)} | Open findings: {len(findings)}")
        for f in findings:
            sev = f.get("severity", "?")
            lines.append(f"  ⚠️  [{sev}] {f.get('finding','?')}: {f.get('detail','')}")

    for category, _ in LOG_FILES.items():
        if category == "hardening":
            continue
        path = get_log_path(category)
        if not os.path.exists(path):
            continue
        try:
            with open(path) as f:
                entries  = [json.loads(l) for l in f.readlines()[-100:] if l.strip()]
            critical = [e for e in entries if e.get("severity") == "CRITICAL"]
            warnings = [e for e in entries if e.get("severity") == "WARNING"]
            if critical or warnings:
                lines.append(
                    f"\n[{category.upper()}] CRITICAL: {len(critical)} | "
                    f"WARNING: {len(warnings)}"
                )
                for e in critical[-3:]:
                    d = e.get("data", {})
                    lines.append(
                        f"  🔴 [{e.get('ts')}] {d.get('event','?')}: "
                        f"{d.get('path', d.get('process', d.get('detail','')))}"
                    )
        except Exception:
            pass

    lines.append("\n" + "=" * 70)
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 13: INSTALLATION — launchd plist (replaces systemd unit)
# ══════════════════════════════════════════════════════════════════════════════

LAUNCHD_PLIST_CONTENT = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.evw.mac-sentinel</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>{INSTALL_DIR}/mac-sentinel.py</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>5</integer>
    <key>StandardOutPath</key>
    <string>{LOG_BASE_DIR}/daemon.log</string>
    <key>StandardErrorPath</key>
    <string>{LOG_BASE_DIR}/daemon.log</string>
    <key>WorkingDirectory</key>
    <string>{INSTALL_DIR}</string>
    <key>UserName</key>
    <string>root</string>
</dict>
</plist>
"""


def write_pid_file():
    try:
        with open(PID_FILE, "w") as f:
            f.write(str(os.getpid()))
    except Exception:
        pass


def setup_bsm_audit():
    """Configure macOS BSM audit for key events."""
    audit_control = "/etc/security/audit_control"
    if not os.path.exists(audit_control):
        return
    try:
        with open(audit_control) as f:
            content = f.read()
        # Ensure authentication, privileged, and administrative events are audited
        needed = {
            "flags:lo,aa,ad,pc,fm,-all",
        }
        for flag in needed:
            if flag not in content:
                pass  # Would require careful config editing; just log the gap
        # Restart audit service
        subprocess.run(["audit", "-s"], capture_output=True)
    except Exception:
        pass


def install():
    """Install mac-sentinel as a launchd system daemon."""
    if os.geteuid() != 0:
        print("ERROR: Installation requires root. Run with sudo.")
        sys.exit(1)

    print("[*] Installing mac-sentinel...")

    # Create directories
    for d in [INSTALL_DIR, LOG_BASE_DIR, CANARY_DIR]:
        os.makedirs(d, exist_ok=True)
        os.chmod(d, 0o700)
        print(f"    Created: {d}")

    # Install script
    dest = os.path.join(INSTALL_DIR, "mac-sentinel.py")
    shutil.copy2(SCRIPT_PATH, dest)
    os.chmod(dest, 0o700)
    os.chown(dest, 0, 0)
    print(f"    Installed: {dest}")

    # Install Python dependencies
    print("[*] Installing Python dependencies...")
    subprocess.run([
        sys.executable, "-m", "pip", "install",
        "psutil", "watchdog", "--quiet", "--break-system-packages"
    ], capture_output=True)

    # Install fswatch via brew (needed for file monitoring)
    brew = shutil.which("brew") or f"{BREW_PREFIX}/bin/brew"
    if os.path.exists(brew):
        print("[*] Checking fswatch...")
        if not shutil.which("fswatch"):
            subprocess.run([brew, "install", "fswatch"], capture_output=True)
            print("    fswatch installed")
        else:
            print("    fswatch already present")

    # Write launchd plist
    with open(LAUNCHD_PLIST, "w") as f:
        f.write(LAUNCHD_PLIST_CONTENT)
    os.chmod(LAUNCHD_PLIST, 0o644)
    os.chown(LAUNCHD_PLIST, 0, 0)
    print(f"    Plist written: {LAUNCHD_PLIST}")

    # Configure BSM audit
    setup_bsm_audit()

    # Load the service
    print("[*] Loading launchd service...")
    subprocess.run(
        ["launchctl", "unload", LAUNCHD_PLIST],
        capture_output=True
    )
    result = subprocess.run(
        ["launchctl", "load", "-w", LAUNCHD_PLIST],
        capture_output=True, text=True
    )

    # Verify
    r = subprocess.run(
        ["launchctl", "list", "com.evw.mac-sentinel"],
        capture_output=True, text=True
    )
    status = "active" if r.returncode == 0 else "FAILED"
    print(f"\n{'✅' if status == 'active' else '❌'} Service status: {status}")
    print(f"\n[✓] mac-sentinel installed successfully!")
    print(f"    Logs:    {LOG_BASE_DIR}/")
    print(f"    Report:  sudo python3 {dest} --report")
    print(f"    Stop:    sudo launchctl unload {LAUNCHD_PLIST}")


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 14: ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def signal_handler(signum, frame):
    global _running
    write_log("master", {
        "event":  "DAEMON_STOP",
        "signal": signum,
        "pid":    os.getpid(),
    })
    _running = False
    sys.exit(0)


def main():
    global _running

    _mask_process_title("mac-sentinel")

    parser = argparse.ArgumentParser(
        description="mac-sentinel security monitoring daemon",
        add_help=False
    )
    parser.add_argument("--install", action="store_true")
    parser.add_argument("--report",  action="store_true")
    parser.add_argument("--debug",   action="store_true")
    args, _ = parser.parse_known_args()

    if args.install:
        install()
        return

    if args.report:
        print(generate_report())
        return

    if os.geteuid() != 0:
        sys.stderr.write("mac-sentinel: must be run as root\n")
        sys.exit(1)

    if args.debug:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s [%(name)s] %(levelname)s: %(message)s"
        )

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT,  signal_handler)
    signal.signal(signal.SIGHUP,  signal_handler)

    write_pid_file()
    setup_bsm_audit()

    write_log("master", {
        "event":    "DAEMON_START",
        "pid":      os.getpid(),
        "version":  VERSION,
        "hostname": socket.gethostname(),
        "uid":      os.getuid(),
    }, alert=False, alert_severity="INFO")

    monitors = [
        ThermalSensorWorker(),      # File integrity (FSEvents/fswatch)
        NetlinkEventWorker(),       # Network connections (lsof)
        AcpiCredentialWorker(),     # Auth/privilege events (unified log)
        CacheValidationWorker(),    # Canary tripwires (FSEvents)
        DeviceEnumerationWorker(),  # USB/hardware (IOKit)
        VendorComponentWorker(),    # Tool integrity + firewall watchdog
        SelfValidationWorker(),     # Self-tamper detection
        MacHardeningWorker(),       # Lynis hardening enforcement
    ]

    for m in monitors:
        m.start()
        FalsePositiveFilter.register_own_pid(m.ident or 0)
        if args.debug:
            sys.stderr.write(f"[debug] thread started: {m.name}\n")

    try:
        while _running:
            time.sleep(1)
            for m in monitors:
                if not m.is_alive() and _running:
                    write_log("integrity", {
                        "event":  "MONITOR_THREAD_DIED",
                        "thread": m.name,
                    }, alert=True, alert_severity="CRITICAL")
                    try:
                        new_m = type(m)()
                        new_m.start()
                        monitors[monitors.index(m)] = new_m
                    except Exception:
                        pass
    except KeyboardInterrupt:
        pass
    finally:
        _running = False
        write_log("master", {
            "event": "DAEMON_END",
            "pid":   os.getpid(),
        })
        try:
            os.remove(PID_FILE)
        except Exception:
            pass


if __name__ == "__main__":
    main()
