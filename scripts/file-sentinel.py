#!/usr/bin/env python3
"""
file-sentinel.py — kqueue-based file change monitor for macOS 26+ Tahoe.

BSM audit (auditd) was removed/killed in macOS 26 Tahoe. This version uses
kqueue (macOS-native, stdlib-only) to detect file and directory changes in
real time without auditd, without root for user paths, and without any
external packages.

Trade-off vs BSM: no process attribution (kqueue does not expose which
process caused the change).

Run as root (LaunchDaemon) for coverage of /Library/LaunchDaemons and /etc.

Usage:
    sudo python3 file-sentinel.py [--watch /path ...] [--log /path]
    sudo python3 file-sentinel.py --report [-n N]
"""

from __future__ import annotations

import argparse
import json
import os
import select as _select
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

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

# KeepAlive daemon: never let the guard exit the process — trip = log + skip
os.environ.setdefault("EVW_GUARD_POLICY", "continue")

DEFAULT_LOG = Path("/var/log/file-sentinel.log")

# User home is hardcoded: this daemon runs as root, where Path.home() is
# /var/root, so the real user paths must be spelled out explicitly.
USER_HOME = Path("/Users/evw")

DEFAULT_WATCH = [
    str(USER_HOME / ".credentials"),
    str(USER_HOME / ".claude"),
    str(USER_HOME / "dev/scripts"),
    str(USER_HOME / ".ssh"),
    str(USER_HOME / "Library/LaunchAgents"),
    str(USER_HOME / "Library/Application Support/ai-orchestrator"),
    "/Library/LaunchDaemons",
    "/etc/pf.anchors",
]

DEFAULT_ALERT = [
    str(USER_HOME / ".credentials"),
    str(USER_HOME / ".claude"),
    str(USER_HOME / "dev/scripts"),
    str(USER_HOME / ".ssh"),
    str(USER_HOME / ".zshrc"),
    str(USER_HOME / ".zprofile"),
    str(USER_HOME / "Library/LaunchAgents"),
    str(USER_HOME / "Library/Application Support/ai-orchestrator"),
    "/Library/LaunchDaemons",
    "/etc/pf.conf",
    "/etc/pf.anchors",
]

_VNODE_FLAGS = (
    _select.KQ_NOTE_WRITE  |
    _select.KQ_NOTE_EXTEND |
    _select.KQ_NOTE_DELETE |
    _select.KQ_NOTE_RENAME |
    _select.KQ_NOTE_ATTRIB
)

_NOTE_NAMES: dict[int, str] = {
    _select.KQ_NOTE_DELETE: "DELETE",
    _select.KQ_NOTE_WRITE:  "WRITE",
    _select.KQ_NOTE_EXTEND: "WRITE",
    _select.KQ_NOTE_ATTRIB: "ATTRIB",
    _select.KQ_NOTE_RENAME: "RENAME",
}


def _event_name(fflags: int) -> str:
    for flag, name in _NOTE_NAMES.items():
        if fflags & flag:
            return name
    return "CHANGE"


def log_record(log_path: Path, record: dict) -> None:
    try:
        with open(log_path, "a") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass


def notify(title: str, msg: str) -> None:
    # AppleScript string-literal escaping: backslash first, then double-quote
    # (a filename like  foo\"...  would otherwise break out of the literal).
    safe_msg   = msg.replace("\\", "\\\\").replace('"', '\\"')
    safe_title = title.replace("\\", "\\\\").replace('"', '\\"')
    try:
        subprocess.run(
            ["osascript", "-e",
             f'display notification "{safe_msg}" with title "{safe_title}"'],
            capture_output=True, timeout=5,
        )
    except (subprocess.TimeoutExpired, OSError):
        pass


def _open_evtonly(path: str) -> int | None:
    try:
        return os.open(path, os.O_RDONLY | os.O_EVTONLY)
    except OSError:
        return None


def _snapshot(dirpath: str) -> dict[str, tuple[float, int]]:
    """Return {filename: (mtime, size)} for immediate children of dirpath."""
    snap: dict[str, tuple[float, int]] = {}
    try:
        for name in os.listdir(dirpath):
            full = os.path.join(dirpath, name)
            try:
                st = os.stat(full)
                snap[name] = (st.st_mtime, st.st_size)
            except OSError:
                pass
    except OSError:
        pass
    return snap


class Watcher:
    def __init__(
        self,
        watch_dirs: list[str],
        alert_dirs: list[str],
        log_path: Path,
    ) -> None:
        self.watch_dirs = watch_dirs
        self.alert_dirs = alert_dirs
        self.log_path   = log_path
        self.kq         = _select.kqueue()
        self._fd_path:   dict[int, str]                      = {}
        self._snapshots: dict[str, dict[str, tuple[float, int]]] = {}

    def _register(self, fd: int, path: str) -> None:
        ev = _select.kevent(
            fd,
            filter=_select.KQ_FILTER_VNODE,
            flags=_select.KQ_EV_ADD | _select.KQ_EV_ENABLE | _select.KQ_EV_CLEAR,
            fflags=_VNODE_FLAGS,
        )
        try:
            self.kq.control([ev], 0)
        except OSError:
            os.close(fd)
            return
        self._fd_path[fd] = path

    def _add_path(self, path: str) -> None:
        if not os.path.exists(path):
            return
        fd = _open_evtonly(path)
        if fd is None:
            return
        self._register(fd, path)
        if os.path.isdir(path):
            self._snapshots[path] = _snapshot(path)
            for name in os.listdir(path):
                full = os.path.join(path, name)
                if os.path.isfile(full) and full not in self._fd_path.values():
                    ffd = _open_evtonly(full)
                    if ffd is not None:
                        self._register(ffd, full)

    def _close_fd(self, fd: int) -> None:
        self._fd_path.pop(fd, None)
        try:
            os.close(fd)
        except OSError:
            pass

    def _is_alert(self, path: str) -> bool:
        return any(path.startswith(a) for a in self.alert_dirs)

    def _emit(self, ts: str, event: str, path: str) -> None:
        record = {"ts": ts, "event": event, "path": path}
        print(f"[{ts}] {event:8s}  {path}", flush=True)
        log_record(self.log_path, record)
        if self._is_alert(path):
            notify(
                "File Sentinel — sensitive change",
                f"{event}: {os.path.basename(path)}",
            )

    def run(self) -> None:
        for path in self.watch_dirs:
            self._add_path(path)

        print(
            f"[file-sentinel] kqueue watching {len(self._fd_path)} paths → {self.log_path}",
            flush=True,
        )

        while True:
            events = guard_run("kq-poll", self.kq.control, None, 64, 2.0)
            if events is None or events is SKIP:
                time.sleep(1)
                continue

            ts = datetime.now().isoformat(timespec="seconds")

            for ev in events:
                fd   = ev.ident
                path = self._fd_path.get(fd)
                if path is None:
                    continue

                if os.path.isdir(path):
                    old = self._snapshots.get(path, {})
                    new = _snapshot(path)
                    for name, info in new.items():
                        full = os.path.join(path, name)
                        if name not in old:
                            self._emit(ts, "CREATE", full)
                            if os.path.isfile(full):
                                ffd = _open_evtonly(full)
                                if ffd is not None:
                                    self._register(ffd, full)
                        elif info != old[name]:
                            self._emit(ts, "WRITE", full)
                    for name in old:
                        if name not in new:
                            self._emit(ts, "DELETE", os.path.join(path, name))
                    self._snapshots[path] = new
                else:
                    event_name = _event_name(ev.fflags)
                    self._emit(ts, event_name, path)

                # Re-register if the file/dir was deleted or renamed
                if ev.fflags & (_select.KQ_NOTE_DELETE | _select.KQ_NOTE_RENAME):
                    self._close_fd(fd)
                    time.sleep(0.1)
                    if os.path.exists(path):
                        new_fd = _open_evtonly(path)
                        if new_fd is not None:
                            self._register(new_fd, path)

            # Periodically re-add watched paths that may have been created since start
            for watch_dir in self.watch_dirs:
                if watch_dir not in self._fd_path.values() and os.path.exists(watch_dir):
                    self._add_path(watch_dir)


def print_report(log_path: Path, n: int = 100) -> None:
    if not log_path.exists():
        print("No sentinel log found.")
        return

    lines = log_path.read_text().splitlines()
    records = []
    for line in lines[-n:]:
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            pass

    print(f"\n{'='*70}")
    print(f"File Sentinel — last {len(records)} events  ({log_path})")
    print(f"{'='*70}\n")

    event_counts: dict[str, int] = {}
    for r in records:
        e = r.get("event", "?")
        event_counts[e] = event_counts.get(e, 0) + 1
    print("Event counts:")
    for ev, cnt in sorted(event_counts.items(), key=lambda x: -x[1]):
        print(f"  {cnt:5d}  {ev}")

    print("\nMost recent events:")
    for r in records[-30:]:
        print(f"  [{r.get('ts','?')}] {r.get('event','?'):8s}  {r.get('path','?')}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="File-change sentinel (kqueue, macOS 26+ Tahoe)"
    )
    parser.add_argument("--watch",  action="append",
                        help="Directory/file to watch (repeatable)")
    parser.add_argument("--alert",  action="append",
                        help="Path that triggers a notification on change")
    parser.add_argument("--log",    default=str(DEFAULT_LOG),
                        help=f"JSON log path (default: {DEFAULT_LOG})")
    parser.add_argument("--report", action="store_true",
                        help="Print last N events and exit")
    parser.add_argument("-n",       type=int, default=100,
                        help="Events to show with --report")
    args = parser.parse_args()

    log_path = Path(args.log)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    if args.report:
        print_report(log_path, n=args.n)
        return

    watcher = Watcher(
        watch_dirs = args.watch or DEFAULT_WATCH,
        alert_dirs = args.alert or DEFAULT_ALERT,
        log_path   = log_path,
    )
    watcher.run()


if __name__ == "__main__":
    main()
