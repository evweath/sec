#!/usr/bin/env python3
"""evw-alert-viewer.py — persistent Sentinel alert-history viewer.

Every alert the sentinel system pops up (alert-center dialogs/notifications —
they all come from /var/db/evw-security-system/alerts/*.json) is collected
into a persistent history file; this viewer shows it as a live table.

  Columns : log entry # (chronological across the whole log: oldest = 1)
            · Time (date+time) · Level (CRITICAL/WARNING/INFO/LOCKED)
            · Description
  Sort    : click any column header (click again to reverse)
  Search  : the filter box matches across ALL columns (and the alert body)
  Details : single-click updates the lower pane; double-click opens a
            scrollable popup window with the full alert
  Refresh : every 5 s — new alerts appear as they are posted
  Locked  : alert files that are unreadable as this user (root-owned, so
            they need sudo to read) appear as LOCKED rows. Clicking one
            pops up a sudo-password dialog; after the password is entered
            the row unlocks and the entire alert (decoded fields + the
            full raw JSON) is shown in the details pane. Unlocks are
            in-memory only — the history JSONL is never modified by this.

The popup dialogs expire and disappear (alert-center gives up after 120 s);
this history and viewer do not — history is an append-only JSONL that is
never pruned, and the LaunchAgent (com.evw.alert-viewer, KeepAlive on crash)
keeps the window available.

Usage:
  evw-alert-viewer.py                 # GUI (default)
  evw-alert-viewer.py --collect-only  # headless: merge alerts -> history, print summary
  evw-alert-viewer.py --smoke-test    # build the UI, self-destruct after 2.5 s
  options: --alerts-dir PATH --history PATH

Python 3.9 compatible, stdlib only (tkinter).

REQUIREMENT: run with /opt/homebrew/bin/python3.15 (Tk 9.x). Apple's
/usr/bin/python3 ships Tk 8.5, whose ttk.Treeview leaks ~4 GB/min under
this app — it OOM-crashed the host on 2026-10-21 (96 GB swap/compressor).
"""
import glob
import json
import os
import subprocess
import sys
import time

SEC = "/Users/evw/dev/security"
ALERTS_DIR = "/var/db/evw-security-system/alerts"
HISTORY = os.path.join(SEC, "logs", "alert-history.jsonl")
POLL_MS = 5000

SEVERITIES = ("CRITICAL", "WARNING", "INFO")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


# ── collection: alerts dir -> persistent JSONL history ───────────────────────

def norm_ts(v):
    """Alert ts may be an epoch int/float or an ISO string; return epoch float."""
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z",
                    "%Y-%m-%dT%H:%M:%S.%fZ"):
            try:
                return time.mktime(time.strptime(v, fmt)) if fmt.endswith("Z") \
                    else __import__("datetime").datetime.strptime(v, fmt).timestamp()
            except ValueError:
                continue
    return time.time()


def fmt_time(epoch):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epoch))


def alert_details_text(r):
    if r.get("locked"):
        return (
            "%s  ·  LOCKED  ·  %s\n\n"
            "This log entry is stored in a root-owned file and cannot be\n"
            "read without sudo. Click the entry and enter your sudo\n"
            "password to reveal the full message."
            % (fmt_time(r["ts"]), r["path"]))
    text = "%s  ·  %s  ·  source=%s\nid=%s\n\n%s" % (
        fmt_time(r["ts"]), r["severity"], r["source"] or "-",
        r.get("real_id") or r["id"], r["body"] or r["title"])
    if r.get("raw") is not None:
        text += ("\n\n—— full alert file (read via sudo) ——\n"
                 + r["raw"].rstrip())
    return text


def load_history(path):
    hist = {}
    try:
        with open(path, errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                if isinstance(r, dict) and r.get("id"):
                    hist[r["id"]] = r
    except OSError:
        pass
    return hist


def collect(alerts_dir, hist_path):
    """Merge every alert in alerts_dir into the history JSONL. Returns
    (total_in_history, new_this_pass, corrupt_files, locked_file_paths).
    Locked files are unreadable as this user (root-owned — reading them
    needs sudo); they are NOT written to the history JSONL, the GUI lists
    them as LOCKED rows instead."""
    hist = load_history(hist_path)
    new, bad, locked = [], 0, []
    for path in sorted(glob.glob(os.path.join(alerts_dir, "*.json"))):
        try:
            with open(path, errors="replace") as f:
                a = json.load(f)
        except OSError:
            locked.append(path)
            continue
        except ValueError:
            bad += 1
            continue
        if not isinstance(a, dict) or a.get("id") is None:
            bad += 1
            continue
        aid = str(a["id"])
        if aid in hist:
            continue
        sev = str(a.get("severity", "INFO")).upper()
        hist[aid] = {
            "id": aid,
            "ts": norm_ts(a.get("ts", time.time())),
            "severity": sev if sev in SEV_RANK else "INFO",
            "title": str(a.get("title", "")),
            "body": str(a.get("body", "")),
            "source": str(a.get("source", "")),
        }
        new.append(aid)
    if new:
        os.makedirs(os.path.dirname(hist_path), exist_ok=True)
        with open(hist_path, "a") as f:
            for aid in new:
                f.write(json.dumps(hist[aid]) + "\n")
    return len(hist), len(new), bad, locked


# ── GUI ──────────────────────────────────────────────────────────────────────

def run_gui(alerts_dir, hist_path, smoke_test=False):
    import tkinter as tk
    from tkinter import messagebox, ttk

    root = tk.Tk()
    root.title("evw sentinel — alert history")
    root.geometry("980x620")

    history = {}          # id -> record (in-memory mirror of the JSONL)
    locked = {}           # "locked:<filename>" -> record of a root-owned
                          # alert file; in-memory only, unlocked via sudo
    rows = {}             # tree iid -> id
    popups = {}           # alert id -> detail Toplevel
    pending_unlock = {"after": None}
    rank = dict(SEV_RANK, LOCKED=len(SEV_RANK))
    sort_state = {"col": "time", "reverse": True}   # newest first
    query = tk.StringVar()

    # ── top bar: search + counts ──
    top = ttk.Frame(root)
    top.pack(fill="x", padx=8, pady=(8, 4))
    ttk.Label(top, text="Search:").pack(side="left")
    search = ttk.Entry(top, textvariable=query, width=40)
    search.pack(side="left", padx=(4, 12))
    counts = ttk.Label(top, text="")
    counts.pack(side="left")

    # ── table ──
    frame = ttk.Frame(root)
    frame.pack(fill="both", expand=True, padx=8)
    cols = ("num", "time", "level", "description")
    tree = ttk.Treeview(frame, columns=cols, show="headings")
    widths = {"num": 90, "time": 170, "level": 90, "description": 560}
    for c in cols:
        tree.column(c, width=widths[c], anchor=("e" if c == "num" else "w"),
                    stretch=(c == "description"))
    vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=vsb.set)
    tree.pack(side="left", fill="both", expand=True)
    vsb.pack(side="right", fill="y")
    tree.tag_configure("CRITICAL", background="#ffd7d5", foreground="#8b0000")
    tree.tag_configure("WARNING", background="#fff3cd", foreground="#8a6d00")
    tree.tag_configure("INFO", foreground="#444444")
    tree.tag_configure("LOCKED", background="#dde3ea", foreground="#33415c")

    # ── details pane ──
    dframe = ttk.Frame(root)
    dframe.pack(fill="x", padx=8, pady=8)
    details = tk.Text(dframe, height=7, wrap="word", state="disabled",
                      background="#f6f6f6")
    dsb = ttk.Scrollbar(dframe, orient="vertical", command=details.yview)
    details.configure(yscrollcommand=dsb.set)
    details.pack(side="left", fill="both", expand=True)
    dsb.pack(side="right", fill="y")

    def matches(r, q):
        if not q:
            return True
        hay = " ".join((str(r.get("num", "")), fmt_time(r["ts"]),
                        r["severity"], r["title"], r["body"],
                        r["source"])).lower()
        return all(term in hay for term in q.lower().split())

    def sort_key(r):
        col = sort_state["col"]
        if col == "time":
            return r["ts"]
        if col == "num":
            return r.get("num", 0)
        if col == "level":
            return (rank.get(r["severity"], 9), -r["ts"])
        return r["title"].casefold()

    def assign_numbers():
        """log entry # is chronological across the whole log: oldest = 1."""
        entries = sorted(list(history.values()) + list(locked.values()),
                         key=lambda r: (r["ts"], r["id"]))
        for i, r in enumerate(entries, 1):
            r["num"] = i

    def locked_record(path):
        fn = os.path.basename(path)
        try:
            ts = os.stat(path).st_mtime
        except OSError:
            ts = time.time()
        return {"id": "locked:" + fn, "ts": ts, "severity": "LOCKED",
                "title": "locked — sudo required: " + fn, "body": "",
                "source": "root-owned alert file", "path": path,
                "locked": True}

    def rebuild_locked(paths):
        """Sync the locked-row set with collect()'s unreadable-file list.
        Already-unlocked rows keep their revealed content. Returns True
        when the set changed (table needs a redraw)."""
        changed = False
        seen = set()
        for p in paths:
            pid = "locked:" + os.path.basename(p)
            seen.add(pid)
            cur = locked.get(pid)
            if cur is None or (cur.get("locked") and cur.get("path") != p):
                locked[pid] = locked_record(p)
                changed = True
        for pid in list(locked):
            if pid not in seen:
                del locked[pid]
                changed = True
        return changed

    def refill():
        assign_numbers()
        q = query.get().strip()
        sel_ids = [rows[i] for i in tree.selection() if i in rows]
        tree.delete(*tree.get_children())
        rows.clear()
        shown = 0
        entries = list(history.values()) + list(locked.values())
        for r in sorted(entries, key=sort_key,
                        reverse=sort_state["reverse"]):
            if not matches(r, q):
                continue
            iid = tree.insert("", "end",
                              values=(r["num"], fmt_time(r["ts"]),
                                      r["severity"], r["title"]),
                              tags=(r["severity"],))
            rows[iid] = r["id"]
            shown += 1
        for iid, aid in rows.items():
            if aid in sel_ids:
                tree.selection_set(iid)
        n_locked = sum(1 for r in locked.values() if r.get("locked"))
        counts.config(text="%d shown / %d total%s" % (
            shown, len(entries),
            " · %d locked (click -> sudo)" % n_locked if n_locked else ""))

    def header_clicked(col):
        if sort_state["col"] == col:
            sort_state["reverse"] = not sort_state["reverse"]
        else:
            sort_state["col"] = col
            sort_state["reverse"] = (col == "time")
        update_headings()
        refill()

    def update_headings():
        labels = {"num": "log entry #", "time": "Time", "level": "Level",
                  "description": "Description"}
        for c in cols:
            arrow = ""
            if sort_state["col"] == c:
                arrow = " ▼" if sort_state["reverse"] else " ▲"
            tree.heading(c, text=labels[c] + arrow,
                         command=lambda c=c: header_clicked(c))

    def selected_record():
        sel = tree.selection()
        if not sel:
            return None
        aid = rows.get(sel[0])
        return history.get(aid) or locked.get(aid)

    def set_details(text):
        details.config(state="normal")
        details.delete("1.0", "end")
        details.insert("1.0", text)
        details.config(state="disabled")

    def show_details(_event=None):
        r = selected_record()
        if r:
            set_details(alert_details_text(r))

    def detail_popup(r):
        existing = popups.get(r["id"])
        if existing is not None and existing.winfo_exists():
            existing.lift()
            existing.focus_force()
            return existing

        dlg = tk.Toplevel(root)
        popups[r["id"]] = dlg
        dlg.title("alert #%s — %s" % (r.get("num", "?"), r["severity"]))
        dlg.geometry("760x460")
        dlg.minsize(520, 300)

        header = ttk.Frame(dlg)
        header.pack(fill="x", padx=12, pady=(12, 6))
        ttk.Label(header, text=fmt_time(r["ts"])).pack(side="left")
        ttk.Label(header, text=" · %s" % r["severity"]).pack(side="left")
        ttk.Label(header, text=" · %s" % (r["source"] or "-")).pack(side="left")
        ttk.Label(dlg, text=r["title"], wraplength=720,
                  font=("TkDefaultFont", 12, "bold")).pack(fill="x", padx=12,
                                                            pady=(0, 6))

        body_frame = ttk.Frame(dlg)
        body_frame.pack(fill="both", expand=True, padx=12)
        body = tk.Text(body_frame, wrap="word")
        body.insert("1.0", alert_details_text(r))
        body.config(state="disabled")
        body_scroll = ttk.Scrollbar(body_frame, orient="vertical",
                                    command=body.yview)
        body.configure(yscrollcommand=body_scroll.set)
        body.pack(side="left", fill="both", expand=True)
        body_scroll.pack(side="right", fill="y")

        def close(_event=None):
            popups.pop(r["id"], None)
            dlg.destroy()

        def copy_all():
            root.clipboard_clear()
            root.clipboard_append(alert_details_text(r))

        buttons = ttk.Frame(dlg)
        buttons.pack(fill="x", padx=12, pady=12)
        ttk.Button(buttons, text="Copy details", command=copy_all).pack(side="left")
        ttk.Button(buttons, text="Close", command=close).pack(side="right")
        dlg.bind("<Escape>", close)
        dlg.bind("<Command-w>", close)
        dlg.protocol("WM_DELETE_WINDOW", close)
        dlg.lift()
        dlg.focus_force()
        return dlg

    def row_double_clicked(event):
        iid = tree.identify_row(event.y)
        if not iid or iid not in rows:
            return "break"
        if pending_unlock["after"] is not None:
            root.after_cancel(pending_unlock["after"])
            pending_unlock["after"] = None
        tree.selection_set(iid)
        r = selected_record()
        if r and r.get("locked"):
            unlock_locked(r)
        if r:
            show_details()
            detail_popup(r)
        return "break"

    def ask_sudo_password(path):
        """Modal sudo-password prompt; returns the password or None (cancel)."""
        dlg = tk.Toplevel(root)
        dlg.title("sudo password required")
        dlg.transient(root)
        dlg.resizable(False, False)
        ttk.Label(dlg, justify="left", wraplength=430,
                  text="This log entry is stored in a root-owned file:\n"
                       "%s\n\nEnter your sudo password to read the full "
                       "message:" % path).pack(padx=14, pady=(14, 8))
        pw = tk.StringVar()
        ent = ttk.Entry(dlg, textvariable=pw, show="*", width=34)
        ent.pack(padx=14)
        out = {"pw": None}

        def ok(_e=None):
            out["pw"] = pw.get()
            dlg.destroy()

        btns = ttk.Frame(dlg)
        btns.pack(pady=12)
        ttk.Button(btns, text="Read", command=ok).pack(side="left", padx=6)
        ttk.Button(btns, text="Cancel",
                   command=dlg.destroy).pack(side="left", padx=6)
        dlg.bind("<Return>", ok)
        dlg.bind("<Escape>", lambda _e: dlg.destroy())
        dlg.protocol("WM_DELETE_WINDOW", dlg.destroy)
        ent.focus_set()
        dlg.grab_set()
        root.wait_window(dlg)
        return out["pw"]

    def unlock_locked(rec):
        """Prompt for sudo (retry on failure) and reveal the full alert."""
        path = rec["path"]
        while True:
            pw = ask_sudo_password(path)
            if pw is None:
                return
            try:
                proc = subprocess.run(
                    ["/usr/bin/sudo", "-S", "-p", "", "/bin/cat", path],
                    input=pw + "\n", capture_output=True, text=True,
                    timeout=20)
            except (OSError, subprocess.SubprocessError) as e:
                messagebox.showerror("sudo failed",
                                     "could not run sudo: %r" % e, parent=root)
                return
            if proc.returncode == 0:
                break
            if not messagebox.askretrycancel(
                    "sudo failed",
                    "sudo rejected the password. stderr:\n%s"
                    % (proc.stderr.strip() or "(none)"), parent=root):
                return
        raw = proc.stdout
        rec["locked"] = False
        rec["raw"] = raw
        try:
            a = json.loads(raw)
        except ValueError:
            a = None
        if isinstance(a, dict):
            sev = str(a.get("severity", "INFO")).upper()
            rec["severity"] = sev if sev in SEV_RANK else "INFO"
            rec["title"] = str(a.get("title", "")) or rec["title"]
            rec["body"] = str(a.get("body", ""))
            rec["source"] = str(a.get("source", "")) or rec["source"]
            rec["ts"] = norm_ts(a.get("ts", rec["ts"]))
            rec["real_id"] = str(a.get("id", ""))
        refill()
        show_details()

    def row_clicked(event):
        iid = tree.identify_row(event.y)
        if not iid or iid not in rows:
            return
        r = history.get(rows[iid]) or locked.get(rows[iid])
        if not (r and r.get("locked")):
            return
        if pending_unlock["after"] is not None:
            root.after_cancel(pending_unlock["after"])

        def unlock_if_still_selected():
            pending_unlock["after"] = None
            if tree.selection() and tree.selection()[0] == iid:
                unlock_locked(r)

        pending_unlock["after"] = root.after(350, unlock_if_still_selected)

    tree.bind("<<TreeviewSelect>>", show_details)
    tree.bind("<ButtonRelease-1>", row_clicked)
    tree.bind("<Double-Button-1>", row_double_clicked)
    query.trace_add("write", lambda *_: refill())

    def refresh():
        try:
            _total, new, bad, locked_paths = collect(alerts_dir, hist_path)
            changed = rebuild_locked(locked_paths)
            if new or not history or changed:
                history.clear()
                history.update(load_history(hist_path))
                refill()
            if bad:
                counts.config(text=counts.cget("text")
                              + " · %d corrupt skipped" % bad)
        except Exception as e:  # never let the poller die
            counts.config(text="refresh error: %r" % e)
        if not smoke_test:
            root.after(POLL_MS, refresh)

    history.update(load_history(hist_path))
    _t, new, _b, locked_paths = collect(alerts_dir, hist_path)
    if new:
        history.clear()
        history.update(load_history(hist_path))
    rebuild_locked(locked_paths)
    update_headings()
    refill()
    if smoke_test:
        root.after(2500, root.destroy)
    else:
        root.after(POLL_MS, refresh)
    root.mainloop()


def main():
    args = sys.argv[1:]
    alerts_dir, hist_path = ALERTS_DIR, HISTORY
    if "--alerts-dir" in args:
        alerts_dir = args[args.index("--alerts-dir") + 1]
    if "--history" in args:
        hist_path = args[args.index("--history") + 1]

    if "--collect-only" in args:
        total, new, bad, locked = collect(alerts_dir, hist_path)
        print("alert-history: total=%d new=%d corrupt=%d locked=%d -> %s"
              % (total, new, bad, len(locked), hist_path))
        return
    run_gui(alerts_dir, hist_path, smoke_test="--smoke-test" in args)


if __name__ == "__main__":
    main()
