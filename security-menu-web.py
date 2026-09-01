#!/usr/bin/env python3
"""
security-menu-web.py — browser UI for security-menu.sh.

Serves a localhost-only page listing every security script with a real
checkbox, grouped by section, in a scrollable view. Check what you want,
press "Run checked", watch live output in the bottom panel.

Safety: binds 127.0.0.1 only, a random per-start token is required on the
page URL (?t=) and on all API calls, the Host header is validated on every
request (DNS-rebinding mitigation), indices are validated server-side, and
MOD/SVC/ARGS selections require confirmed=true from the browser's own
confirmation step.

Usage: python3 security-menu-web.py [--port N] [--no-browser]
"""

import argparse
import hmac
import json
import os
import secrets
import subprocess
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

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

# Long-running server: never prompt from HTTP handler threads — log + skip
# failed steps (EVW_GUARD_POLICY=continue) so a bad batch can't kill the UI.
os.environ.setdefault("EVW_GUARD_POLICY", "continue")

BASE = os.path.dirname(os.path.abspath(__file__))
MENU = os.path.join(BASE, "security-menu.sh")
MAX_OUTPUT = 400_000
RISKY = ("MOD", "SVC", "ARGS")


def load_entries():
    p = guard_run("menu-json", subprocess.run,
                  ["bash", MENU, "--json"], capture_output=True, text=True, cwd=BASE)
    if p is None or p is SKIP:
        sys.exit("error: security-menu.sh --json failed (see stderr)")
    if p.returncode != 0:
        sys.exit(f"error: security-menu.sh --json failed: {p.stderr.strip()}")
    return json.loads(p.stdout)


ENTRIES = load_entries()
N = len(ENTRIES)
TOKEN = secrets.token_urlsafe(24)

state = {"running": False, "output": "", "code": None}
state_lock = threading.Lock()


def append_output(text):
    with state_lock:
        state["output"] = (state["output"] + text)[-MAX_OUTPUT:]


def run_selection(indices):
    csv = ",".join(str(i) for i in indices)
    try:
        proc = guard_run(
            "menu-run", subprocess.Popen,
            ["bash", MENU, "--run", csv, "--yes"],
            cwd=BASE, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        if proc is None or proc is SKIP:
            append_output("\n[web] runner error: menu-run failed (see server stderr)\n")
            state["code"] = 1
            return
        for line in proc.stdout:
            append_output(line)
        state["code"] = proc.wait()
    except Exception as e:  # noqa: BLE001 - surface anything to the pane
        append_output(f"\n[web] runner error: {e}\n")
        state["code"] = 1
    finally:
        with state_lock:
            state["running"] = False


PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Master Security Menu</title>
<style>
  :root { --bg:#0d1117; --panel:#161b22; --line:#30363d; --fg:#c9d1d9;
          --dim:#8b949e; --amber:#d29922; --green:#3fb950; --accent:#1f6feb; }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--fg);
         font:14px/1.45 -apple-system, "SF Mono", Menlo, monospace; }
  header { position:sticky; top:0; z-index:10; background:var(--panel);
           border-bottom:1px solid var(--line); padding:10px 16px; }
  header h1 { display:inline; font-size:16px; margin:0 14px 0 0; }
  header .count { color:var(--green); font-weight:600; }
  header button { background:var(--accent); color:#fff; border:0; border-radius:6px;
                  padding:6px 14px; margin-left:8px; cursor:pointer; font:inherit; }
  header button.secondary { background:#21262d; border:1px solid var(--line); color:var(--fg); }
  header button:disabled { opacity:.45; cursor:not-allowed; }
  header input[type=search] { background:var(--bg); border:1px solid var(--line);
                              border-radius:6px; color:var(--fg); padding:6px 10px;
                              width:240px; margin-left:8px; font:inherit; }
  .hint { color:var(--dim); font-size:12px; margin-top:6px; }
  main { padding:0 16px 46vh; }
  h2 { position:sticky; top:64px; z-index:5; background:var(--bg);
       font-size:13px; color:var(--accent); margin:0; padding:12px 4px 6px;
       border-bottom:1px solid var(--line); }
  label.row { display:grid; grid-template-columns:28px 44px 130px minmax(220px,42%) 150px 1fr;
              align-items:center; gap:6px; padding:7px 4px; border-bottom:1px solid #21262d;
              cursor:pointer; }
  label.row:hover { background:#161b22; }
  label.row.checked { background:#12261a; }
  label.row input { width:18px; height:18px; accent-color:var(--green); cursor:pointer; }
  .num { color:var(--dim); text-align:right; padding-right:6px; }
  .tag { font-size:12px; color:var(--green); }
  .tag.risky { color:var(--amber); }
  .path { font-weight:600; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .lastrun { color:var(--dim); font-size:12px; white-space:nowrap; }
  .desc { color:var(--dim); font-size:13px; }
  #output { position:fixed; left:0; right:0; bottom:0; height:42vh; z-index:20;
            background:var(--panel); border-top:1px solid var(--line);
            display:flex; flex-direction:column; }
  #output .bar { padding:8px 16px; border-bottom:1px solid var(--line);
                 display:flex; align-items:center; gap:12px; }
  #output .bar b { font-size:13px; }
  #status { color:var(--dim); font-size:12px; }
  #status.running { color:var(--amber); }
  #out { flex:1; overflow-y:auto; margin:0; padding:10px 16px; font-size:12.5px;
         white-space:pre-wrap; word-break:break-word; }
  .min #out { display:none; }
  #output.min { height:auto; }
</style>
</head>
<body>
<header>
  <h1>Master Security Menu</h1>
  <span class="count" id="count">0 checked</span>
  <button id="run">Run checked</button>
  <button class="secondary" id="all">Check all</button>
  <button class="secondary" id="clear">Clear</button>
  <input type="search" id="filter" placeholder="filter (name, tag, description)…">
  <div class="hint">Click a row or its checkbox to select. Scripts tagged MOD/SVC ask for
  confirmation. SUDO scripts prompt for the password in the terminal running this server
  (run <code>sudo -v</code> there first). Server: localhost only, token-protected.</div>
</header>
<main id="list"></main>
<div id="output" class="min">
  <div class="bar"><b>Output</b><span id="status">idle</span>
    <button class="secondary" id="toggle">show/hide</button></div>
  <pre id="out"></pre>
</div>
<script>
const ENTRIES = __ENTRIES__;
const TOKEN = "__TOKEN__";
const RISKY = ["MOD", "SVC", "ARGS"];
const list = document.getElementById("list");
const countEl = document.getElementById("count");
const outEl = document.getElementById("out");
const statusEl = document.getElementById("status");
const outputEl = document.getElementById("output");
let polling = null;

// Build the scrollable list, grouped by section.
let section = null, h2 = null;
for (const e of ENTRIES) {
  if (e.section !== section) {
    section = e.section;
    h2 = document.createElement("h2");
    h2.textContent = section;
    list.appendChild(h2);
  }
  const row = document.createElement("label");
  row.className = "row";
  const risky = RISKY.some(t => e.tags.includes(t));
  row.innerHTML = `<input type="checkbox" data-n="${e.n}">
    <span class="num">${e.n}</span>
    <span class="tag ${risky ? "risky" : ""}">${e.tags}</span>
    <span class="path" title="${e.path}">${e.path}</span>
    <span class="lastrun">${e.lastrun || "never"}</span>
    <span class="desc">${e.desc}</span>`;
  row.dataset.search = `${e.n} ${e.tags} ${e.path} ${e.desc}`.toLowerCase();
  list.appendChild(row);
}

const boxes = () => [...document.querySelectorAll("input[type=checkbox]")];
function refresh() {
  const n = boxes().filter(b => b.checked).length;
  countEl.textContent = n + " checked";
  for (const b of boxes()) b.closest("label.row").classList.toggle("checked", b.checked);
}
list.addEventListener("change", refresh);

document.getElementById("all").onclick = () => {
  const bs = boxes(), anyUnchecked = bs.some(b => !b.checked);
  bs.forEach(b => b.checked = anyUnchecked); refresh();
};
document.getElementById("clear").onclick = () => { boxes().forEach(b => b.checked = false); refresh(); };
document.getElementById("filter").oninput = ev => {
  const q = ev.target.value.toLowerCase();
  for (const row of document.querySelectorAll("label.row"))
    row.style.display = row.dataset.search.includes(q) ? "" : "none";
};
document.getElementById("toggle").onclick = () => outputEl.classList.toggle("min");

async function poll() {
  const r = await fetch("/api/status", {headers: {"X-Menu-Token": TOKEN}});
  if (!r.ok) return;
  const s = await r.json();
  outEl.textContent = s.output;
  outEl.scrollTop = outEl.scrollHeight;
  if (s.running) {
    statusEl.textContent = "running…";
    statusEl.className = "running";
  } else {
    statusEl.textContent = s.code === null ? "idle" : "finished (exit " + s.code + ")";
    statusEl.className = "";
    document.getElementById("run").disabled = false;
    clearInterval(polling); polling = null;
  }
}

document.getElementById("run").onclick = async () => {
  const indices = boxes().filter(b => b.checked).map(b => +b.dataset.n);
  if (!indices.length) { alert("No scripts checked."); return; }
  const risky = indices.some(n => RISKY.some(t => ENTRIES[n-1].tags.includes(t)));
  let confirmed = false;
  if (risky) {
    confirmed = confirm("Selection includes scripts that MODIFY the system or install daemons. Proceed?");
    if (!confirmed) return;
  }
  const r = await fetch("/api/run", {
    method: "POST",
    headers: {"Content-Type": "application/json", "X-Menu-Token": TOKEN},
    body: JSON.stringify({indices, confirmed}),
  });
  if (!r.ok) { alert("Run rejected: " + (await r.json()).error); return; }
  outputEl.classList.remove("min");
  document.getElementById("run").disabled = true;
  statusEl.textContent = "running…"; statusEl.className = "running";
  if (!polling) polling = setInterval(poll, 1000);
  poll();
};
refresh();
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="text/plain"):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _token_ok(self):
        return self.headers.get("X-Menu-Token") == TOKEN

    def _host_ok(self):
        # DNS-rebinding mitigation: only the loopback Host this server bound
        host = (self.headers.get("Host") or "").strip().lower()
        port = self.server.server_address[1]
        return host in (f"127.0.0.1:{port}", f"localhost:{port}")

    def do_GET(self):
        # error-guard: a failing request must never kill the dashboard
        guard_run("http-get", self._do_GET)

    def _do_GET(self):
        if not self._host_ok():
            return self._send(403, "forbidden")
        url = urlparse(self.path)
        if url.path == "/":
            # page embeds the token — only serve it to a token-bearing URL
            t = parse_qs(url.query).get("t", [""])[0]
            if not hmac.compare_digest(t.encode(), TOKEN.encode()):
                return self._send(403, "forbidden")
            html = PAGE.replace("__TOKEN__", TOKEN).replace("__ENTRIES__", json.dumps(ENTRIES))
            self._send(200, html, "text/html; charset=utf-8")
        elif url.path == "/api/status":
            if not self._token_ok():
                return self._send(403, '{"error":"bad token"}', "application/json")
            with state_lock:
                body = json.dumps(state)
            self._send(200, body, "application/json")
        else:
            self._send(404, "not found")

    def do_POST(self):
        # error-guard: a failing request must never kill the dashboard
        guard_run("http-post", self._do_POST)

    def _do_POST(self):
        if not self._host_ok():
            return self._send(403, "forbidden")
        if urlparse(self.path).path != "/api/run":
            return self._send(404, "not found")
        if not self._token_ok():
            return self._send(403, '{"error":"bad token"}', "application/json")
        try:
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length) or b"{}")
            indices = sorted({int(i) for i in body.get("indices", [])})
        except Exception:  # noqa: BLE001
            return self._send(400, '{"error":"bad request"}', "application/json")
        if not indices or any(i < 1 or i > N for i in indices):
            return self._send(400, '{"error":"bad indices"}', "application/json")
        risky = any(any(t in ENTRIES[i - 1]["tags"] for t in RISKY) for i in indices)
        if risky and not body.get("confirmed"):
            return self._send(409, '{"error":"confirmation required"}', "application/json")
        with state_lock:
            if state["running"]:
                return self._send(409, '{"error":"already running"}', "application/json")
            state.update(running=True, output="", code=None)
        threading.Thread(target=run_selection, args=(indices,), daemon=True).start()
        self._send(200, '{"ok":true}', "application/json")

    def log_message(self, *args):
        pass


def main():
    ap = argparse.ArgumentParser(description="Web UI for security-menu.sh")
    ap.add_argument("--port", type=int, default=0, help="default: random free port")
    ap.add_argument("--no-browser", action="store_true", help="don't auto-open the browser")
    args = ap.parse_args()

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    port = server.server_address[1]
    url = f"http://127.0.0.1:{port}/?t={TOKEN}"
    print(f"Master Security Menu web UI: {url}")
    print("Open that exact URL — the ?t= per-start token is required (a bare "
          "request gets 403), and it changes on every start.")
    print("SUDO-tagged scripts will prompt for the sudo password in THIS terminal "
          "(run 'sudo -v' here first). Ctrl-C to stop.")
    if not args.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
