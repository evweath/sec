#!/usr/bin/env python3
"""
evw-wazuh-dashboard.py — loopback web dashboard for the Wazuh agent +
evw-wazuh-guard on this Mac.

Shows: agent daemon states, manager address + reachability (tcp 1514/1515),
guard state + manager connection transitions, and a live tail of
evw-wazuh-guard.log (plus ossec.log connect lines when readable).

- Stdlib only. Binds 127.0.0.1 only; per-start token required as ?t=
  (printed at startup); Host header pinned to loopback (DNS-rebinding
  mitigation). Read-only GETs; no state changes possible through this UI.
- Run as root (sudo) for full detail (guard log + ossec.conf + ossec.log are
  root-only). As a normal user it degrades gracefully and marks the
  sections that need sudo.

Usage: python3 evw-wazuh-dashboard.py [--port N] [--no-browser] [--lines N]
Menu:  sudo bash ~/dev/security/security-menu.sh  (entry: evw-wazuh-dashboard.py)
"""

import argparse
import json
import os
import secrets
import socket
import subprocess
import sys
import webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error_guard.py)
try:
    import pathlib as _pathlib, sys as _sys
    _d = _pathlib.Path(__file__).resolve().parent
    for _ in range(6):
        if (_d / "lib" / "error_guard.py").exists():
            _sys.path.insert(0, str(_d / "lib"))
            break
        _d = _d.parent
    from error_guard import guard_run, GuardError
except ImportError:
    def guard_run(_l, fn, *a, **kw): return fn(*a, **kw)
    class GuardError(Exception): pass

OSSEC_DIR = "/Library/Ossec"
OSSEC_CONF = OSSEC_DIR + "/etc/ossec.conf"
OSSEC_LOG = OSSEC_DIR + "/logs/ossec.log"
GUARD_LOGS = ["/private/var/log/evw-wazuh-guard.log",
              os.path.expanduser("~/Library/Logs/evw-wazuh-guard.log")]
GUARD_STATE = "/var/tmp/evw-wazuh-guard.state"
DAEMONS = ["wazuh-agentd", "wazuh-logcollector", "wazuh-syscheckd",
           "wazuh-execd", "wazuh-modulesd"]
MANAGER_PORTS = (1515, 1514)
DEFAULT_MANAGER = "10.0.0.2"

TOKEN = secrets.token_hex(16)


def sh(args, timeout=6):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.stdout.strip()
    except Exception:
        return ""


def manager_address():
    try:
        with open(OSSEC_CONF) as f:
            import re
            m = re.search(r"<address>([^<]+)</address>", f.read())
            if m:
                return m.group(1), True
    except Exception:
        pass
    return DEFAULT_MANAGER, False


def reachable(ip, port, timeout=2):
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


def collect_status():
    st = {"time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
          "euid_root": (os.geteuid() == 0)}

    v = sh(["pkgutil", "--pkg-info", "com.wazuh.pkg.wazuh-agent"])
    st["pkg_version"] = None
    for line in v.splitlines():
        if line.startswith("version:"):
            st["pkg_version"] = line.split(":", 1)[1].strip()

    st["daemons"] = {}
    for d in DAEMONS:
        pid = sh(["pgrep", "-f", d]).split("\n")[0]
        st["daemons"][d] = pid or None

    mgr, conf_readable = manager_address()
    st["manager"] = {"address": mgr, "conf_readable": conf_readable,
                     "ports": {str(p): reachable(mgr, p) for p in MANAGER_PORTS}}

    gpid = sh(["pgrep", "-f", "evw-wazuh-guard.sh"]).split("\n")[0]
    st["guard"] = {"running": bool(gpid), "pid": gpid or None}
    try:
        with open(GUARD_STATE) as f:
            st["guard"]["manager_state"] = f.read().strip()
    except Exception:
        st["guard"]["manager_state"] = None

    st["ossec_log_connects"] = None
    if os.access(OSSEC_LOG, os.R_OK):
        out = sh(["bash", "-c",
                  "grep -E 'Connected to server|Unable to connect|Could not resolve|Connection refused' "
                  + OSSEC_LOG + " | tail -3"])
        st["ossec_log_connects"] = out.splitlines() if out else []
    return st


def tail_log(n):
    for path in GUARD_LOGS:
        if os.path.isfile(path) and os.access(path, os.R_OK):
            out = sh(["tail", "-n", str(n), path])
            return {"path": path, "readable": True,
                    "lines": out.splitlines() if out else []}
    return {"path": GUARD_LOGS[0], "readable": False, "lines": []}


PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>evw wazuh dashboard</title>
<style>
 body{background:#0d1117;color:#c9d1d9;font:14px/1.45 -apple-system,monospace;margin:0;padding:16px}
 h1{font-size:18px;color:#58a6ff;margin:0 0 4px}
 h2{font-size:14px;color:#8b949e;margin:18px 0 6px;text-transform:uppercase;letter-spacing:.06em}
 .grid{display:flex;gap:24px;flex-wrap:wrap}
 .card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 16px;min-width:280px}
 .ok{color:#3fb950}.bad{color:#f85149}.dim{color:#8b949e}.warn{color:#d29922}
 table{border-collapse:collapse} td{padding:2px 14px 2px 0;vertical-align:top}
 #log{background:#010409;border:1px solid #30363d;border-radius:8px;padding:10px;
      white-space:pre-wrap;font:12px/1.5 ui-monospace,monospace;max-height:46vh;overflow-y:auto}
 .alert{color:#f85149;font-weight:600}.state{color:#d29922}.okline{color:#3fb950}
 a{color:#58a6ff}button{background:#21262d;color:#c9d1d9;border:1px solid #30363d;
      border-radius:6px;padding:4px 10px;cursor:pointer}
</style></head><body>
<h1>Wazuh agent + guard — STATUS_HOST</h1>
<div class="dim" id="ts">loading…</div>
<div class="grid">
 <div class="card"><h2>Agent daemons</h2><table id="daemons"></table>
   <div class="dim" id="pkg"></div></div>
 <div class="card"><h2>Manager</h2><table id="manager"></table>
   <div id="connects"></div></div>
 <div class="card"><h2>evw-wazuh-guard</h2><table id="guard"></table></div>
</div>
<h2>guard log <span class="dim" id="logsrc"></span>
  <button onclick="paused=!paused;this.textContent=paused?'resume':'pause'">pause</button></h2>
<div id="log">loading…</div>
<script>
let paused=false;
const T="?t=__TOKEN__";
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}
function row(k,v,cls){return `<tr><td class="dim">${esc(k)}</td><td class="${cls||''}">${v}</td></tr>`}
async function refresh(){
 if(paused)return;
 try{
  const st=await (await fetch('/api/status'+T)).json();
  document.getElementById('ts').textContent=st.time+(st.euid_root?' · root':' · user (some sections limited — run with sudo for full detail)');
  let h='';for(const[d,p]of Object.entries(st.daemons))
   h+=row(d,p?'running · pid '+p:'NOT RUNNING',p?'ok':'bad');
  document.getElementById('daemons').innerHTML=h;
  document.getElementById('pkg').textContent='pkg: '+(st.pkg_version||'not installed');
  const m=st.manager;let mh=row('address',esc(m.address)+(m.conf_readable?'':' <span class="warn">(default — ossec.conf unreadable)</span>'));
  for(const[p,ok]of Object.entries(m.ports))mh+=row('tcp/'+p,ok?'reachable':'UNREACHABLE',ok?'ok':'bad');
  document.getElementById('manager').innerHTML=mh;
  document.getElementById('connects').innerHTML=st.ossec_log_connects===null?
   '<div class="dim">ossec.log: needs root</div>':
   st.ossec_log_connects.map(l=>`<div class="dim">${esc(l)}</div>`).join('');
  const g=st.guard;
  document.getElementById('guard').innerHTML=
   row('process',g.running?'running · pid '+g.pid:'NOT RUNNING',g.running?'ok':'bad')+
   row('manager state',esc(g.manager_state||'unknown'),
       g.manager_state==='connected'?'ok':(g.manager_state==='disconnected'?'warn':''));
 }catch(e){}
 try{
  const lg=await (await fetch('/api/log'+T)).json();
  document.getElementById('logsrc').textContent=' — '+lg.path+(lg.readable?'':' (needs root)');
  document.getElementById('log').innerHTML=lg.readable?
   lg.lines.map(l=>{const e=esc(l);
     const c=l.includes('ALERT')?'alert':(l.includes('manager state')?'state':(l.includes('ok:')?'okline':''));
     return `<span class="${c}">${e}</span>`}).join('\n'):
   '(guard log not readable as this user — restart the dashboard with sudo)';
  const el=document.getElementById('log');el.scrollTop=el.scrollHeight;
 }catch(e){}
}
refresh();setInterval(refresh,8000);
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def _ok_host(self):
        host = self.headers.get("Host", "")
        return host.startswith("127.0.0.1") or host.startswith("localhost")

    def _send_json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if not self._ok_host():
            self._send_json({"error": "bad host"}, 403)
            return
        if q.get("t", [""])[0] != TOKEN:
            self._send_json({"error": "bad token"}, 403)
            return
        if u.path == "/":
            body = PAGE.replace("__TOKEN__", TOKEN).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif u.path == "/api/status":
            self._send_json(guard_run("collect-status", collect_status))
        elif u.path == "/api/log":
            n = int(q.get("n", [str(LINES)])[0] or LINES)
            n = max(1, min(n, 2000))
            self._send_json(guard_run("tail-log", tail_log, n))
        else:
            self._send_json({"error": "not found"}, 404)

    def log_message(self, *a):  # quiet
        pass


LINES = 300

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8790)
    ap.add_argument("--lines", type=int, default=300)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()

    LINES = args.lines
    PAGE = PAGE.replace("STATUS_HOST", socket.gethostname())

    url = f"http://127.0.0.1:{args.port}/?t={TOKEN}"
    print(f"evw-wazuh-dashboard serving on {url}")
    print("loopback only · tokenized · Ctrl-C to stop")
    if not args.no_browser:
        webbrowser.open(url)
    ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()
