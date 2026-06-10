#!/bin/bash
# evw-ls-watchdog.sh — Little Snitch rule hygiene, runs every 10 minutes.
#
# Each run:
#   1. Exports the current LS model
#   2. AUTO-DELETES rules matching any of:
#        - Via unsigned binary (identifier.SHA256/...)
#        - remote=any AND origin=monitor (auto-created blanket allows)
#        - allow rule for a blocked domain (TikTok, Zoho tracking, WhatsApp)
#        - allow rule for a disabled/guarded process (origin=monitor)
#   3. AUTO-TIGHTENS: adds port=443/TCP to allow rules that have a specific
#        remote-hosts target but no port restriction
#   4. Only imports the model if changes were made
#   5. Skips import if one happened within the last 5 minutes (debounce)
#
# Deployed to: /usr/local/bin/evw-ls-watchdog.sh
# LaunchDaemon: com.evw.ls-watchdog  (root, StartInterval=600)

set -uo pipefail

LOG="/private/var/log/evw-ls-watchdog.log"
LAST_IMPORT_FILE="/private/var/run/evw-ls-watchdog-last.ts"
LSCLI="/Applications/Little Snitch.app/Contents/Components/littlesnitch"
DEBOUNCE=300

log() { printf '[%s] %s\n' "$(date -Iseconds)" "$*" >> "$LOG"; }

# Log rotation: keep last 2 MB
if [[ -f "$LOG" ]] && (( $(wc -c < "$LOG") > 2097152 )); then
    mv "$LOG" "${LOG}.1"
fi

log "--- watchdog tick ---"

# Write heartbeat so the monitor daemon can confirm we're alive
date +%s > /private/var/run/evw-ls-watchdog-heartbeat.ts

# Debounce: skip if a model import happened very recently
if [[ -f "$LAST_IMPORT_FILE" ]]; then
    last_ts=$(cat "$LAST_IMPORT_FILE" 2>/dev/null || echo 0)
    now_ts=$(date +%s)
    age=$(( now_ts - last_ts ))
    if (( age < DEBOUNCE )); then
        log "SKIP debounce: last import ${age}s ago (min ${DEBOUNCE}s)"
        exit 0
    fi
fi

if [[ ! -x "$LSCLI" ]]; then
    log "ERROR: LS CLI not found at $LSCLI"
    exit 1
fi

TS=$(date +%s)
EXPORT="/var/tmp/ls-watchdog-${TS}.json"
MODIFIED="/var/tmp/ls-watchdog-mod-${TS}.json"
REPORT="/var/tmp/ls-watchdog-report-${TS}.txt"

"$LSCLI" export-model "$EXPORT" 2>/dev/null || true
if [[ ! -f "$EXPORT" ]] || (( $(wc -c < "$EXPORT") < 1000 )); then
    log "ERROR: export failed or empty (Little Snitch not running?)"
    rm -f "$EXPORT"
    exit 1
fi
log "exported $(wc -c < "$EXPORT") bytes"

# Run analysis and patching; env vars pass file paths into the heredoc
_LS_SRC="$EXPORT" _LS_DST="$MODIFIED" _LS_RPT="$REPORT" python3 << 'PYEOF'
import json, os, sys, re

src         = os.environ["_LS_SRC"]
dst         = os.environ["_LS_DST"]
report_path = os.environ["_LS_RPT"]

with open(src) as f:
    model = json.load(f)

rules = model.get("rules", [])
orig_count = len(rules)

# Domain-level: any subdomain of these triggers deletion
BLOCKED_DOMAINS = {
    "tiktok.com", "tiktokcdn-us.com", "tiktokv.us", "tiktokw.us",
    "ttcdn-us.com", "tiktokshops.us", "bytedance.com",
    "zohopublic.com", "zohocdn.com",
    "api.whatsapp.com", "web.whatsapp.com", "www.whatsapp.com",
}
# Exact-host matches
BLOCKED_HOSTS = {
    "salesiq.zoho.com",
    "pagesense-collect.zoho.com",
    "pagesense-hb-collect.zoho.com",
}

# Monitor-origin allow rules for these processes should not exist
DISABLED_PROCS = {
    "com.apple.replayd", "com.apple.studentd",
    "com.apple.remotemanagementd", "com.apple.RemoteManagementAgent",
    "com.apple.sharingd", "com.apple.identityservicesd",
    "com.apple.replicatord", "com.apple.privatecloudcomputed",
    "com.apple.universalcontrol", "com.apple.AirPlayReceiver",
    "com.apple.AirPlayUIAgent", "com.apple.rapportd",
    "com.apple.bluetoothd", "com.apple.screensharingd",
    "com.apple.ARDAgent", "com.apple.nearbyd",
    "com.apple.mediaremoted", "com.apple.avconferenced",
    "com.apple.PersonalHotspotAgent",
}

def short_proc(r):
    p = r.get("process", "<ANY>")
    if p.startswith("identifier.APPLE/"): return p[17:]
    if p.startswith("identifier."): return p.split("/")[-1] if "/" in p else p
    return p

def rule_remote(r):
    for k in ("remote", "remote-hosts", "remote-domains", "remote-addresses"):
        v = r.get(k, "")
        if v: return str(v)
    return ""

def host_is_blocked(hostname):
    h = hostname.strip().lstrip("*.")
    if h in BLOCKED_HOSTS:
        return True
    for bd in BLOCKED_DOMAINS:
        if h == bd or h.endswith("." + bd):
            return True
    return False

def rule_hits_blocked_domain(r):
    for field in ("remote-hosts", "remote-domains"):
        v = str(r.get(field, ""))
        if not v:
            continue
        for token in re.split(r"[,\s]+", v):
            token = token.strip()
            if token and host_is_blocked(token):
                return True
    return False

def should_delete(r):
    if r.get("protected"):
        return None
    action = r.get("action", "")
    if action not in ("allow", "suggestion"):
        return None

    via    = str(r.get("via", ""))
    proc   = r.get("process", "")
    remote = r.get("remote", "")
    origin = r.get("origin", "")

    if via.startswith("identifier.SHA256/"):
        return "unsigned-binary via={}...".format(via[18:34])

    if remote in ("any", "*") and origin == "monitor":
        return "any-remote monitor rule"

    if rule_hits_blocked_domain(r):
        return "blocked-domain {}".format(rule_remote(r)[:50])

    if origin in ("monitor", "network monitor") and proc:
        proc_tail = proc.split("/")[-1] if "/" in proc else proc
        for dp in DISABLED_PROCS:
            if dp in proc or proc_tail in dp:
                return "disabled-process {}".format(short_proc(r))

    return None

def should_tighten(r):
    if r.get("protected") or r.get("disabled"):
        return False
    if r.get("action") != "allow":
        return False
    if not r.get("remote-hosts"):
        return False
    if r.get("ports"):
        return False
    if r.get("protocol", "any") in ("udp", "icmp"):
        return False
    return True

deleted   = []
tightened = []
kept      = []

for r in rules:
    reason = should_delete(r)
    if reason:
        proc   = short_proc(r)
        remote = rule_remote(r)[:50]
        uses   = r.get("useCount", 0)
        deleted.append("  DEL  {:<40}  {}  uses={}  reason={}".format(
            proc, remote, uses, reason))
        continue

    if should_tighten(r):
        r = dict(r)
        r["ports"]    = "443"
        r["protocol"] = "tcp"
        proc   = short_proc(r)[:38]
        remote = str(r.get("remote-hosts", ""))[:40]
        uses   = r.get("useCount", 0)
        tightened.append("  ADD_PORT  {:<40}  {}  uses={}".format(proc, remote, uses))

    kept.append(r)

model["rules"] = kept
final_count    = len(kept)
changed        = len(deleted) + len(tightened)

lines = [
    "orig={}  deleted={}  tightened={}  final={}  changed={}".format(
        orig_count, len(deleted), len(tightened), final_count,
        "YES" if changed else "NO"),
]
if deleted:
    lines += ["--- DELETED ---"] + deleted
if tightened:
    lines += ["--- TIGHTENED ---"] + tightened

with open(report_path, "w") as f:
    f.write("\n".join(lines) + "\n")

if changed:
    with open(dst, "w") as f:
        json.dump(model, f, indent=2, separators=(",", " : "))
        f.write("\n")
    sys.exit(0)   # 0 = changes made
else:
    sys.exit(2)   # 2 = no changes needed
PYEOF
PY_EXIT=$?

# Append report lines to log
if [[ -f "$REPORT" ]]; then
    while IFS= read -r line; do log "$line"; done < "$REPORT"
    rm -f "$REPORT"
fi

if [[ $PY_EXIT -eq 0 ]] && [[ -f "$MODIFIED" ]]; then
    "$LSCLI" restore-model "$MODIFIED" 2>/dev/null \
        && log "IMPORT OK" \
        || log "IMPORT FAILED"
    date +%s > "$LAST_IMPORT_FILE"
elif [[ $PY_EXIT -eq 2 ]]; then
    log "no changes needed"
else
    log "ERROR: python exited $PY_EXIT"
fi

rm -f "$EXPORT" "$MODIFIED"
exit 0
