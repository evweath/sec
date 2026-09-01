#!/bin/bash
# security-menu.sh — master launcher for every security script in this folder.
# Each entry shows what the script does next to its name.
# Tags: [RO]=read-only report  [MOD]=modifies system  [SUDO]=needs root
#       [SVC]=installs/runs a daemon or long-running monitor  [ARGS]=asks for arguments
#       [DAEMON]=runs forever in the foreground: the menu smoke-runs it for
#       MENU_DAEMON_TIMEOUT seconds (default 60), stops it, and counts a
#       full-window run as SUCCESS — install the matching *-setup.sh entry
#       to run it permanently. Any other script is killed and reported failed
#       after MENU_TIMEOUT seconds (default 900).
#
# Press "b" (or pass --bg / set MENU_DAEMON_BG=1) to flip [DAEMON] entries
# into background mode: the daemon is detached with nohup (output to
# logs/daemon-<name>-<timestamp>.log) and the batch continues immediately
# with the next script. A daemon that is already running is not duplicated
# (pgrep check); the batch summary lists everything left running.
#
# Interactive usage:
#   1 4 7-9   toggle the checkbox next to those entries
#   a         check all (or uncheck all if everything is checked)
#   c         clear all checkboxes
#   r         run all checked scripts
#   !1 3 8    run these scripts immediately without touching checkboxes
#   l         relist the menu          q   quit
#
# Scripts tagged [SUDO] are elevated through sudo when the menu itself is not
# running as root: sudo -v primes credentials (one password prompt, then the
# normal sudo timestamp cache applies). If sudo authentication fails, that
# script and all later SUDO-tagged scripts in the same batch are skipped.
#
# After every script run, a one-line outcome banner is shown — "OK" on
# success, or "FAILED" with the last lines of that script's log section —
# plus the batch log file's name and full path. On a terminal the banner
# stays on screen for 5 seconds, then the batch continues automatically.
#
# The date column beside each entry is that script's last SUCCESSFUL run
# (DD/MM/YYYY HH:MM; "never" when none is recorded). Stored in
# logs/last-success.tsv and updated after every successful run.
#
# Non-interactive usage:
#   security-menu.sh --list            print the menu and exit
#   security-menu.sh --check           verify all referenced files exist and parse
#   security-menu.sh --json            dump entries as JSON (used by security-menu-web.py)
#   security-menu.sh --run 1,3,5-8 [--yes] [--bg]   run entries non-interactively
#     (--yes skips the confirm prompt; --bg detaches [DAEMON] entries and continues)
# Web UI: security-menu-web.py (browser checkbox interface to this menu)
# Logs: logs/menu-YYYYMMDD-HHMMSS.log — one per batch; system-context header,
#   per-script section (args, timing, exit code) and, on failure, a diagnostics
#   block so a broken script can be debugged from the log alone.

set -u

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error-guard.sh)
_eg_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
while [ "$_eg_d" != "/" ] && [ ! -f "$_eg_d/lib/error-guard.sh" ]; do _eg_d="$(dirname "$_eg_d")"; done
[ -f "$_eg_d/lib/error-guard.sh" ] && . "$_eg_d/lib/error-guard.sh"; unset _eg_d
command -v guard_run >/dev/null 2>&1 || guard_run() { shift; "$@"; }
command -v guard_throw >/dev/null 2>&1 || guard_throw() { printf 'error-guard: throw: %s\n' "$*" >&2; return 1; }

cd "$(dirname "$0")"
mkdir -p logs
ASSUME_YES=0
DAEMON_BG="${MENU_DAEMON_BG:-0}"   # 1 = detach [DAEMON] entries with nohup and continue
LAST_RUNS="logs/last-success.tsv"   # path<TAB>DD/MM/YYYY HH:MM of last successful run

json_esc() { local s="$1"; s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; printf '%s' "$s"; }

# Remember when a script last completed successfully (shown in the menu).
record_success() {
  local p="$1"
  [[ -f "$LAST_RUNS" ]] && grep -vF "$p"$'\t' "$LAST_RUNS" > "$LAST_RUNS.tmp" 2>/dev/null
  printf '%s\t%s\n' "$p" "$(date '+%d/%m/%Y %H:%M')" >> "$LAST_RUNS.tmp"
  mv -f "$LAST_RUNS.tmp" "$LAST_RUNS"
}
last_run() {
  [[ -f "$LAST_RUNS" ]] && awk -F '\t' -v p="$1" '$1==p {d=$2} END {print d}' "$LAST_RUNS"
}

do_json() {
  local i sep
  printf '[\n'
  for ((i=0; i<N; i++)); do
    sep=","; [[ "$i" -eq $((N-1)) ]] && sep=""
    printf '  {"n":%d,"section":"%s","path":"%s","tags":"%s","lastrun":"%s","desc":"%s"}%s\n' \
      "$((i+1))" "$(json_esc "${SEC[$i]}")" "$(json_esc "${PTH[$i]}")" \
      "$(json_esc "${TAG[$i]}")" "$(json_esc "$(last_run "${PTH[$i]}")")" \
      "$(json_esc "${DSC[$i]}")" "$sep"
  done
  printf ']\n'
}

SEC=(); PTH=(); TAG=(); DSC=(); PRE=(); CHK=()
# add <section> <path> <tags> <desc> [preset-args]
# preset-args: arguments always passed to the script (unless tagged [ARGS],
# which prompts instead). Used for entries whose own confirm gate is already
# covered by the menu's MODIFY/SVC confirmation (e.g. install-all.sh --yes).
add() { SEC+=("$1"); PTH+=("$2"); TAG+=("$3"); DSC+=("$4"); PRE+=("${5:-}"); CHK+=(0); }
N=0

# ─── SCANS & AUDITS ──────────────────────────────────────────────────────────
S="SCANS & AUDITS"
add "$S" "tcc-audit.sh"                              "[RO,SUDO]" "Dump TCC privacy grants (screen, accessibility, camera, mic) to a dated report"
add "$S" "scan-hashes.sh"                            "[RO]"      "Snapshot key binary/config hashes with diff vs previous scan"
add "$S" "l5-stamp.sh"                               "[RO]"      "Weekly SHA-256 manifest of system files, OTS-stamped, git-committed"
add "$S" "build-fs-baseline.sh"                      "[RO]"      "Three-tier filesystem hash baseline with delta report + OTS stamp"
add "$S" "imported/scripts/seccheck.sh"              "[RO]"      "Posture audit: SIP, DNS, firewalls, listeners, launchd, LS rules, certs"
add "$S" "imported/scripts/mac_harden_rescan.sh"     "[RO,SUDO]" "Daily audit: SIP, FileVault, firewall, persistence, kexts, sudoers, profiles"
add "$S" "scripts/verify.sh"                         "[RO,SUDO]" "Drift audit: binary hashes, listeners, disabled services, firewall, TCC"
add "$S" "imported/scripts/dump-connections.sh"      "[RO,SUDO]" "Dump all network connections, netstat, nettop, LS logs to a file"
add "$S" "scan-2026-05-21/hunt-osascript-parent.sh"  "[RO,SUDO]" "Trace parent processes of osascript executions for 120 seconds"

# ─── LITTLE SNITCH ───────────────────────────────────────────────────────────
S="LITTLE SNITCH"
add "$S" "ls-domain-audit.py"                                  "[RO]"       "Audit LS model for suspicious domains, dead rules, unsigned vias"
add "$S" "ls-permissive-analysis.py"                           "[RO]"       "Rank LS allow rules by permissiveness, flag unsigned anomalies"
add "$S" "ls-full-analysis.py"                                 "[RO]"       "Audit LS rule export for missing critical deny rules and drift"
add "$S" "scan-2026-08-10/ls-rules-deep-audit.py"              "[RO]"       "Offline deep analysis of an exported LS rule model"
add "$S" "ls-dedup.py"                                         "[MOD]"      "Deduplicate LS rules by functional fingerprint, merge use counts"
add "$S" "ls-tighten-all.py"                                   "[MOD]"      "Tighten LS model JSON: add denies, drop stale/unused allows"
add "$S" "ls-apply-tightening.sh"                              "[MOD,SUDO]" "Export live model, dedup+tighten offline, import after typing APPLY (--dry-run for report only)"
add "$S" "scan-2026-05-25/export-littlesnitch.sh"              "[RO,SUDO]"  "Export LS rules to JSON and normalize permissions"
add "$S" "evw-ls-watchdog.sh"                                  "[SVC,SUDO]" "LS rule-hygiene loop: deletes forged/permissive allows, tightens ports"
add "$S" "evw-ls-watchdog-monitor.sh"                          "[SVC,SUDO]" "Alert if the LS watchdog heartbeat goes stale"
add "$S" "evw-ls-watchdog-setup.sh"                            "[SVC,SUDO]" "Install LS watchdog + monitor as LaunchDaemons"
add "$S" "run-with-ls-silent.sh"                               "[MOD,SUDO,ARGS]" "Run a wrapped command while LS is temporarily silent-allow"

# ─── HARDENING & LOCKDOWN ────────────────────────────────────────────────────
S="HARDENING & LOCKDOWN"
add "$S" "harden.sh"                                   "[MOD,SUDO]" "Comprehensive hardening: sharing off, firewall on, telemetry stripped"
add "$S" "harden-now.sh"                               "[MOD,SUDO]" "One-shot: pin DNS (CF/Google/Quad9), firewall prune, auto-updates, ARD/netbiosd/AirDrop off"
add "$S" "lock-remote-access.sh"                       "[MOD,SUDO]" "Audit and disable every remote-access/sharing service, idempotent"
add "$S" "restore-hardening-2026-06-12.sh"             "[MOD,SUDO]" "Re-apply 11 launchd disables for remote-mgmt daemons, relock plist (schg)"
add "$S" "scan-2026-05-19/harden.sh"                   "[MOD,SUDO]" "Block-all firewall, Bluetooth off, AWDL-down watcher, service shutdown"
add "$S" "scan-2026-05-19/audit-and-cutoff.sh"         "[MOD,SUDO]" "Audit remote-access avenues (TCC, sudoers, hooks), then disable them"
add "$S" "imported/scripts/hardening.sh"               "[MOD,SUDO]" "pmset, TouchID-sudo, login-window, ClamAV/OSSEC/BSM-audit tweaks"
add "$S" "imported/sec/hardening.sh"                   "[MOD,SUDO]" "One-time fixes: firewall exceptions, SMB guest, remote services, kext removal"
add "$S" "imported/sec/lockdown.sh"                    "[MOD,SUDO]" "Idempotent lockdown enforcement, re-applied at boot via LaunchDaemon"
add "$S" "imported/sec/pending-privileged.sh"          "[MOD,SUDO]" "Run the queued, user-reviewed sudo settings (firewall, FV key, Gatekeeper)"
add "$S" "imported/scripts/macharden_tahoe26.py"       "[MOD,SUDO]" "Interactive Tahoe hardening suite + hardened Kodachi VM provisioning"
add "$S" "imported/scripts/install_daily_harden.sh"    "[SVC,SUDO]" "Register mac_harden_rescan.sh as a daily 9AM root LaunchDaemon"
add "$S" "imported/sec/setup.sh"                       "[MOD]"      "Fresh-install bootstrap: CLT, Homebrew, hardened Postgres, sentinel agents"

# ─── MONITORING & GUARDS ─────────────────────────────────────────────────────
S="MONITORING & GUARDS"
add "$S" "evw-plist-monitor.sh"                        "[SVC,DAEMON,SUDO]" "Log every filesystem event touching disabled.501.plist, with snapshots"
add "$S" "evw-replayd-guard.sh"                        "[SVC,DAEMON,SUDO]" "Kill replayd on sight after logging parent chain, lsof, TCC grants"
add "$S" "evw-audit-monitor.py"                        "[SVC,DAEMON,SUDO]" "Real-time alerts on suspicious exec args / URL opens (unified log + BSM)"
add "$S" "evw-dns-guard.sh"                            "[SVC,SUDO]" "Re-pin DNS servers on all network services when drift detected"
add "$S" "evw-dns-guard-setup.sh"                      "[SVC,SUDO]" "Install DNS-pinning guard as a root LaunchDaemon (every 5 min)"
add "$S" "evw-studentd-guard.sh"                       "[SVC,DAEMON,SUDO]" "Kill studentd every 5 min (airportd EXCLUDED — killing it drops Wi-Fi)"
add "$S" "scripts/evw-file-vault.py"                   "[SVC,DAEMON,SUDO]" "Versioned snapshots of security-critical files; every change reversible"
add "$S" "scripts/vault-restore.sh"                    "[MOD,SUDO]"  "Restore any watched file to a previous vaulted version"
add "$S" "scripts/tm-restore.sh"                       "[MOD,SUDO]"  "Restore folders from Time Machine backup with full permissions (offline, resumable)"
add "$S" "scripts/evw-auto-conn-guard.py"              "[SVC,DAEMON,SUDO]" "[AUTO-EVW] Score outbound conns; auto kill+1h-block on high score; fully undoable"
add "$S" "scripts/evw-auto-undo.sh"                    "[MOD,SUDO]"  "[AUTO-EVW] Undo any auto-guard action by id, or flush all auto blocks"
add "$S" "scripts/ls-hygiene.py"                       "[MOD,SUDO]"  "[AUTO-EVW-LS] Audit+clean Little Snitch rules (tracker allows, OCSP/DHCP-killing denies) with backup+undo"
add "$S" "scripts/evw-ls-hygiene-guard.sh"             "[SVC,DAEMON,SUDO]" "[AUTO-EVW-LS] LS rule hygiene every 5 min, persistent (backup+undo always)"
# DISABLED 2026-09-01: comms-guard caused recurring ~100s Wi-Fi outages — killing
# bluetoothd flaps the shared Wi-Fi/BT radio. Evidence: /Users/evw/dev/fix/netdiag/STATE.md
# add "$S" "evw-comms-guard.sh"                        "[SVC,DAEMON,SUDO]" "DISABLED — caused Wi-Fi outages; do not run"
# add "$S" "evw-comms-setup.sh"                        "[SVC,SUDO]" "DISABLED — caused Wi-Fi outages; do not run"
add "$S" "install-all.sh"                              "[SVC,SUDO]" "One-pass installer deploying all guard daemons to /usr/local/bin" "--yes"
add "$S" "imported/scripts/binding-monitor.sh"         "[SVC,SUDO]" "Detect processes listening on 0.0.0.0, alert, optionally terminate"
add "$S" "imported/scripts/config-sentinel.sh"         "[RO]"       "SHA-256 baseline monitor of credentials/config/persistence files, alerts"
add "$S" "imported/scripts/file-sentinel.py"           "[SVC,DAEMON,SUDO]" "Real-time kqueue file-change monitor for sensitive directories"
add "$S" "imported/scripts/mac-sentinel-install.sh"    "[SVC,SUDO]" "Lynis hardening + install mac-sentinel root monitor (corrected Lynis syntax; cleans old aliases)"
add "$S" "imported/scripts/setup-audit.sh"             "[MOD,SUDO]" "Enable macOS BSM auditing with file-change tracking for this user"
add "$S" "imported/sec/secdash.py"                     "[SVC,DAEMON]" "Loopback-only security dashboard (HTTP + SQLite): posture, alerts, control"

# ─── NETWORK & PRIVACY ───────────────────────────────────────────────────────
S="NETWORK & PRIVACY"
add "$S" "imported/scripts/rotate_hostname.sh"         "[MOD,SUDO]" "Rotate hostname to a random plausible device name"
add "$S" "imported/scripts/rotate_mac.sh"              "[MOD,SUDO]" "Rotate WiFi interface MAC to a random locally-administered address"
add "$S" "imported/scripts/setup-pf.sh"                "[MOD,SUDO]" "Install PF anchor blocking external inbound to dev ports"

# ─── INCIDENT RESPONSE (May 2026 studentd / RemoteManagement) ───────────────
S="INCIDENT RESPONSE ONE-OFFS"
add "$S" "scan-2026-05-21/fix-studentd-final.sh"       "[MOD,SUDO]" "Disable studentd via correct label, remove KeepAlive trigger"
add "$S" "scan-2026-05-21/disable-remotemgmt.sh"       "[MOD,SUDO]" "Bootout + disable RemoteManagement, Screen Sharing, Remote Desktop"
add "$S" "scan-2026-05-21/kill-remotemgmt.sh"          "[MOD,SUDO]" "Force-kill RemoteManagement processes, observe launchd respawn"

# ─── UTILITIES & FORENSICS ───────────────────────────────────────────────────
S="UTILITIES & FORENSICS"
add "$S" "preserve-recording.sh"                       "[MOD]"      "Hash and encrypt a forensic screen recording to an external drive"
add "$S" "package-and-encrypt.sh"                      "[RO]"       "Bundle hardening scripts into an AES-256 encrypted tarball"
add "$S" "imported/scripts/keychain-authorize.sh"      "[MOD]"      "Grant Apple-signed binaries silent read of migrated Keychain items"
add "$S" "imported/scripts/migrate-to-keychain.sh"     "[MOD]"      "Move ~/.credentials .env secrets into Keychain, shred plaintext originals"
add "$S" "security-memory-manager.py"                  "[MOD]"      "Encrypted, HMAC-chained local storage for security scan state"

N=${#PTH[@]}

# ─── presentation ────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then B=$'\e[1m'; D=$'\e[2m'; R=$'\e[0m'; Y=$'\e[33m'; G=$'\e[32m'; else B=""; D=""; R=""; Y=""; G=""; fi

checked_count() {
  local i c=0
  for ((i=0; i<N; i++)); do [[ "${CHK[$i]}" -eq 1 ]] && c=$((c+1)); done
  printf '%d' "$c"
}

print_menu() {
  local cur="" i t cb lr
  printf '\n%s== MASTER SECURITY MENU ==%s  (%d scripts, %s%d checked%s, folder: %s, daemons: %s)\n' \
    "$B" "$R" "$N" "$G" "$(checked_count)" "$R" "$PWD" \
    "$([[ "$DAEMON_BG" -eq 1 ]] && printf 'background' || printf 'smoke %ss' "${MENU_DAEMON_TIMEOUT:-60}")"
  for ((i=0; i<N; i++)); do
    if [[ "${SEC[$i]}" != "$cur" ]]; then cur="${SEC[$i]}"; printf '\n%s-- %s --%s\n' "$B" "$cur" "$R"; fi
    t="${TAG[$i]}"
    case "$t" in *MOD*|*SVC*) t="${Y}${t}${R}";; esac
    if [[ "${CHK[$i]}" -eq 1 ]]; then cb="${G}[x]${R}"; else cb="[ ]"; fi
    lr="$(last_run "${PTH[$i]}")"
    printf '%s %3d) %-7s %-42s %s%-16s%s %s\n' \
      "$cb" "$((i+1))" "$t" "${PTH[$i]}" "$D" "${lr:-never}" "$R" "${D}${DSC[$i]}${R}"
  done
  printf '\nDate column: last successful run (DD/MM/YYYY HH:MM; never = none recorded).'
  printf '\n"b" daemon mode: %s (smoke-run vs background-and-continue).' \
    "$([[ "$DAEMON_BG" -eq 1 ]] && printf 'background' || printf 'smoke')"
  printf '\nToggle checkboxes: numbers/ranges (e.g. "1 4 7-9"), "a" all, "c" clear.'
  printf '\nRun: "r" run checked, "!1 3 8" run now, "l" relist, "q" quit.\n'
}

# Snapshot of the environment, written to the log header and to the failure
# diagnostics block. All read-only commands; keep it cheap and secret-free.
log_system_context() {
  printf 'date:    %s\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')"
  printf 'user:    %s (euid %s)\n' "$(id -un)" "$EUID"
  printf 'host:    %s\n' "$(hostname)"
  printf 'cwd:     %s\n' "$PWD"
  printf 'macos:   %s (%s)\n' "$(sw_vers -productVersion 2>/dev/null)" "$(sw_vers -buildVersion 2>/dev/null)"
  printf 'kernel:  %s\n' "$(uname -srm)"
  printf 'bash:    %s\n' "$BASH_VERSION"
  printf 'python3: %s\n' "$(python3 --version 2>&1)"
  printf 'dns:     %s\n' "$(scutil --dns 2>/dev/null | awk '/nameserver\[[0-9]+\]/{print $3}' | sort -u | tr '\n' ' ')"
}

FAIL_LIST=()
BG_LIST=()

# run_timed <seconds> <cmd...> — run cmd with a hard ceiling. Returns the
# command's own exit status, or 124 when OUR watcher had to kill it (an
# externally SIGTERM'd command returns 143 instead, so the two differ).
# `set -m` puts the command in its own process group so the watcher kills
# the whole tree — otherwise an orphaned `sleep` child would hold the tee
# pipe open and stall the batch after the kill.
run_timed() {
  local secs="$1"; shift
  local flag; flag="$(mktemp -t menu-timeout.XXXXXX)"; rm -f "$flag"
  set -m
  "$@" &
  local pid=$!
  ( sleep "$secs" && kill -TERM -- "-$pid" 2>/dev/null && : > "$flag" ) >/dev/null 2>&1 &
  local watcher=$!
  wait "$pid" 2>/dev/null
  local rc=$?
  kill "$watcher" 2>/dev/null
  wait "$watcher" 2>/dev/null
  set +m
  if [ -f "$flag" ]; then rm -f "$flag"; return 124; fi
  rm -f "$flag"
  return "$rc"
}

run_one() {
  local i="$1" p="${PTH[$1]}" extra="" st t0 l0 l1 elev=""
  if [[ ! -f "$p" ]]; then
    printf 'MISSING: %s\n' "$p"
    printf '\n>>> [%d] %s\n    MISSING FILE (cwd: %s)\n' "$((i+1))" "$p" "$PWD" >> "$LOG"
    FAIL_LIST+=("[$((i+1))] $p — missing file (exit 127)")
    return 127
  fi
  if [[ "${TAG[$i]}" == *ARGS* ]]; then
    printf 'Arguments for %s (blank for none): ' "$p"; read -r extra
  else
    extra="${PRE[$i]}"
  fi
  l0=$(( $(wc -l < "$LOG" 2>/dev/null) + 1 ))
  t0=$SECONDS
  printf '\n%s>>> [%d] %s%s\n' "$B" "$((i+1))" "$p" "$R"
  {
    printf '\n>>> [%d] %s\n' "$((i+1))" "$p"
    printf '    desc: %s\n' "${DSC[$i]}"
    printf '    tags: %s | args: %s | euid: %s\n' "${TAG[$i]}" "${extra:-none}" "$EUID"
    printf '    started: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
  } >> "$LOG"
  if [[ "${TAG[$i]}" == *SUDO* && "$EUID" -ne 0 ]]; then
    if [[ "${SUDO_FAILED:-0}" -eq 1 ]]; then
      printf '%s    needs root — skipping (sudo previously failed)%s\n' "$Y" "$R"
      printf '    needs root — skipping (sudo previously failed)\n' >> "$LOG"
      FAIL_LIST+=("[$((i+1))] $p — skipped: sudo previously failed")
      return 1
    fi
    printf '%s    needs root — elevating via sudo%s\n' "$Y" "$R"
    printf '    needs root — elevating via sudo\n' >> "$LOG"
    if sudo -v; then
      elev="sudo"
    else
      SUDO_FAILED=1
      printf '%s    sudo authentication failed — skipping this and later SUDO scripts%s\n' "$Y" "$R"
      printf '    sudo authentication failed — skipping this and later SUDO scripts\n' >> "$LOG"
      FAIL_LIST+=("[$((i+1))] $p — sudo authentication failed")
      return 1
    fi
  fi
  local tlim="${MENU_TIMEOUT:-900}"
  if [[ "${TAG[$i]}" == *DAEMON* && "$DAEMON_BG" -eq 1 ]]; then
    # Background mode: detach the daemon and continue to the next script.
    local base dlog bgpid existing
    base="$(basename "$p")"
    existing="$(pgrep -f "$base" 2>/dev/null | tr '\n' ' ')"
    if [ -n "$existing" ]; then
      printf '%s    already running (PID %s) — not starting a duplicate%s\n' "$Y" "$existing" "$R"
      printf '    already running (PID %s) — not starting a duplicate\n' "$existing" >> "$LOG"
      st=0
    else
      dlog="logs/daemon-${base%.*}-$(date +%Y%m%d-%H%M%S).log"
      case "$p" in
        *.py) nohup $elev python3 "$p" $extra >> "$dlog" 2>&1 < /dev/null & ;;
        *)    nohup $elev bash    "$p" $extra >> "$dlog" 2>&1 < /dev/null & ;;
      esac
      bgpid=$!
      disown 2>/dev/null || true
      sleep 1
      if kill -0 "$bgpid" 2>/dev/null; then
        printf '%s    started in background (PID %d) — continuing to next script%s\n' "$G" "$bgpid" "$R"
        printf '    output: %s (stop: %skill %d)\n' "$PWD/$dlog" "${elev:+$elev }" "$bgpid"
        printf '    started in background (PID %d); output: %s\n' "$bgpid" "$PWD/$dlog" >> "$LOG"
        BG_LIST+=("[$((i+1))] $p — background PID $bgpid")
        st=0
      else
        printf '%s    background start failed — output: %s%s\n' "$Y" "$PWD/$dlog" "$R"
        { printf '    background start failed; output tail:\n'; tail -n 5 "$dlog"; } >> "$LOG"
        st=1
      fi
    fi
  elif [[ "${TAG[$i]}" == *DAEMON* ]]; then
    tlim="${MENU_DAEMON_TIMEOUT:-60}"
    # Foreground daemons never exit by design: bounded smoke run, no guard
    # wrapper (a full-window run ends in our own timeout kill, not a failure).
    case "$p" in
      *.py) run_timed "$tlim" $elev python3 "$p" $extra 2>&1 | tee -a "$LOG"; st=${PIPESTATUS[0]} ;;
      *)    run_timed "$tlim" $elev bash    "$p" $extra 2>&1 | tee -a "$LOG"; st=${PIPESTATUS[0]} ;;
    esac
  else
    case "$p" in
      *.py) guard_run "script:$p" run_timed "$tlim" $elev python3 "$p" $extra 2>&1 | tee -a "$LOG"; st=${PIPESTATUS[0]} ;;
      *)    guard_run "script:$p" run_timed "$tlim" $elev bash    "$p" $extra 2>&1 | tee -a "$LOG"; st=${PIPESTATUS[0]} ;;
    esac
  fi
  if [[ "$st" -eq 124 && "${TAG[$i]}" == *DAEMON* ]]; then
    printf '%s    daemon: ran the full %ds window, then stopped (long-running by design)%s\n' "$G" "$tlim" "$R"
    printf '    daemon: ran the full %ds window, then stopped — long-running by design (install its *-setup.sh entry for permanent operation)\n' "$tlim" >> "$LOG"
    st=0
  elif [[ "$st" -eq 124 ]]; then
    printf '%s    TIMEOUT: killed after %ds (override with MENU_TIMEOUT)%s\n' "$Y" "$tlim" "$R"
    printf '    TIMEOUT: killed after %ds\n' "$tlim" >> "$LOG"
  fi
  # Outcome banner: brief success statement, or a brief error excerpt pulled
  # from this script's section of the log file, plus the log's name and path.
  # On a terminal it stays up 5s, then the batch continues (no pause w/o TTY).
  local dur=$((SECONDS-t0)) excerpt=""
  if [[ "$st" -ne 0 ]]; then
    excerpt="$(tail -n 3 "$LOG" 2>/dev/null | sed 's/^/      /')"
  fi
  printf '%s<<< [%d] exit %d after %ds%s\n' "$B" "$((i+1))" "$st" "$dur" "$R"
  printf '<<< [%d] exit %d after %ds\n' "$((i+1))" "$st" "$dur" >> "$LOG"
  if [[ "$st" -ne 0 ]]; then
    {
      printf '    --- failure diagnostics: [%d] %s exited %d after %ds ---\n' "$((i+1))" "$p" "$st" "$dur"
      log_system_context
      printf '    --- end diagnostics ---\n'
    } >> "$LOG"
    l1=$(( $(wc -l < "$LOG" 2>/dev/null) + 0 ))
    FAIL_LIST+=("[$((i+1))] $p — exit $st after ${dur}s (log lines $l0-$l1)")
  fi
  if [[ "$st" -eq 0 ]]; then
    printf '%s    OK: %s succeeded (%ds)%s\n' "$G" "$p" "$dur" "$R"
    record_success "$p"
  else
    printf '%s    FAILED: %s (exit %d, %ds) — last log lines:%s\n' "$Y" "$p" "$st" "$dur" "$R"
    printf '%s\n' "$excerpt"
  fi
  printf '    log: %s — %s/%s\n' "$(basename "$LOG")" "$PWD" "$LOG"
  [[ -t 1 ]] && sleep 5
  return "$st"
}

expand_selection() {
  local tok a b out=()
  for tok in ${1//,/ }; do
    if [[ "$tok" =~ ^([0-9]+)-([0-9]+)$ ]]; then
      a=${BASH_REMATCH[1]}; b=${BASH_REMATCH[2]}
      for ((; a<=b; a++)); do out+=("$a"); done
    elif [[ "$tok" =~ ^[0-9]+$ ]]; then
      out+=("$tok")
    else
      printf 'Ignoring invalid token: %s\n' "$tok" >&2
    fi
  done
  printf '%s\n' "${out[@]}"
}

needs_confirm() { [[ "${TAG[$1]}" == *MOD* || "${TAG[$1]}" == *SVC* || "${TAG[$1]}" == *ARGS* ]]; }

# Shared runner: takes 0-based indices, confirms if risky, runs in numeric order.
run_batch() {
  local idxs=("$@") i f risky=0 fails=0 t0
  [[ ${#idxs[@]} -eq 0 ]] && { printf 'Nothing to run.\n'; return 0; }
  for i in "${idxs[@]}"; do needs_confirm "$i" && risky=1; done
  printf '\nWill run %d script(s):\n' "${#idxs[@]}"
  for i in "${idxs[@]}"; do printf '  %s %s\n' "${TAG[$i]}" "${PTH[$i]}"; done
  if [[ "$risky" -eq 1 && "$ASSUME_YES" -eq 0 ]]; then
    printf '%sSelection includes scripts that MODIFY the system or install daemons.%s Proceed? [y/N] ' "$Y" "$R"
    read -r ok; [[ "$ok" =~ ^[yY]$ ]] || { printf 'Cancelled.\n'; return 1; }
  fi
  LOG="logs/menu-$(date +%Y%m%d-%H%M%S).log"
  FAIL_LIST=()
  BG_LIST=()
  t0=$SECONDS
  {
    printf '========================================================================\n'
    printf 'security-menu.sh batch log\n'
    log_system_context
    printf 'queued:  %d script(s)\n' "${#idxs[@]}"
    for i in "${idxs[@]}"; do printf '  [%d] %s %s\n' "$((i+1))" "${TAG[$i]}" "${PTH[$i]}"; done
    printf '========================================================================\n'
  } >> "$LOG"
  for i in "${idxs[@]}"; do guard_run "run_one" run_one "$i" || fails=$((fails+1)); done
  {
    printf '\n========================================================================\n'
    printf 'batch summary — %d succeeded, %d failed, %ds total\n' "$((${#idxs[@]}-fails))" "$fails" "$((SECONDS-t0))"
    if [[ "$fails" -gt 0 ]]; then
      printf 'failures:\n'
      for f in "${FAIL_LIST[@]}"; do printf '  %s\n' "$f"; done
    fi
    if [[ "${#BG_LIST[@]}" -gt 0 ]]; then
      printf 'background daemons left running (stop with sudo pkill -f <name>):\n'
      for f in "${BG_LIST[@]}"; do printf '  %s\n' "$f"; done
    fi
  } | tee -a "$LOG"
  printf '\nDone. %d succeeded, %d failed. Log: %s\n' "$((${#idxs[@]}-fails))" "$fails" "$LOG"
  if [[ "$fails" -gt 0 ]]; then
    printf '%sFailed entries (log sections listed above — open the log at those lines):%s\n' "$Y" "$R"
    for f in "${FAIL_LIST[@]}"; do printf '  %s%s%s\n' "$Y" "$f" "$R"; done
  fi
  return "$fails"
}

# Toggle checkboxes from a selection string like "1 4 7-9".
toggle_selection() {
  local n i toggled=0
  while read -r n; do
    if [[ "$n" =~ ^[0-9]+$ && "$n" -ge 1 && "$n" -le "$N" ]]; then
      i=$((n-1))
      if [[ "${CHK[$i]}" -eq 1 ]]; then CHK[$i]=0; else CHK[$i]=1; fi
      toggled=$((toggled+1))
    else
      printf 'Out of range: %s\n' "$n"
    fi
  done < <(expand_selection "$1" | sort -nu)
  printf '%d checkbox(es) toggled, %d now checked.\n' "$toggled" "$(checked_count)"
}

toggle_all() {
  local i target=1
  [[ "$(checked_count)" -eq "$N" ]] && target=0
  for ((i=0; i<N; i++)); do CHK[$i]=$target; done
  [[ "$target" -eq 1 ]] && printf 'All %d checked.\n' "$N" || printf 'All cleared.\n'
}

run_checked() {
  local idxs=() i
  for ((i=0; i<N; i++)); do [[ "${CHK[$i]}" -eq 1 ]] && idxs+=("$i"); done
  if [[ ${#idxs[@]} -eq 0 ]]; then
    printf 'No scripts checked — toggle checkboxes with numbers first, then "r".\n'
    return 0
  fi
  run_batch "${idxs[@]}"
}

run_immediate() {
  local idxs=() n
  while read -r n; do
    [[ "$n" =~ ^[0-9]+$ && "$n" -ge 1 && "$n" -le "$N" ]] && idxs+=("$((n-1))") || printf 'Out of range: %s\n' "$n"
  done < <(expand_selection "$1" | sort -nu)
  [[ ${#idxs[@]} -eq 0 ]] && { printf 'Nothing to run.\n'; return 0; }
  run_batch "${idxs[@]}"
}

interactive() {
  print_menu
  while true; do
    printf '\n> '; read -r sel || { printf '\n'; return 0; }
    case "$sel" in
      q|Q|quit|exit) return 0 ;;
      l|L) print_menu ;;
      a|A) toggle_all; print_menu ;;
      b|B) DAEMON_BG=$((1-DAEMON_BG))
           printf 'Daemon mode: %s.\n' "$([[ "$DAEMON_BG" -eq 1 ]] && printf 'background (daemons detach, batch continues)' || printf 'smoke-run (60s window)')"
           print_menu ;;
      c|C) for ((i=0; i<N; i++)); do CHK[$i]=0; done; printf 'All checkboxes cleared.\n'; print_menu ;;
      r|R|run) run_checked; print_menu ;;
      "!"*)  run_immediate "${sel#!}"; print_menu ;;
      "")    : ;;
      *)     toggle_selection "$sel"; print_menu ;;
    esac
  done
}

do_list() { print_menu; }

do_check() {
  local i bad=0
  for ((i=0; i<N; i++)); do
    local p="${PTH[$i]}"
    if [[ ! -f "$p" ]]; then printf 'MISSING   %s\n' "$p"; bad=$((bad+1)); continue; fi
    case "$p" in
      *.py) python3 -c 'import ast,sys; ast.parse(open(sys.argv[1]).read())' "$p" 2>/dev/null \
              && printf 'OK        %s\n' "$p" || { printf 'PY-ERROR  %s\n' "$p"; bad=$((bad+1)); } ;;
      *)    bash -n "$p" 2>/dev/null \
              && printf 'OK        %s\n' "$p" || { printf 'SH-ERROR  %s\n' "$p"; bad=$((bad+1)); } ;;
    esac
  done
  printf '\n%d entries, %d problems.\n' "$N" "$bad"
  return "$bad"
}

case "${1:-}" in
  --list)  do_list ;;
  --check) do_check ;;
  --json)  do_json ;;
  --run)   shift
           list="${1:?usage: security-menu.sh --run 1,3,5-8 [--yes] [--bg]}"
           shift
           for a in "$@"; do
             case "$a" in
               --yes) ASSUME_YES=1 ;;
               --bg)  DAEMON_BG=1 ;;
             esac
           done
           run_immediate "$list" ;;
  -h|--help) sed -n '2,23p' "$0" ;;
  "")      interactive ;;
  *)       printf 'Unknown option: %s (try --help)\n' "$1" >&2; exit 2 ;;
esac
