#!/bin/bash
# security-menu.sh — master launcher for every security script in this folder.
# Each entry shows what the script does next to its name.
# Tags: [RO]=read-only report  [MOD]=modifies system  [SUDO]=needs root
#       [SVC]=installs/runs a daemon or long-running monitor  [ARGS]=asks for arguments
#
# Interactive usage:
#   1 4 7-9   toggle the checkbox next to those entries
#   a         check all (or uncheck all if everything is checked)
#   c         clear all checkboxes
#   r         run all checked scripts
#   !1 3 8    run these scripts immediately without touching checkboxes
#   l         relist the menu          q   quit
#
# Non-interactive usage:
#   security-menu.sh --list            print the menu and exit
#   security-menu.sh --check           verify all referenced files exist and parse
#   security-menu.sh --json            dump entries as JSON (used by security-menu-web.py)
#   security-menu.sh --run 1,3,5-8 [--yes]   run entries non-interactively (--yes skips confirm)
# Web UI: security-menu-web.py (browser checkbox interface to this menu)
# Logs: logs/menu-YYYYMMDD-HHMMSS.log — one per batch; system-context header,
#   per-script section (args, timing, exit code) and, on failure, a diagnostics
#   block so a broken script can be debugged from the log alone.

set -u
cd "$(dirname "$0")"
mkdir -p logs
ASSUME_YES=0

json_esc() { local s="$1"; s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; printf '%s' "$s"; }

do_json() {
  local i sep
  printf '[\n'
  for ((i=0; i<N; i++)); do
    sep=","; [[ "$i" -eq $((N-1)) ]] && sep=""
    printf '  {"n":%d,"section":"%s","path":"%s","tags":"%s","desc":"%s"}%s\n' \
      "$((i+1))" "$(json_esc "${SEC[$i]}")" "$(json_esc "${PTH[$i]}")" \
      "$(json_esc "${TAG[$i]}")" "$(json_esc "${DSC[$i]}")" "$sep"
  done
  printf ']\n'
}

SEC=(); PTH=(); TAG=(); DSC=(); CHK=()
add() { SEC+=("$1"); PTH+=("$2"); TAG+=("$3"); DSC+=("$4"); CHK+=(0); }
N=0

# ─── SCANS & AUDITS ──────────────────────────────────────────────────────────
S="SCANS & AUDITS"
add "$S" "tcc-audit.sh"                              "[RO,SUDO]" "Dump TCC privacy grants (screen, accessibility, camera, mic) to a dated report"
add "$S" "scan-hashes.sh"                            "[RO]"      "Snapshot key binary/config hashes with diff vs previous scan"
add "$S" "l5-full-home.sh"                           "[RO]"      "Hash home/system security files into a manifest, OTS-timestamped"
add "$S" "l5-stamp.sh"                               "[RO]"      "Weekly SHA-256 manifest of system files, OTS-stamped, git-committed"
add "$S" "build-fs-baseline.sh"                      "[RO]"      "Three-tier filesystem hash baseline with delta report + OTS stamp"
add "$S" "imported/scripts/seccheck.sh"              "[RO]"      "Posture audit: SIP, DNS, firewalls, listeners, launchd, LS rules, certs"
add "$S" "imported/scripts/mac_harden_rescan.sh"     "[RO,SUDO]" "Daily audit: SIP, FileVault, firewall, persistence, kexts, sudoers, profiles"
add "$S" "scan-2026-05-19/verify.sh"                 "[RO,SUDO]" "Drift audit: binary hashes, listeners, disabled services, firewall, TCC"
add "$S" "scan-2026-08-21/sudo-collect.sh"           "[RO,SUDO]" "Collect root-only data (LS model, TCC.db, launchd, auditd) into scan folder"
add "$S" "imported/scripts/dump-connections.sh"      "[RO,SUDO]" "Dump all network connections, netstat, nettop, LS logs to a file"
add "$S" "scan-2026-05-21/hunt-osascript-parent.sh"  "[RO,SUDO]" "Trace parent processes of osascript executions for 120 seconds"

# ─── LITTLE SNITCH ───────────────────────────────────────────────────────────
S="LITTLE SNITCH"
add "$S" "ls-domain-audit.py"                                  "[RO]"       "Audit LS model for suspicious domains, dead rules, unsigned vias"
add "$S" "ls-permissive-analysis.py"                           "[RO]"       "Rank LS allow rules by permissiveness, flag unsigned anomalies"
add "$S" "ls-full-analysis.py"                                 "[RO]"       "Audit LS rule export for missing critical deny rules and drift"
add "$S" "scan-2026-08-10/ls-rules-deep-audit.py"              "[RO]"       "Offline deep analysis of an exported LS rule model"
add "$S" "scan-2026-06-03/ls-rule-audit.py"                    "[RO,SUDO]"  "Export LS model, verify critical denies, diff vs prior baseline"
add "$S" "ls-dedup.py"                                         "[MOD]"      "Deduplicate LS rules by functional fingerprint, merge use counts"
add "$S" "ls-tighten-all.py"                                   "[MOD]"      "Tighten LS model JSON: add denies, drop stale/unused allows"
add "$S" "ls-apply-tightening.sh"                              "[MOD,SUDO]" "Export live model, dedup+tighten offline, import after typing APPLY"
add "$S" "ls-tighten-rules.sh"                                 "[MOD,SUDO]" "Delete risky LS rules; restrict host-specific allows to port 443"
add "$S" "ls-remove-terminal-any.sh"                           "[MOD,SUDO]" "Remove the overly broad Terminal-to-any LS allow rule atomically"
add "$S" "ls-add-deny-tiktok-zoho.sh"                          "[MOD,SUDO]" "Replace TikTok/Zoho allow rules with domain-level denies"
add "$S" "scan-2026-06-02/add-missing-deny-rules.py"           "[MOD,SUDO]" "Add deny-all rules for launchctl and ARDAgent kickstart"
add "$S" "scan-2026-06-02/add-influxdata-deny.py"              "[MOD,SUDO]" "Deny Terminal-to-influxdata.com (Homebrew telemetry)"
add "$S" "scan-2026-05-25/export-littlesnitch.sh"              "[RO,SUDO]"  "Export LS rules to JSON and normalize permissions (latest version)"
add "$S" "scan-2026-05-23/export-littlesnitch.sh"              "[RO,SUDO]"  "Export LS rules to JSON (2026-05-23 snapshot version)"
add "$S" "scan-2026-05-21/export-littlesnitch.sh"              "[RO,SUDO]"  "Export LS rules to JSON (2026-05-21 snapshot version)"
add "$S" "scan-2026-05-25/import-deny-rules.sh"                "[MOD,SUDO]" "Restore a merged LS rule model and verify rule count"
add "$S" "apply-ls-patch-2026-06-12.sh"                        "[MOD,SUDO]" "Import pre-patched LS model, redeploy watchdog to /usr/local/bin"
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
add "$S" "evw-plist-monitor.sh"                        "[SVC,SUDO]" "Log every filesystem event touching disabled.501.plist, with snapshots"
add "$S" "evw-replayd-guard.sh"                        "[SVC,SUDO]" "Kill replayd on sight after logging parent chain, lsof, TCC grants"
add "$S" "evw-audit-monitor.sh"                        "[SVC,SUDO]" "Tail BSM auditpipe, log alerts on suspicious exec arguments"
add "$S" "evw-audit-monitor.py"                        "[SVC,SUDO]" "Real-time alerts on suspicious exec args / URL opens (unified log + BSM)"
add "$S" "evw-dns-guard.sh"                            "[SVC,SUDO]" "Re-pin DNS servers on all network services when drift detected"
add "$S" "evw-dns-guard-setup.sh"                      "[SVC,SUDO]" "Install DNS-pinning guard as a root LaunchDaemon (every 5 min)"
add "$S" "evw-comms-guard.sh"                          "[SVC,SUDO]" "Kill Bluetooth/AirPlay/Continuity/remote-desktop daemons every 25s"
add "$S" "evw-comms-setup.sh"                          "[SVC,SUDO]" "Disable non-WiFi comm daemons and install the comms guard"
add "$S" "install-all.sh"                              "[SVC,SUDO]" "One-pass installer deploying all guard daemons to /usr/local/bin"
add "$S" "imported/scripts/binding-monitor.sh"         "[SVC,SUDO]" "Detect processes listening on 0.0.0.0, alert, optionally terminate"
add "$S" "imported/scripts/config-sentinel.sh"         "[RO]"       "SHA-256 baseline monitor of credentials/config/persistence files, alerts"
add "$S" "imported/scripts/file-sentinel.py"           "[SVC,SUDO]" "Real-time kqueue file-change monitor for sensitive directories"
add "$S" "imported/scripts/mac-sentinel-install.sh"    "[SVC,SUDO]" "Lynis hardening + install mac-sentinel root monitor (cleans old aliases)"
add "$S" "imported/scripts/mac-sentinel-install 2.sh"  "[SVC,SUDO]" "Revised mac-sentinel installer with corrected Lynis skip-test syntax"
add "$S" "imported/files/mac-sentinel-install.sh"      "[SVC,SUDO]" "WARNING: installs sentinel disguised as com.apple.thermald (audit 2026-08-26)"
add "$S" "imported/scripts/setup-audit.sh"             "[MOD,SUDO]" "Enable macOS BSM auditing with file-change tracking for this user"
add "$S" "imported/sec/secdash.py"                     "[SVC]"      "Loopback-only security dashboard (HTTP + SQLite): posture, alerts, control"

# ─── NETWORK & PRIVACY ───────────────────────────────────────────────────────
S="NETWORK & PRIVACY"
add "$S" "imported/scripts/rotate_hostname.sh"         "[MOD,SUDO]" "Rotate hostname to a random plausible device name"
add "$S" "imported/scripts/rotate_mac.sh"              "[MOD,SUDO]" "Rotate WiFi interface MAC to a random locally-administered address"
add "$S" "imported/scripts/setup-pf.sh"                "[MOD,SUDO]" "Install PF anchor blocking external inbound to dev ports"

# ─── INCIDENT RESPONSE (May 2026 studentd / RemoteManagement) ───────────────
S="INCIDENT RESPONSE ONE-OFFS"
add "$S" "scan-2026-05-21/disable-studentd.sh"         "[MOD,SUDO]" "First-pass attempt to disable studentd and classroom services"
add "$S" "scan-2026-05-21/disable-studentd-v2.sh"      "[MOD,SUDO]" "Disable studentd in the user gui launchd domain, verify no respawn"
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
  local cur="" i t cb
  printf '\n%s== MASTER SECURITY MENU ==%s  (%d scripts, %s%d checked%s, folder: %s)\n' \
    "$B" "$R" "$N" "$G" "$(checked_count)" "$R" "$PWD"
  for ((i=0; i<N; i++)); do
    if [[ "${SEC[$i]}" != "$cur" ]]; then cur="${SEC[$i]}"; printf '\n%s-- %s --%s\n' "$B" "$cur" "$R"; fi
    t="${TAG[$i]}"
    case "$t" in *MOD*|*SVC*) t="${Y}${t}${R}";; esac
    if [[ "${CHK[$i]}" -eq 1 ]]; then cb="${G}[x]${R}"; else cb="[ ]"; fi
    printf '%s %3d) %-7s %-42s %s\n' "$cb" "$((i+1))" "$t" "${PTH[$i]}" "${D}${DSC[$i]}${R}"
  done
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

run_one() {
  local i="$1" p="${PTH[$1]}" extra="" st t0 l0 l1
  if [[ ! -f "$p" ]]; then
    printf 'MISSING: %s\n' "$p"
    printf '\n>>> [%d] %s\n    MISSING FILE (cwd: %s)\n' "$((i+1))" "$p" "$PWD" >> "$LOG"
    FAIL_LIST+=("[$((i+1))] $p — missing file (exit 127)")
    return 127
  fi
  if [[ "${TAG[$i]}" == *ARGS* ]]; then
    printf 'Arguments for %s (blank for none): ' "$p"; read -r extra
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
    printf '%s    WARNING: tagged SUDO but not running as root — likely to fail%s\n' "$Y" "$R"
    printf '    WARNING: tagged SUDO but not running as root — likely to fail\n' >> "$LOG"
  fi
  case "$p" in
    *.py) python3 "$p" $extra 2>&1 | tee -a "$LOG"; st=${PIPESTATUS[0]} ;;
    *)    bash    "$p" $extra 2>&1 | tee -a "$LOG"; st=${PIPESTATUS[0]} ;;
  esac
  printf '%s<<< [%d] exit %d after %ds%s\n' "$B" "$((i+1))" "$st" "$((SECONDS-t0))" "$R"
  printf '<<< [%d] exit %d after %ds\n' "$((i+1))" "$st" "$((SECONDS-t0))" >> "$LOG"
  if [[ "$st" -ne 0 ]]; then
    {
      printf '    --- failure diagnostics: [%d] %s exited %d after %ds ---\n' "$((i+1))" "$p" "$st" "$((SECONDS-t0))"
      log_system_context
      printf '    --- end diagnostics ---\n'
    } >> "$LOG"
    l1=$(( $(wc -l < "$LOG" 2>/dev/null) + 0 ))
    FAIL_LIST+=("[$((i+1))] $p — exit $st after $((SECONDS-t0))s (log lines $l0-$l1)")
  fi
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
  t0=$SECONDS
  {
    printf '========================================================================\n'
    printf 'security-menu.sh batch log\n'
    log_system_context
    printf 'queued:  %d script(s)\n' "${#idxs[@]}"
    for i in "${idxs[@]}"; do printf '  [%d] %s %s\n' "$((i+1))" "${TAG[$i]}" "${PTH[$i]}"; done
    printf '========================================================================\n'
  } >> "$LOG"
  for i in "${idxs[@]}"; do run_one "$i" || fails=$((fails+1)); done
  {
    printf '\n========================================================================\n'
    printf 'batch summary — %d succeeded, %d failed, %ds total\n' "$((${#idxs[@]}-fails))" "$fails" "$((SECONDS-t0))"
    if [[ "$fails" -gt 0 ]]; then
      printf 'failures:\n'
      for f in "${FAIL_LIST[@]}"; do printf '  %s\n' "$f"; done
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
           list="${1:?usage: security-menu.sh --run 1,3,5-8 [--yes]}"
           [[ "${2:-}" == "--yes" ]] && ASSUME_YES=1
           run_immediate "$list" ;;
  -h|--help) sed -n '2,23p' "$0" ;;
  "")      interactive ;;
  *)       printf 'Unknown option: %s (try --help)\n' "$1" >&2; exit 2 ;;
esac
