#!/usr/bin/env bash
# =============================================================================
# rebuild-mac-v2.sh — capture and rebuild the complete current security stack.
#
# Capture current machine:
#   sudo bash /Users/evw/dev/security/rebuild-mac-v2.sh --capture --yes
#
# Rebuild a fresh macOS install:
#   bash /Users/evw/dev/security/rebuild-mac-v2.sh --yes
#
# Options:
#   --capture       refresh rebuild/state-v2 from this machine
#   --source PATH   copy the toolkit from PATH instead of cloning GitHub
#   --state PATH    use an alternate captured-state directory
#   --core          skip Homebrew bundle/app installation
#   --dry-run       print planned actions without changing the system
#   --yes           do not ask before replacing an existing state-v2 directory
#
# The rebuild path intentionally does not use Time Machine. GitHub is only a
# source for reviewed, repository-tracked code. Local-only secrets and ignored
# security artifacts must come from the encrypted/offline preservation bundle.
# =============================================================================

set -uo pipefail

SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)/$(basename "${BASH_SOURCE[0]}")"
REPO_DIR="$(dirname "$SCRIPT_PATH")"
TARGET_DIR="$HOME/dev/security"
STATE="$TARGET_DIR/rebuild/state-v2"
SOURCE_DIR=""
MODE="rebuild"
FULL_APPS=1
DRY_RUN=0
ASSUME_YES=0
FAILURES=0
MANUAL=()

usage() {
    sed -n '1,28p' "$SCRIPT_PATH"
}

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*"; }
ok() { log "[ok] $*"; }
warn() { log "[!] $*"; }
fail() { log "[FAIL] $*"; FAILURES=$((FAILURES + 1)); }
step() { printf '\n=== %s ===\n' "$*"; }
manual() { MANUAL+=("$1"); }

run() {
    if [[ $DRY_RUN -eq 1 ]]; then
        printf 'DRY-RUN:'
        printf ' %q' "$@"
        printf '\n'
        return 0
    fi
    "$@"
}

try() {
    local label="$1"
    shift
    if [[ $DRY_RUN -eq 1 ]]; then
        run "$@"
        log "[plan] $label"
        return 0
    fi
    if run "$@"; then
        ok "$label"
    else
        fail "$label failed: $*"
    fi
}

add_failure_trap() {
    FAILURES=$((FAILURES + 1))
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --capture) MODE="capture"; shift ;;
        --source) SOURCE_DIR="${2:-}"; shift 2 ;;
        --state) STATE="${2:-}"; shift 2 ;;
        --core) FULL_APPS=0; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        --yes) ASSUME_YES=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) warn "ignoring unknown option: $1"; shift ;;
    esac
done

LOG_DIR="$REPO_DIR/rebuild/logs"
mkdir -p "$LOG_DIR"
LOG="$LOG_DIR/rebuild-v2-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG") 2>&1

require_user() {
    if [[ "$(id -un)" != "evw" ]]; then
        warn "this rebuild assumes user 'evw'; current user is $(id -un)"
        manual "Review every /Users/evw path and LaunchAgent before continuing as $(id -un)."
    fi
}

require_sudo() {
    [[ $DRY_RUN -eq 1 ]] && return 0
    sudo -v || { log "sudo is required"; exit 1; }
    (while true; do sudo -n true; sleep 60; done) &
    SUDO_KEEPER=$!
    trap 'kill "$SUDO_KEEPER" 2>/dev/null || true' EXIT
}

copy_file() {
    local src="$1" dst="$2" mode="${3:-644}"
    [[ -f "$src" ]] || return 1
    if [[ $DRY_RUN -eq 1 ]]; then
        printf 'DRY-RUN: copy %q -> %q (mode %s)\n' "$src" "$dst" "$mode"
        return 0
    fi
    mkdir -p "$(dirname "$dst")"
    cp "$src" "$dst"
    chmod "$mode" "$dst"
}

capture() {
    step "capture: preflight"
    require_user
    require_sudo
    if [[ $DRY_RUN -eq 1 ]]; then
        log "dry-run: would refresh $STATE from the current machine"
        return 0
    fi
    [[ -x /opt/homebrew/bin/brew ]] || warn "Homebrew missing; Brewfile will be absent"

    if [[ -d "$STATE" ]]; then
        if [[ $ASSUME_YES -ne 1 ]]; then
            read -r -p "Replace existing $STATE? Type REPLACE: " answer
            [[ "$answer" == "REPLACE" ]] || { log "capture cancelled"; exit 1; }
        fi
        local previous="$STATE.previous-$(date +%Y%m%d-%H%M%S)"
        run mv "$STATE" "$previous"
        warn "previous state moved to $previous"
    fi
    run mkdir -p \
        "$STATE/launchagents" \
        "$STATE/launchdaemons" \
        "$STATE/etc/pf.anchors" \
        "$STATE/colima" \
        "$STATE/security" \
        "$STATE/inventory"

    step "capture: Little Snitch"
    local lscli="/Applications/Little Snitch.app/Contents/Components/littlesnitch"
    if [[ -x "$lscli" ]]; then
        try "Little Snitch model export" sudo "$lscli" export-model "$STATE/ls-model.json"
        [[ -f "$STATE/ls-model.json" ]] && run chmod 644 "$STATE/ls-model.json"
        local lsreg="/Library/Application Support/Objective Development/Little Snitch/registration.xpl"
        if sudo test -f "$lsreg"; then
            try "Little Snitch registration capture" sudo cp "$lsreg" "$STATE/ls-registration.xpl"
            run sudo chown "$(id -u):$(id -g)" "$STATE/ls-registration.xpl" 2>/dev/null || true
            run chmod 600 "$STATE/ls-registration.xpl"
            warn "ls-registration.xpl is sensitive; keep state-v2 offline and never commit it"
        else
            warn "Little Snitch registration not found"
        fi
    else
        warn "Little Snitch CLI missing"
    fi

    step "capture: Homebrew and applications"
    if [[ -x /opt/homebrew/bin/brew ]]; then
        # Homebrew refuses to run as root; drop to the invoking user.
        local brew_user="${SUDO_USER:-$(id -un)}"
        if [[ "$(id -un)" == "root" && "$brew_user" != "root" ]]; then
            local brewtmp
            brewtmp="$(mktemp /tmp/Brewfile.XXXXXX)"
            chown "$brew_user" "$brewtmp"
            try "Brewfile capture" sudo -u "$brew_user" /opt/homebrew/bin/brew bundle dump --force --file "$brewtmp"
            [[ -s "$brewtmp" ]] && run mv "$brewtmp" "$STATE/Brewfile"
            run sudo -u "$brew_user" /opt/homebrew/bin/brew leaves > "$STATE/brew-leaves.txt"
            run sudo -u "$brew_user" /opt/homebrew/bin/brew list --cask > "$STATE/brew-casks.txt"
        else
            try "Brewfile capture" /opt/homebrew/bin/brew bundle dump --force --file "$STATE/Brewfile"
            run /opt/homebrew/bin/brew leaves > "$STATE/brew-leaves.txt"
            run /opt/homebrew/bin/brew list --cask > "$STATE/brew-casks.txt"
        fi
    fi
    run ls /Applications > "$STATE/apps.txt"

    step "capture: launchd state"
    run sh -c 'for p in "$HOME"/Library/LaunchAgents/*.plist; do [ -f "$p" ] && cp "$p" "$1/"; done' _ "$STATE/launchagents"
    run sh -c 'for p in /Library/LaunchDaemons/*.plist; do case "$(basename "$p")" in com.apple.*) ;; *) [ -f "$p" ] && cp "$p" "$1/" ;; esac; done' _ "$STATE/launchdaemons"
    run launchctl list > "$STATE/inventory/launchctl-user.txt"
    run sudo launchctl print-disabled system > "$STATE/inventory/launchd-disabled-system.txt"
    run sudo plutil -p /var/db/com.apple.xpc.launchd/disabled.501.plist > "$STATE/inventory/disabled-501.plist.txt" 2>/dev/null || true

    step "capture: network and security configuration"
    [[ -f /etc/hosts ]] && copy_file /etc/hosts "$STATE/etc/hosts"
    run sh -c 'for p in /etc/pf.anchors/com.ew.*; do [ -f "$p" ] && cp "$p" "$1/"; done' _ "$STATE/etc/pf.anchors"
    copy_file "$REPO_DIR/security-system.json" "$STATE/security/security-system.json"
    run systemextensionsctl list > "$STATE/inventory/systemextensions.txt"
    run networksetup -listallnetworkservices > "$STATE/inventory/network-services.txt"
    run scutil --dns > "$STATE/inventory/dns.txt"
    run ps -axo pid,ppid,user,command > "$STATE/inventory/processes.txt"
    run lsof -nP -iTCP -sTCP:LISTEN > "$STATE/inventory/listeners.txt" 2>/dev/null || true

    step "capture: Colima and Wazuh structure"
    copy_file "$HOME/.colima/default/colima.yaml" "$STATE/colima/colima.yaml"
    copy_file "$HOME/.colima/_lima/colima/override.yaml" "$STATE/colima/override.yaml"
    copy_file "$HOME/.colima/_lima/_config/networks.yaml" "$STATE/colima/networks.yaml"
    if [[ -d "$REPO_DIR/wazuh-stack" ]]; then
        run sh -c 'cd "$1" && shasum -a 256 docker-compose.yml generate-indexer-certs.yml config/wazuh_cluster/wazuh_manager.conf config/wazuh_indexer/wazuh.indexer.yml config/wazuh_dashboard/wazuh.yml 2>/dev/null' _ "$REPO_DIR/wazuh-stack" > "$STATE/security/wazuh-stack.sha256"
        warn "Wazuh compose/credential/certificate contents are not copied into state-v2; preserve them in the encrypted offline bundle"
    fi
    if pkgutil --pkg-info com.wazuh.pkg.wazuh-agent >/dev/null 2>&1; then
        run sh -c 'pkgutil --pkg-info com.wazuh.pkg.wazuh-agent' > "$STATE/inventory/wazuh-agent.txt"
    fi

    step "capture: git and recovery metadata"
    if [[ -d "$REPO_DIR/.git" ]]; then
        run git -C "$REPO_DIR" status --short --branch > "$STATE/inventory/git-status.txt"
        run git -C "$REPO_DIR" log -10 --oneline --decorate > "$STATE/inventory/git-log.txt"
        run git -C "$REPO_DIR" remote -v > "$STATE/inventory/git-remotes.txt"
    fi
    run gh auth status > "$STATE/inventory/gh-auth.txt" 2>&1 || true

    cat > "$STATE/README.txt" <<EOF2
Captured: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Machine: $(scutil --get LocalHostName 2>/dev/null || hostname)
macOS: $(sw_vers -productVersion 2>/dev/null) ($(sw_vers -buildVersion 2>/dev/null))

state-v2 is for rebuilding this machine. Keep it offline. It may contain the
Little Snitch registration file; never commit that file or upload it.
EOF2

    step "capture: manifest"
    run sh -c 'cd "$1" && find . -type f ! -name MANIFEST.sha256 -print | LC_ALL=C sort | while IFS= read -r f; do shasum -a 256 "$f"; done > MANIFEST.sha256' _ "$STATE"
    ok "state captured to $STATE"
}

install_homebrew() {
    step "1/12 prerequisites"
    if ! xcode-select -p >/dev/null 2>&1; then
        warn "Xcode Command Line Tools missing; launching installer"
        run xcode-select --install || true
        manual "Finish the Xcode CLT installer, then re-run rebuild-mac-v2.sh."
    else
        ok "Xcode CLT present"
    fi
    if [[ ! -x /opt/homebrew/bin/brew ]]; then
        warn "Homebrew missing; installing"
        if [[ $DRY_RUN -eq 1 ]]; then
            log "dry-run: would download and run the Homebrew installer"
        else
            run /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        fi
    fi
    [[ -x /opt/homebrew/bin/brew ]] && eval "$(/opt/homebrew/bin/brew shellenv)"
}

install_apps() {
    step "2/12 applications"
    [[ $FULL_APPS -eq 1 ]] || { warn "application phase skipped by --core"; return; }
    if [[ -f "$STATE/Brewfile" && -x /opt/homebrew/bin/brew ]]; then
        try "Homebrew bundle" /opt/homebrew/bin/brew bundle --file "$STATE/Brewfile"
    else
        warn "no state Brewfile or Homebrew unavailable"
    fi
    manual "Install or verify non-bundle apps if needed: Xcode, Kimi, PrettySwift for Xcode, Developer, and any App Store apps."
}

restore_littlesnitch() {
    step "3/12 Little Snitch"
    local lsapp="/Applications/Little Snitch.app"
    local lscli="$lsapp/Contents/Components/littlesnitch"
    if [[ ! -d "$lsapp" ]]; then
        warn "Little Snitch is not installed"
        manual "Install Little Snitch, approve its network extension, then rerun this script."
        return
    fi
    if [[ -f "$STATE/ls-registration.xpl" ]]; then
        try "Little Snitch registration" sudo install -m 600 -o root -g wheel "$STATE/ls-registration.xpl" "/Library/Application Support/Objective Development/Little Snitch/registration.xpl"
    fi
    if [[ -f "$STATE/ls-model.json" && -x "$lscli" ]]; then
        if ! run sudo "$lscli" restore-model "$STATE/ls-model.json"; then
            warn "Little Snitch model restore failed until the extension is approved"
            manual "Approve Little Snitch Network Extension, open the app once, then run: sudo '$lscli' restore-model '$STATE/ls-model.json'"
        fi
    fi
}

install_security_stack() {
    step "4/12 core security stack"
    try "install-all" sudo bash "$TARGET_DIR/install-all.sh" --yes
    try "security-system setup" sudo bash "$TARGET_DIR/evw-security-system-setup.sh"
    try "security-audit setup" sudo bash "$TARGET_DIR/evw-security-audit-setup.sh"
    try "integrity setup" sudo bash "$TARGET_DIR/evw-integrity-setup.sh"
    try "LS watchdog setup" sudo bash "$TARGET_DIR/evw-ls-watchdog-setup.sh"
    try "LS hourly cleanup setup" sudo bash "$TARGET_DIR/evw-ls-hourly-cleanup-setup.sh"
    try "harden-now" sudo bash "$TARGET_DIR/harden-now.sh"
}

install_optional_daemon() {
    local label="$1" source_path="$2" dest_name="${3:-$(basename "$2")}"
    local plist="$STATE/launchdaemons/$label.plist"
    [[ -f "$plist" ]] || return 0
    if [[ $DRY_RUN -eq 1 ]]; then
        log "dry-run: would ensure system/$label is registered"
    elif sudo launchctl print "system/$label" >/dev/null 2>&1; then
        ok "$label already registered"
        return 0
    fi
    if [[ ! -f "$source_path" ]]; then
        warn "$label source missing: $source_path"
        return 0
    fi
    case "$source_path" in
        /usr/*|/bin/*|/sbin/*) ;;
        *) try "install $label program" sudo install -m 755 -o root -g wheel "$source_path" "/usr/local/bin/$dest_name" ;;
    esac
    try "install $label plist" sudo install -m 644 -o root -g wheel "$plist" "/Library/LaunchDaemons/$label.plist"
    run sudo launchctl bootout system "/Library/LaunchDaemons/$label.plist" 2>/dev/null || true
    try "bootstrap $label" sudo launchctl bootstrap system "/Library/LaunchDaemons/$label.plist"
}

restore_extra_daemons() {
    step "5/12 captured specialist daemons"
    install_optional_daemon com.evw.auto-conn-guard "$TARGET_DIR/scripts/evw-auto-conn-guard.py"
    install_optional_daemon com.evw.file-vault "$TARGET_DIR/scripts/evw-file-vault.py"
    install_optional_daemon com.evw.ls-hygiene-guard "$TARGET_DIR/scripts/evw-ls-hygiene-guard.sh"
    install_optional_daemon com.evw.studentd-guard "$TARGET_DIR/evw-studentd-guard.sh"
    install_optional_daemon com.ew.lockdown "$TARGET_DIR/sec/lockdown.sh" evw-lockdown.sh
    install_optional_daemon local.security.harden "$TARGET_DIR/scripts/mac_harden_rescan.sh"
    install_optional_daemon com.evw.plist-eslogger /usr/bin/eslogger
    install_optional_daemon local.awdl-down /sbin/ifconfig
}

restore_user_agents() {
    step "6/12 user LaunchAgents"
    run mkdir -p "$HOME/Library/LaunchAgents"
    local count=0 plist base
    for plist in "$STATE/launchagents"/*.plist; do
        [[ -f "$plist" ]] || continue
        base="$(basename "$plist")"
        run cp "$plist" "$HOME/Library/LaunchAgents/$base"
        run launchctl bootout "gui/$(id -u)/${base%.plist}" 2>/dev/null || true
        if run launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/$base"; then
            count=$((count + 1))
        else
            fail "user agent failed: $base"
        fi
    done
    ok "user LaunchAgents loaded: $count"
}

restore_colima() {
    step "7/12 Colima"
    command -v colima >/dev/null 2>&1 || { warn "colima missing"; return; }
    run mkdir -p "$HOME/.colima/default" "$HOME/.colima/_lima/colima" "$HOME/.colima/_lima/_config"
    [[ -f "$STATE/colima/colima.yaml" ]] && copy_file "$STATE/colima/colima.yaml" "$HOME/.colima/default/colima.yaml"
    [[ -f "$STATE/colima/override.yaml" ]] && copy_file "$STATE/colima/override.yaml" "$HOME/.colima/_lima/colima/override.yaml"
    [[ -f "$STATE/colima/networks.yaml" ]] && copy_file "$STATE/colima/networks.yaml" "$HOME/.colima/_lima/_config/networks.yaml"
    run colima stop >/dev/null 2>&1 || true
    try "colima start" colima start
    try "colima status" colima status
}

restore_wazuh() {
    step "8/12 Wazuh"
    command -v docker >/dev/null 2>&1 || { warn "docker missing"; return; }
    try "local Wazuh manager setup" bash "$TARGET_DIR/evw-wazuh-local-manager.sh" setup
    if pkgutil --pkg-info com.wazuh.pkg.wazuh-agent >/dev/null 2>&1; then
        try "Wazuh agent setup" sudo bash "$TARGET_DIR/evw-wazuh-setup.sh" 127.0.0.1
    else
        warn "Wazuh agent package missing"
        manual "Install the signed Wazuh agent package matching the captured version, then run: sudo bash $TARGET_DIR/evw-wazuh-setup.sh 127.0.0.1"
    fi
}

restore_postgres() {
    step "9/12 PostgreSQL"
    if [[ -x /opt/homebrew/opt/postgresql@16/bin/postgres ]]; then
        try "PostgreSQL service" /opt/homebrew/bin/brew services start postgresql@16
    else
        warn "postgresql@16 missing"
    fi
}

initialize_integrity() {
    step "10/12 integrity baseline and backup verification"
    try "integrity full scan" sudo /usr/local/bin/evw-integrity.py full --tiers A,B,C,D
    try "integrity verify" sudo /usr/local/bin/evw-integrity.py verify --sample 5000
    try "backup check" sudo /usr/local/bin/evw-backup-check.py --report "$TARGET_DIR/scan-$(date +%F)/backup-check.txt"
}

final_audit() {
    step "11/12 full audit"
    if [[ $DRY_RUN -eq 1 ]]; then
        log "dry-run: would run security audit and capture launchctl/listener reports"
        return 0
    fi
    try "security audit" sudo bash /usr/local/bin/evw-security-audit.sh --auto
    run launchctl list > "$TARGET_DIR/rebuild/logs/rebuild-v2-final-launchctl-user.txt"
    run sudo launchctl list > "$TARGET_DIR/rebuild/logs/rebuild-v2-final-launchctl-system.txt" 2>/dev/null || true
    run sudo lsof -nP -iTCP -sTCP:LISTEN > "$TARGET_DIR/rebuild/logs/rebuild-v2-final-listeners.txt"
}

print_manual_steps() {
    step "12/12 manual steps"
    cat <<EOF2
1. Approve the Little Snitch network extension if macOS asks.
2. Re-run this script after approving Little Snitch if model restore failed.
3. Re-enroll Touch ID.
4. Run gh auth login, then test GitHub access with: gh auth status
5. Restore credentials/secrets only from the encrypted offline preservation bundle.
6. Do not sign in to iCloud, FaceTime, Messages, or Private Relay unless deliberately re-enabling them.
7. Reboot, then run: sudo bash /usr/local/bin/evw-security-audit.sh --auto
8. Review the newest scan directory, especially integrity-full.txt, backup-check.txt, network-state.txt, and ls-full-analysis.txt.
9. To recover a tracked deleted file, dry-run first:
   sudo /usr/local/bin/evw-rollback.py restore --source github --repo-root /Users/evw/dev/security --paths /Users/evw/dev/security/PATH --dry-run
EOF2
    local item
    for item in "${MANUAL[@]:-}"; do [[ -n "$item" ]] && printf ' - %s\n' "$item"; done
}

rebuild() {
    step "0/12 preflight"
    require_user
    require_sudo
    if [[ $DRY_RUN -eq 0 && $ASSUME_YES -ne 1 ]]; then
        read -r -p "This will install services and restore captured state. Type REBUILD: " answer
        [[ "$answer" == "REBUILD" ]] || { log "rebuild cancelled"; exit 1; }
    fi
    [[ -d "$TARGET_DIR" ]] || die_missing_repo
    [[ -d "$STATE" ]] || { log "missing state: $STATE"; exit 1; }
    ok "state: $STATE"
    install_homebrew
    install_apps
    restore_littlesnitch
    install_security_stack
    restore_extra_daemons
    restore_user_agents
    restore_colima
    restore_wazuh
    restore_postgres
    initialize_integrity
    final_audit
    print_manual_steps
    if [[ $FAILURES -eq 0 ]]; then
        ok "rebuild-v2 completed with no failed scripted phases"
    else
        warn "rebuild-v2 completed with $FAILURES failed phase(s); inspect $LOG"
    fi
}

die_missing_repo() {
    log "toolkit repo is missing at $TARGET_DIR"
    if [[ -n "$SOURCE_DIR" && -d "$SOURCE_DIR" ]]; then
        run mkdir -p "$TARGET_DIR"
        run rsync -a --exclude .git "$SOURCE_DIR/" "$TARGET_DIR/"
        ok "copied toolkit from $SOURCE_DIR"
    else
        log "restore from offline copy first, or use: gh repo clone evweath/sec '$TARGET_DIR'"
        exit 1
    fi
}

case "$MODE" in
    capture) capture ;;
    rebuild) rebuild ;;
    *) log "unknown mode: $MODE"; exit 64 ;;
esac

log "log: $LOG"
exit "$FAILURES"
