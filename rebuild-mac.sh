#!/usr/bin/env bash
# =============================================================================
# rebuild-mac.sh — rebuild THIS Mac from ground zero to its captured state.
#
# On a fresh, unconfigured macOS (same admin user 'evw'):
#
#   1. Get this repo onto the machine (Passport copy, or:
#      git clone git@github.com:evweath/sec.git ~/dev/security)
#   2. bash ~/dev/security/rebuild-mac.sh                 (core, ~15–25 min)
#      bash ~/dev/security/rebuild-mac.sh --full-apps     (+ Homebrew/apps)
#      bash ~/dev/security/rebuild-mac.sh --source /Volumes/Passport/sec
#
# Then complete the printed manual checklist (≈5 min of GUI clicks).
#
# Phases:
#   0 preflight      — user/sudo/network/repo sanity
#   1 prerequisites  — Xcode CLT + Homebrew (if missing)
#   2 toolkit        — repo at ~/dev/security
#   3 apps           — (--full-apps) brew bundle + Little Snitch cask
#   4 littlesnitch   — license restore + rule-model restore
#   5 security stack — install-all.sh + security-system/audit setups + harden-now
#   6 posture        — disabled.501.plist+schg, BT/pmset/lock/mDNS/AirDrop/UC/
#                      SSH, /etc/hosts, HighPoint kext purge
#   7 user agents    — ~/Library/LaunchAgents from state
#   8 verify         — daemon registration + LS sanity + manual checklist
#
# Idempotent: every step checks before acting; safe to re-run after a failure.
# =============================================================================

set -uo pipefail

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error-guard.sh)
_eg_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
while [ "$_eg_d" != "/" ] && [ ! -f "$_eg_d/lib/error-guard.sh" ]; do _eg_d="$(dirname "$_eg_d")"; done
[ -f "$_eg_d/lib/error-guard.sh" ] && . "$_eg_d/lib/error-guard.sh"; unset _eg_d
command -v guard_run >/dev/null 2>&1 || guard_run() { shift; "$@"; }

SEC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="$HOME/dev/security"
STATE="$TARGET_DIR/rebuild/state"
LSAPP="/Applications/Little Snitch.app"
LSCLI="$LSAPP/Contents/Components/littlesnitch"
FULL_APPS=0
SOURCE_DIR=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --full-apps) FULL_APPS=1; shift ;;
        --source) SOURCE_DIR="${2:-}"; shift 2 ;;
        *) shift ;;
    esac
done

LOGD="$SEC_DIR/rebuild/logs"; mkdir -p "$LOGD"
LOG="$LOGD/rebuild-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG") 2>&1

step() { echo ""; echo "════════════════ $(date +%H:%M:%S) $*"; }
ok()   { echo "[✓] $*"; }
warn() { echo "[!] $*"; }
die()  { echo "[✗] $*" >&2; exit 1; }
MANUAL=()   # manual checklist entries
add_manual() { MANUAL+=("$1"); }

# ── 0. Preflight ──────────────────────────────────────────────────────────────
step "0/8 preflight"
[[ "$(id -un)" == "evw" ]] || warn "expected user 'evw', got '$(id -un)' — paths assume evw"
sudo -v || die "sudo required"
( while true; do sudo -n true; sleep 60; done ) & SUDO_KEEPER=$!
trap 'kill $SUDO_KEEPER 2>/dev/null' EXIT
ping -c1 -t3 github.com >/dev/null 2>&1 && ok "network up" || warn "no network — install phases will fail; posture phases still work"

# ── 1. Prerequisites: CLT + Homebrew ─────────────────────────────────────────
step "1/8 prerequisites"
if xcode-select -p >/dev/null 2>&1; then
    ok "Xcode CLT present"
else
    warn "Xcode CLT missing — launching installer (GUI dialog may appear)"
    xcode-select --install 2>/dev/null || true
    add_manual "Finish the Xcode CLT installer dialog, then re-run rebuild-mac.sh"
fi
if [[ -x /opt/homebrew/bin/brew ]]; then
    ok "Homebrew present"
    eval "$(/opt/homebrew/bin/brew shellenv)"
else
    if [[ $FULL_APPS -eq 1 ]]; then
        warn "installing Homebrew…"
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" || \
            add_manual "Install Homebrew (brew.sh), then re-run with --full-apps"
        [[ -x /opt/homebrew/bin/brew ]] && eval "$(/opt/homebrew/bin/brew shellenv)"
    else
        warn "Homebrew missing (fine for core rebuild; use --full-apps to install)"
    fi
fi

# ── 2. Toolkit repo at ~/dev/security ─────────────────────────────────────────
step "2/8 toolkit"
if [[ "$SEC_DIR" != "$TARGET_DIR" ]]; then
    if [[ -d "$TARGET_DIR/.git" ]]; then
        ok "repo already at $TARGET_DIR (leaving as-is)"
    else
        info_m="installing toolkit to $TARGET_DIR"
        echo "[*] $info_m"
        mkdir -p "$TARGET_DIR"
        if [[ -n "$SOURCE_DIR" && -d "$SOURCE_DIR" ]]; then
            guard_run "rsync-source" rsync -a --exclude .git "$SOURCE_DIR/" "$TARGET_DIR/"
        elif [[ -d "$SEC_DIR/.git" || -f "$SEC_DIR/install-all.sh" ]]; then
            guard_run "rsync-self" rsync -a --exclude .git "$SEC_DIR/" "$TARGET_DIR/"
        else
            guard_run "git-clone" git clone git@github.com:evweath/sec.git "$TARGET_DIR" || \
                guard_run "git-clone-https" git clone https://github.com/evweath/sec.git "$TARGET_DIR" || \
                die "cannot obtain toolkit repo (use --source <path>)"
        fi
        ok "toolkit at $TARGET_DIR"
    fi
else
    ok "running from $TARGET_DIR"
fi
[[ -f "$TARGET_DIR/install-all.sh" ]] || die "toolkit incomplete at $TARGET_DIR"
[[ -d "$STATE" ]] || warn "no rebuild/state/ — run rebuild/capture-state.sh on the old machine first; using seeded defaults"

# ── 3. Apps (--full-apps) ─────────────────────────────────────────────────────
step "3/8 apps"
if [[ $FULL_APPS -eq 1 && -x /opt/homebrew/bin/brew && -f "$STATE/Brewfile" ]]; then
    guard_run "brew-bundle" /opt/homebrew/bin/brew bundle --file "$STATE/Brewfile" && \
        ok "Brewfile installed" || warn "brew bundle had failures (see log)"
    [[ -d "$LSAPP" ]] || guard_run "ls-cask" /opt/homebrew/bin/brew install --cask little-snitch || true
else
    echo "    (skipped — core rebuild; re-run with --full-apps for Homebrew/apps)"
fi

# ── 4. Little Snitch: license + rule model ────────────────────────────────────
step "4/8 little snitch"
if [[ -d "$LSAPP" ]]; then
    ok "Little Snitch installed"
    if [[ -f "$STATE/ls-registration.xpl" ]]; then
        guard_run "ls-reg-restore" sudo install -m 600 -o root -g wheel "$STATE/ls-registration.xpl" \
            "/Library/Application Support/Objective Development/Little Snitch/registration.xpl" && \
            ok "license restored" || warn "license restore failed"
    fi
    if [[ -f "$STATE/ls-model.json" && -x "$LSCLI" ]]; then
        if guard_run "ls-model-restore" sudo "$LSCLI" restore-model "$STATE/ls-model.json"; then
            ok "rule model restored ($(python3 -c "import json;print(len(json.load(open('$STATE/ls-model.json'))['rules']))" 2>/dev/null || echo '?') rules)"
        else
            warn "model restore failed — LS daemon may need first-launch/sysexp approval"
            add_manual "Little Snitch: approve the network extension, open the app once, then:
       sudo \"$LSCLI\" restore-model \"$STATE/ls-model.json\""
        fi
    fi
else
    warn "Little Snitch not installed"
    add_manual "Install Little Snitch (obdev.at or: brew install --cask little-snitch), approve the
       network extension, then: sudo \"$LSCLI\" restore-model \"$STATE/ls-model.json\""
fi

# ── 5. Security stack (delegates to the toolkit's own installers) ─────────────
step "5/8 security stack"
guard_run "install-all"    sudo bash "$TARGET_DIR/install-all.sh" --yes            || warn "install-all.sh had failures"
guard_run "sec-sys-setup"  sudo bash "$TARGET_DIR/evw-security-system-setup.sh"    || warn "security-system setup had failures"
guard_run "sec-audit"      sudo bash "$TARGET_DIR/evw-security-audit-setup.sh"     || warn "security-audit setup had failures"
guard_run "harden-now"     sudo bash "$TARGET_DIR/harden-now.sh"                   || warn "harden-now.sh had failures"
ok "security stack installed (see warnings above if any)"

# ── 6. Posture (explicit, idempotent) ─────────────────────────────────────────
step "6/8 posture"
DP=/var/db/com.apple.xpc.launchd/disabled.501.plist
if [[ -f "$STATE/disabled-501-entries.txt" ]]; then
    sudo chflags noschg "$DP" 2>/dev/null || true
    n=0
    while IFS= read -r label; do
        [[ -n "$label" ]] || continue
        if ! sudo /usr/libexec/PlistBuddy -c "Print :$label" "$DP" >/dev/null 2>&1; then
            guard_run "dp-add" sudo /usr/libexec/PlistBuddy -c "Add :$label bool true" "$DP" && n=$((n+1))
        fi
    done < "$STATE/disabled-501-entries.txt"
    sudo chflags schg "$DP" && ok "disabled.501.plist: entries ensured (+$n new), schg re-applied"
fi
guard_run "bt-off"        sudo defaults write /Library/Preferences/com.apple.bluetooth ControllerPowerState -int 0
guard_run "pmset"         sudo pmset -a womp 0 powernap 0
guard_run "pw-immediate"  defaults -currentHost write com.apple.screensaver askForPassword -int 1
guard_run "pw-delay"      defaults -currentHost write com.apple.screensaver askForPasswordDelay -int 0
guard_run "mdns-quiet"    sudo defaults write /Library/Preferences/com.apple.mDNSResponder NoMulticastAdvertisements -bool true
guard_run "airdrop-off"   sudo defaults write /Library/Preferences/com.apple.NetworkBrowser DisableAirDrop -bool true
ifconfig awdl0 down 2>/dev/null || true
guard_run "uc-off"        defaults write com.apple.universalcontrol Enabled -bool false
guard_run "handoff-off"   defaults write com.apple.coreservices.useractivityd ActivityAdvertisingAllowed -bool false
defaults write com.apple.coreservices.useractivityd ActivityReceivingAllowed -bool false
guard_run "remote-login"  sudo systemsetup -setremotelogin Off 2>/dev/null || true
[[ -f /etc/ssh/sshd_config ]] && guard_run "sshd-perms" sudo chmod 600 /etc/ssh/sshd_config
if [[ -f "$STATE/etc/hosts" ]]; then
    guard_run "hosts" sudo install -m 644 -o root -g wheel "$STATE/etc/hosts" /etc/hosts && ok "/etc/hosts restored"
fi
guard_run "highpoint-purge" sudo rm -rf /Library/Extensions/HighPointIOP.kext /Library/Extensions/HighPointRR.kext 2>/dev/null || true
[[ -d "$STATE/etc/pf.anchors" ]] && \
    guard_run "pf-anchors" sudo cp "$STATE/etc/pf.anchors/"com.ew.* /etc/pf.anchors/ 2>/dev/null || true
ok "posture applied (BT off, WoL/PowerNap off, immediate lock, mDNS quiet, AirDrop/UC/Handoff off, SSH off, hosts, kext purge)"

# ── 7. User LaunchAgents ──────────────────────────────────────────────────────
step "7/8 user agents"
mkdir -p "$HOME/Library/LaunchAgents"
n=0
for p in "$STATE/launchagents/"*.plist; do
    [[ -f "$p" ]] || continue
    base="$(basename "$p")"
    cp "$p" "$HOME/Library/LaunchAgents/$base"
    launchctl bootout "gui/$(id -u)/${base%.plist}" 2>/dev/null || true
    guard_run "agent-load" launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/$base" && n=$((n+1))
done
ok "user LaunchAgents: $n loaded"

# ── 8. Verify + manual checklist ──────────────────────────────────────────────
step "8/8 verify"
fails=0
for label in com.evw.plist-monitor com.evw.replayd-guard com.evw.audit-monitor \
             com.ew.file-sentinel com.ew.binding-monitor com.evw.dns-guard \
             com.ew.pf-devports com.evw.security-system; do
    if sudo launchctl print "system/$label" >/dev/null 2>&1; then
        ok "daemon up: $label"
    else
        warn "daemon NOT up: $label"; fails=$((fails+1))
    fi
done
if [[ -x "$LSCLI" ]]; then
    if sudo "$LSCLI" export-model /tmp/ls-rebuild-check.json 2>/dev/null; then
        cnt=$(python3 -c "import json;print(len(json.load(open('/tmp/ls-rebuild-check.json'))['rules']))" 2>/dev/null || echo 0)
        ok "Little Snitch: $cnt rules live"; rm -f /tmp/ls-rebuild-check.json
    fi
fi
echo ""
if [[ $fails -eq 0 ]]; then ok "VERIFY: all core daemons registered"; else warn "VERIFY: $fails daemon(s) missing — see above"; fi

{
    echo "════════════════ MANUAL CHECKLIST (cannot be scripted) ════════════════"
    cat << 'EOF'
 1. Little Snitch: System Settings → General → Login Items & Extensions →
    Network Extensions → approve Obdev; open Little Snitch once (license
    auto-restored if state/ls-registration.xpl was present; else enter it)
 2. Re-run after LS is live:  sudo bash ~/dev/security/rebuild-mac.sh
    (idempotent — will restore the rule model and re-verify)
 3. TCC: approve notification/access prompts from evw daemons as they appear
 4. GitHub: add this Mac's SSH key at github.com/settings/keys (git push/pull)
 5. Touch ID: re-enroll (System Settings → Touch ID & Password)
 6. Memory: restore *.csmem from Passport via security-memory-manager.py
 7. OTS: reinstall opentimestamps-client (pipx install opentimestamps-client)
    for L5 Bitcoin anchoring
 8. Do NOT sign into iCloud / FaceTime / Messages / Private Relay
    (verified clean state 2026-09-03 — the retry storms are unsigned-daemon noise)
 9. Reboot once, then confirm: bash ~/dev/security/scripts/verify.sh
10. Refresh state for next time: sudo bash ~/dev/security/rebuild/capture-state.sh
EOF
    for m in "${MANUAL[@]:-}"; do [[ -n "$m" ]] && echo " - $m"; done
} | tee "$TARGET_DIR/rebuild/LAST-RUN-MANUAL-STEPS.txt"

echo ""
ok "rebuild core complete — log: $LOG"
echo "    manual steps: $TARGET_DIR/rebuild/LAST-RUN-MANUAL-STEPS.txt"
