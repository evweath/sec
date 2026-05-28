#!/usr/bin/env bash
# harden.sh — macOS hardening for high-threat-model use
#
# Threat model: persistent, well-resourced adversary.
# Honest caveat: a script cannot defend you against a true APT. The single
# biggest win on macOS for this threat model is Apple's Lockdown Mode
# (System Settings → Privacy & Security → Lockdown Mode). Toggle it before
# trusting anything below. Tor Browser (cask installed here) is the right
# tool for anonymous browsing — the tor daemon installed below only gives
# you a SOCKS proxy, NOT anonymity for arbitrary apps.
#
# What this script does:
#   • Pre-flight audit (FileVault, SIP, Gatekeeper, open ports, XProtect)
#   • Disables every Sharing service (SSH, ARD, SMB, AFP, printer, Bluetooth)
#   • Enables Application Firewall + stealth + logging
#   • Strips telemetry / diagnostic submission / personalized ads
#   • Spotlight & Safari privacy defaults
#   • Login window: no guest, no autologin, hide last user, lock on sleep
#   • Forces all auto-update channels ON
#   • Switches DNS to Quad9 (DNSSEC-validating) on every active service
#   • Installs: lynis, nmap, gpg, ykman, clamav, tor, dnscrypt-proxy
#   • Installs (cask): tor-browser, signal, santa, little-snitch
#   • Installs Wazuh agent (OSSEC's actively-maintained successor)
#   • Starts tor daemon (SOCKS on 127.0.0.1:9050) — see caveat above
#   • Updates ClamAV signatures (freshclam)
#   • Runs Lynis audit at the end and saves a report
#
# What this script will NOT do (you must do manually):
#   • Enable Lockdown Mode (GUI only)
#   • Turn on FileVault (GUI / recovery-key flow)
#   • Approve Santa system extension (GUI)
#   • Configure YubiKey enrollment per account
#
# Run:   chmod +x harden.sh && ./harden.sh
# Log:   ~/security-hardening-YYYYMMDD-HHMMSS.log

set -uo pipefail

# ────────────────────────────────────────────────────────────────────────────
# Setup
# ────────────────────────────────────────────────────────────────────────────
LOG="$HOME/security-hardening-$(date +%Y%m%d-%H%M%S).log"
touch "$LOG"; chmod 600 "$LOG"
exec > >(tee -a "$LOG") 2>&1

RED=$'\033[0;31m'; GRN=$'\033[0;32m'; YLW=$'\033[0;33m'; BLU=$'\033[0;34m'; NC=$'\033[0m'
log()     { printf "%s[*]%s %s\n" "$BLU" "$NC" "$*"; }
ok()      { printf "%s[+]%s %s\n" "$GRN" "$NC" "$*"; }
warn()    { printf "%s[!]%s %s\n" "$YLW" "$NC" "$*"; }
err()     { printf "%s[x]%s %s\n" "$RED" "$NC" "$*"; }
section() { printf "\n%s═══ %s ═══%s\n" "$BLU" "$*" "$NC"; }
try()     { "$@" || warn "command failed (continuing): $*"; }

# Guardrails
[[ "$(uname)" == "Darwin" ]] || { err "macOS only"; exit 1; }
[[ "$EUID" -ne 0 ]] || { err "Do NOT run as root — script will sudo where needed"; exit 1; }

# Brief abort window
cat <<EOF

${YLW}This will make significant system changes (sharing off, firewall on,
defaults rewritten, DNS changed, brew packages installed, Wazuh agent
installed). Press Ctrl-C within 10 seconds to abort.${NC}

Log: $LOG
EOF
sleep 10

# Prime sudo + keepalive
log "Priming sudo (you'll be prompted once)…"
sudo -v || { err "sudo required"; exit 1; }
( while true; do sudo -n true; sleep 50; kill -0 "$$" 2>/dev/null || exit; done ) 2>/dev/null &
SUDO_KEEPALIVE=$!
trap 'kill $SUDO_KEEPALIVE 2>/dev/null || true' EXIT

# ────────────────────────────────────────────────────────────────────────────
# 1. Pre-flight audit
# ────────────────────────────────────────────────────────────────────────────
section "1. Pre-flight audit"
log "macOS version:";     sw_vers
log "Hardware:";          system_profiler SPHardwareDataType | grep -E "(Model|Chip|Processor|Serial)" | sed 's/^/    /'
log "FileVault:";         try fdesetup status
log "SIP:";               try csrutil status
log "Gatekeeper:";        try spctl --status
log "Secure Boot (if Intel T2):"
  try /usr/libexec/remotectl dumpstate 2>/dev/null | grep -i 'secure boot' || true
log "Open listening TCP ports (before):"
sudo lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | tee "$HOME/open-ports-before.txt" || true
log "Open UDP sockets (before):"
sudo lsof -nP -iUDP 2>/dev/null | tee "$HOME/open-udp-before.txt" || true

# ────────────────────────────────────────────────────────────────────────────
# 2. Homebrew
# ────────────────────────────────────────────────────────────────────────────
section "2. Homebrew"
if ! command -v brew >/dev/null 2>&1; then
    log "Installing Homebrew…"
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    if [[ -x /opt/homebrew/bin/brew ]]; then eval "$(/opt/homebrew/bin/brew shellenv)"
    elif [[ -x /usr/local/bin/brew ]]; then eval "$(/usr/local/bin/brew shellenv)"; fi
fi
try brew update

# ────────────────────────────────────────────────────────────────────────────
# 3. Disable ALL remote-access / sharing services (comprehensive)
# ────────────────────────────────────────────────────────────────────────────
section "3. Disable remote access & sharing services"

# SSH Remote Login (-f skips the y/n prompt that otherwise hangs piped runs)
try sudo systemsetup -f -setremotelogin off

# Apple Remote Desktop (ARD)
try sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart \
    -deactivate -stop -uninstall

# Disable every known remote-access / sharing launchd unit.
# Some won't exist on this machine — launchctl disable still records the flag.
SYSTEM_LABELS=(
    com.openssh.sshd
    com.apple.screensharing
    com.apple.screensharing.agent
    com.apple.screensharing.MessagesAgent
    com.apple.screensharing.menuextra
    com.apple.RemoteDesktop.agent
    com.apple.smbd
    com.apple.AppleFileServer
    com.apple.netbiosd
    com.apple.AEServer
    com.apple.studentd
    com.apple.classroomd
    com.apple.teacherd
    com.apple.amp.mediasharingd
    com.apple.AssetCache.builtin
    com.apple.AssetCacheLocatorService
    com.apple.AssetCacheManagerService
    com.apple.AssetCacheTetheratorService
    com.apple.InternetSharing
)
for L in "${SYSTEM_LABELS[@]}"; do
    try sudo launchctl disable "system/$L"
    sudo launchctl print "system/$L" >/dev/null 2>&1 && try sudo launchctl bootout "system/$L"
done

# Printer Sharing
try cupsctl --no-share-printers
try cupsctl --no-remote-admin
try cupsctl --no-remote-any

# Internet Sharing
try sudo defaults write /Library/Preferences/SystemConfiguration/com.apple.nat NAT -dict Enabled -int 0

# Bluetooth Sharing (OBEX)
try defaults -currentHost write com.apple.Bluetooth PrefKeyServicesEnabled -bool false
try defaults write com.apple.bluetooth PrefKeyFTPServerEnabled  -bool false
try defaults write com.apple.bluetooth PrefKeyOBEXServerEnabled -bool false

# AirDrop / Handoff / Universal Clipboard / Continuity (sharingd is a user LaunchAgent)
USER_UID=$(id -u)
try launchctl disable "gui/$USER_UID/com.apple.sharingd"
try defaults write com.apple.NetworkBrowser DisableAirDrop -bool true
try defaults -currentHost write com.apple.coreservices.useractivityd ActivityAdvertisingAllowed -bool false
try defaults -currentHost write com.apple.coreservices.useractivityd ActivityReceivingAllowed  -bool false

# Quick post-disable audit
log "Remote Login (should be Off):"; try sudo systemsetup -getremotelogin
log "ARD status:";                    try sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
ok "Remote access & sharing services disabled (covers SSH, ARD, Screen Sharing, SMB, AFP,"
ok "NetBIOS, Apple Events, Classroom (studentd/classroomd/teacherd), Media Sharing,"
ok "Content Caching/AssetCache, Internet Sharing, Printer Sharing, Bluetooth Sharing,"
ok "AirDrop/Handoff/Universal Clipboard)"

# ────────────────────────────────────────────────────────────────────────────
# 4. Application firewall + stealth
# ────────────────────────────────────────────────────────────────────────────
section "4. Application firewall (alf)"
SFW=/usr/libexec/ApplicationFirewall/socketfilterfw
try sudo "$SFW" --setglobalstate on
try sudo "$SFW" --setstealthmode on
try sudo "$SFW" --setallowsigned off
try sudo "$SFW" --setallowsignedapp off
try sudo "$SFW" --setloggingmode on
try sudo "$SFW" --setloggingopt detail
ok "alf on, stealth on, signed-pass-through off, logging on"

# ────────────────────────────────────────────────────────────────────────────
# 5. Privacy / telemetry
# ────────────────────────────────────────────────────────────────────────────
section "5. Telemetry, diagnostics, ads"
DM="/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist"
try sudo defaults write "$DM" AutoSubmit            -bool false
try sudo defaults write "$DM" AutoSubmitVersion     -int 4
try sudo defaults write "$DM" ThirdPartyDataSubmit  -bool false
try sudo defaults write "$DM" ThirdPartyDataSubmitVersion -int 4
try defaults write com.apple.CrashReporter DialogType none
try defaults write com.apple.assistant.support "Siri Data Sharing Opt-In Status" -int 2
try defaults write com.apple.AdLib forceLimitAdTracking          -bool true
try defaults write com.apple.AdLib allowApplePersonalizedAdvertising -bool false
try defaults write com.apple.AdLib allowIdentifierForAdvertising -bool false
# Safari
try defaults write com.apple.Safari UniversalSearchEnabled       -bool false
try defaults write com.apple.Safari SuppressSearchSuggestions    -bool true
try defaults write com.apple.Safari SendDoNotTrackHTTPHeader     -bool true
try defaults write com.apple.Safari WebKitStorageBlockingPolicy  -int  2
try defaults write com.apple.Safari WebKitPreferences.storageBlockingPolicy -int 2
try defaults write com.apple.Safari AutoOpenSafeDownloads        -bool false
try defaults write com.apple.Safari WarnAboutFraudulentWebsites  -bool true
# Quarantine on for downloads
try defaults write com.apple.LaunchServices LSQuarantine -bool true
ok "Telemetry / ads / Safari hardened"

# ────────────────────────────────────────────────────────────────────────────
# 6. Login window + screen lock
# ────────────────────────────────────────────────────────────────────────────
section "6. Login window & screen lock"
try sudo defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled  -bool NO
try sudo defaults write /Library/Preferences/com.apple.loginwindow SHOWFULLNAME  -bool YES
try sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null
try sudo rm -f /etc/kcpassword
try defaults write com.apple.screensaver askForPassword      -int 1
try defaults write com.apple.screensaver askForPasswordDelay -int 0
# Login window banner
try sudo defaults write /Library/Preferences/com.apple.loginwindow LoginwindowText \
    "Unauthorized access prohibited. All activity is logged."
ok "Login window hardened"

# ────────────────────────────────────────────────────────────────────────────
# 7. Software updates: everything ON
# ────────────────────────────────────────────────────────────────────────────
section "7. Auto-updates"
try sudo softwareupdate --schedule on
SU=/Library/Preferences/com.apple.SoftwareUpdate
try sudo defaults write $SU AutomaticCheckEnabled            -bool true
try sudo defaults write $SU AutomaticDownload                -int  1
try sudo defaults write $SU AutomaticallyInstallMacOSUpdates -bool true
try sudo defaults write $SU CriticalUpdateInstall            -int  1
try sudo defaults write $SU ConfigDataInstall                -int  1
try sudo defaults write /Library/Preferences/com.apple.commerce AutoUpdate -bool true
ok "Auto-update fully enabled (incl. critical/XProtect data)"

# ────────────────────────────────────────────────────────────────────────────
# 8. DNS — Quad9 (DNSSEC, malware blocking)
# ────────────────────────────────────────────────────────────────────────────
section "8. DNS → Quad9"
while IFS= read -r svc; do
    [[ -n "$svc" && "$svc" != \** ]] || continue
    log "  $svc"
    try sudo networksetup -setdnsservers "$svc" 9.9.9.9 149.112.112.112 2620:fe::fe 2620:fe::9
done < <(networksetup -listallnetworkservices | tail -n +2)
try sudo dscacheutil -flushcache
try sudo killall -HUP mDNSResponder
ok "DNS hardened on all active services"

# ────────────────────────────────────────────────────────────────────────────
# 9. Security tooling (brew)
# ────────────────────────────────────────────────────────────────────────────
section "9. Install audit & defensive tooling"
try brew install lynis nmap gpg pinentry-mac ykman clamav tor dnscrypt-proxy stronghold
try brew install --cask tor-browser signal santa little-snitch
ok "Tools installed (where available)"

# ────────────────────────────────────────────────────────────────────────────
# 10. OSSEC (Wazuh agent — OSSEC's actively-maintained fork)
# ────────────────────────────────────────────────────────────────────────────
section "10. OSSEC / Wazuh agent"
# OSSEC proper no longer has a maintained macOS brew formula. Wazuh is the
# actively-developed fork and is what you actually want for a HIDS today.
ARCH=$(uname -m)
case "$ARCH" in
    arm64) WAZ_ARCH="arm64"  ;;
    x86_64) WAZ_ARCH="intel64" ;;
    *) WAZ_ARCH="" ;;
esac
if [[ -n "$WAZ_ARCH" ]]; then
    WAZ_PKG="/tmp/wazuh-agent.pkg"
    # latest 4.x release page is stable; this URL pattern is what Wazuh docs use
    if curl -fsSL "https://packages.wazuh.com/4.x/macos/" -o /tmp/wazuh-index.html 2>/dev/null; then
        WAZ_FILE=$(grep -oE "wazuh-agent-[0-9.]+-[0-9]+\.${WAZ_ARCH}\.pkg" /tmp/wazuh-index.html | sort -V | tail -1)
        if [[ -n "$WAZ_FILE" ]]; then
            log "Downloading $WAZ_FILE"
            if curl -fsSL "https://packages.wazuh.com/4.x/macos/$WAZ_FILE" -o "$WAZ_PKG"; then
                try sudo installer -pkg "$WAZ_PKG" -target /
                ok "Wazuh agent installed. Configure manager IP in /Library/Ossec/etc/ossec.conf"
            else
                warn "Wazuh agent download failed — install manually from packages.wazuh.com"
            fi
        else
            warn "Could not parse Wazuh release index — install manually from packages.wazuh.com"
        fi
    else
        warn "Could not reach packages.wazuh.com — install Wazuh agent manually"
    fi
else
    warn "Unknown CPU arch $ARCH; skipping Wazuh"
fi

# ────────────────────────────────────────────────────────────────────────────
# 11. Tor daemon (SOCKS proxy on 127.0.0.1:9050) — NOT anonymity for apps
# ────────────────────────────────────────────────────────────────────────────
section "11. Tor daemon"
warn "Reminder: this daemon ≠ anonymity. Use Tor Browser for browsing."
try brew services start tor

# ────────────────────────────────────────────────────────────────────────────
# 12. ClamAV signatures
# ────────────────────────────────────────────────────────────────────────────
section "12. ClamAV signature update"
CLAMDIR="$(brew --prefix)/etc/clamav"
if [[ -d "$CLAMDIR" ]]; then
    [[ -f "$CLAMDIR/freshclam.conf" ]] || cp "$CLAMDIR/freshclam.conf.sample" "$CLAMDIR/freshclam.conf" 2>/dev/null || true
    try sed -i '' 's/^Example/#Example/' "$CLAMDIR/freshclam.conf"
    try freshclam
fi

# ────────────────────────────────────────────────────────────────────────────
# 13. GPG agent
# ────────────────────────────────────────────────────────────────────────────
section "13. GPG"
mkdir -p "$HOME/.gnupg" && chmod 700 "$HOME/.gnupg"
if [[ ! -f "$HOME/.gnupg/gpg-agent.conf" ]]; then
    printf "default-cache-ttl 600\nmax-cache-ttl 7200\npinentry-program %s/bin/pinentry-mac\n" \
        "$(brew --prefix 2>/dev/null || echo /opt/homebrew)" > "$HOME/.gnupg/gpg-agent.conf"
fi
ok "GPG agent configured"

# ────────────────────────────────────────────────────────────────────────────
# 14. Lynis audit (baseline report)
# ────────────────────────────────────────────────────────────────────────────
section "14. Lynis audit"
LYNIS_REPORT="$HOME/lynis-report-$(date +%Y%m%d-%H%M%S).txt"
try sudo lynis audit system --quick --no-colors --logfile /tmp/lynis.log --report-file /tmp/lynis-report.dat > "$LYNIS_REPORT" 2>&1
ok "Lynis report: $LYNIS_REPORT"

# ────────────────────────────────────────────────────────────────────────────
# 15. Post-flight comparison
# ────────────────────────────────────────────────────────────────────────────
section "15. Post-flight"
log "Open listening TCP ports (after):"
sudo lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | tee "$HOME/open-ports-after.txt" || true
diff "$HOME/open-ports-before.txt" "$HOME/open-ports-after.txt" || true

# ────────────────────────────────────────────────────────────────────────────
# 16. Summary + required manual steps
# ────────────────────────────────────────────────────────────────────────────
section "Summary"
ok  "Automated hardening complete. Log: $LOG"
warn ""
warn "REQUIRED MANUAL STEPS (script cannot do these):"
warn "  1. System Settings → Privacy & Security → Lockdown Mode → ON"
warn "     (single biggest win for your threat model)"
warn "  2. System Settings → Privacy & Security → FileVault → confirm ON"
warn "  3. System Settings → Privacy & Security → approve Santa system extension"
warn "  4. Enroll YubiKey on every account that matters (Apple ID, email, GitHub, banks)"
warn "  5. Open Tor Browser at least once to seed bridges if needed"
warn "  6. Configure Wazuh manager IP in /Library/Ossec/etc/ossec.conf (or remove if unused)"
warn "  7. Configure Little Snitch rules on first launch (default-deny outbound)"
warn ""
warn "OPERATIONAL ADVICE for nation-state threat models:"
warn "  • A hardened laptop is not enough. Compartmentalize: separate device for sensitive work."
warn "  • Contact EFF, Access Now Digital Security Helpline, or Citizen Lab for tailored advice."
warn "  • Patches > HIDS against APTs. The auto-update settings above are the most useful change here."
warn "  • Review the Lynis report and act on its Suggestions section."
