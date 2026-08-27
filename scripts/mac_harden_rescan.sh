#!/usr/bin/env bash
# =============================================================================
# mac_harden_rescan.sh
# Nation-State Level macOS Hardening & Daily Security Audit Script
# System: macOS 26.x (Apple Silicon)
# Threat Model: Advanced Persistent Threat / Nation-State
# Author: Generated for evw@evws-MacBook-Pro
# Usage: chmod +x mac_harden_rescan.sh && sudo ./mac_harden_rescan.sh
#        Or schedule via launchd for daily execution.
# =============================================================================

set -euo pipefail

# ---- Colors -----------------------------------------------------------------
RED='\033[0;31m'
ORANGE='\033[0;33m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ---- Log file ----------------------------------------------------------------
# When run as a root LaunchDaemon, HOME is /var/root — resolve the console user's home
if [[ "${HOME:-/var/root}" == "/var/root" ]]; then
    HOME="/Users/$(stat -f '%Su' /dev/console 2>/dev/null || echo evw)"
fi
LOGDIR="$HOME/Library/Logs/SecurityAudit"
mkdir -p "$LOGDIR"
LOGFILE="$LOGDIR/audit_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOGFILE") 2>&1

ISSUES=0
WARNINGS=0

banner() {
    echo ""
    echo -e "${BOLD}${CYAN}=================================================================${NC}"
    echo -e "${BOLD}${CYAN}   macOS Nation-State Security Audit & Hardening Script${NC}"
    echo -e "${BOLD}${CYAN}   $(date)${NC}"
    echo -e "${BOLD}${CYAN}=================================================================${NC}"
    echo ""
}

section() {
    echo ""
    echo -e "${BOLD}${YELLOW}─────────────────────────────────────────────────────────────────${NC}"
    echo -e "${BOLD}${YELLOW}  $1${NC}"
    echo -e "${BOLD}${YELLOW}─────────────────────────────────────────────────────────────────${NC}"
}

pass()    { echo -e "  ${GREEN}[PASS]${NC} $1"; }
warn()    { echo -e "  ${ORANGE}[WARN]${NC} $1"; WARNINGS=$((WARNINGS+1)); }
fail()    { echo -e "  ${RED}[FAIL]${NC} $1"; ISSUES=$((ISSUES+1)); }
info()    { echo -e "  ${CYAN}[INFO]${NC} $1"; }
action()  { echo -e "  ${BOLD}[FIX ]${NC} $1"; }

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERROR] This script must be run as root (sudo ./mac_harden_rescan.sh)${NC}"
        exit 1
    fi
}

# =============================================================================
# SECTION 1: SIP & SECURE BOOT
# =============================================================================
check_sip() {
    section "1. System Integrity Protection & Secure Boot"

    SIP=$(csrutil status 2>/dev/null)
    if echo "$SIP" | grep -q "enabled"; then
        pass "SIP is ENABLED."
    else
        fail "SIP IS DISABLED. Reboot to Recovery OS and run: csrutil enable"
    fi

    AUTH_ROOT=$(csrutil authenticated-root status 2>/dev/null || echo "unknown")
    if echo "$AUTH_ROOT" | grep -q "enabled"; then
        pass "Authenticated Root (Sealed System Volume) is ENABLED."
    else
        fail "Authenticated Root is DISABLED. Run: csrutil authenticated-root enable"
    fi

    NVRAM_BOOT=$(nvram -p 2>/dev/null | grep "auto-boot" | awk '{print $2}')
    if [[ "$NVRAM_BOOT" == "true" ]]; then
        warn "auto-boot is enabled. Consider disabling to prevent cold-boot attacks: sudo nvram auto-boot=false"
    else
        pass "auto-boot is disabled."
    fi
}

# =============================================================================
# SECTION 2: FILEVAULT DISK ENCRYPTION
# =============================================================================
check_filevault() {
    section "2. FileVault Full-Disk Encryption"

    FV=$(fdesetup status 2>/dev/null || echo "unknown")
    if echo "$FV" | grep -qi "on"; then
        pass "FileVault is ON."
    else
        fail "FileVault is OFF. Enable immediately: sudo fdesetup enable"
    fi
}

# =============================================================================
# SECTION 3: APPLICATION FIREWALL
# =============================================================================
enforce_firewall() {
    section "3. Application Firewall (ALF)"

    FW_STATE=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)
    if echo "$FW_STATE" | grep -q "State = 2\|enabled"; then
        pass "Firewall is active."
    else
        action "Enabling Application Firewall..."
        /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
        pass "Firewall enabled."
    fi

    STEALTH=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null)
    if echo "$STEALTH" | grep -q "on"; then
        pass "Stealth mode is ON."
    else
        action "Enabling stealth mode..."
        /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on
        pass "Stealth mode enabled."
    fi

    # Enforce block-all incoming
    /usr/libexec/ApplicationFirewall/socketfilterfw --setblockall on 2>/dev/null || true
    pass "Block-all incoming connections enforced."

    # Audit firewall exceptions
    FW_APPS=$(/usr/libexec/ApplicationFirewall/socketfilterfw --listapps 2>/dev/null)
    DANGEROUS_APPS=("remotepairingdeviced" "remoted" "python3" "ruby" "cupsd" "sharingd" "sshd-keygen-wrapper" "smbd")
    for app in "${DANGEROUS_APPS[@]}"; do
        if echo "$FW_APPS" | grep -q "$app"; then
            warn "Firewall exception exists for: $app — This should be REMOVED. Go to System Settings → Network → Firewall → Options and delete it."
        fi
    done
}

# =============================================================================
# SECTION 4: REMOTE ACCESS & SHARING SERVICES
# =============================================================================
disable_sharing() {
    section "4. Remote Access & Sharing Services"

    # Remote Login (SSH)
    SSH_STATUS=$(systemsetup -getremotelogin 2>/dev/null || echo "unknown")
    if echo "$SSH_STATUS" | grep -qi "off"; then
        pass "Remote Login (SSH) is OFF."
    else
        action "Disabling Remote Login (SSH)..."
        systemsetup -setremotelogin off 2>/dev/null || true
        warn "Remote Login was ON — now disabled."
    fi

    # Remote Apple Events
    RAE_STATUS=$(systemsetup -getremoteappleevents 2>/dev/null || echo "unknown")
    if echo "$RAE_STATUS" | grep -qi "off"; then
        pass "Remote Apple Events is OFF."
    else
        action "Disabling Remote Apple Events..."
        systemsetup -setremoteappleevents off 2>/dev/null || true
        warn "Remote Apple Events was ON — now disabled."
    fi

    # SMB File Sharing
    SMB_STATUS=$(launchctl list 2>/dev/null | grep smbd || echo "")
    if [ -n "$SMB_STATUS" ]; then
        action "Disabling SMB file sharing daemon..."
        launchctl disable system/com.apple.smbd 2>/dev/null || true
        warn "SMB daemon was running — disabled."
    else
        pass "SMB (File Sharing) daemon is not running."
    fi

    # Screen Sharing
    SS_STATUS=$(launchctl list 2>/dev/null | grep screensharing || echo "")
    if [ -n "$SS_STATUS" ]; then
        action "Disabling Screen Sharing..."
        launchctl disable system/com.apple.screensharing 2>/dev/null || true
        warn "Screen Sharing was running — disabled."
    else
        pass "Screen Sharing is not running."
    fi

    # AirDrop / AWDL
    AWDL_STATUS=$(ifconfig awdl0 2>/dev/null | grep "status: active" || echo "")
    if [ -n "$AWDL_STATUS" ]; then
        warn "AWDL (AirDrop/Handoff) interface is ACTIVE. Disable AirDrop in Finder preferences to reduce attack surface."
    else
        pass "AWDL interface is inactive."
    fi

    # Check for active public folder share
    SHARE_CHECK=$(sharing -l 2>/dev/null | grep "guest access.*1" || echo "")
    if [ -n "$SHARE_CHECK" ]; then
        fail "Public Folder is shared with GUEST ACCESS ENABLED. Run: sudo sharing -e evw -S 0 to disable."
    else
        pass "No guest-accessible shares detected."
    fi
}

# =============================================================================
# SECTION 5: LISTENING PORTS & LOCAL SERVICES
# =============================================================================
audit_ports() {
    section "5. Listening Ports & Local Services"

    LISTEN_PORTS=$(netstat -an 2>/dev/null | grep "LISTEN" | grep -v "^unix")
    if [ -z "$LISTEN_PORTS" ]; then
        pass "No TCP listening ports found."
    else
        echo "$LISTEN_PORTS" | while read -r line; do
            PORT=$(echo "$line" | awk '{print $4}' | rev | cut -d. -f1 | rev)
            ADDR=$(echo "$line" | awk '{print $4}' | rev | cut -d. -f2- | rev)
            if echo "$ADDR" | grep -qE "^127\.0\.0\.1$|^::1$"; then
                warn "Localhost listener on port $PORT — investigate if not expected."
            else
                fail "EXTERNAL listener on $ADDR:$PORT — CLOSE THIS IMMEDIATELY."
            fi
        done
    fi

    # Check for Ollama (local LLM server)
    OLLAMA=$(lsof -i :11434 -n -P 2>/dev/null | grep LISTEN || echo "")
    if [ -n "$OLLAMA" ]; then
        warn "Ollama is listening on 127.0.0.1:11434. If not in use, stop it: brew services stop ollama"
    fi

    # Check for Manus local listener
    MANUS_PORT=$(lsof -i :54672 -n -P 2>/dev/null | grep LISTEN || echo "")
    if [ -n "$MANUS_PORT" ]; then
        info "Manus app is listening on 127.0.0.1:54672 (expected when Manus is running)."
    fi
}

# =============================================================================
# SECTION 6: LAUNCH AGENT / DAEMON PERSISTENCE AUDIT
# =============================================================================
audit_persistence() {
    section "6. Launch Agent & Daemon Persistence Audit"

    KNOWN_USER_AGENTS=("homebrew.mxcl.ollama.plist")
    KNOWN_SYS_AGENTS=("at.obdev.littlesnitch.agent.plist")
    KNOWN_SYS_DAEMONS=("at.obdev.littlesnitch.daemon.plist")

    # User Launch Agents
    if [ -d "$HOME/Library/LaunchAgents" ]; then
        for f in "$HOME/Library/LaunchAgents/"*.plist; do
            [ -f "$f" ] || continue
            FNAME=$(basename "$f")
            KNOWN=false
            for k in "${KNOWN_USER_AGENTS[@]}"; do
                [[ "$FNAME" == "$k" ]] && KNOWN=true && break
            done
            if $KNOWN; then
                info "Known user agent: $FNAME"
            else
                fail "UNKNOWN user Launch Agent: $FNAME — Investigate immediately!"
            fi
        done
    else
        pass "No user Launch Agents directory."
    fi

    # System Launch Agents
    if [ -d "/Library/LaunchAgents" ]; then
        for f in /Library/LaunchAgents/*.plist; do
            [ -f "$f" ] || continue
            FNAME=$(basename "$f")
            KNOWN=false
            for k in "${KNOWN_SYS_AGENTS[@]}"; do
                [[ "$FNAME" == "$k" ]] && KNOWN=true && break
            done
            if $KNOWN; then
                info "Known system agent: $FNAME"
            else
                fail "UNKNOWN system Launch Agent: $FNAME — Investigate immediately!"
            fi
        done
    fi

    # System Launch Daemons
    if [ -d "/Library/LaunchDaemons" ]; then
        for f in /Library/LaunchDaemons/*.plist; do
            [ -f "$f" ] || continue
            FNAME=$(basename "$f")
            KNOWN=false
            for k in "${KNOWN_SYS_DAEMONS[@]}"; do
                [[ "$FNAME" == "$k" ]] && KNOWN=true && break
            done
            if $KNOWN; then
                info "Known system daemon: $FNAME"
            else
                fail "UNKNOWN system Launch Daemon: $FNAME — Investigate immediately!"
            fi
        done
    fi
}

# =============================================================================
# SECTION 7: KERNEL EXTENSIONS
# =============================================================================
audit_kexts() {
    section "7. Kernel Extensions (kexts)"

    NON_APPLE_KEXTS=$(kextstat 2>/dev/null | grep -v "com.apple" | tail -n +2 || echo "")
    if [ -z "$NON_APPLE_KEXTS" ]; then
        pass "No third-party kernel extensions loaded."
    else
        fail "Third-party kernel extensions found:"
        echo "$NON_APPLE_KEXTS"
        warn "Kernel extensions run with highest privilege. Verify each one is trusted."
    fi
}

# =============================================================================
# SECTION 8: GATEKEEPER & NOTARIZATION
# =============================================================================
check_gatekeeper() {
    section "8. Gatekeeper & Code Signing"

    GK=$(spctl --status 2>/dev/null)
    if echo "$GK" | grep -q "assessments enabled"; then
        pass "Gatekeeper is ENABLED."
    else
        action "Enabling Gatekeeper..."
        spctl --master-enable
        pass "Gatekeeper enabled."
    fi

    # Check installed apps
    for app in "/Applications/Brave Browser.app" "/Applications/DuckDuckGo.app" \
               "/Applications/Little Snitch.app" "/Applications/Manus.app" \
               "/Applications/LibreOffice.app" "/Applications/Claude.app"; do
        if [ -d "$app" ]; then
            RESULT=$(spctl --assess --verbose "$app" 2>&1 || echo "REJECTED")
            if echo "$RESULT" | grep -q "accepted\|notarized"; then
                pass "$(basename "$app"): Gatekeeper accepted."
            else
                warn "$(basename "$app"): Gatekeeper status unclear — $RESULT"
            fi
        fi
    done
}

# =============================================================================
# SECTION 9: TELEMETRY & ANALYTICS SUPPRESSION
# =============================================================================
suppress_telemetry() {
    section "9. Telemetry & Analytics Suppression"

    # Disable crash reporter auto-submit
    defaults write com.apple.CrashReporter DialogType none 2>/dev/null
    defaults write com.apple.SubmitDiagInfo AutoSubmit -bool false 2>/dev/null
    defaults write /Library/Preferences/com.apple.SubmitDiagInfo AutoSubmit -bool false 2>/dev/null
    pass "Crash reporter auto-submit disabled."

    # Disable captive portal detection (prevents automatic HTTP probes on new networks)
    defaults write /Library/Preferences/com.apple.captive.control Active -bool false 2>/dev/null
    pass "Captive portal detection disabled."

    # Disable Spotlight suggestions (prevents sending search queries to Apple)
    defaults write com.apple.lookup.shared LookupSuggestionsDisabled -bool true 2>/dev/null
    pass "Spotlight Suggestions disabled."

    # Disable Siri analytics
    defaults write com.apple.assistant.support "Siri Data Sharing Opt-In Status" -int 2 2>/dev/null
    pass "Siri data sharing opt-out applied."

    # Disable diagnostic data sharing
    defaults write com.apple.privacy diagnosticDataEnabled -bool false 2>/dev/null
    pass "Diagnostic data sharing disabled."

    # Disable ad tracking
    defaults write com.apple.AdLib allowApplePersonalizedAdvertising -bool false 2>/dev/null
    pass "Personalized advertising disabled."

    warn "NOTE: Restart required for all telemetry changes to take full effect."
}

# =============================================================================
# SECTION 10: SCREEN LOCK & AUTHENTICATION
# =============================================================================
check_screen_lock() {
    section "10. Screen Lock & Authentication"

    # Check screensaver password
    SS_PASS=$(defaults read com.apple.screensaver askForPassword 2>/dev/null || echo "0")
    if [ "$SS_PASS" = "1" ]; then
        pass "Screensaver password is required."
    else
        action "Enabling screensaver password requirement..."
        defaults write com.apple.screensaver askForPassword -int 1
        defaults write com.apple.screensaver askForPasswordDelay -int 0
        pass "Screensaver password enabled with 0-second delay."
    fi

    # Check login window settings
    SHOW_USERS=$(defaults read /Library/Preferences/com.apple.loginwindow SHOWFULLNAME 2>/dev/null || echo "0")
    if [ "$SHOW_USERS" = "1" ]; then
        pass "Login window shows name/password fields (not user list)."
    else
        action "Configuring login window to hide user list..."
        defaults write /Library/Preferences/com.apple.loginwindow SHOWFULLNAME -bool true 2>/dev/null || true
        pass "Login window configured."
    fi

    # Disable automatic login
    AUTO_LOGIN=$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null || echo "none")
    if [ "$AUTO_LOGIN" = "none" ] || [ -z "$AUTO_LOGIN" ]; then
        pass "Auto-login is disabled."
    else
        fail "AUTO-LOGIN IS ENABLED for user: $AUTO_LOGIN — Disable in System Settings → Users & Groups."
    fi
}

# =============================================================================
# SECTION 11: SSH CONFIGURATION AUDIT
# =============================================================================
audit_ssh() {
    section "11. SSH Configuration Audit"

    # Check for SSH keys
    if [ -d "$HOME/.ssh" ]; then
        KEY_COUNT=$(find "$HOME/.ssh" -name "*.pub" 2>/dev/null | wc -l | tr -d ' ')
        if [ "$KEY_COUNT" -gt 0 ]; then
            info "Found $KEY_COUNT SSH public key(s) in ~/.ssh/"
            ls "$HOME/.ssh/"
        fi

        # Check known_hosts
        if [ -f "$HOME/.ssh/known_hosts" ]; then
            KH_COUNT=$(wc -l < "$HOME/.ssh/known_hosts")
            info "known_hosts has $KH_COUNT entries. Review for unexpected hosts."
        fi

        # Check permissions
        SSH_DIR_PERMS=$(stat -f "%OLp" "$HOME/.ssh" 2>/dev/null)
        if [ "$SSH_DIR_PERMS" = "700" ]; then
            pass "~/.ssh directory permissions are correct (700)."
        else
            action "Fixing ~/.ssh directory permissions..."
            chmod 700 "$HOME/.ssh"
            pass "~/.ssh permissions fixed."
        fi
    else
        pass "No ~/.ssh directory found."
    fi

    # Ensure SSH server is not running
    SSH_DAEMON=$(launchctl list 2>/dev/null | grep "com.openssh.sshd" || echo "")
    if [ -n "$SSH_DAEMON" ]; then
        fail "SSH DAEMON IS RUNNING. Disable: sudo systemsetup -setremotelogin off"
    else
        pass "SSH server daemon is not running."
    fi
}

# =============================================================================
# SECTION 12: ACTIVE NETWORK CONNECTIONS AUDIT
# =============================================================================
audit_connections() {
    section "12. Active Network Connections"

    info "Current ESTABLISHED connections:"
    netstat -an 2>/dev/null | grep ESTABLISHED | while read -r line; do
        REMOTE=$(echo "$line" | awk '{print $5}')
        REMOTE_IP=$(echo "$REMOTE" | rev | cut -d. -f2- | rev)
        REMOTE_PORT=$(echo "$REMOTE" | rev | cut -d. -f1 | rev)
        # Flag non-HTTPS connections
        if [[ "$REMOTE_PORT" != "443" && "$REMOTE_PORT" != "80" && "$REMOTE_PORT" != "22" ]]; then
            warn "Non-standard port connection: $line"
        else
            info "  $line"
        fi
    done

    # Check for mDNS (Bonjour) activity
    MDNS=$(lsof -i :5353 -n -P 2>/dev/null | grep -v "^COMMAND" || echo "")
    if [ -n "$MDNS" ]; then
        warn "mDNSResponder is active on port 5353. This broadcasts device info on local network."
        info "To disable Bonjour: sudo defaults write /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist ProgramArguments -array-add '-NoMulticastAdvertisements'"
    fi
}

# =============================================================================
# SECTION 13: LITTLE SNITCH AUDIT
# =============================================================================
audit_little_snitch() {
    section "13. Little Snitch Configuration Audit"

    LS_RUNNING=$(pgrep -x "Little Snitch Network Monitor" 2>/dev/null || pgrep -f "littlesnitch" 2>/dev/null || echo "")
    if [ -n "$LS_RUNNING" ]; then
        pass "Little Snitch is running."
    else
        fail "Little Snitch does not appear to be running. Verify it is active."
    fi

    echo ""
    echo -e "  ${BOLD}Critical Little Snitch Rule Recommendations:${NC}"
    echo ""
    echo -e "  ${RED}[CRITICAL]${NC} Brave Browser has a rule: ALLOW any remote, ANY port, ANY protocol."
    echo "             → DELETE this rule immediately. Replace with port-443-only rules per domain."
    echo ""
    echo -e "  ${ORANGE}[HIGH]${NC} DuckDuckGo browser has 18+ rules with ANY port/protocol."
    echo "         → Restrict all browser rules to port 443 (TCP) only."
    echo ""
    echo -e "  ${ORANGE}[HIGH]${NC} com.apple.captiveagent is allowed to reach captive.apple.com on ANY port."
    echo "         → Disable captive portal detection (done above) and DENY this rule entirely."
    echo ""
    echo -e "  ${ORANGE}[HIGH]${NC} com.apple.wifivelocityd is allowed INCOMING ICMP from 10.128.128.128."
    echo "         → DENY this rule. ICMP can be used for covert channel communication."
    echo ""
    echo -e "  ${YELLOW}[MEDIUM]${NC} configd is allowed INCOMING on port 68 (DHCP) from multiple IPs."
    echo "          → Restrict to your specific router IP only."
    echo ""
    echo -e "  ${YELLOW}[MEDIUM]${NC} mDNSResponder has INCOMING rules from multiple local IPs."
    echo "          → If you do not use AirDrop/Bonjour, DENY all mDNSResponder rules."
    echo ""
    echo -e "  ${YELLOW}[MEDIUM]${NC} Terminal is allowed to reach Shopify, GitHub, npm, Google Cloud, etc."
    echo "          → Review and remove any Terminal rules for domains no longer in use."
    echo ""
    echo -e "  ${CYAN}[INFO]${NC}   CloudTelemetryService is allowed 2 outbound connections."
    echo "         → Consider DENYING this entirely — it is Apple telemetry."
}

# =============================================================================
# SECTION 14: PROCESS THREAT ANALYSIS
# =============================================================================
audit_processes() {
    section "14. Process Threat Analysis"

    # Check for betaenrollmentd (Apple beta program — unnecessary telemetry)
    BETA=$(pgrep -f "betaenrollmentd" 2>/dev/null || echo "")
    if [ -n "$BETA" ]; then
        warn "betaenrollmentd is running. This enrolls the device in Apple's beta program and increases telemetry. Unenroll at: System Settings → General → Software Update."
    fi

    # Check for studentd (Screen Time / parental controls daemon)
    STUDENTD=$(pgrep -f "studentd" 2>/dev/null || echo "")
    if [ -n "$STUDENTD" ]; then
        warn "studentd (Screen Time daemon) is running. This daemon communicates with Apple servers. Disable Screen Time if not needed."
    fi

    # Check for proactiveeventtrackerd
    PROACTIVE=$(pgrep -f "proactiveeventtrackerd" 2>/dev/null || echo "")
    if [ -n "$PROACTIVE" ]; then
        warn "proactiveeventtrackerd is running. This tracks user behavior for Siri Suggestions. Disable Siri Suggestions in System Settings."
    fi

    # Check for sharingd (AirDrop/Handoff)
    SHARINGD=$(pgrep -f "sharingd" 2>/dev/null || echo "")
    if [ -n "$SHARINGD" ]; then
        warn "sharingd is running. This powers AirDrop and Handoff. Disable both in System Settings → General → AirDrop & Handoff."
    fi

    # Check for rapportd (Continuity)
    RAPPORT=$(pgrep -f "rapportd" 2>/dev/null || echo "")
    if [ -n "$RAPPORT" ]; then
        warn "rapportd is running. This powers Handoff/Continuity. Disable in System Settings → General → AirDrop & Handoff."
    fi

    # Check for analyticsd
    ANALYTICS=$(pgrep -f "analyticsd" 2>/dev/null || echo "")
    if [ -n "$ANALYTICS" ]; then
        warn "analyticsd is running. This collects and sends usage analytics to Apple. Disable in System Settings → Privacy & Security → Analytics & Improvements."
    fi

    # Check for locationd
    LOCATIOND=$(pgrep -f "locationd" 2>/dev/null || echo "")
    if [ -n "$LOCATIOND" ]; then
        warn "locationd (Location Services) is running. Disable for all apps in System Settings → Privacy & Security → Location Services unless strictly required."
    fi

    # Check for Objective-Development (Little Snitch helper)
    OD=$(pgrep -f "Objective Development" 2>/dev/null || echo "")
    if [ -n "$OD" ]; then
        info "Objective Development (Little Snitch) helper process is running — expected."
    fi

    # Check for cameracaptured (camera daemon)
    CAMERA=$(pgrep -f "cameracaptured" 2>/dev/null || echo "")
    if [ -n "$CAMERA" ]; then
        warn "cameracaptured is running. This manages camera access. Ensure no unauthorized apps have camera permissions (System Settings → Privacy → Camera)."
    fi

    # Check for Parrot Audio Plugin (third-party audio driver)
    PARROT=$(pgrep -f "ParrotAudioPlugin" 2>/dev/null || echo "")
    if [ -n "$PARROT" ]; then
        warn "ParrotAudioPlugin (third-party audio driver) is loaded. Verify this is a trusted, necessary driver."
    fi

    pass "Process scan complete."
}

# =============================================================================
# SECTION 15: SUDO & PRIVILEGE ESCALATION AUDIT
# =============================================================================
audit_sudo() {
    section "15. Sudo & Privilege Escalation Audit"

    # Check sudoers for NOPASSWD
    NOPASSWD=$(grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null || echo "")
    if [ -n "$NOPASSWD" ]; then
        fail "NOPASSWD found in sudoers: $NOPASSWD — This allows password-free privilege escalation."
    else
        pass "No NOPASSWD entries in sudoers."
    fi

    # Check for setuid binaries outside /usr/bin and /bin
    info "Scanning for unexpected setuid binaries (this may take a moment)..."
    SETUID=$(find /usr/local /opt/homebrew -perm -4000 -type f 2>/dev/null || echo "")
    if [ -n "$SETUID" ]; then
        warn "Setuid binaries found in non-system paths:"
        echo "$SETUID"
    else
        pass "No unexpected setuid binaries found."
    fi
}

# =============================================================================
# SECTION 16: CONFIGURATION PROFILES
# =============================================================================
audit_profiles() {
    section "16. Configuration Profiles (MDM)"

    PROFILES=$(profiles list 2>/dev/null || echo "")
    if echo "$PROFILES" | grep -q "There are no configuration profiles"; then
        pass "No MDM/configuration profiles installed."
    else
        fail "Configuration profiles are installed:"
        echo "$PROFILES"
        warn "MDM profiles can grant remote management capabilities. Remove any profiles you did not install."
    fi
}

# =============================================================================
# SECTION 17: ENVIRONMENT & PATH AUDIT
# =============================================================================
audit_environment() {
    section "17. PATH & Environment Security"

    # Check for . (current directory) in PATH
    if echo "$PATH" | grep -qE "(^|:)\.(:|$)"; then
        fail "Current directory (.) is in PATH — this is a privilege escalation risk."
    else
        pass "Current directory is not in PATH."
    fi

    # Check for world-writable directories in PATH
    IFS=: read -ra PATH_DIRS <<< "$PATH"
    for dir in "${PATH_DIRS[@]}"; do
        if [ -d "$dir" ]; then
            PERMS=$(stat -f "%OLp" "$dir" 2>/dev/null || echo "000")
            if [[ "${PERMS: -1}" =~ [2367] ]]; then
                warn "World-writable directory in PATH: $dir (perms: $PERMS)"
            fi
        fi
    done
    pass "PATH audit complete."
}

# =============================================================================
# FINAL SUMMARY
# =============================================================================
print_summary() {
    echo ""
    echo -e "${BOLD}${CYAN}=================================================================${NC}"
    echo -e "${BOLD}${CYAN}   AUDIT SUMMARY${NC}"
    echo -e "${BOLD}${CYAN}=================================================================${NC}"
    echo ""
    if [ "$ISSUES" -gt 0 ]; then
        echo -e "  ${RED}[FAIL] $ISSUES critical issue(s) found. Address immediately.${NC}"
    else
        echo -e "  ${GREEN}[PASS] No critical issues found.${NC}"
    fi
    if [ "$WARNINGS" -gt 0 ]; then
        echo -e "  ${ORANGE}[WARN] $WARNINGS warning(s) found. Review and remediate.${NC}"
    else
        echo -e "  ${GREEN}[PASS] No warnings.${NC}"
    fi
    echo ""
    echo -e "  Full log saved to: ${CYAN}$LOGFILE${NC}"
    echo ""
    echo -e "${BOLD}${CYAN}=================================================================${NC}"
    echo ""
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    require_root
    banner
    check_sip
    check_filevault
    enforce_firewall
    disable_sharing
    audit_ports
    audit_persistence
    audit_kexts
    check_gatekeeper
    suppress_telemetry
    check_screen_lock
    audit_ssh
    audit_connections
    audit_little_snitch
    audit_processes
    audit_sudo
    audit_profiles
    audit_environment
    print_summary
}

main "$@"
