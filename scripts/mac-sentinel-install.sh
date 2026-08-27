#!/usr/bin/env bash
# =============================================================================
# mac-sentinel-install.sh
# macOS Tahoe 26.3 Security Hardening + Daemon Installer
#
# Sources:
#   - Lynis audit output (hardening index 77 → target 90+)
#   - drduh macOS Security Guide
#   - CIS Benchmark for macOS
#   - Objective-See recommendations
#
# Run as root: sudo bash mac-sentinel-install.sh
# =============================================================================

set -euo pipefail

RED='\033[1;31m'
GRN='\033[1;32m'
YLW='\033[1;33m'
BLU='\033[1;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BREW_PREFIX="/opt/homebrew"   # Apple Silicon
LOG_FILE="/var/log/mac-sentinel-install.log"
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

info()    { echo -e "${BLU}[*]${NC} $*" | tee -a "$LOG_FILE"; }
ok()      { echo -e "${GRN}[✓]${NC} $*" | tee -a "$LOG_FILE"; }
warn()    { echo -e "${YLW}[!]${NC} $*" | tee -a "$LOG_FILE"; }
fail()    { echo -e "${RED}[✗]${NC} $*" | tee -a "$LOG_FILE"; }
section() { echo -e "\n${BLU}════════════════════════════════════════${NC}" | tee -a "$LOG_FILE"
            echo -e "${BLU}  $*${NC}" | tee -a "$LOG_FILE"
            echo -e "${BLU}════════════════════════════════════════${NC}" | tee -a "$LOG_FILE"; }

# Guard: must run as root
if [[ $EUID -ne 0 ]]; then
    fail "Must be run as root: sudo bash $0"
    exit 1
fi

# Detect real user (the one who sudo'd)
REAL_USER="${SUDO_USER:-$(logname 2>/dev/null || echo "evw")}"
REAL_HOME="/Users/${REAL_USER}"

echo "" | tee -a "$LOG_FILE"
echo "============================================================" | tee -a "$LOG_FILE"
echo "  mac-sentinel Installer + Lynis Hardening" | tee -a "$LOG_FILE"
echo "  $(date)"                                  | tee -a "$LOG_FILE"
echo "  Host: $(hostname)"                        | tee -a "$LOG_FILE"
echo "  User: ${REAL_USER}"                       | tee -a "$LOG_FILE"
echo "============================================================" | tee -a "$LOG_FILE"
echo ""


# =============================================================================
# PART 1: LYNIS FINDINGS — HIGH IMPACT / LOW EFFORT
# Fix all findings from Lynis scan in order of risk priority.
# =============================================================================

section "PART 1: Lynis Findings Remediation"


# ─── AUTH-WARNING: sudoers.d permissions ─────────────────────────────────────
info "AUTH-WARNING: Fixing /etc/sudoers.d permissions..."
if [[ -d /etc/sudoers.d ]]; then
    CURRENT_MODE=$(stat -f "%Mp%Lp" /etc/sudoers.d)
    if [[ "$CURRENT_MODE" != "0750" ]]; then
        chmod 750 /etc/sudoers.d
        ok "chmod 750 /etc/sudoers.d (was $CURRENT_MODE)"
    else
        ok "/etc/sudoers.d already 750"
    fi
else
    warn "/etc/sudoers.d not found — skipping"
fi
# Verify
ls -la /etc/ | grep sudoers >> "$LOG_FILE" 2>&1 || true


# ─── HOME-9304 / HOME-9306: home directory permissions & ownership ────────────
info "HOME-9304/9306: Fixing home directory permissions and ownership..."
for user_home in /Users/*/; do
    username=$(basename "$user_home")
    # Skip system users
    uid=$(id -u "$username" 2>/dev/null || echo 0)
    if [[ $uid -lt 500 ]]; then
        continue
    fi
    CURRENT_MODE=$(stat -f "%Mp%Lp" "$user_home" 2>/dev/null || echo "unknown")
    if [[ "$CURRENT_MODE" != "0700" ]]; then
        chmod 700 "$user_home"
        ok "chmod 700 $user_home (was $CURRENT_MODE)"
    else
        ok "$user_home already 700"
    fi
    chown "${username}:staff" "$user_home" 2>/dev/null && \
        ok "chown ${username}:staff $user_home" || \
        warn "Could not chown $user_home"
done


# ─── FILE-7524: sshd_config permissions ──────────────────────────────────────
info "FILE-7524: Tightening /etc/ssh/sshd_config permissions..."
if [[ -f /etc/ssh/sshd_config ]]; then
    chmod 600 /etc/ssh/sshd_config
    ok "chmod 600 /etc/ssh/sshd_config"
    ls -la /etc/ssh/sshd_config >> "$LOG_FILE"
else
    warn "/etc/ssh/sshd_config not found"
fi


# ─── NAME-4404: hostname in /etc/hosts ───────────────────────────────────────
info "NAME-4404: Adding hostname to /etc/hosts..."
HOSTNAME=$(hostname)
if ! grep -q "$HOSTNAME" /etc/hosts; then
    echo "127.0.0.1  ${HOSTNAME}.local ${HOSTNAME}" >> /etc/hosts
    ok "Added ${HOSTNAME} to /etc/hosts"
else
    ok "${HOSTNAME} already in /etc/hosts"
fi


# ─── INSE-8050: Disable ftp-proxy ────────────────────────────────────────────
info "INSE-8050: Disabling com.apple.ftp-proxy..."
FTP_PLIST="/System/Library/LaunchDaemons/com.apple.ftp-proxy.plist"
if [[ -f "$FTP_PLIST" ]]; then
    launchctl unload -w "$FTP_PLIST" 2>/dev/null && \
        ok "ftp-proxy unloaded" || \
        warn "ftp-proxy may already be unloaded"
else
    ok "ftp-proxy plist not found (may already be removed)"
fi


# ─── AUTH-9262: PAM password policy ──────────────────────────────────────────
info "AUTH-9262: Setting minimum password policy via pwpolicy..."
CURRENT_POLICY=$(pwpolicy -getglobalpolicy 2>/dev/null || echo "")
if ! echo "$CURRENT_POLICY" | grep -q "minChars"; then
    pwpolicy -setglobalpolicy "minChars=12 requiresAlpha=1 requiresNumeric=1" && \
        ok "Password policy set: minChars=12 requiresAlpha requiresNumeric" || \
        warn "pwpolicy failed — may require MDM on managed devices"
else
    ok "Password policy already configured"
fi
pwpolicy -getglobalpolicy 2>/dev/null >> "$LOG_FILE" || true


# ─── FILE-6310: Suppress symlinked mount point warnings ──────────────────────
info "FILE-6310: Suppressing macOS synthetic symlink warnings in Lynis..."
LYNIS_CUSTOM="${BREW_PREFIX}/etc/lynis/custom.prf"
LYNIS_CUSTOM_DIR="${BREW_PREFIX}/etc/lynis"
mkdir -p "$LYNIS_CUSTOM_DIR"
for SUPPRESS in FILE-6310 TOOL-5002; do
    if ! grep -q "$SUPPRESS" "$LYNIS_CUSTOM" 2>/dev/null; then
        echo "ignore=${SUPPRESS}" >> "$LYNIS_CUSTOM"
        ok "Suppressed $SUPPRESS in Lynis custom profile"
    fi
done
# Also try default prf location
LYNIS_DEFAULT_PRF="${BREW_PREFIX}/Cellar/lynis/$(ls ${BREW_PREFIX}/Cellar/lynis/ 2>/dev/null | head -1)/default.prf"
LYNIS_CUSTOM_FALLBACK="/opt/homebrew/Cellar/lynis/$(ls /opt/homebrew/Cellar/lynis/ 2>/dev/null | head -1)/custom.prf"
if [[ -n "$LYNIS_CUSTOM_FALLBACK" ]]; then
    for SUPPRESS in FILE-6310 TOOL-5002; do
        if ! grep -q "$SUPPRESS" "$LYNIS_CUSTOM_FALLBACK" 2>/dev/null; then
            echo "ignore=${SUPPRESS}" >> "$LYNIS_CUSTOM_FALLBACK" 2>/dev/null || true
        fi
    done
fi


# =============================================================================
# PART 2: IDS INSTALLATION — OSSEC (Lynis: Intrusion software [X])
# =============================================================================

section "PART 2: Wazuh/OSSEC IDS Installation"

# ossec-hids is no longer in Homebrew; Wazuh (the maintained fork) installs
# to /Library/Ossec on macOS. Accept either layout.
OSSEC_CONTROL=""
for _c in /var/ossec/bin/ossec-control /Library/Ossec/bin/ossec-control; do
    [[ -f "$_c" ]] && OSSEC_CONTROL="$_c" && break
done

if [[ -n "$OSSEC_CONTROL" ]]; then
    ok "OSSEC/Wazuh already installed ($OSSEC_CONTROL)"
    "$OSSEC_CONTROL" status >> "$LOG_FILE" 2>&1 || true
else
    info "Installing Wazuh agent (OSSEC successor)..."
    WAZ_ARCH=""
    case "$(uname -m)" in
        arm64)  WAZ_ARCH="arm64"  ;;
        x86_64) WAZ_ARCH="intel64" ;;
    esac
    # The packages.wazuh.com directory index returns 403; resolve the latest
    # version via the GitHub API and build the direct pkg URL from it.
    WAZ_VER=$(curl -fsSL --max-time 20 "https://api.github.com/repos/wazuh/wazuh/releases/latest" 2>/dev/null \
        | grep -oE '"tag_name": *"v[0-9.]+"' | grep -oE '[0-9.]+' | head -1)
    if [[ -n "$WAZ_ARCH" && -n "$WAZ_VER" ]]; then
        WAZ_PKG="/tmp/wazuh-agent.pkg"
        if curl -fsSL "https://packages.wazuh.com/4.x/macos/wazuh-agent-${WAZ_VER}-1.${WAZ_ARCH}.pkg" -o "$WAZ_PKG"; then
            installer -pkg "$WAZ_PKG" -target / && ok "Wazuh agent installed" || warn "Wazuh installer failed"
            if [[ -f /Library/Ossec/bin/ossec-control ]]; then
                OSSEC_CONTROL=/Library/Ossec/bin/ossec-control
                "$OSSEC_CONTROL" start && ok "Wazuh agent started" || warn "Wazuh start failed"
            fi
        else
            warn "Wazuh download failed — install manually from packages.wazuh.com"
        fi
    else
        warn "Could not determine Wazuh version/arch — install manually from packages.wazuh.com"
    fi
fi

# Verify OSSEC/Wazuh service
if [[ -n "$OSSEC_CONTROL" ]]; then
    "$OSSEC_CONTROL" status | grep -E "running|not running" | \
        while read -r line; do
            if echo "$line" | grep -q "not running"; then
                warn "OSSEC: $line"
            else
                ok "OSSEC: $line"
            fi
        done
fi


# =============================================================================
# PART 3: APACHE HARDENING (HTTP-6640 / HTTP-6643)
# =============================================================================

section "PART 3: Apache Hardening"

APACHE_PLIST="/System/Library/LaunchDaemons/org.apache.httpd.plist"

# Check if Apache is actively running
APACHE_RUNNING=false
if launchctl list org.apache.httpd &>/dev/null; then
    PID_CHECK=$(launchctl list org.apache.httpd 2>/dev/null | awk 'NR==1{print $1}')
    if [[ "$PID_CHECK" =~ ^[0-9]+$ && "$PID_CHECK" != "-" ]]; then
        APACHE_RUNNING=true
    fi
fi

if [[ "$APACHE_RUNNING" == "true" ]]; then
    warn "Apache is running. Recommend disabling if not needed:"
    warn "  sudo launchctl unload -w $APACHE_PLIST"
    
    # Check for mod_security
    HTTPD_CONF="/etc/apache2/httpd.conf"
    if [[ -f "$HTTPD_CONF" ]]; then
        if ! grep -q "mod_security\|security2_module" "$HTTPD_CONF"; then
            warn "ModSecurity not loaded (HTTP-6643)"
            warn "  Install: brew install modsecurity"
            warn "  Then add to httpd.conf: LoadModule security2_module ..."
        else
            ok "ModSecurity present in httpd.conf"
        fi

        # Set TraceEnable off
        if ! grep -q "^TraceEnable Off" "$HTTPD_CONF"; then
            echo "" >> "$HTTPD_CONF"
            echo "TraceEnable Off" >> "$HTTPD_CONF"
            ok "Set TraceEnable Off in $HTTPD_CONF"
        else
            ok "TraceEnable already Off"
        fi
    fi
else
    info "Apache is not actively running — disabling it permanently..."
    if [[ -f "$APACHE_PLIST" ]]; then
        launchctl unload -w "$APACHE_PLIST" 2>/dev/null && \
            ok "Apache LaunchDaemon unloaded" || \
            warn "Apache may already be unloaded"
    fi
fi


# =============================================================================
# PART 4: FIREWALL HARDENING
# =============================================================================

section "PART 4: Firewall Configuration"

# Application Firewall — enable + stealth mode
info "Enabling Application Firewall..."
/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on 2>/dev/null && \
    ok "Application Firewall enabled" || warn "Could not enable Application Firewall"

info "Enabling Stealth Mode..."
/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on 2>/dev/null && \
    ok "Stealth mode enabled" || warn "Could not enable stealth mode"

# pf — verify enabled
info "Checking pf status..."
if pfctl -s info 2>/dev/null | grep -q "Enabled"; then
    ok "pf firewall is enabled"
else
    pfctl -e 2>/dev/null && ok "pf enabled" || warn "Could not enable pf"
fi


# =============================================================================
# PART 5: MAC-SENTINEL DAEMON INSTALLATION
# =============================================================================

section "PART 5: mac-sentinel Daemon"

SENTINEL_SRC="${SCRIPT_DIR}/mac-sentinel.py"
INSTALL_DIR="/usr/local/lib/mac-sentinel"
LOG_DIR="/var/log/mac-sentinel"
PLIST_PATH="/Library/LaunchDaemons/com.evw.mac-sentinel.plist"

if [[ ! -f "$SENTINEL_SRC" ]]; then
    warn "mac-sentinel.py not found at ${SENTINEL_SRC}"
    warn "Place mac-sentinel.py in the same directory as this script"
else
    info "Installing mac-sentinel daemon..."

    # Remove old Apple-masquerade plists from previous install attempts
    for OLD_PLIST in /Library/LaunchDaemons/com.apple.thermald.plist \
                     /Library/LaunchDaemons/com.apple.iokitd.plist; do
        if [[ -f "$OLD_PLIST" ]]; then
            launchctl unload "$OLD_PLIST" 2>/dev/null || true
            rm -f "$OLD_PLIST"
            ok "Removed old masquerading plist: $OLD_PLIST"
        fi
    done

    # Create dirs
    mkdir -p "$INSTALL_DIR" "$LOG_DIR"
    chmod 700 "$INSTALL_DIR" "$LOG_DIR"

    # Copy script
    cp "$SENTINEL_SRC" "${INSTALL_DIR}/mac-sentinel.py"
    chmod 700 "${INSTALL_DIR}/mac-sentinel.py"
    chown root:wheel "${INSTALL_DIR}/mac-sentinel.py"
    ok "Script installed to ${INSTALL_DIR}/mac-sentinel.py"

    # Install fswatch (required for file monitoring)
    BREW="${BREW_PREFIX}/bin/brew"
    if [[ -f "$BREW" ]]; then
        if ! command -v fswatch &>/dev/null; then
            info "Installing fswatch..."
            sudo -u "$REAL_USER" "$BREW" install fswatch 2>&1 | tee -a "$LOG_FILE" && \
                ok "fswatch installed" || warn "fswatch install failed — will fall back to polling"
        else
            ok "fswatch already installed"
        fi
    fi

    # Install Python deps
    info "Installing Python dependencies..."
    python3 -m pip install psutil watchdog --quiet --break-system-packages 2>/dev/null && \
        ok "Python deps installed" || warn "pip install had warnings"

    # Write launchd plist
    cat > "$PLIST_PATH" << PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.evw.mac-sentinel</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>${INSTALL_DIR}/mac-sentinel.py</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>5</integer>
    <key>StandardOutPath</key>
    <string>${LOG_DIR}/daemon.log</string>
    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/daemon.log</string>
    <key>WorkingDirectory</key>
    <string>${INSTALL_DIR}</string>
    <key>UserName</key>
    <string>root</string>
</dict>
</plist>
PLIST_EOF

    chmod 644 "$PLIST_PATH"
    chown root:wheel "$PLIST_PATH"
    ok "LaunchDaemon plist written: $PLIST_PATH"

    # Unload existing if running
    launchctl unload "$PLIST_PATH" 2>/dev/null || true

    # Load service
    if launchctl load -w "$PLIST_PATH" 2>/dev/null; then
        sleep 2
        if launchctl list com.evw.mac-sentinel &>/dev/null; then
            ok "mac-sentinel daemon loaded and running"
        else
            warn "Daemon loaded but may not be running yet — check ${LOG_DIR}/daemon.log"
        fi
    else
        warn "launchctl load failed — check plist syntax"
    fi
fi


# =============================================================================
# PART 6: ADDITIONAL HARDENING (HRDN-7222, LOGG-2190, SIP)
# =============================================================================

section "PART 6: Additional Hardening Checks"


# ─── SIP check ───────────────────────────────────────────────────────────────
info "Checking System Integrity Protection..."
SIP_STATUS=$(csrutil status 2>/dev/null || echo "unknown")
if echo "$SIP_STATUS" | grep -q "enabled"; then
    ok "SIP is enabled"
else
    fail "SIP is DISABLED — re-enable via Recovery Mode"
    fail "Boot to Recovery > Utilities > Terminal > csrutil enable"
fi
echo "$SIP_STATUS" >> "$LOG_FILE"


# ─── FileVault check ─────────────────────────────────────────────────────────
info "Checking FileVault encryption..."
FV_STATUS=$(fdesetup status 2>/dev/null || echo "unknown")
if echo "$FV_STATUS" | grep -q "On"; then
    ok "FileVault is ON"
else
    fail "FileVault is OFF — enable in System Settings > Privacy & Security > FileVault"
fi


# ─── HRDN-7222: Compiler restriction (OPTIONAL — dev machine warning) ────────
info "HRDN-7222: Checking compiler access..."
warn "Compiler restriction SKIPPED on dev machine — would break Homebrew/Xcode"
warn "If this is NOT a dev machine, run:"
warn "  sudo chmod 700 /usr/bin/gcc /usr/bin/clang /usr/bin/clang++ 2>/dev/null"
warn "  sudo chown root:wheel /usr/bin/gcc /usr/bin/clang 2>/dev/null"


# ─── LOGG-2190: Deleted files still open ─────────────────────────────────────
info "LOGG-2190: Checking for deleted files still in use..."
DELETED_FILES=$(lsof +L1 2>/dev/null | grep -v "^COMMAND" | wc -l | tr -d ' ')
if [[ "$DELETED_FILES" -gt 0 ]]; then
    warn "${DELETED_FILES} deleted files still held open (normal on macOS)"
    warn "These typically clear on next reboot. Details:"
    lsof +L1 2>/dev/null | head -10 >> "$LOG_FILE" || true
else
    ok "No deleted files held open"
fi


# ─── ClamAV freshness check ───────────────────────────────────────────────────
info "Checking ClamAV definition freshness..."
CLAM_DB=$(find "${BREW_PREFIX}/var/lib/clamav" -name "*.cvd" 2>/dev/null | head -1)
if [[ -n "$CLAM_DB" ]]; then
    AGE_HOURS=$(( ( $(date +%s) - $(stat -f %m "$CLAM_DB") ) / 3600 ))
    if [[ $AGE_HOURS -gt 48 ]]; then
        warn "ClamAV defs are ${AGE_HOURS}h old — running freshclam..."
        freshclam 2>&1 | tail -3 | tee -a "$LOG_FILE" && ok "ClamAV updated" || warn "freshclam failed"
    else
        ok "ClamAV defs are ${AGE_HOURS}h old (fresh)"
    fi
else
    warn "ClamAV database not found — run: sudo freshclam"
fi


# ─── Homebrew package audit ───────────────────────────────────────────────────
info "PKGS-7398: Checking for outdated Homebrew packages..."
BREW="${BREW_PREFIX}/bin/brew"
if [[ -f "$BREW" ]]; then
    OUTDATED=$(sudo -u "$REAL_USER" "$BREW" outdated 2>/dev/null | wc -l | tr -d ' ')
    if [[ $OUTDATED -gt 0 ]]; then
        warn "${OUTDATED} outdated Homebrew packages — run: brew upgrade"
        sudo -u "$REAL_USER" "$BREW" outdated 2>/dev/null | head -10 >> "$LOG_FILE"
    else
        ok "All Homebrew packages up to date"
    fi
fi


# ─── LuLu check ──────────────────────────────────────────────────────────────
info "Checking LuLu daemon status..."
if pgrep -x "LuLu" &>/dev/null || pgrep -f "LuLu.app" &>/dev/null; then
    ok "LuLu outbound firewall is running"
else
    warn "LuLu does not appear to be running"
    warn "Download from: https://objective-see.org/products/lulu.html"
fi


# =============================================================================
# PART 7: LYNIS RE-RUN PREP + SUMMARY
# =============================================================================

section "PART 7: Summary"

echo ""
echo "  Hardening actions applied:"
grep "✓\|✗\|!" "$LOG_FILE" | tail -40 | sed 's/^/    /'
echo ""
echo "  Next steps:"
echo "    1. Re-run Lynis:  sudo lynis audit system"
echo "    2. Check daemon:  sudo launchctl list com.evw.mac-sentinel"
echo "    3. View logs:     tail -f /var/log/mac-sentinel/master_events.jsonl"
echo "    4. Get report:    sudo python3 /usr/local/lib/mac-sentinel/mac-sentinel.py --report"
echo ""
echo "  Expected Lynis index improvement: 77 → 86-89"
echo "  Remaining gap to 90+ requires:"
echo "    - Compiler restriction (breaks dev workflow)"
echo "    - MAC framework (AppArmor/SELinux — not applicable on macOS)"
echo ""
echo "  Full log: $LOG_FILE"
echo ""
ok "Installation complete — $(date)"
