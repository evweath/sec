#!/bin/bash
# Stringent hardening bundle
# Date: 2026-05-19
# Goal: maximum surface reduction while preserving outbound HTTPS (browser + terminal Claude/AI access)
# Scope: firewall block-all-incoming, Bluetooth off, AWDL off + persistent, additional service shutdown,
#        AirDrop/Handoff defaults off. Does NOT touch /System/ binaries.

set -u
LOG="$(dirname "$0")/harden.log"
exec > >(tee -a "$LOG") 2>&1

echo "=========================================="
echo " STRINGENT HARDEN  $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
echo "=========================================="
if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: must run as root (sudo)." >&2
  exit 1
fi

section() { echo ""; echo "===== $* ====="; }

USER_NAME="evw"
USER_UID=$(id -u "$USER_NAME")

# ========== 1. Apple Application Firewall: block-all-incoming ==========
section "1. Apple firewall — block-all-incoming + stealth + no auto-allow"
/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on 2>&1
/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on 2>&1
/usr/libexec/ApplicationFirewall/socketfilterfw --setblockall on 2>&1
/usr/libexec/ApplicationFirewall/socketfilterfw --setallowsigned off 2>&1
/usr/libexec/ApplicationFirewall/socketfilterfw --setallowsignedapp off 2>&1
echo "--- state ---"
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode
/usr/libexec/ApplicationFirewall/socketfilterfw --getblockall
/usr/libexec/ApplicationFirewall/socketfilterfw --getallowsigned

# ========== 2. Bluetooth controller off ==========
section "2. Bluetooth controller power off"
defaults write /Library/Preferences/com.apple.Bluetooth ControllerPowerState -int 0
killall -HUP bluetoothd 2>/dev/null || true
sleep 1
echo "ControllerPowerState = $(defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState 2>&1)"
echo "(NOTE: on the very latest macOS, this defaults-write method is unreliable; verify Bluetooth is off in Control Center)"

# ========== 3. AWDL down + persistent watcher ==========
section "3. AWDL (peer-to-peer Wi-Fi) — down + persistent watcher"
ifconfig awdl0 down 2>&1 || true

cat > /Library/LaunchDaemons/local.awdl-down.plist <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>local.awdl-down</string>
  <key>ProgramArguments</key>
  <array>
    <string>/sbin/ifconfig</string>
    <string>awdl0</string>
    <string>down</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>StartInterval</key>
  <integer>60</integer>
  <key>StandardOutPath</key>
  <string>/var/log/local.awdl-down.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/local.awdl-down.log</string>
</dict>
</plist>
EOF
chown root:wheel /Library/LaunchDaemons/local.awdl-down.plist
chmod 644 /Library/LaunchDaemons/local.awdl-down.plist
launchctl bootout system/local.awdl-down 2>/dev/null || true
launchctl bootstrap system /Library/LaunchDaemons/local.awdl-down.plist 2>&1 \
  || launchctl load -w /Library/LaunchDaemons/local.awdl-down.plist 2>&1
sleep 2
echo "--- awdl0 status ---"
ifconfig awdl0 2>&1 | head -2

# ========== 4. Tier-2 service shutdown (launchctl disable + bootout) ==========
section "4. Disable additional system services"
for label in \
  com.apple.RemoteDesktop.PrivilegeProxy \
  com.apple.netbiosd \
  com.apple.AirPlayXPCHelper \
  com.apple.mediasharingd ; do
  echo "[disable] $label"
  launchctl disable "system/$label" 2>&1 | sed 's/^/    /'
  launchctl bootout "system/$label" 2>/dev/null && echo "    [bootout] success" || echo "    [bootout] not loaded (ok)"
done

section "4b. Disable user-level agents"
for label in com.apple.studentd ; do
  echo "[disable] user/$USER_UID/$label"
  launchctl disable "user/$USER_UID/$label" 2>&1 | sed 's/^/    /'
  launchctl bootout "user/$USER_UID/$label" 2>/dev/null && echo "    [bootout] success" || echo "    [bootout] not loaded (ok)"
done

# ========== 5. AirDrop / Handoff / Continuity defaults ==========
section "5. AirDrop / Handoff defaults (per-user)"
sudo -u "$USER_NAME" defaults write com.apple.sharingd DiscoverableMode "Off" 2>&1
sudo -u "$USER_NAME" defaults write com.apple.coreservices.useractivityd ActivityAdvertisingAllowed -bool false 2>&1
sudo -u "$USER_NAME" defaults write com.apple.coreservices.useractivityd ActivityReceivingAllowed -bool false 2>&1
echo "--- sharingd discoverable mode ---"
sudo -u "$USER_NAME" defaults read com.apple.sharingd DiscoverableMode 2>&1 || echo "(unset)"

# ========== 6. Final verify ==========
section "6. FINAL VERIFY"

echo "[firewall]"
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode
/usr/libexec/ApplicationFirewall/socketfilterfw --getblockall

echo ""
echo "[bluetooth ControllerPowerState]"
defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState 2>&1

echo ""
echo "[awdl0]"
ifconfig awdl0 2>&1 | head -1

echo ""
echo "[disabled system services]"
launchctl print-disabled system 2>&1 | grep -i -E 'remotedesktop|netbios|airplayxpc|mediasharing|smbd|applefile|openssh|sshd|screensharing|InternetSharing'

echo ""
echo "[disabled user agents]"
launchctl print-disabled user/$USER_UID 2>&1 | grep -i -E 'studentd' || echo "(not in disabled list)"

echo ""
echo "[listening sockets — should be empty or local-only]"
lsof -nP -iTCP -sTCP:LISTEN 2>&1 | head -20

echo ""
echo "=========================================="
echo " DONE  $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
echo "=========================================="
echo ""
echo "MANUAL STEPS REMAINING (System Settings UI — cannot script):"
echo "  1. Privacy & Security → Lockdown Mode → ON  (requires reboot)"
echo "  2. General → AirDrop & Handoff → AirDrop: 'Receiving Off', Handoff: OFF, AirPlay Receiver: OFF"
echo "  3. General → Sharing → confirm ALL toggles are off"
echo "  4. Verify Bluetooth is off in Control Center"
