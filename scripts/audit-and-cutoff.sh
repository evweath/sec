#!/bin/bash
# Audit and cut-off of remote-access avenues
# Date: 2026-05-19
# Auth: user-authorized (Yes — full cut-off + audit)
# All output is logged to audit-and-cutoff.log

set -u
LOG="$(dirname "$0")/audit-and-cutoff.log"
exec > >(tee -a "$LOG") 2>&1

echo "=========================================="
echo " AUDIT + CUT-OFF  $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
echo " (must be run as root)"
echo "=========================================="
if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: not root. Re-run with sudo." >&2
  exit 1
fi

section() { echo ""; echo "===== $* ====="; }

# ---------- AUDIT (reads) ----------

section "SSH (Remote Login) status"
systemsetup -getremotelogin 2>&1

section "Remote Apple Events status"
systemsetup -getremoteappleevents 2>&1

section "ARD / Remote Management kickstart -status"
/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status 2>&1

section "Internet Sharing (com.apple.nat)"
defaults read /Library/Preferences/SystemConfiguration/com.apple.nat 2>&1 | head -60
ls -la /Library/Preferences/SystemConfiguration/com.apple.nat.plist 2>&1

section "launchctl print-disabled system (filtered)"
launchctl print-disabled system 2>&1 | grep -i -E 'screensharing|remotedesk|remotemanagement|ardagent|sshd|RemoteLogin|RemoteAppleEvents|InternetSharing|com.apple.ssh|com.apple.smbd|com.apple.AppleFileServer' || echo "(no matches)"

section "Sharing-related launchd services that are LOADED"
launchctl print system 2>&1 | grep -i -E 'screensharing|remotedesk|remotemanagement|ardagent|sshd|RemoteLogin|RemoteAppleEvents|InternetSharing|com.apple.ssh' | head -40

section "All listening TCP sockets (sudo lsof)"
lsof -nP -iTCP -sTCP:LISTEN 2>&1 | head -80

section "All UDP listeners (sudo lsof)"
lsof -nP -iUDP 2>&1 | grep -v '\->' | head -60

section "TCC: Screen Capture grants"
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT client, auth_value, datetime(last_modified,'unixepoch') AS modified FROM access WHERE service='kTCCServiceScreenCapture' ORDER BY last_modified DESC;" 2>&1

section "TCC: Accessibility grants"
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT client, auth_value, datetime(last_modified,'unixepoch') AS modified FROM access WHERE service='kTCCServiceAccessibility' ORDER BY last_modified DESC;" 2>&1

section "TCC: ListenEvent (input monitoring) grants"
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT client, auth_value, datetime(last_modified,'unixepoch') AS modified FROM access WHERE service='kTCCServiceListenEvent' ORDER BY last_modified DESC;" 2>&1

section "TCC: PostEvent (synthetic input) grants"
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT client, auth_value, datetime(last_modified,'unixepoch') AS modified FROM access WHERE service='kTCCServicePostEvent' ORDER BY last_modified DESC;" 2>&1

section "/etc/sudoers and /etc/sudoers.d listing"
ls -la /etc/sudoers /etc/sudoers.d 2>&1
echo "--- /etc/sudoers contents ---"
cat /etc/sudoers 2>&1

section "Root LoginHook / LogoutHook"
defaults read /var/root/Library/Preferences/com.apple.loginwindow LoginHook 2>&1 || echo "(no LoginHook)"
defaults read /var/root/Library/Preferences/com.apple.loginwindow LogoutHook 2>&1 || echo "(no LogoutHook)"
defaults read /Library/Preferences/com.apple.loginwindow LoginHook 2>&1 || echo "(no global LoginHook)"
defaults read /Library/Preferences/com.apple.loginwindow LogoutHook 2>&1 || echo "(no global LogoutHook)"

section "Little Snitch live config directory listing"
ls -la "/Library/Application Support/Objective Development/Little Snitch/" 2>&1

section "Little Snitch list-preferences"
"/Applications/Little Snitch.app/Contents/Components/littlesnitch" list-preferences 2>&1 | head -60

section "Little Snitch traffic last 30 minutes (top peers)"
B=$(date -v-30M +"%Y-%m-%d %H:%M:%S")
E=$(date +"%Y-%m-%d %H:%M:%S")
"/Applications/Little Snitch.app/Contents/Components/littlesnitch" log-traffic -b "$B" -e "$E" 2>&1 | head -80

# ---------- CUT-OFF (writes) ----------

section "DISABLE: Remote Login (SSH)"
BEFORE=$(systemsetup -getremotelogin 2>&1)
echo "before: $BEFORE"
systemsetup -setremotelogin off 2>&1
AFTER=$(systemsetup -getremotelogin 2>&1)
echo "after:  $AFTER"

section "DISABLE: Remote Apple Events"
BEFORE=$(systemsetup -getremoteappleevents 2>&1)
echo "before: $BEFORE"
systemsetup -setremoteappleevents off 2>&1
AFTER=$(systemsetup -getremoteappleevents 2>&1)
echo "after:  $AFTER"

section "DISABLE: ARD / Remote Management (kickstart -deactivate)"
echo "before:" ; /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status 2>&1
/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart \
  -deactivate -configure -access -off 2>&1
echo "after:" ; /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status 2>&1

section "DISABLE: Screen Sharing (com.apple.screensharing)"
launchctl disable system/com.apple.screensharing 2>&1
launchctl bootout system/com.apple.screensharing 2>&1 || echo "(bootout: already inactive or SIP-protected; disable persists across reboot)"
launchctl print-disabled system 2>&1 | grep -i 'screensharing' || echo "(disabled state lookup failed)"

section "DISABLE: Internet Sharing (com.apple.nat NAT.Enabled=0)"
CURRENT=$(defaults read /Library/Preferences/SystemConfiguration/com.apple.nat NAT 2>&1)
echo "before: $CURRENT"
# Set NAT.Enabled = 0 if NAT dict exists; if not, no action needed
if defaults read /Library/Preferences/SystemConfiguration/com.apple.nat NAT >/dev/null 2>&1 ; then
  /usr/libexec/PlistBuddy -c "Set :NAT:Enabled false" /Library/Preferences/SystemConfiguration/com.apple.nat.plist 2>&1 \
    || /usr/libexec/PlistBuddy -c "Set :NAT:Enabled 0" /Library/Preferences/SystemConfiguration/com.apple.nat.plist 2>&1 \
    || echo "(no Enabled key to set — Internet Sharing was likely never configured)"
else
  echo "(no NAT dict — Internet Sharing was never configured)"
fi
launchctl bootout system/com.apple.InternetSharing 2>&1 || echo "(InternetSharing not running)"
echo "after:"
defaults read /Library/Preferences/SystemConfiguration/com.apple.nat 2>&1 | head -20

# ---------- VERIFY ----------

section "VERIFY: ports listening after cut-off"
lsof -nP -iTCP -sTCP:LISTEN 2>&1 | head -40

section "VERIFY: remote-related disabled state"
launchctl print-disabled system 2>&1 | grep -i -E 'screensharing|remotedesk|remotemanagement|ardagent|sshd|RemoteLogin|RemoteAppleEvents|InternetSharing'

echo ""
echo "=========================================="
echo " DONE  $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
echo "=========================================="
