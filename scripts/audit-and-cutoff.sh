#!/bin/bash
# Audit and cut-off of remote-access avenues
# Date: 2026-05-19
# Auth: user-authorized (Yes — full cut-off + audit)
# All output is logged to audit-and-cutoff.log

set -u

# Log captures /etc/sudoers and TCC grant tables — keep it owner-only.
umask 077

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error-guard.sh)
_eg_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
while [ "$_eg_d" != "/" ] && [ ! -f "$_eg_d/lib/error-guard.sh" ]; do _eg_d="$(dirname "$_eg_d")"; done
[ -f "$_eg_d/lib/error-guard.sh" ] && . "$_eg_d/lib/error-guard.sh"; unset _eg_d
command -v guard_run >/dev/null 2>&1 || guard_run() { shift; "$@"; }
command -v guard_throw >/dev/null 2>&1 || guard_throw() { printf 'error-guard: throw: %s\n' "$*" >&2; return 1; }

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
guard_run "launchctl-print-disabled" launchctl print-disabled system 2>&1 | grep -i -E 'screensharing|remotedesk|remotemanagement|ardagent|sshd|RemoteLogin|RemoteAppleEvents|InternetSharing|com.apple.ssh|com.apple.smbd|com.apple.AppleFileServer' || echo "(no matches)"

section "Sharing-related launchd services that are LOADED"
guard_run "launchctl-print-system" launchctl print system 2>&1 | grep -i -E 'screensharing|remotedesk|remotemanagement|ardagent|sshd|RemoteLogin|RemoteAppleEvents|InternetSharing|com.apple.ssh' | head -40

section "All listening TCP sockets (sudo lsof)"
lsof -nP -iTCP -sTCP:LISTEN 2>&1 | head -80

section "All UDP listeners (sudo lsof)"
lsof -nP -iUDP 2>&1 | grep -v '\->' | head -60

section "TCC: Screen Capture grants"
guard_run "tcc-screencapture" sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT client, auth_value, datetime(last_modified,'unixepoch') AS modified FROM access WHERE service='kTCCServiceScreenCapture' ORDER BY last_modified DESC;" 2>&1

section "TCC: Accessibility grants"
guard_run "tcc-accessibility" sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT client, auth_value, datetime(last_modified,'unixepoch') AS modified FROM access WHERE service='kTCCServiceAccessibility' ORDER BY last_modified DESC;" 2>&1

section "TCC: ListenEvent (input monitoring) grants"
guard_run "tcc-listenevent" sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT client, auth_value, datetime(last_modified,'unixepoch') AS modified FROM access WHERE service='kTCCServiceListenEvent' ORDER BY last_modified DESC;" 2>&1

section "TCC: PostEvent (synthetic input) grants"
guard_run "tcc-postevent" sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
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
if [ "${BEFORE##*: }" = "On" ]; then
  # systemsetup -setremotelogin asks an interactive "(yes/no)?" confirmation;
  # with stdin at EOF (e.g. run from security-menu.sh) it re-prompts forever.
  # Feed it "yes" so the prompt can never spin (10MB-log incident 2026-08-31).
  echo yes | guard_run "set-remotelogin-off" systemsetup -setremotelogin off 2>&1
else
  echo "(already off — nothing to do)"
fi
AFTER=$(systemsetup -getremotelogin 2>&1)
echo "after:  $AFTER"

section "DISABLE: Remote Apple Events"
BEFORE=$(systemsetup -getremoteappleevents 2>&1)
echo "before: $BEFORE"
guard_run "set-remoteappleevents-off" systemsetup -setremoteappleevents off 2>&1
AFTER=$(systemsetup -getremoteappleevents 2>&1)
echo "after:  $AFTER"

section "DISABLE: ARD / Remote Management (kickstart -deactivate)"
echo "before:" ; /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status 2>&1
guard_run "ard-kickstart-deactivate" /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart \
  -deactivate -configure -access -off 2>&1
echo "after:" ; /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status 2>&1

section "DISABLE: Screen Sharing (com.apple.screensharing)"
guard_run "launchctl-disable-screensharing" launchctl disable system/com.apple.screensharing 2>&1
launchctl bootout system/com.apple.screensharing 2>&1 || echo "(bootout: already inactive or SIP-protected; disable persists across reboot)"
guard_run "launchctl-print-disabled" launchctl print-disabled system 2>&1 | grep -i 'screensharing' || echo "(disabled state lookup failed)"

section "DISABLE: Internet Sharing (com.apple.nat NAT.Enabled=0)"
CURRENT=$(defaults read /Library/Preferences/SystemConfiguration/com.apple.nat NAT 2>&1)
echo "before: $CURRENT"
# Set NAT.Enabled = 0 if NAT dict exists; if not, no action needed
if defaults read /Library/Preferences/SystemConfiguration/com.apple.nat NAT >/dev/null 2>&1 ; then
  nat_disable() {
    /usr/libexec/PlistBuddy -c "Set :NAT:Enabled false" /Library/Preferences/SystemConfiguration/com.apple.nat.plist 2>&1 \
      || /usr/libexec/PlistBuddy -c "Set :NAT:Enabled 0" /Library/Preferences/SystemConfiguration/com.apple.nat.plist 2>&1 \
      || echo "(no Enabled key to set — Internet Sharing was likely never configured)"
  }
  guard_run "nat-disable" nat_disable
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
guard_run "launchctl-print-disabled" launchctl print-disabled system 2>&1 | grep -i -E 'screensharing|remotedesk|remotemanagement|ardagent|sshd|RemoteLogin|RemoteAppleEvents|InternetSharing'

echo ""
echo "=========================================="
echo " DONE  $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
echo "=========================================="
