#!/bin/bash
# Rotate MAC address on WiFi interface to a random locally-administered address.
# Triggers automatically on network change; also run manually before joining untrusted networks.
# Usage: sudo ./rotate_mac.sh [interface]   (default: en0)

set -uo pipefail

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error-guard.sh)
_eg_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
while [ "$_eg_d" != "/" ] && [ ! -f "$_eg_d/lib/error-guard.sh" ]; do _eg_d="$(dirname "$_eg_d")"; done
[ -f "$_eg_d/lib/error-guard.sh" ] && . "$_eg_d/lib/error-guard.sh"; unset _eg_d
command -v guard_run >/dev/null 2>&1 || guard_run() { shift; "$@"; }
command -v guard_throw >/dev/null 2>&1 || guard_throw() { printf 'error-guard: throw: %s\n' "$*" >&2; return 1; }

IFACE="${1:-en0}"

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: must run as root (use sudo)"
    exit 1
fi

if ! ifconfig "$IFACE" &>/dev/null; then
    echo "ERROR: Interface $IFACE not found. Available: $(ifconfig -l)"
    exit 1
fi

# Generate a random locally-administered, unicast MAC
# Locally administered: bit 1 of first octet = 1
# Unicast: bit 0 of first octet = 0
RAND_HEX=$(openssl rand -hex 6)
FIRST_OCTET=$(printf "%02x" $(( (0x${RAND_HEX:0:2} & 0xFE) | 0x02 )))
NEW_MAC="${FIRST_OCTET}:${RAND_HEX:2:2}:${RAND_HEX:4:2}:${RAND_HEX:6:2}:${RAND_HEX:8:2}:${RAND_HEX:10:2}"

OLD_MAC=$(ifconfig "$IFACE" | awk '/ether/{print $2}')
echo "[$(date)] Rotating $IFACE: $OLD_MAC → $NEW_MAC"

# WiFi interfaces must be powered off before MAC change on macOS
IS_WIFI=$(networksetup -listallhardwareports 2>/dev/null | awk "/Hardware Port:/{port=\$0} /Device: $IFACE\$/{if (port ~ /Wi-Fi|Airport/) print \"yes\"; exit}")
if [ "$IS_WIFI" = "yes" ] || networksetup -listallhardwareports 2>/dev/null | grep -A1 "Wi-Fi\|Airport" | grep -q "Device: $IFACE"; then
    echo "  WiFi interface detected — powering off before MAC change"
    guard_run "airport-power" networksetup -setairportpower "$IFACE" off
    sleep 1
fi

# Change MAC
guard_run "mac-change" ifconfig "$IFACE" ether "$NEW_MAC"
STATUS=$?

# Power WiFi back on
if [ "$IS_WIFI" = "yes" ] || networksetup -listallhardwareports 2>/dev/null | grep -A1 "Wi-Fi\|Airport" | grep -q "Device: $IFACE"; then
    guard_run "airport-power" networksetup -setairportpower "$IFACE" on
    sleep 2
fi

if [ $STATUS -ne 0 ]; then
    echo "ERROR: ifconfig ether failed (status $STATUS)"
    exit 1
fi

ACTUAL_MAC=$(ifconfig "$IFACE" | awk '/ether/{print $2}')
if [ "$ACTUAL_MAC" = "$NEW_MAC" ]; then
    echo "[$(date)] SUCCESS: $IFACE MAC is now $ACTUAL_MAC"
else
    echo "[$(date)] WARNING: MAC is $ACTUAL_MAC (expected $NEW_MAC — some Apple Silicon Macs restore MAC on reconnect)"
fi
