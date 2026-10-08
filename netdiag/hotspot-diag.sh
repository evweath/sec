#!/bin/bash
# hotspot-diag.sh — capture full Wi-Fi/DHCP/routing state while connected to
# the Android hotspot (the broken network). Run it WHILE on the hotspot, then
# switch back to working Wi-Fi and hand the log to the agent.
#
# Usage:  bash ~/dev/security/netdiag/hotspot-diag.sh
# Output: netdiag/logs/hotspot-diag-YYYYMMDD-HHMMSS.txt

set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="$DIR/logs/hotspot-diag-$(date +%Y%m%d-%H%M%S).txt"
mkdir -p "$DIR/logs"

{
    echo "# hotspot-diag — $(date -u +%Y-%m-%dT%H:%M:%SZ) local $(date -Iseconds)"
    echo ""

    echo "== current Wi-Fi network (system_profiler) =="
    system_profiler SPAirPortDataType 2>/dev/null \
        | sed -n '/Current Network Information/,/^ *Other Local Wi-Fi Networks/p'
    echo ""

    echo "== ipconfig getsummary en0 (DHCP lease) =="
    ipconfig getsummary en0 2>&1
    echo ""

    echo "== ipconfig getpacket en0 (raw DHCP options: router, mask, lease) =="
    ipconfig getpacket en0 2>&1
    echo ""

    echo "== ifconfig en0 =="
    ifconfig en0 2>&1
    echo ""

    echo "== netstat -rn -f inet (default route present?) =="
    netstat -rn -f inet 2>&1 | head -20
    echo ""

    echo "== route -n get default =="
    route -n get default 2>&1
    echo ""

    echo "== route -n get 1.1.1.1 =="
    route -n get 1.1.1.1 2>&1
    echo ""

    echo "== arp -an (is the gateway resolving?) =="
    arp -an 2>&1
    echo ""

    GW=$(netstat -rn -f inet 2>/dev/null | awk '$1=="default"{print $2; exit}')
    echo "== gateway guess: ${GW:-NONE} =="
    if [ -n "${GW:-}" ]; then
        echo "-- ping -c3 -t5 gateway $GW --"
        ping -c3 -t5 "$GW" 2>&1
    else
        echo "(no default route — pinging DHCP siaddr candidates instead)"
        for c in $(ipconfig getpacket en0 2>/dev/null | awk '/server_identifier|router/ {gsub(/[{}]/,""); print $NF}'); do
            echo "-- ping -c3 -t5 $c --"
            ping -c3 -t5 "$c" 2>&1
        done
    fi
    echo ""

    echo "== ping -c3 -t5 1.1.1.1 (raw IPv4, no DNS) =="
    ping -c3 -t5 1.1.1.1 2>&1
    echo ""

    echo "== ping6 -c3 2606:4700:4700::1111 (raw IPv6 — T-Mobile is v6-only + 464XLAT; v6 pass + v4 fail = phone XLAT broken) =="
    ping6 -c3 2606:4700:4700::1111 2>&1
    echo ""

    echo "== scutil --dns (first resolvers) =="
    scutil --dns 2>&1 | grep -E "nameserver\[" | sort -u | head -8
    echo ""

    echo "== pf autoblock table (needs sudo; skipped if unavailable) =="
    sudo -n pfctl -t auto_evw_block -T show 2>&1 | head -20
    echo ""

    echo "== self-assigned check =="
    if ifconfig en0 | grep -q "inet 169\.254\."; then
        echo "** SELF-ASSIGNED 169.254.x.x — DHCP never answered (phone-side failure) **"
    else
        echo "IP is not link-local: $(ifconfig en0 | awk '/inet /{print $2}')"
    fi
} > "$LOG" 2>&1

echo "wrote $LOG"
grep -E "SELF-ASSIGNED|yiaddr|default |status:" "$LOG" | head -8
