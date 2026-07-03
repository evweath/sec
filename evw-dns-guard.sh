#!/bin/bash
# evw-dns-guard.sh — DNS drift guard, runs every 5 minutes.
#
# Enforces the hardened Quad9 (DNSSEC-validating, malware-blocking) resolver
# set on every active network service. If any service has drifted off Quad9
# (e.g. wiped to DHCP/ISP defaults by a reboot or network reset), it re-pins
# the correct servers, flushes the DNS cache, and restarts mDNSResponder.
#
# Mirrors harden.sh section 8. Only acts on drift; a clean tick is a no-op
# apart from the heartbeat + log line.
#
# NAT64 SAFETY (see INCIDENT 2026-07-03): On an IPv6-only / NAT64 network
# (e.g. T-Mobile), IPv4-only hosts are only reachable when the DNS resolver
# performs DNS64 synthesis. Quad9's standard resolver does NOT do DNS64, so
# pinning it there strips the ISP's DNS64 and makes IPv4-only sites (e.g.
# admin.shopify.com) unreachable ("Network is unreachable"). This guard
# therefore DISABLES itself whenever there is no IPv4 default route, i.e. the
# network is IPv6-only and depends on the ISP's DNS64 resolver. It only
# enforces Quad9 on dual-stack networks where doing so is safe.
#
# Deployed to: /usr/local/bin/evw-dns-guard.sh
# LaunchDaemon: com.evw.dns-guard  (root, StartInterval=300)

set -uo pipefail

LOG="/private/var/log/evw-dns-guard.log"
HEARTBEAT="/private/var/run/evw-dns-guard-heartbeat.ts"

# Expected Quad9 servers, in the exact order harden.sh sets them.
EXPECTED=(9.9.9.9 149.112.112.112 2620:fe::fe 2620:fe::9)

log() { printf '[%s] %s\n' "$(date -Iseconds)" "$*" >> "$LOG"; }

# Log rotation: keep last 2 MB
if [[ -f "$LOG" ]] && (( $(wc -c < "$LOG") > 2097152 )); then
    mv "$LOG" "${LOG}.1"
fi

log "--- dns-guard tick ---"

# Heartbeat so a future monitor can confirm we're alive
date +%s > "$HEARTBEAT" 2>/dev/null

# NAT64 safety gate: if there is no IPv4 default route, this is an IPv6-only
# network that relies on the ISP's DNS64 resolver to reach IPv4-only hosts.
# Pinning Quad9 (no DNS64) there breaks connectivity, so stand down entirely.
if ! netstat -rn -f inet 2>/dev/null | grep -qE '^default'; then
    log "STAND DOWN: no IPv4 default route — IPv6-only/NAT64 network; leaving ISP DNS64 in place"
    exit 0
fi

# Normalized, sorted expected set for comparison
expected_norm=$(printf '%s\n' "${EXPECTED[@]}" | sort | tr '\n' ' ')

changed=0

while IFS= read -r svc; do
    # Skip blanks and disabled services (prefixed with *)
    [[ -n "$svc" && "$svc" != \** ]] || continue

    current=$(networksetup -getdnsservers "$svc" 2>/dev/null)

    # "There aren't any DNS Servers set on X." => treat as empty
    if [[ "$current" == *"aren't any"* ]]; then
        current_norm=""
    else
        current_norm=$(printf '%s\n' "$current" | sort | tr '\n' ' ')
    fi

    if [[ "$current_norm" != "$expected_norm" ]]; then
        log "DRIFT on '$svc': had [${current_norm:-<none>}] expected [${expected_norm}]"
        if networksetup -setdnsservers "$svc" "${EXPECTED[@]}" 2>>"$LOG"; then
            log "  re-pinned Quad9 on '$svc'"
            changed=1
        else
            log "  ERROR: failed to set DNS on '$svc'"
        fi
    fi
done < <(networksetup -listallnetworkservices 2>/dev/null | tail -n +2)

if (( changed )); then
    dscacheutil -flushcache 2>/dev/null
    killall -HUP mDNSResponder 2>/dev/null
    log "cache flushed + mDNSResponder restarted"
else
    log "OK: all services on Quad9"
fi

exit 0
