#!/bin/bash
# evw-dns-guard.sh — DNS drift guard, runs every 5 minutes.
#
# Enforces the pinned resolver set (1.1.1.1, 1.0.0.1, 8.8.8.8, 9.9.9.9)
# on every active network service. If any service has drifted off the pinned
# set (e.g. wiped to DHCP/ISP defaults by a reboot or network reset), it
# re-pins the correct servers, flushes the DNS cache, and restarts mDNSResponder.
#
# Mirrors harden.sh section 8. Only acts on drift; a clean tick is a no-op
# apart from the heartbeat + log line.
#
# NAT64 SAFETY (see INCIDENT 2026-07-03): On an IPv6-only / NAT64 network
# (e.g. T-Mobile), IPv4-only hosts are only reachable when the DNS resolver
# performs DNS64 synthesis. None of the pinned resolvers do DNS64, so
# pinning them there strips the ISP's DNS64 and makes IPv4-only sites (e.g.
# admin.shopify.com) unreachable ("Network is unreachable"). This guard
# therefore DISABLES itself whenever there is no IPv4 default route, i.e. the
# network is IPv6-only and depends on the ISP's DNS64 resolver. It only
# enforces the pinned set on dual-stack networks where doing so is safe.
#
# Deployed to: /usr/local/bin/evw-dns-guard.sh
# LaunchDaemon: com.evw.dns-guard  (root, StartInterval=300)

set -uo pipefail

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error-guard.sh)
_eg_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
# As root, only trust a root-owned lib: a user-writable ancestor dir (e.g.
# Intel Homebrew's /usr/local) could plant one and have it sourced as root.
_eg_ok() { [ -f "$1" ] && { [ "$EUID" -ne 0 ] || [ "$(stat -f %u "$1" 2>/dev/null)" = "0" ]; }; }
while [ "$_eg_d" != "/" ] && ! _eg_ok "$_eg_d/lib/error-guard.sh"; do _eg_d="$(dirname "$_eg_d")"; done
_eg_ok "$_eg_d/lib/error-guard.sh" && . "$_eg_d/lib/error-guard.sh"; unset _eg_d; unset -f _eg_ok
command -v guard_run >/dev/null 2>&1 || guard_run() { shift; "$@"; }
command -v guard_throw >/dev/null 2>&1 || guard_throw() { printf 'error-guard: throw: %s\n' "$*" >&2; return 1; }
# EVW_GUARD_POLICY unset: launchd one-shot — a tripped breaker aborts (no TTY).

LOG="/private/var/log/evw-dns-guard.log"
HEARTBEAT="/private/var/run/evw-dns-guard-heartbeat.ts"

# Expected DNS servers, in the exact order harden.sh sets them.
EXPECTED=(1.1.1.1 1.0.0.1 8.8.8.8 9.9.9.9)

log() { printf '[%s] %s\n' "$(date -Iseconds)" "$*" >> "$LOG"; }

# Log rotation: keep last 2 MB
if [[ -f "$LOG" ]] && (( $(wc -c < "$LOG") > 2097152 )); then
    guard_run "log-rotate" mv "$LOG" "${LOG}.1"
fi

log "--- dns-guard tick ---"

# Heartbeat so a future monitor can confirm we're alive
date +%s > "$HEARTBEAT" 2>/dev/null

# NAT64 safety gate: if there is no IPv4 default route, this is an IPv6-only
# network that relies on the ISP's DNS64 resolver to reach IPv4-only hosts.
# Pinning the resolver set (no DNS64) there breaks connectivity, so stand down.
if ! netstat -rn -f inet 2>/dev/null | grep -qE '^default'; then
    log "STAND DOWN: no IPv4 default route — IPv6-only/NAT64 network; leaving ISP DNS64 in place"
    exit 0
fi

# Normalized, sorted expected set for comparison
expected_norm=$(printf '%s\n' "${EXPECTED[@]}" | sort | tr '\n' ' ')

changed=0

# If listing services fails, the drift loop below would be a no-op and the
# final "OK" line a lie — detect it and WARN instead.
service_list=$(guard_run "listallnetworkservices" networksetup -listallnetworkservices 2>/dev/null)
if [[ $? -ne 0 || -z "$service_list" ]]; then
    log "WARN: could not list network services — drift check skipped"
    exit 0
fi

while IFS= read -r svc; do
    # Skip blanks and disabled services (prefixed with *)
    [[ -n "$svc" && "$svc" != \** ]] || continue

    current=$(guard_run "getdnsservers" networksetup -getdnsservers "$svc" 2>/dev/null)

    # "There aren't any DNS Servers set on X." => treat as empty
    if [[ "$current" == *"aren't any"* ]]; then
        current_norm=""
    else
        current_norm=$(printf '%s\n' "$current" | sort | tr '\n' ' ')
    fi

    if [[ "$current_norm" != "$expected_norm" ]]; then
        log "DRIFT on '$svc': had [${current_norm:-<none>}] expected [${expected_norm}]"
        if guard_run "setdnsservers" networksetup -setdnsservers "$svc" "${EXPECTED[@]}" 2>>"$LOG"; then
            log "  re-pinned DNS on '$svc'"
            changed=1
        else
            log "  ERROR: failed to set DNS on '$svc'"
        fi
    fi
done < <(printf '%s\n' "$service_list" | tail -n +2)

if (( changed )); then
    guard_run "flushcache" dscacheutil -flushcache 2>/dev/null
    killall -HUP mDNSResponder 2>/dev/null
    log "cache flushed + mDNSResponder restarted"
else
    log "OK: all services on pinned DNS"
fi

exit 0
