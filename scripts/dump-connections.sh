#!/bin/bash

set -uo pipefail

# Dump of the full socket table + Little Snitch logs — keep it owner-only.
umask 077

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error-guard.sh)
_eg_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
while [ "$_eg_d" != "/" ] && [ ! -f "$_eg_d/lib/error-guard.sh" ]; do _eg_d="$(dirname "$_eg_d")"; done
[ -f "$_eg_d/lib/error-guard.sh" ] && . "$_eg_d/lib/error-guard.sh"; unset _eg_d
command -v guard_run >/dev/null 2>&1 || guard_run() { shift; "$@"; }
command -v guard_throw >/dev/null 2>&1 || guard_throw() { printf 'error-guard: throw: %s\n' "$*" >&2; return 1; }

OUTPUT=~/ls-full-dump-$(date +%Y%m%d-%H%M%S).txt

echo "========================================" > "$OUTPUT"
echo "CONNECTION DUMP — $(date)" >> "$OUTPUT"
echo "========================================" >> "$OUTPUT"

echo -e "\n\n[1] ALL CONNECTIONS (lsof)" >> "$OUTPUT"
echo "PROCESS | PID | USER | FD | TYPE | DEVICE | SIZE | NODE | ADDRESS" >> "$OUTPUT"
echo "------------------------------------------------------------------------" >> "$OUTPUT"
guard_run "lsof-all" sudo lsof -i -n -P >> "$OUTPUT"

echo -e "\n\n[2] NETSTAT — ALL STATES" >> "$OUTPUT"
echo "------------------------------------------------------------------------" >> "$OUTPUT"
guard_run "netstat-tcp" netstat -an -p tcp >> "$OUTPUT"
guard_run "netstat-udp" netstat -an -p udp >> "$OUTPUT"

echo -e "\n\n[3] NETTOP SNAPSHOT" >> "$OUTPUT"
echo "------------------------------------------------------------------------" >> "$OUTPUT"
guard_run "nettop" sudo nettop -P -t wifi -t wired -t external -c -n -l 1 >> "$OUTPUT" 2>/dev/null

echo -e "\n\n[4] LITTLE SNITCH NATIVE LOGS" >> "$OUTPUT"
echo "------------------------------------------------------------------------" >> "$OUTPUT"
LS_LOG_DIR=~/Library/Logs/Little\ Snitch
if [ -d "$LS_LOG_DIR" ]; then
    cat "$LS_LOG_DIR"/*.log >> "$OUTPUT" 2>/dev/null
else
    echo "No Little Snitch logs found at $LS_LOG_DIR" >> "$OUTPUT"
fi

echo -e "\n\n[5] UNIQUE PROCESSES MAKING CONNECTIONS" >> "$OUTPUT"
echo "------------------------------------------------------------------------" >> "$OUTPUT"
guard_run "lsof-procs" sudo lsof -i -n -P | awk 'NR>1 {print $1, $2, $3}' | sort -u >> "$OUTPUT"

echo -e "\n\n[6] DNS CONNECTIONS ONLY" >> "$OUTPUT"
echo "------------------------------------------------------------------------" >> "$OUTPUT"
guard_run "lsof-dns" sudo lsof -i :53 -n -P >> "$OUTPUT"

echo "Dump complete: $OUTPUT"
