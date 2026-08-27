#!/bin/bash
OUTPUT=~/ls-full-dump-$(date +%Y%m%d-%H%M%S).txt

echo "========================================" > "$OUTPUT"
echo "CONNECTION DUMP — $(date)" >> "$OUTPUT"
echo "========================================" >> "$OUTPUT"

echo -e "\n\n[1] ALL CONNECTIONS (lsof)" >> "$OUTPUT"
echo "PROCESS | PID | USER | FD | TYPE | DEVICE | SIZE | NODE | ADDRESS" >> "$OUTPUT"
echo "------------------------------------------------------------------------" >> "$OUTPUT"
sudo lsof -i -n -P >> "$OUTPUT"

echo -e "\n\n[2] NETSTAT — ALL STATES" >> "$OUTPUT"
echo "------------------------------------------------------------------------" >> "$OUTPUT"
netstat -an -p tcp >> "$OUTPUT"
netstat -an -p udp >> "$OUTPUT"

echo -e "\n\n[3] NETTOP SNAPSHOT" >> "$OUTPUT"
echo "------------------------------------------------------------------------" >> "$OUTPUT"
sudo nettop -P -t wifi -t wired -t external -c -n -l 1 >> "$OUTPUT" 2>/dev/null

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
sudo lsof -i -n -P | awk 'NR>1 {print $1, $2, $3}' | sort -u >> "$OUTPUT"

echo -e "\n\n[6] DNS CONNECTIONS ONLY" >> "$OUTPUT"
echo "------------------------------------------------------------------------" >> "$OUTPUT"
sudo lsof -i :53 -n -P >> "$OUTPUT"

echo "Dump complete: $OUTPUT"
