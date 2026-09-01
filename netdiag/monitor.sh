#!/bin/bash
# netdiag/monitor.sh — persistent connectivity monitor.
# Launched with nohup so it survives Kimi/terminal disconnects.
# One line per ~2s cycle; each layer is probed independently so we can tell
# Wi-Fi drops from DNS failures from proxy/filter interference.
DIR="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$DIR/logs"
LOG="$DIR/logs/monitor.log"
AIRPORT="/System/Library/PrivateFrameworks/Apple80211.framework/Resources/airport"
echo "# START $(date '+%F %T') pid=$$" >> "$LOG"
prev=""
while true; do
  ts=$(date '+%F %T'); epoch=$(date +%s)
  gw=$(route -n get default 2>/dev/null | awk '/gateway:/{print $2; exit}')
  [ -z "$gw" ] && gw=none

  gw_ok=FAIL;  [ "$gw" != none ] && ping -c1 -t2 "$gw" >/dev/null 2>&1 && gw_ok=ok
  net_ok=FAIL; ping -c1 -t2 1.1.1.1 >/dev/null 2>&1 && net_ok=ok
  dns_ok=FAIL; dig +time=1 +tries=1 +short one.one.one.one @1.1.1.1 2>/dev/null | grep -q '^1\.' && dns_ok=ok
  sysdns_ok=FAIL; dscacheutil -q host -a name captive.apple.com 2>/dev/null | grep -q ip_address && sysdns_ok=ok
  # HTTPS probe against a known-allowed host. Little Snitch blocks curl to most
  # hosts (incl. captive.apple.com:80), so that probe was constant-FAIL noise.
  code=$(curl -s -o /dev/null -m 5 -w "%{http_code}" https://api.moonshot.cn 2>/dev/null)
  http_ok=FAIL
  [ -n "$code" ] && [ "$code" != "000" ] && http_ok=ok

  wifi=$(ifconfig en0 2>/dev/null | awk '/status:/{print $2}')
  rssi=""
  [ -x "$AIRPORT" ] && rssi=$("$AIRPORT" -I 2>/dev/null | awk '/agrCtlRSSI:/{print $2}')

  state="wifi=${wifi:-?} gw=$gw_ok net=$net_ok dns=$dns_ok sysdns=$sysdns_ok http=$http_ok"
  change=""
  [ -n "$prev" ] && [ "$state" != "$prev" ] && change="*** CHANGE ***"
  echo "$ts ($epoch) $state http_code=${code:-none} rssi=${rssi:-n/a} gwip=$gw $change" >> "$LOG"
  prev="$state"
  sleep 2
done
