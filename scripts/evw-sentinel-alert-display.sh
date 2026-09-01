#!/bin/bash
# evw-sentinel-alert-display.sh — live mac-sentinel alert terminal.
#
# Opened automatically at every login/boot (via evw-sentinel-alert-launch.sh /
# com.evw.sentinel-alert-term LaunchAgent) in a 1500x20 scrollable Terminal so
# each alert stays on ONE line.
#
# Colors (2026-09-01 request): CRITICAL = red, WARNING = yellow, INFO = plain.
# Header prints the full log locations. Entries numbered from 1 each boot.
# Everything displayed is mirrored PLAIN-TEXT (no color codes) to:
#   /Users/evw/Library/Logs/mac-sentinel-alert-display.log
FEED=/Users/evw/Library/Logs/mac-sentinel-alert-feed.log
DISPLAY_LOG=/Users/evw/Library/Logs/mac-sentinel-alert-display.log
mkdir -p /Users/evw/Library/Logs

RED=$'\033[1;31m'; YLW=$'\033[1;33m'; NC=$'\033[0m'

# Resize our own window via xterm escape sequence (DECSLPP rows;cols) —
# no AppleScript/Apple events, so no TCC Automation consent is required.
printf '\033[8;20;1500t'
printf '\033]2;mac-sentinel SECURITY ALERTS\007'

clear
{
echo "================================================================================"
echo " mac-sentinel SECURITY ALERTS — live display"
echo " Display log (this content): $DISPLAY_LOG"
echo " Alert feed (source):        $FEED"
echo " Legend: RED = CRITICAL, YELLOW = WARNING, plain = INFO"
echo " Numbering restarts at 1 each boot. Session start: $(date '+%A, %B %d, %Y %I:%M:%S %p')"
echo "================================================================================"
} | tee -a "$DISPLAY_LOG"

n=0
# tail from the END of the feed: only NEW alerts get numbered this boot.
tail -n 0 -F "$FEED" 2>/dev/null | while IFS= read -r line; do
    [ -z "$line" ] && continue
    n=$((n+1))
    entry=$(printf '#%d  %s' "$n" "$line")
    printf '%s\n' "$entry" >> "$DISPLAY_LOG"          # log: plain text
    case "$line" in                                    # terminal: colorized
        *'"severity": "CRITICAL"'*) printf '%s%s%s\n' "$RED" "$entry" "$NC" ;;
        *'"severity": "WARNING"'*)  printf '%s%s%s\n' "$YLW" "$entry" "$NC" ;;
        *)                            printf '%s\n' "$entry" ;;
    esac
done
