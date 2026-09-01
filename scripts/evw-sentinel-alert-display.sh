#!/bin/bash
# evw-sentinel-alert-display.sh — live mac-sentinel alert terminal.
#
# Opened automatically in a new Terminal window at every login/boot by the
# com.evw.sentinel-alert-term LaunchAgent. Prints the full log-file locations
# at the top, then displays each new alert as a NUMBERED entry (numbering
# restarts at 1 every boot). Everything displayed is mirrored to the display
# log: /Users/evw/Library/Logs/mac-sentinel-alert-display.log
FEED=/Users/evw/Library/Logs/mac-sentinel-alert-feed.log
DISPLAY_LOG=/Users/evw/Library/Logs/mac-sentinel-alert-display.log
mkdir -p /Users/evw/Library/Logs

clear
{
echo "================================================================================"
echo " mac-sentinel SECURITY ALERTS — live display"
echo " Display log (this content): $DISPLAY_LOG"
echo " Alert feed (source):        $FEED"
echo " Numbering restarts at 1 each boot. Session start: $(date '+%A, %B %d, %Y %I:%M:%S %p')"
echo "================================================================================"
} | tee -a "$DISPLAY_LOG"

n=0
# tail from the END of the feed: only NEW alerts get numbered this boot.
tail -n 0 -F "$FEED" 2>/dev/null | while IFS= read -r line; do
    [ -z "$line" ] && continue
    n=$((n+1))
    printf '#%d  %s\n' "$n" "$line" | tee -a "$DISPLAY_LOG"
done
