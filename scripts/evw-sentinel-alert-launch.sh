#!/bin/bash
# evw-sentinel-alert-launch.sh — spawn the sentinel alert terminal via
# AppleScript so we can size it: 1500 columns x 20 rows (macOS clamps to the
# screen width) with normal scrollback — keeps every alert on its own line.
/usr/bin/osascript <<'OSA'
tell application "Terminal"
    activate
    do script "/usr/local/bin/evw-sentinel-alert-display.sh"
    delay 1
    set number of columns of front window to 1500
    set number of rows of front window to 20
end tell
OSA
