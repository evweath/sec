#!/bin/bash
# evw-ls-hygiene-guard.sh — [AUTO-EVW-LS] periodic Little Snitch rule hygiene.
#
# Every 5 minutes (persistent across reboots via com.evw.ls-hygiene-guard
# LaunchDaemon): export the LS model, delete clear-cut risk rules (tracker
# allows, OCSP/trustd-killing denies, configd/DHCP denies), plant durable
# tracker denies — and restore-model ONLY when something actually changed
# (ruleset reloads briefly interrupt flows; no-op cycles cost nothing).
#
# Safety (same as manual runs): pre-patch model backup kept per applied change
# in /var/log/mac-sentinel/ (last 30 kept), per-run undo JSON, and an
# [AUTO-EVW-LS] line appended to AUTO-ACTIONS.md for backtracking.
# Successor to the removed com.evw.ls-watchdog (which ran every 10 min and
# could delete user-approved rules broadly; this one is narrowly targeted).
set -uo pipefail
umask 077

LSCLI="/Applications/Little Snitch.app/Contents/Components/littlesnitch"
HYGIENE="/usr/local/bin/ls-hygiene.py"
INTERVAL=300   # 5 minutes, per user request 2026-09-01
LOGDIR=/var/log/mac-sentinel
LOG=/private/var/log/evw-ls-hygiene-guard.log
mkdir -p "$LOGDIR"

log() { printf '%s %s\n' "$(date -Iseconds)" "$*" >> "$LOG"; }

log "=== evw-ls-hygiene-guard started (PID=$$, interval=${INTERVAL}s) ==="

while true; do
    WORK=$(mktemp -d /var/tmp/ls-hyg.XXXXXXXX) || { sleep "$INTERVAL"; continue; }
    if "$LSCLI" export-model "$WORK/model.json" 2>>"$LOG"; then
        cp "$WORK/model.json" "$WORK/pre.json"
        OUT=$(/usr/bin/python3 "$HYGIENE" "$WORK/model.json" --apply \
              --report "$WORK/report.md" --undo "$WORK/undo.json" 2>>"$LOG")
        DEL=$(echo "$OUT" | sed -n 's/.*DELETE=\([0-9][0-9]*\).*/\1/p'); DEL=${DEL:-0}
        ADD=$(echo "$OUT" | sed -n 's/.*ADD-DENY=\([0-9][0-9]*\).*/\1/p'); ADD=${ADD:-0}
        if [ $((DEL + ADD)) -gt 0 ]; then
            TS=$(date +%Y%m%d-%H%M%S)
            mv "$WORK/pre.json"  "$LOGDIR/ls-model-pre-hygiene-$TS.json"
            cp "$WORK/undo.json" "$LOGDIR/ls-hygiene-undo-$TS.json" 2>/dev/null
            if "$LSCLI" restore-model "$WORK/model.json" 2>>"$LOG"; then
                log "APPLIED: DELETE=$DEL ADD-DENY=$ADD (backup ls-model-pre-hygiene-$TS.json)"
                printf '%s [AUTO-EVW-LS] guard applied: DELETE=%s ADD-DENY=%s undo=%s\n' \
                  "$(date -Iseconds)" "$DEL" "$ADD" "$LOGDIR/ls-hygiene-undo-$TS.json" \
                  >> "$LOGDIR/AUTO-ACTIONS.md"
            else
                log "ERROR: restore-model failed — pre-patch backup at $LOGDIR/ls-model-pre-hygiene-$TS.json"
            fi
            # prune old backups, keep last 30
            ls -t "$LOGDIR"/ls-model-pre-hygiene-*.json 2>/dev/null | tail -n +31 | xargs rm -f 2>/dev/null
        else
            log "clean (no risk rules)"
        fi
    else
        log "ERROR: export-model failed (LS CLI access disabled?)"
    fi
    rm -rf "$WORK"
    sleep "$INTERVAL"
done
