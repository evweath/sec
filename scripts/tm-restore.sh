#!/bin/bash
# tm-restore.sh — restore folders OUT of a Time Machine backup with FULL access.
#
# Fully offline; safe to run for HOURS; resumable (re-run with the same STAGE
# dir — finished folders are skipped via .done markers, partial files resume
# via rsync).
#
#   1. Copies each folder from the (read-only) TM backup to
#      ~/Desktop/TM-Restore-<timestamp>/ via rsync
#   2. Fixes copies for full access: clears locks (uchg/schg), strips ACLs,
#      chowns to you, grants u+rwX
#   3. Copies the fixed folders back onto the TM DISK at
#      <TMVOL>/TM-Restored/<timestamp>/  (OUTSIDE the protected backup bundle)
#      MOVE=1 deletes the Desktop staging copy after a verified copy-back
#
# MODES:
#   sudo bash tm-restore.sh "<folder-in-backup>" [more...]   # explicit folders
#   sudo bash tm-restore.sh --all                            # EVERY subfolder of
#                                                            # the backup's Users dir
#   ALL_ROOT=".../Macintosh HD - Data" sudo bash tm-restore.sh --all
#                                                            # truly EVERYTHING
#                                                            # (system included)
#   sudo bash tm-restore.sh                                  # list backup root
# In --all mode folders are processed OLDEST (mtime) FIRST -> newest last.
#
# ENV:
#   TMVOL=/Volumes/passport1   override live-volume autodetect
#   MOVE=1                     remove Desktop staging after verified copy-back
#   STAGE=/Users/evw/Desktop/TM-Restore-<ts>   resume a previous run
#
# PREREQUISITES: run in Terminal/iTerm WITH Full Disk Access (System Settings >
# Privacy & Security > Full Disk Access) — TM backups AND removable volumes
# refuse access otherwise, even for root. If the TM volume mounted read-only:
#   sudo mount -uw /Volumes/passport1
#
# Default backup root (this Mac, 2026-05-02 snapshot):
TM_BACKUP_ROOT="/Volumes/.timemachine/317DF289-05E6-40C6-B712-4F6D8138FA50/2026-05-02-111543.backup/2026-05-02-111543.backup/Macintosh HD - Data"

set -uo pipefail

TS=$(date +%Y%m%d-%H%M%S)
USER_NAME="${SUDO_USER:-evw}"
USER_HOME=$(dscl . -read "/Users/$USER_NAME" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
[ -z "$USER_HOME" ] && USER_HOME="/Users/$USER_NAME"
RESUMING=0
if [ -n "${STAGE:-}" ]; then
    RESUMING=1
    TS=$(basename "$STAGE" | sed 's/^TM-Restore-//')
fi
STAGE="${STAGE:-$USER_HOME/Desktop/TM-Restore-$TS}"
MOVE="${MOVE:-0}"
FAILED=()

log() { printf '[%s] %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG"; }

[ "$(id -u)" -ne 0 ] && { echo "ERROR: run with sudo"; exit 1; }

if [ ! -d "$TM_BACKUP_ROOT" ]; then
    echo "ERROR: backup root not found: $TM_BACKUP_ROOT"
    echo "TM drive attached? Check /Volumes/.timemachine/"
    exit 1
fi

# ── autodetect the LIVE Time Machine volume (writable, outside snapshots) ────
TMVOL="${TMVOL:-}"
if [ -z "$TMVOL" ]; then
    uuid=$(echo "$TM_BACKUP_ROOT" | cut -d/ -f4)
    mntline=$(mount | grep -F " on /Volumes/.timemachine/" | grep -F "$uuid" | head -1)
    if echo "$mntline" | grep -q '@'; then
        dev=$(echo "$mntline" | sed -E 's|^[^@]*@([^ ]+) on .*|\1|')
    else
        dev=$(echo "$mntline" | sed -E 's|^([^ ]+) on .*|\1|')
    fi
    base=$(echo "$dev" | sed -E 's/(s[0-9]+)s[0-9]+$/\1/')
    TMVOL=$(mount | grep "^$base on /Volumes/" | grep -v '\.timemachine' \
            | head -1 | sed -E 's|^[^ ]+ on (/Volumes/.*) \(.*|\1|')
fi
[ -z "$TMVOL" ] && { echo "ERROR: cannot autodetect live TM volume. Pass TMVOL=/Volumes/<name>"; exit 1; }

# ── no-arg mode: show what can be restored ───────────────────────────────────
if [ $# -eq 0 ]; then
    echo "Backup root: $TM_BACKUP_ROOT"
    echo "Live TM volume (restore target): $TMVOL"
    echo; echo "Top level of backup:"; ls -la "$TM_BACKUP_ROOT" 2>&1 | head -30
    echo; echo "Users:"; ls -la "$TM_BACKUP_ROOT/Users" 2>&1
    echo; echo "Examples:"
    echo "  sudo bash $0 \"$TM_BACKUP_ROOT/Users/evw/Documents\""
    echo "  sudo bash $0 --all"
    exit 0
fi

mkdir -p "$STAGE" || { echo "ERROR: cannot create $STAGE"; exit 1; }
LOG="$STAGE/restore.log"; touch "$LOG"
DEST_ROOT="$TMVOL/TM-Restored/$TS"
if ! mkdir -p "$DEST_ROOT" 2>/dev/null; then
    echo "ERROR: cannot write $DEST_ROOT"
    echo "Fixes: run from a Full-Disk-Access Terminal; if mounted read-only:"
    echo "  sudo mount -uw $TMVOL"
    exit 1
fi

log "=== tm-restore started (resume=$RESUMING) ==="
log "stage: $STAGE"
log "dest:  $DEST_ROOT"

caffeinate -dims & CAFF=$!
trap 'kill $CAFF 2>/dev/null' EXIT

fix_perms() {
    chflags -R nouchg "$1" 2>/dev/null
    chflags -R noschg "$1" 2>/dev/null
    chmod -R -N "$1" 2>/dev/null
    chown -R "$USER_NAME":staff "$1" 2>/dev/null
    chmod -R u+rwX "$1" 2>/dev/null
}

count_files() { find "$1" -type f 2>/dev/null | wc -l | tr -d ' '; }

# ── build the work list ──────────────────────────────────────────────────────
if [ "${1:-}" = "--all" ]; then
    ALL_ROOT="${ALL_ROOT:-$TM_BACKUP_ROOT/Users}"
    log "ALL MODE: every subfolder of $ALL_ROOT (oldest mtime first)"
    WORK=()
    while IFS= read -r d; do WORK+=("$d"); done < <(
        find "$ALL_ROOT" -mindepth 1 -maxdepth 1 -type d -exec stat -f '%m %N' {} + 2>/dev/null \
        | sort -n | cut -d' ' -f2-)
    log "found ${#WORK[@]} folders"
else
    WORK=("$@")
fi
printf '%s\n' "${WORK[@]}" > "$STAGE/MANIFEST.txt"

total=${#WORK[@]}; i=0; done_cnt=0
for SRC in "${WORK[@]}"; do
    i=$((i+1))
    name=$(basename "$SRC")
    marker="$STAGE/.done-$(echo "$SRC" | shasum | cut -c1-12)"
    if [ -f "$marker" ]; then
        log "[$i/$total] SKIP (done): $SRC"; done_cnt=$((done_cnt+1)); continue
    fi
    if [ ! -e "$SRC" ]; then
        log "[$i/$total] SKIP missing: $SRC"; FAILED+=("$SRC (missing)"); continue
    fi
    dst_stage="$STAGE/$name"
    log "[$i/$total] COPY $SRC -> $dst_stage"
    rsync -a --stats "$SRC/" "$dst_stage/" >> "$LOG" 2>&1
    rc=$?
    { [ $rc -eq 23 ] || [ $rc -eq 24 ]; } && log "WARN: rsync partial ($rc) — some files unreadable, continuing"
    [ $rc -gt 24 ] && { log "FAIL rsync $SRC (rc=$rc)"; FAILED+=("$SRC (rsync $rc)"); continue; }

    s_cnt=$(count_files "$SRC"); d_cnt=$(count_files "$dst_stage")
    log "[$i/$total] stage verify: src=$s_cnt files copied=$d_cnt files"
    fix_perms "$dst_stage"

    log "[$i/$total] COPY-BACK -> $DEST_ROOT/$name"
    if rsync -a "$dst_stage/" "$DEST_ROOT/$name/" >> "$LOG" 2>&1; then
        fix_perms "$DEST_ROOT/$name"
        touch "$marker"
        [ "$MOVE" = "1" ] && [ "$d_cnt" -eq "$s_cnt" ] && rm -rf "$dst_stage" \
            && log "[$i/$total] MOVE: staging removed"
    else
        log "FAIL copy-back $name"; FAILED+=("$SRC (copy-back)"); continue
    fi
done

chown -R "$USER_NAME":staff "$TMVOL/TM-Restored" 2>/dev/null
chmod -R u+rwX "$TMVOL/TM-Restored" 2>/dev/null

log "=== DONE: $done_cnt skipped-done, $((total - done_cnt - ${#FAILED[@]})) copied, ${#FAILED[@]} failed of $total ==="
if [ ${#FAILED[@]} -gt 0 ]; then
    log "FAILURES: ${FAILED[*]}"
    echo "Some folders failed — see $LOG"
    exit 1
fi
echo "OK: Desktop staging: $STAGE"
echo "OK: TM-disk copies:  $DEST_ROOT"
