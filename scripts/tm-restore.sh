#!/bin/bash
# tm-restore.sh v4 — restore folders OUT of Time Machine backups with FULL
# access, WITHOUT filling the Mac's disk, WITH full access to ALL snapshots on
# the TM disk (not just the few the system auto-mounts).
#
# WHY v4: Finder shows ~20 TM backup folders but Terminal sees only 2-3 —
# those are APFS SNAPSHOTS on the TM volume; macOS auto-mounts only a few under
# /Volumes/.timemachine. This script enumerates ALL snapshots via
# `diskutil apfs listSnapshots` and mounts the rest itself (read-only).
#
# Per folder, strictly one at a time (backup -> Desktop staging -> permission
# fix -> verified copy-back to the TM disk -> staging deleted), so staging
# never accumulates. Automatic troubleshooting ladder, no human input needed
# (see [TSHOOT] log lines): snapshot failover, read probes with retries,
# mount -uw remedies, rsync -> ditto -> cp engine fallback, second-pass
# verify with MISSING-<folder>.txt diagnostics, disk guards on BOTH staging
# and destination. Log/manifest/.done markers live in the TM-disk dest, so the
# Desktop staging dir is REMOVED when the run finishes clean.
#
# MODES:
#   sudo bash tm-restore.sh                          # list backup info + snapshots
#   sudo bash tm-restore.sh "<folder>" [more...]     # from newest snapshot
#   sudo bash tm-restore.sh --all                    # all Users subfolders, newest snapshot
#   sudo bash tm-restore.sh --list-snapshots         # show ALL snapshots on the disk
#   sudo bash tm-restore.sh --snapshot 2026-05-02-111543 --all
#   sudo bash tm-restore.sh --all-snapshots          # EVERY snapshot, oldest first
# Folders always processed OLDEST-mtime-first; snapshots oldest-first in
# --all-snapshots mode.
#
# ENV:  TMVOL=/Volumes/passport1  KEEP=1  STAGE=<dir>
#   ALL_ROOT (default "<backup>/Users" for --all / --all-snapshots)
#
# PREREQUISITES: Terminal/iTerm WITH Full Disk Access + sudo. Mounting
# non-auto-mounted snapshots is TCC-restricted — the script reports EPERM
# precisely if the context lacks FDA.
#
# Default backup root (this Mac): newest auto-mounted snapshot, else newest
# snapshot on the TM volume (auto-mounted or self-mounted).
TM_BACKUP_DEFAULT="/Volumes/.timemachine/317DF289-05E6-40C6-B712-4F6D8138FA50/2026-05-02-111543.backup/2026-05-02-111543.backup/Macintosh HD - Data"

set -uo pipefail

USER_NAME="${SUDO_USER:-evw}"
USER_HOME=$(dscl . -read "/Users/$USER_NAME" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
[ -z "$USER_HOME" ] && USER_HOME="/Users/$USER_NAME"
KEEP="${KEEP:-0}"
TS=$(date +%Y%m%d-%H%M%S)
STAGE="${STAGE:-$USER_HOME/Desktop/TM-Restore-$TS}"
MNT_BASE=/private/var/tmp/tm-restore-mnt
FAILED=()
UMOUNTS=()
LOG=/dev/null

say()  { printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }
log()  { say "$*" | tee -a "$LOG"; }
tshoot(){ say "[TSHOOT] $*" | tee -a "$LOG"; }

[ "$(id -u)" -ne 0 ] && { echo "ERROR: run with sudo"; exit 1; }

# ── resolve TM volume + device (mount table; df lies about .timemachine) ─────
TMVOL="${TMVOL:-}"
mntline=$(mount | grep -F " on /Volumes/.timemachine/" | head -1)
if echo "$mntline" | grep -q '@'; then
    TMDEV=$(echo "$mntline" | sed -E 's|^[^@]*@([^ ]+) on .*|\1|')
else
    TMDEV=$(echo "$mntline" | sed -E 's|^([^ ]+) on .*|\1|')
fi
TMUUID=$(echo "$mntline" | sed -E 's|.* on /Volumes/.timemachine/([^/]+)/.*|\1|')
[ -z "$TMDEV" ] && TMDEV=$(mount | grep -F ".backup" | grep -oE '/dev/disk[0-9]+s[0-9]+' | head -1)
[ -z "$TMVOL" ] && [ -n "$TMDEV" ] && \
    TMVOL=$(mount | grep "^$TMDEV on /Volumes/" | grep -v '\.timemachine' \
            | head -1 | sed -E 's|^[^ ]+ on (/Volumes/.*) \(.*|\1|')
[ -z "${TMVOL:-}" ] && { say "ERROR: cannot find live TM volume. Pass TMVOL=/Volumes/<name>"; exit 1; }
[ -z "$TMDEV" ] && { say "ERROR: cannot find TM device"; exit 1; }
say "TM device: $TMDEV   live volume: $TMVOL"

list_snapshots() {  # oldest first
    diskutil apfs listSnapshots "$TMDEV" 2>/dev/null \
      | awk -F: '/Name:.*com\.apple\.TimeMachine/{gsub(/^[ \t]+/,"",$2); print $2}' | sort
}
snap_date() { echo "$1" | sed 's/com\.apple\.TimeMachine\.\(.*\)\.backup/\1/'; }

# ── resolve a readable root ("* - Data") for a snapshot; mount if needed ─────
snapshot_root() {  # $1=snapname -> echoes root dir, rc 0; rc 1 on failure
    local snap="$1" d mnt root
    d=$(snap_date "$snap")
    # (a) already auto-mounted?
    for u in /Volumes/.timemachine/*/; do
        if [ -d "$u$d.backup" ]; then
            root=$(find "$u$d.backup" -maxdepth 2 -type d -name '* - Data' 2>/dev/null | head -1)
            [ -n "$root" ] && { echo "$root"; return 0; }
        fi
    done
    # (b) mount it ourselves, read-only
    mnt="$MNT_BASE/$d"
    mkdir -p "$mnt"
    if mount -t apfs -o -s="$snap" "$TMDEV" "$mnt" 2>>"$LOG"; then
        UMOUNTS+=("$mnt")
        root=$(find "$mnt" -maxdepth 1 -type d -name '* - Data' 2>/dev/null | head -1)
        [ -z "$root" ] && root="$mnt"
        tshoot "self-mounted snapshot $d at $mnt"
        echo "$root"; return 0
    fi
    tshoot "mount FAILED for $d — if EPERM: this terminal needs Full Disk Access"
    return 1
}

fix_perms() {
    chflags -R nouchg "$1" 2>/dev/null; chflags -R noschg "$1" 2>/dev/null
    chmod -R -N "$1" 2>/dev/null
    chown -R "$USER_NAME":staff "$1" 2>/dev/null
    chmod -R u+rwX "$1" 2>/dev/null
}
count_files() { find "$1" -type f 2>/dev/null | wc -l | tr -d ' '; }

copy_tree() { # engine ladder: rsync -> ditto -> cp
    rsync -a --stats "$1/" "$2/" >> "$LOG" 2>&1
    local rc=$?
    [ $rc -eq 0 ] && return 0
    { [ $rc -eq 23 ] || [ $rc -eq 24 ]; } && { tshoot "rsync partial ($rc) on $1 — continuing"; return 0; }
    tshoot "rsync failed (rc=$rc) on $1 — falling back to ditto"
    ditto --rsrc "$1" "$2" >> "$LOG" 2>&1 && return 0
    tshoot "ditto failed on $1 — falling back to cp -Rp"
    mkdir -p "$2" && cp -Rp "$1/" "$2/" >> "$LOG" 2>&1 && return 0
    return 1
}

# ── per-folder pipeline (backup -> staging -> fix -> copy-back -> delete) ────
process_folder() {  # $1=SRC  $2=DEST_ROOT  $3=idx  $4=total
    local SRC="$1" DEST_ROOT="$2" i="$3" total="$4"
    local name; name=$(basename "$SRC")
    local marker="$DEST_ROOT/.done-$(echo "$SRC" | shasum | cut -c1-12)"
    [ -f "$marker" ] && { log "[$i/$total] SKIP (done): $SRC"; return 0; }
    [ ! -e "$SRC" ] && { log "[$i/$total] SKIP missing: $SRC"; FAILED+=("$SRC (missing)"); return 1; }

    local need_kb free_kb dst_stage s_cnt d_cnt stage_kb dfree_kb
    need_kb=$(du -sk "$SRC" 2>/dev/null | awk '{print $1}')
    free_kb=$(df -k "$STAGE" | tail -1 | awk '{print $4}')
    if [ -n "$need_kb" ] && [ "$need_kb" -gt 0 ] && [ $((need_kb + need_kb/10)) -ge "$free_kb" ]; then
        log "[$i/$total] SKIP too-large: $SRC (~$((need_kb/1024))MB needed, $((free_kb/1024))MB free)"
        FAILED+=("$SRC (staging space)"); return 1
    fi

    dst_stage="$STAGE/$name"
    log "[$i/$total] COPY $SRC (~$(( ${need_kb:-0}/1024 ))MB)"
    if ! copy_tree "$SRC" "$dst_stage"; then
        log "[$i/$total] FAIL all copy engines: $SRC"; FAILED+=("$SRC (engines)"); return 1
    fi
    s_cnt=$(count_files "$SRC"); d_cnt=$(count_files "$dst_stage")
    if [ "$d_cnt" -ne "$s_cnt" ]; then
        tshoot "count mismatch (src=$s_cnt got=$d_cnt) — second rsync pass"
        rsync -a "$SRC/" "$dst_stage/" >> "$LOG" 2>&1
        d_cnt=$(count_files "$dst_stage")
    fi
    if [ "$d_cnt" -ne "$s_cnt" ]; then
        find "$SRC" -type f 2>/dev/null | sed "s|^$SRC/||" | sort > "$DEST_ROOT/.sl"
        (cd "$dst_stage" && find . -type f | sed 's|^\./||' | sort) > "$DEST_ROOT/.dl"
        comm -23 "$DEST_ROOT/.sl" "$DEST_ROOT/.dl" > "$DEST_ROOT/MISSING-$name.txt"
        rm -f "$DEST_ROOT/.sl" "$DEST_ROOT/.dl"
        tshoot "still mismatched — see $DEST_ROOT/MISSING-$name.txt; staging kept"
    fi
    fix_perms "$dst_stage"

    stage_kb=$(du -sk "$dst_stage" 2>/dev/null | awk '{print $1}')
    dfree_kb=$(df -k "$DEST_ROOT" | tail -1 | awk '{print $4}')
    if [ -n "$stage_kb" ] && [ "$stage_kb" -gt 0 ] && [ $((stage_kb + stage_kb/10)) -ge "$dfree_kb" ]; then
        log "[$i/$total] FAIL: dest full for $name"; FAILED+=("$SRC (dest full)"); return 1
    fi

    log "[$i/$total] COPY-BACK -> $DEST_ROOT/$name"
    if ! rsync -a "$dst_stage/" "$DEST_ROOT/$name/" >> "$LOG" 2>&1; then
        tshoot "copy-back failed — mount -uw $TMVOL and retry"
        mount -uw "$TMVOL" 2>/dev/null
        rsync -a "$dst_stage/" "$DEST_ROOT/$name/" >> "$LOG" 2>&1 || {
            log "[$i/$total] FAIL copy-back $name"; FAILED+=("$SRC (copy-back)"); return 1; }
    fi
    fix_perms "$DEST_ROOT/$name"
    if [ "$KEEP" != "1" ] && [ "$d_cnt" -eq "$s_cnt" ]; then
        rm -rf "$dst_stage" && log "[$i/$total] staging removed (verified $d_cnt files)"
    elif [ "$KEEP" != "1" ]; then
        log "[$i/$total] WARN: mismatch — staging kept: $dst_stage"
    fi
    touch "$marker"
    return 0
}

# ── process one snapshot: resolve root, build folder list, run pipeline ──────
process_snapshot() {  # $1=snapname  $2=mode("all"|explicit)  rest=folders
    local snap="$1" mode="$2"; shift 2
    local d root DEST_ROOT
    d=$(snap_date "$snap")
    root=$(snapshot_root "$snap") || { FAILED+=("snapshot $d (unreadable/unmountable)"); return 1; }
    # readable probe with retries
    local probe="" attempt=0
    while [ $attempt -lt 3 ]; do
        probe=$(find "$root" -type f 2>/dev/null | head -1)
        [ -n "$probe" ] && head -c 1 "$probe" >/dev/null 2>&1 && break
        attempt=$((attempt+1)); tshoot "read probe failed ($attempt/3) on $d — retry in 10s"; sleep 10
    done
    if [ -z "$probe" ] || ! head -c 1 "$probe" >/dev/null 2>&1; then
        tshoot "snapshot $d unreadable — Full Disk Access required (System Settings > Privacy & Security)"
        FAILED+=("snapshot $d (TCC)"); return 1
    fi

    DEST_ROOT="$TMVOL/TM-Restored/$d"
    if ! mkdir -p "$DEST_ROOT" 2>/dev/null; then
        tshoot "dest not writable — mount -uw $TMVOL"
        mount -uw "$TMVOL" 2>/dev/null
        mkdir -p "$DEST_ROOT" 2>/dev/null || { FAILED+=("snapshot $d (dest unwritable)"); return 1; }
    fi
    LOG="$DEST_ROOT/restore.log"
    log "=== snapshot $d  root=$root ==="

    local WORK=()
    if [ "$mode" = "all" ]; then
        local ALL_ROOT="${ALL_ROOT:-$root/Users}"
        while IFS= read -r x; do WORK+=("$x"); done < <(
            find "$ALL_ROOT" -mindepth 1 -maxdepth 1 -type d -exec stat -f '%m %N' {} + 2>/dev/null \
            | sort -n | cut -d' ' -f2-)
        log "found ${#WORK[@]} folders under $ALL_ROOT (oldest first)"
    else
        WORK=("$@")
    fi
    printf '%s\n' "${WORK[@]}" > "$DEST_ROOT/MANIFEST.txt"

    local total=${#WORK[@]} i=0
    for SRC in "${WORK[@]}"; do
        i=$((i+1))
        process_folder "$SRC" "$DEST_ROOT" "$i" "$total"
    done
    chown -R "$USER_NAME":staff "$DEST_ROOT" 2>/dev/null
    chmod -R u+rwX "$DEST_ROOT" 2>/dev/null
    log "=== snapshot $d done ==="
}

# ══ main ═════════════════════════════════════════════════════════════════════
mkdir -p "$STAGE" "$MNT_BASE"
caffeinate -dims & CAFF=$!
trap 'kill $CAFF 2>/dev/null; for m in "${UMOUNTS[@]:-}"; do [ -n "$m" ] && umount "$m" 2>/dev/null; done' EXIT

MODE="${1:-}"
case "$MODE" in
  --list-snapshots)
    echo "Snapshots on $TMDEV ($TMVOL):"
    list_snapshots | while read -r s; do
        d=$(snap_date "$s")
        am=""; for u in /Volumes/.timemachine/*/; do [ -d "$u$d.backup" ] && am=" (auto-mounted)"; done
        echo "  $d$am"
    done
    exit 0
    ;;
  "")
    echo "Live TM volume: $TMVOL  device: $TMDEV"
    echo "Snapshots available: $(list_snapshots | wc -l | tr -d ' ')  (newest: $(list_snapshots | tail -1))"
    echo "Run with --all, --all-snapshots, --snapshot <date>, or explicit folder paths."
    exit 0
    ;;
  --all-snapshots)
    for snap in $(list_snapshots); do
        process_snapshot "$snap" all
    done
    ;;
  --snapshot)
    SNAP_IN="${2:?--snapshot needs a date e.g. 2026-05-02-111543}"
    SNAP="com.apple.TimeMachine.$SNAP_IN.backup"
    shift 2
    if [ "${1:-}" = "--all" ]; then process_snapshot "$SNAP" all
    elif [ $# -gt 0 ]; then  process_snapshot "$SNAP" explicit "$@"
    else process_snapshot "$SNAP" all; fi
    ;;
  --all)
    NEWEST=$(list_snapshots | tail -1)
    process_snapshot "$NEWEST" all
    ;;
  *)
    NEWEST=$(list_snapshots | tail -1)
    process_snapshot "$NEWEST" explicit "$@"
    ;;
esac

rmdir "$STAGE" 2>/dev/null && say "staging dir removed (empty)" || true
say "=== RUN DONE: failures: ${#FAILED[@]} ${FAILED[*]:-} ==="
[ ${#FAILED[@]} -gt 0 ] && exit 1 || exit 0
