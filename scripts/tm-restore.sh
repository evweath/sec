#!/bin/bash
# tm-restore.sh — restore folders OUT of a Time Machine backup with FULL access,
# WITHOUT filling the Mac's internal disk, WITH an automatic troubleshooting
# ladder for the tightly-structured TM destination.
#
# Per folder, strictly one at a time:
#   1. copy from the (read-only) TM backup -> Desktop staging
#   2. fix locks (uchg/schg), strip ACLs, chown to you, grant u+rwX
#   3. copy back onto the TM DISK at <TMVOL>/TM-Restored/<ts>/ (OUTSIDE the
#      protected backup bundle)
#   4. verify file counts, then DELETE the staging copy of THAT folder before
#      starting the next one — staging never accumulates (KEEP=1 to retain)
#
# TROUBLESHOOTING LADDER (every remedy is logged as [TSHOOT]):
#   S1 backup root missing   -> scan /Volumes/.timemachine for ANY snapshots,
#                               print what IS available, precise guidance
#   S2 backup unreadable     -> sample-read probe; on EPERM print exact FDA
#                               (Full Disk Access) instructions for the terminal
#   S3 dest not writable     -> auto `mount -uw <TMVOL>` then re-probe
#   S4 copy engine failure   -> rsync -> ditto --rsrc -> cp -Rp (per folder)
#   S5 verify mismatch       -> second rsync pass; still bad -> write the
#                               missing-files list into the dest for diagnosis,
#                               staging KEPT for inspection
#   S6 staging disk pressure -> du-based guard: folder skipped (logged) if it
#                               would exceed free space +10% headroom
#   S7 dest disk pressure    -> du-of-staging vs free(dest) guard before copy-back
# Log + manifest + diagnostics live in the TM-disk destination (tiny files),
# so the Desktop staging dir is REMOVED when the run finishes clean.
#
# Fully offline; hours-safe; resumable (re-run with same STAGE dir — .done
# markers in the DEST skip finished folders; partial files resume via rsync).
#
# MODES:
#   sudo bash tm-restore.sh "<folder-in-backup>" [more...]   # explicit folders
#   sudo bash tm-restore.sh --all        # EVERY subfolder of the backup Users dir
#   ALL_ROOT=".../Macintosh HD - Data" sudo bash tm-restore.sh --all
#                                        # truly EVERYTHING (system included)
#   sudo bash tm-restore.sh              # list backup root + detected volume
# In --all mode folders are processed OLDEST (mtime) FIRST -> newest last.
#
# ENV:  TMVOL=/Volumes/passport1  KEEP=1  STAGE=<dir>
#
# PREREQUISITES: Terminal/iTerm WITH Full Disk Access (System Settings >
# Privacy & Security > Full Disk Access); sudo.
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
KEEP="${KEEP:-0}"
FAILED=()
LOG=/dev/null   # real log path set after DEST_ROOT exists; early msgs -> stdout

say()  { printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }
log()  { say "$*" | tee -a "$LOG"; }
tshoot(){ say "[TSHOOT] $*" | tee -a "$LOG"; }

[ "$(id -u)" -ne 0 ] && { echo "ERROR: run with sudo"; exit 1; }

# ── STEP 1: backup root exists? else AUTO-FAILOVER to newest available ───────
if [ ! -d "$TM_BACKUP_ROOT" ]; then
    tshoot "default snapshot unavailable — auto-scanning /Volumes/.timemachine"
    CAND=$(find /Volumes/.timemachine -maxdepth 4 -type d -name "* - Data" 2>/dev/null | sort | tail -1)
    if [ -n "$CAND" ]; then
        TM_BACKUP_ROOT="$CAND"
        tshoot "failover: using $TM_BACKUP_ROOT"
    else
        say "ERROR: no TM backup found anywhere (drive attached? check /Volumes/)"
        exit 1
    fi
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
[ -z "$TMVOL" ] && { say "ERROR: cannot autodetect live TM volume. Pass TMVOL=/Volumes/<name>"; exit 1; }

# ── STEP 2: backup READABLE? (auto-retry, then exact FDA guidance) ───────────
probe=""; attempt=0
while [ $attempt -lt 3 ]; do
    probe=$(find "$TM_BACKUP_ROOT" -type f 2>/dev/null | head -1)
    [ -n "$probe" ] && head -c 1 "$probe" >/dev/null 2>&1 && break
    attempt=$((attempt+1))
    tshoot "read probe failed (attempt $attempt/3) — retrying in 10s (drive settling?)"
    sleep 10
done
if [ -z "$probe" ] || ! head -c 1 "$probe" >/dev/null 2>&1; then
    say "ERROR: cannot read files inside the backup (probe: ${probe:-none})"
    say "[TSHOOT] this is macOS privacy protection (TCC), not permissions."
    say "[TSHOOT] grant FULL DISK ACCESS to the app running this script:"
    say "[TSHOOT]   System Settings > Privacy & Security > Full Disk Access > + Terminal (or iTerm)"
    say "[TSHOOT] then start a NEW terminal window and re-run."
    exit 1
fi
say "ok: backup readable (probe ok)"

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

# ── STEP 3: staging + destination writable? (auto mount -uw remedy) ──────────
mkdir -p "$STAGE" || { say "ERROR: cannot create $STAGE"; exit 1; }
DEST_ROOT="$TMVOL/TM-Restored/$TS"
if ! mkdir -p "$DEST_ROOT" 2>/dev/null; then
    tshoot "dest not writable — trying: mount -uw $TMVOL"
    mount -uw "$TMVOL" 2>/dev/null
    if ! mkdir -p "$DEST_ROOT" 2>/dev/null; then
        say "ERROR: still cannot write $DEST_ROOT after mount -uw"
        say "[TSHOOT] run this from a Full-Disk-Access Terminal (removable volumes are TCC-protected too)"
        exit 1
    fi
    tshoot "mount -uw worked — dest writable now"
fi

LOG="$DEST_ROOT/restore.log"; touch "$LOG" || { say "ERROR: cannot write log in $DEST_ROOT"; exit 1; }

log "=== tm-restore started (resume=$RESUMING keep=$KEEP) ==="
log "stage: $STAGE (deleted per-folder after verified copy-back)"
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

# ── copy engine ladder: rsync -> ditto -> cp ─────────────────────────────────
copy_tree() { # $1=src $2=dst  -> rc 0 ok
    rsync -a --stats "$1/" "$2/" >> "$LOG" 2>&1
    rc=$?
    if [ $rc -eq 23 ] || [ $rc -eq 24 ]; then
        tshoot "rsync partial ($rc) on $1 — some files unreadable, continuing with what copied"
        return 0
    fi
    if [ $rc -eq 0 ]; then return 0; fi
    tshoot "rsync failed (rc=$rc) on $1 — falling back to ditto"
    ditto --rsrc "$1" "$2" >> "$LOG" 2>&1 && return 0
    tshoot "ditto failed on $1 — falling back to cp -Rp"
    mkdir -p "$2" && cp -Rp "$1/" "$2/" >> "$LOG" 2>&1 && return 0
    return 1
}

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
printf '%s\n' "${WORK[@]}" > "$DEST_ROOT/MANIFEST.txt"

total=${#WORK[@]}; i=0; done_cnt=0; copied=0
for SRC in "${WORK[@]}"; do
    i=$((i+1))
    name=$(basename "$SRC")
    marker="$DEST_ROOT/.done-$(echo "$SRC" | shasum | cut -c1-12)"
    if [ -f "$marker" ]; then
        log "[$i/$total] SKIP (done): $SRC"; done_cnt=$((done_cnt+1)); continue
    fi
    if [ ! -e "$SRC" ]; then
        log "[$i/$total] SKIP missing: $SRC"; FAILED+=("$SRC (missing)"); continue
    fi

    # S6: staging disk guard
    need_kb=$(du -sk "$SRC" 2>/dev/null | awk '{print $1}')
    free_kb=$(df -k "$STAGE" | tail -1 | awk '{print $4}')
    if [ -n "$need_kb" ] && [ "$need_kb" -gt 0 ] && [ $((need_kb + need_kb/10)) -ge "$free_kb" ]; then
        log "[$i/$total] SKIP too-large: $SRC needs ~$((need_kb/1024))MB, only $((free_kb/1024))MB free on staging disk"
        FAILED+=("$SRC (insufficient staging space)"); continue
    fi

    dst_stage="$STAGE/$name"
    log "[$i/$total] COPY $SRC -> $dst_stage (~$(( ${need_kb:-0}/1024 ))MB)"
    if ! copy_tree "$SRC" "$dst_stage"; then
        log "[$i/$total] FAIL all copy engines: $SRC"; FAILED+=("$SRC (copy engines)"); continue
    fi

    s_cnt=$(count_files "$SRC"); d_cnt=$(count_files "$dst_stage")
    # S5: one automatic second pass on mismatch (rsync resumes)
    if [ "$d_cnt" -ne "$s_cnt" ]; then
        tshoot "count mismatch (src=$s_cnt got=$d_cnt) — second rsync pass"
        rsync -a "$SRC/" "$dst_stage/" >> "$LOG" 2>&1
        d_cnt=$(count_files "$dst_stage")
    fi
    if [ "$d_cnt" -ne "$s_cnt" ]; then
        tshoot "still mismatched after retry (src=$s_cnt got=$d_cnt) — writing missing-files list"
        find "$SRC" -type f 2>/dev/null | sed "s|^$SRC/||" | sort > "$DEST_ROOT/.src-list-$$"
        (cd "$dst_stage" && find . -type f | sed 's|^\./||' | sort) > "$DEST_ROOT/.dst-list-$$"
        comm -23 "$DEST_ROOT/.src-list-$$" "$DEST_ROOT/.dst-list-$$" > "$DEST_ROOT/MISSING-$name.txt"
        rm -f "$DEST_ROOT/.src-list-$$" "$DEST_ROOT/.dst-list-$$"
        tshoot "missing files listed in $DEST_ROOT/MISSING-$name.txt"
    fi
    log "[$i/$total] stage verify: src=$s_cnt files copied=$d_cnt files"
    fix_perms "$dst_stage"

    # S7: destination disk guard
    stage_kb=$(du -sk "$dst_stage" 2>/dev/null | awk '{print $1}')
    dfree_kb=$(df -k "$DEST_ROOT" | tail -1 | awk '{print $4}')
    if [ -n "$stage_kb" ] && [ "$stage_kb" -gt 0 ] && [ $((stage_kb + stage_kb/10)) -ge "$dfree_kb" ]; then
        log "[$i/$total] FAIL: dest full — $name needs ~$((stage_kb/1024))MB, $((dfree_kb/1024))MB free on $TMVOL"
        FAILED+=("$SRC (dest full)"); continue
    fi

    log "[$i/$total] COPY-BACK -> $DEST_ROOT/$name"
    if rsync -a "$dst_stage/" "$DEST_ROOT/$name/" >> "$LOG" 2>&1; then
        fix_perms "$DEST_ROOT/$name"
        if [ "$KEEP" != "1" ]; then
            if [ "$d_cnt" -eq "$s_cnt" ]; then
                rm -rf "$dst_stage" && log "[$i/$total] staging removed (verified $d_cnt files)"
            else
                log "[$i/$total] WARN: mismatch — KEEPING staging for inspection: $dst_stage"
            fi
        fi
        touch "$marker"; copied=$((copied+1))
    else
        tshoot "copy-back failed for $name — trying mount -uw $TMVOL and retrying once"
        mount -uw "$TMVOL" 2>/dev/null
        if rsync -a "$dst_stage/" "$DEST_ROOT/$name/" >> "$LOG" 2>&1; then
            tshoot "copy-back retry succeeded"
            fix_perms "$DEST_ROOT/$name"; touch "$marker"; copied=$((copied+1))
        else
            log "[$i/$total] FAIL copy-back $name (after mount -uw retry)"
            FAILED+=("$SRC (copy-back)"); continue
        fi
    fi
done

chown -R "$USER_NAME":staff "$TMVOL/TM-Restored" 2>/dev/null
chmod -R u+rwX "$TMVOL/TM-Restored" 2>/dev/null

rmdir "$STAGE" 2>/dev/null && log "staging dir removed (empty)" || true

log "=== DONE: $copied copied, $done_cnt skipped-done, ${#FAILED[@]} failed of $total ==="
if [ ${#FAILED[@]} -gt 0 ]; then
    log "FAILURES: ${FAILED[*]}"
    echo "Some folders failed — see $LOG"
    exit 1
fi
echo "OK: restored folders at $DEST_ROOT (full access, permissions fixed)"
[ "$KEEP" != "1" ] && echo "OK: no restore files left on the Desktop"
