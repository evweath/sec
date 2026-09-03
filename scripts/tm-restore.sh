#!/bin/bash
# tm-restore.sh v5 — restore folders OUT of Time Machine backups with FULL
# access, WITHOUT filling the Mac's disk, WITH full access to ALL snapshots on
# the TM disk (not just the few the system auto-mounts).
#
# WHY v4: Finder shows ~20 TM backup folders but Terminal sees only 2-3 —
# those are APFS SNAPSHOTS on the TM volume; macOS auto-mounts only a few under
# /Volumes/.timemachine. This script enumerates ALL snapshots via
# `diskutil apfs listSnapshots` and mounts the rest itself (read-only).
#
# WHY v5 (RESUME AFTER CRASH — no rework): a crash/reboot mid-run is now
# resumable. Just re-run the SAME command; finished work is skipped.
#   * done-markers (.done-<name>-<hash>) are keyed to the folder's path
#     RELATIVE to the snapshot root, so they still match when the snapshot
#     comes back mounted at a DIFFERENT path after a reboot (auto-mounted vs
#     self-mounted). v4 markers (.done-<abshash>) are still honored, so the
#     interrupted run's finished folders stay finished.
#   * a snapshot whose MANIFEST is fully covered by markers is declared
#     .complete WITHOUT mounting it — even if a fresh mount would enumerate
#     a different folder list (auto-mounted vs self-mounted roots differ).
#   * staging is a FIXED dir (~/Desktop/TM-Restore-staging), so a half-copied
#     folder is RESUMED by rsync instead of restarted; staging left behind by
#     a crashed v4 run (timestamped dir on the Desktop) is adopted automatically.
#   * staging records its source snapshot (.snapshot file) — content copied
#     from one snapshot is never mixed into another snapshot's restore set.
#     The check is LAZY (only when a copy actually starts), so completed
#     snapshots that need no staging never disturb a pending resume.
#   * --all resumes the snapshot that has unfinished progress, even if Time
#     Machine has meanwhile created NEWER snapshots. A fully-restored
#     snapshot gets a .complete marker and is skipped from then on.
#   * TM device/volume detection survives "nothing auto-mounted" (the usual
#     post-reboot state): the device is resolved from the live volume's own
#     mount line, and the volume is auto-detected when exactly one
#     /Volumes/*/TM-Restored exists.
#   * --status prints per-snapshot progress (done / remaining folders).
#   * a pid lock (/private/var/tmp/tm-restore.pid) prevents two concurrent runs.
#
# FORCE REDO: delete a folder's .done-<name>-<hash> marker (one folder) or the
# .complete file (whole snapshot) inside $TMVOL/TM-Restored/<date>/.
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
#   sudo bash tm-restore.sh --all                    # EVERY folder on the backed-up
#                                                    # volume (volatile dirs skipped);
#                                                    # auto-resumes interrupted work
#   sudo bash tm-restore.sh --status                 # progress: done / remaining
#   sudo bash tm-restore.sh --list-snapshots         # show ALL snapshots on the disk
#   sudo bash tm-restore.sh --snapshot 2026-05-02-111543 --all
#   sudo bash tm-restore.sh --all-snapshots          # EVERY snapshot, oldest first
# Folders always processed OLDEST-mtime-first; snapshots oldest-first in
# --all-snapshots mode.
#
# ENV:  TMVOL=/Volumes/passport1  KEEP=1
#   STAGE=<dir> (default ~/Desktop/TM-Restore-staging — a FIXED path on
#           purpose, so a re-run resumes a half-copied folder via rsync)
#   ALL_ROOT (default: the backed-up volume root — set to "<root>/Users"
#           to restore only user folders)
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
if [ -z "${STAGE:-}" ]; then STAGE="$USER_HOME/Desktop/TM-Restore-staging"; STAGE_PINNED=0
else STAGE_PINNED=1; fi
MNT_BASE=/private/var/tmp/tm-restore-mnt
LOCK=/private/var/tmp/tm-restore.pid
CUR_SNAP_DATE=""
FAILED=()
UMOUNTS=()
LOG=/dev/null

say()  { printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }
log()  { say "$*" | tee -a "$LOG"; }
# tshoot writes to STDERR (never stdout) so command substitutions like
# $(snapshot_root) don't capture the text into the result variable;
# also appended to the log file directly.
tshoot(){ say "[TSHOOT] $*" >&2; [ -w "$LOG" ] && printf '[%s] [TSHOOT] %s\n' "$(date '+%F %T')" "$*" >> "$LOG" 2>/dev/null; return 0; }

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
# post-crash, often NOTHING is auto-mounted: fall back to the one volume that
# clearly holds previous output, then take its device from the mount table
if [ -z "${TMVOL:-}" ]; then
    tm_cands=()
    for v in /Volumes/*/; do [ -d "$v/TM-Restored" ] && tm_cands+=("${v%/}"); done
    if [ "${#tm_cands[@]}" -eq 1 ]; then
        TMVOL="${tm_cands[0]}"
        say "auto-detected TM volume via TM-Restored: $TMVOL"
    fi
fi
[ -z "$TMDEV" ] && [ -n "${TMVOL:-}" ] && \
    TMDEV=$(mount | grep " on $TMVOL " | head -1 | awk '{print $1}')
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
    # (b) leftover self-mount from a killed (not rebooted) run? reuse it
    mnt="$MNT_BASE/$d"
    if [ -d "$mnt" ] && [ -n "$(ls -A "$mnt" 2>/dev/null)" ]; then
        UMOUNTS+=("$mnt")
        root=$(find "$mnt" -maxdepth 1 -type d -name '* - Data' 2>/dev/null | head -1)
        [ -z "$root" ] && root="$mnt"
        tshoot "reusing leftover mount at $mnt"
        echo "$root"; return 0
    fi
    # (c) mount it ourselves, read-only
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

# ── resume machinery ─────────────────────────────────────────────────────────
# done-markers live in the snapshot's TM-Restored dir. v5 keys them to the
# path RELATIVE to the snapshot root: the same snapshot may mount at a
# different path after a reboot, and an absolute-path key (v4) would then miss
# every marker and redo everything. v4 markers (.done-<sha of absolute SRC>)
# are still recognized so the interrupted run's progress is kept.
marker_name() { # $1=DEST_ROOT $2=SRC $3=root
    local rel="${2#"$3"/}"
    printf '%s/.done-%s-%s' "$1" "$(basename "$2")" "$(printf '%s' "$rel" | shasum | cut -c1-12)"
}
legacy_marker_name() { printf '%s/.done-%s' "$1" "$(echo "$2" | shasum | cut -c1-12)"; }
marker_exists() {
    [ -f "$(marker_name "$1" "$2" "$3")" ] || [ -f "$(legacy_marker_name "$1" "$2")" ]
}

# completion test that does NOT require mounting the snapshot: every folder
# the original run set out to do (its MANIFEST) already has a marker. This
# matters because a fresh mount can enumerate a DIFFERENT folder list than
# the crashed run did (auto-mounted root vs self-mounted root) — re-doing
# the enumeration must not resurrect already-restored folders.
manifest_complete() {  # $1=DEST_ROOT -> rc 0 if MANIFEST exists and is fully marked
    local mf="$1/MANIFEST.txt" line root_hint=""
    [ -f "$mf" ] || return 1
    [ -f "$1/.root" ] && root_hint=$(cat "$1/.root" 2>/dev/null)
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        if [ -n "$root_hint" ]; then
            marker_exists "$1" "$line" "$root_hint" || return 1
        else
            [ -f "$(legacy_marker_name "$1" "$line")" ] || return 1
        fi
    done < "$mf"
    return 0
}

acquire_lock() {  # one run at a time — concurrent runs would share $STAGE
    if [ -f "$LOCK" ]; then
        local oldpid; oldpid=$(cat "$LOCK" 2>/dev/null)
        if [ -n "${oldpid:-}" ] && kill -0 "$oldpid" 2>/dev/null; then
            say "ERROR: another tm-restore.sh is already running (pid $oldpid) — aborting."
            exit 1
        fi
        say "note: previous run died without cleanup (stale pid ${oldpid:-unknown}) — taking over"
    fi
    echo $$ > "$LOCK"
}

adopt_staging() {  # fold a crashed v4 run's timestamped staging dir into $STAGE
    [ "$STAGE_PINNED" = "1" ] && return 0
    local d
    for d in "$USER_HOME"/Desktop/TM-Restore-[0-9]*/; do
        [ -d "$d" ] || continue
        if [ -z "$(ls -A "$d" 2>/dev/null)" ]; then rmdir "$d" 2>/dev/null; continue; fi
        if [ ! -d "$STAGE" ] || rmdir "$STAGE" 2>/dev/null; then
            mv "$d" "$STAGE" && say "resuming: adopted staging left by previous run (${d%/})"
        else
            say "note: old staging at ${d%/} ($(du -sh "$d" 2>/dev/null | cut -f1)) not adopted — $STAGE already has content; delete it manually when no longer needed"
        fi
    done
    mkdir -p "$STAGE"
}

pick_resume_snapshot() {  # stdout: snapname to resume; rc 1 if none
    local snaps dest d total done_cnt best="" bdone=0 btotal=0 sd
    snaps=$(list_snapshots)
    # (1) staged half-copied work binds us to the snapshot it was copied from
    if [ -n "$(find "$STAGE" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | head -1)" ]; then
        sd=""; [ -f "$STAGE/.snapshot" ] && sd=$(cat "$STAGE/.snapshot" 2>/dev/null)
        # (1b) no tag: a staged folder named "<date>.backup" (what self-mounted
        # --all runs stage) names its own snapshot
        if [ -z "$sd" ]; then
            local one bn dd
            one=$(find "$STAGE" -mindepth 1 -maxdepth 1 -type d 2>/dev/null)
            if [ "$(printf '%s\n' "$one" | grep -c .)" -eq 1 ]; then
                bn=$(basename "$one")
                dd=$(echo "$bn" | grep -oE '^[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{6}')
                if [ -n "$dd" ] && echo "$snaps" | grep -qF "com.apple.TimeMachine.$dd.backup"; then
                    sd="$dd"; printf '%s\n' "$sd" > "$STAGE/.snapshot"
                    tshoot "staged folder '$bn' identifies its snapshot: $sd"
                fi
            fi
        fi
        # (1c) still no tag: infer from which snapshot shows unfinished
        # progress (unambiguous only if exactly one does)
        if [ -z "$sd" ]; then
            local cands=() c ct
            for dest in "$TMVOL/TM-Restored"/*/; do
                [ -d "$dest" ] || continue
                [ -f "$dest/.complete" ] && continue
                [ -f "$dest/MANIFEST.txt" ] || continue
                ct=$(grep -c . "$dest/MANIFEST.txt" 2>/dev/null); ct=${ct:-0}
                c=$(find "$dest" -maxdepth 1 -name '.done-*' 2>/dev/null | wc -l | tr -d ' ')
                [ "$c" -gt 0 ] && [ "$c" -lt "$ct" ] && cands+=("$(basename "$dest")")
            done
            if [ "${#cands[@]}" -eq 1 ]; then
                sd="${cands[0]}"
                printf '%s\n' "$sd" > "$STAGE/.snapshot"
                tshoot "untagged staging inferred to belong to snapshot $sd"
            else
                tshoot "staging from previous version has no snapshot tag; assuming newest — remove $STAGE/* if that is wrong"
            fi
        fi
        if [ -n "$sd" ] && echo "$snaps" | grep -qF "com.apple.TimeMachine.$sd.backup"; then
            tshoot "staging holds partial work from snapshot $sd — resuming that snapshot"
            echo "com.apple.TimeMachine.$sd.backup"; return 0
        fi
    fi
    # (2) otherwise: newest snapshot with unfinished progress on the TM disk
    [ -d "$TMVOL/TM-Restored" ] || return 1
    for dest in "$TMVOL/TM-Restored"/*/; do
        [ -d "$dest" ] || continue
        [ -f "$dest/.complete" ] && continue
        d=$(basename "$dest")
        echo "$snaps" | grep -qF "com.apple.TimeMachine.$d.backup" || continue
        [ -f "$dest/MANIFEST.txt" ] || continue
        total=$(grep -c . "$dest/MANIFEST.txt" 2>/dev/null); total=${total:-0}
        done_cnt=$(find "$dest" -maxdepth 1 -name '.done-*' 2>/dev/null | wc -l | tr -d ' ')
        if [ "$done_cnt" -gt 0 ] && [ "$done_cnt" -lt "$total" ]; then
            best="$d"; bdone="$done_cnt"; btotal="$total"
        fi
    done
    [ -n "$best" ] || return 1
    tshoot "interrupted run found on snapshot $best ($bdone/$btotal folders done)"
    echo "com.apple.TimeMachine.$best.backup"
}

status_report() {  # read-only progress overview; mounts nothing
    local base="$TMVOL/TM-Restored" dest d mf total done_cnt line prefix root_hint rel m lm remaining
    echo "Resume status — $base:"
    if [ ! -d "$base" ]; then echo "  (nothing yet — no TM-Restored folder on $TMVOL)"; fi
    for dest in "$base"/*/; do
        [ -d "$dest" ] || continue
        d=$(basename "$dest"); mf="$dest/MANIFEST.txt"
        done_cnt=$(find "$dest" -maxdepth 1 -name '.done-*' 2>/dev/null | wc -l | tr -d ' ')
        if [ -f "$dest/.complete" ]; then echo "  $d: COMPLETE ($done_cnt folders)"; continue; fi
        total="?"; remaining=""
        if [ -f "$mf" ]; then
            total=$(grep -c . "$mf" 2>/dev/null); total=${total:-0}
            root_hint=""; [ -f "$dest/.root" ] && root_hint=$(cat "$dest/.root" 2>/dev/null)
            # fallback for pre-v5 dests (no .root file): common path prefix
            prefix=""
            while IFS= read -r line; do
                [ -z "$line" ] && continue
                if [ -z "$prefix" ]; then prefix="$line"; else
                    while [ -n "$prefix" ] && [ "${line#"$prefix"/}" = "$line" ]; do prefix="${prefix%/*}"; done
                fi
            done < "$mf"
            while IFS= read -r line; do
                [ -z "$line" ] && continue
                if [ -n "$root_hint" ]; then rel="${line#"$root_hint"/}"; else rel="${line#"$prefix"/}"; fi
                m="$dest/.done-$(basename "$line")-$(printf '%s' "$rel" | shasum | cut -c1-12)"
                lm="$dest/.done-$(echo "$line" | shasum | cut -c1-12)"
                [ -f "$m" ] || [ -f "$lm" ] || remaining="$remaining    $(basename "$line")\n"
            done < "$mf"
        fi
        echo "  $d: $done_cnt/$total folders done"
        [ -n "$remaining" ] && { echo "  remaining:"; printf '%b' "$remaining"; }
    done
    if [ -d "$STAGE" ] && [ -n "$(ls -A "$STAGE" 2>/dev/null)" ]; then
        echo "Staging: $STAGE ($(du -sh "$STAGE" 2>/dev/null | cut -f1))$([ -f "$STAGE/.snapshot" ] && echo " — partial work from snapshot $(cat "$STAGE/.snapshot" 2>/dev/null)")"
    fi
}

copy_tree() { # engine ladder: rsync -> ditto -> cp
    rsync -a --stats "$1/" "$2/" >> "$LOG" 2>&1
    local rc=$?
    [ $rc -eq 0 ] && return 0
    { [ $rc -eq 23 ] || [ $rc -eq 24 ]; } && { tshoot "rsync partial ($rc) on $1 — continuing"; return 0; }
    if [ $rc -eq 20 ] || [ $rc -eq 130 ]; then
        say "INTERRUPTED by user (rc=$rc) — stopping cleanly (no engine fallback)."
        say "Resume by re-running the SAME command — finished folders are skipped, the current one continues in $STAGE."
        exit 130
    fi
    tshoot "rsync failed (rc=$rc) on $1 — falling back to ditto"
    ditto --rsrc "$1" "$2" >> "$LOG" 2>&1 && return 0
    tshoot "ditto failed on $1 — falling back to cp -Rp"
    mkdir -p "$2" && cp -Rp "$1/" "$2/" >> "$LOG" 2>&1 && return 0
    return 1
}

# ── per-folder pipeline (backup -> staging -> fix -> copy-back -> delete) ────
process_folder() {  # $1=SRC  $2=DEST_ROOT  $3=idx  $4=total  $5=root
    local SRC="$1" DEST_ROOT="$2" i="$3" total="$4" root="$5"
    local name; name=$(basename "$SRC")
    if marker_exists "$DEST_ROOT" "$SRC" "$root"; then
        log "[$i/$total] SKIP (done): $SRC"; return 0
    fi
    [ ! -e "$SRC" ] && { log "[$i/$total] SKIP missing: $SRC"; FAILED+=("$SRC (missing)"); return 1; }

    local need_kb free_kb dst_stage s_cnt d_cnt stage_kb dfree_kb have_kb=0 eff_need=0
    dst_stage="$STAGE/$name"
    # a half-copied staging dir from an interrupted run counts toward what is
    # already done — both for the disk guard below and for rsync (which only
    # transfers what is missing/different)
    [ -d "$dst_stage" ] && have_kb=$(du -sk "$dst_stage" 2>/dev/null | awk '{print $1}')
    have_kb=${have_kb:-0}
    need_kb=$(du -sk "$SRC" 2>/dev/null | awk '{print $1}')
    free_kb=$(df -k "$STAGE" | tail -1 | awk '{print $4}')
    if [ -n "$need_kb" ] && [ "$need_kb" -gt 0 ] 2>/dev/null; then
        eff_need=$(( need_kb - have_kb )); [ "$eff_need" -lt 0 ] && eff_need=0
        if [ $((eff_need + eff_need/10)) -ge "$free_kb" ]; then
            log "[$i/$total] SKIP too-large: $SRC (~$((eff_need/1024))MB still needed, $((free_kb/1024))MB free)"
            FAILED+=("$SRC (staging space)"); return 1
        fi
    fi

    # staging affinity (lazy — only once a copy really starts, so snapshots
    # that complete purely via markers never disturb a pending resume):
    # staged content from a DIFFERENT snapshot must not feed this restore
    local prev aside
    prev=""; [ -f "$STAGE/.snapshot" ] && prev=$(cat "$STAGE/.snapshot" 2>/dev/null)
    if [ -n "$prev" ] && [ "$prev" != "$CUR_SNAP_DATE" ] && \
       [ -n "$(find "$STAGE" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | head -1)" ]; then
        aside="$STAGE.from-$prev.$(date +%Y%m%d-%H%M%S)"
        say "staging holds work from snapshot $prev — moving it aside to $aside"
        mv "$STAGE" "$aside" && mkdir -p "$STAGE"
    fi
    mkdir -p "$STAGE"; printf '%s\n' "$CUR_SNAP_DATE" > "$STAGE/.snapshot"

    [ -d "$dst_stage" ] && [ "$have_kb" -gt 0 ] && \
        log "[$i/$total] RESUME: staging already holds $((have_kb/1024))MB of $name — rsync continues it"
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
    touch "$(marker_name "$DEST_ROOT" "$SRC" "$root")"
    return 0
}

# ── process one snapshot: resolve root, build folder list, run pipeline ──────
process_snapshot() {  # $1=snapname  $2=mode("all"|explicit)  rest=folders
    local snap="$1" mode="$2"; shift 2
    local d root DEST_ROOT
    d=$(snap_date "$snap")
    if [ "$mode" = "all" ]; then
        if [ -f "$TMVOL/TM-Restored/$d/.complete" ]; then
            log "=== snapshot $d already complete (.complete marker) — nothing to do ==="
            return 0
        fi
        if manifest_complete "$TMVOL/TM-Restored/$d"; then
            touch "$TMVOL/TM-Restored/$d/.complete"
            log "=== snapshot $d: all manifest folders already done — marking .complete, skipping ==="
            return 0
        fi
    fi
    CUR_SNAP_DATE="$d"
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
    printf '%s\n' "$root" > "$DEST_ROOT/.root"
    log "=== snapshot $d  root=$root ==="

    local WORK=()
    if [ "$mode" = "all" ]; then
        local ALL_ROOT="${ALL_ROOT:-$root}"
        # volatile/system dirs that are pointless or unsafe to restore
        local SKIP_DIRS=" .vol mnt cores sw pkg MobileSoftwareUpdate .TemporaryItems .Trashes .fseventsd .Spotlight-V100 .DocumentRevisions-V100 dev net home "
        local b
        while IFS= read -r x; do
            b=$(basename "$x")
            case "$SKIP_DIRS" in *" $b "*) tshoot "skip volatile dir: $x"; continue;; esac
            WORK+=("$x")
        done < <(
            find "$ALL_ROOT" -mindepth 1 -maxdepth 1 -type d -exec stat -f '%m %N' {} + 2>/dev/null \
            | sort -n | cut -d' ' -f2-)
        log "found ${#WORK[@]} folders under $ALL_ROOT (oldest first, volatile dirs skipped)"
    else
        WORK=("$@")
    fi
    printf '%s\n' "${WORK[@]}" > "$DEST_ROOT/MANIFEST.txt"

    local total=${#WORK[@]} i=0 done_so_far=0
    for SRC in "${WORK[@]}"; do
        marker_exists "$DEST_ROOT" "$SRC" "$root" && done_so_far=$((done_so_far+1))
    done
    [ "$done_so_far" -gt 0 ] && \
        log "resume: $done_so_far/$total folders already done — $((total-done_so_far)) remaining"
    for SRC in "${WORK[@]}"; do
        i=$((i+1))
        process_folder "$SRC" "$DEST_ROOT" "$i" "$total" "$root"
    done
    chown -R "$USER_NAME":staff "$DEST_ROOT" 2>/dev/null
    chmod -R u+rwX "$DEST_ROOT" 2>/dev/null
    # whole-snapshot completion marker: lets future runs skip this snapshot
    local alldone=1
    for SRC in "${WORK[@]}"; do
        marker_exists "$DEST_ROOT" "$SRC" "$root" || { alldone=0; break; }
    done
    if [ "$alldone" -eq 1 ]; then
        touch "$DEST_ROOT/.complete"
        log "=== snapshot $d done — COMPLETE ==="
    else
        log "=== snapshot $d done — INCOMPLETE (re-run to resume; --status shows what is left) ==="
    fi
}

# ══ main ═════════════════════════════════════════════════════════════════════
MODE="${1:-}"
case "$MODE" in
  --list-snapshots|""|--status) ;;                  # read-only: no lock needed
  *) acquire_lock; adopt_staging ;;
esac
mkdir -p "$STAGE" "$MNT_BASE"
rmdir "$MNT_BASE"/* 2>/dev/null                     # stale EMPTY mount dirs from a dead run
caffeinate -dims & CAFF=$!
trap 'kill $CAFF 2>/dev/null; rm -f "$LOCK"; for m in "${UMOUNTS[@]:-}"; do [ -n "$m" ] && umount "$m" 2>/dev/null; done' EXIT

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
    echo "Run with --all, --all-snapshots, --snapshot <date>, --status, or explicit folder paths."
    echo "An interrupted run resumes automatically on re-run (done-markers + staging reuse)."
    exit 0
    ;;
  --status)
    status_report
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
    if RSNAP=$(pick_resume_snapshot); then
        if [ "$RSNAP" != "$NEWEST" ]; then
            say "RESUME: snapshot $(snap_date "$RSNAP") has unfinished work — continuing it"
            say "        (to restore the newest snapshot instead: sudo bash $0 --snapshot $(snap_date "$NEWEST") --all)"
        fi
        NEWEST="$RSNAP"
    fi
    process_snapshot "$NEWEST" all
    ;;
  *)
    NEWEST=$(list_snapshots | tail -1)
    process_snapshot "$NEWEST" explicit "$@"
    ;;
esac

# staging cleanup: if only the .snapshot tag (and Finder cruft) remains, drop it
if [ -d "$STAGE" ] && [ -z "$(find "$STAGE" -mindepth 1 -maxdepth 1 ! -name '.snapshot' ! -name '.DS_Store' 2>/dev/null)" ]; then
    rm -f "$STAGE/.snapshot"
    rmdir "$STAGE" 2>/dev/null && say "staging dir removed (empty)" || true
fi
say "=== RUN DONE: failures: ${#FAILED[@]} ${FAILED[*]:-} ==="
if [ ${#FAILED[@]} -gt 0 ]; then
    say "re-run the SAME command to resume — finished folders are skipped; 'sudo bash $0 --status' shows what is left"
    exit 1
fi
exit 0
