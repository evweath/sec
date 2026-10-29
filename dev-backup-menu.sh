#!/usr/bin/env bash
# =============================================================================
# dev-backup-menu.sh — backup control center: every method, each on a schedule
#
#   Time Machine        whole Mac, hourly        → external "Backups" volume
#   Versioned snapshots ~/dev, daily 21:30       → browsable dated copies (rsync)
#   GitHub backup       ~/dev repos, daily 21:45 → commit+push each repo
#   Restic cloud        home dir, daily 22:15    → encrypted, deduplicated,
#                                                  point-in-time, offsite (B2/S3)
#
# Run with no arguments for the menu. Non-interactive modes (used by launchd):
#   dev-backup-menu.sh snapshot        run one versioned snapshot + prune
#   dev-backup-menu.sh ghbackup        commit+push all ~/dev repos
#   dev-backup-menu.sh restic-backup   encrypted home backup + retention prune
#   dev-backup-menu.sh status          print status overview
#
# Config: ~/.dev-backup.conf (chmod 600 — holds cloud credentials)
# Restic: ~/.config/restic/password (the encryption password — ALSO save a copy
#         in your password manager; without it the backups are unrecoverable)
# =============================================================================
set -uo pipefail

DEV_DIR="$HOME/dev"
CONF="$HOME/.dev-backup.conf"
SNAP_DEST_DEFAULT="$HOME/dev-snapshots"
KEEP_DAYS_DEFAULT=30
LOG_DIR="$HOME/Library/Logs"
SNAP_LOG="$LOG_DIR/dev-snapshot.log"
GH_LOG="$LOG_DIR/dev-github-backup.log"
RESTIC_LOG="$LOG_DIR/dev-restic-backup.log"
LA_DIR="$HOME/Library/LaunchAgents"
SNAP_LABEL="com.evw.dev-snapshot"
GH_LABEL="com.evw.dev-github-backup"
RESTIC_LABEL="com.evw.dev-restic-backup"
RESTIC_DIR="$HOME/.config/restic"
RESTIC_PWFILE="$RESTIC_DIR/password"
RESTIC_EXCLUDES="$RESTIC_DIR/excludes.txt"
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"

# Rsync excludes: regenerable or bulky churn. Databases and archives ARE kept —
# they are part of what you may want to recover.
RSYNC_EXCLUDES=(
  .venv venv node_modules __pycache__ .pytest_cache .mypy_cache .ruff_cache
  dist build target .next .turbo htmlcov coverage
  logs exports scan_cache
  local-backups mainbakups backups security-backups
  .DS_Store
)

# ── config ────────────────────────────────────────────────────────────────────
cfg_get() {  # cfg_get KEY default
  local key="$1" default="$2"
  if [ -f "$CONF" ]; then
    local v
    v=$(grep -E "^${key}=" "$CONF" 2>/dev/null | tail -1 | cut -d= -f2-)
    [ -n "$v" ] && { echo "$v"; return; }
  fi
  echo "$default"
}
cfg_set() {  # cfg_set KEY value
  local key="$1" value="$2"
  touch "$CONF"; chmod 600 "$CONF"
  grep -vE "^${key}=" "$CONF" > "$CONF.tmp" 2>/dev/null || true
  echo "${key}=${value}" >> "$CONF.tmp"
  mv "$CONF.tmp" "$CONF"; chmod 600 "$CONF"
}

log() { echo "$(date '+%F %T') $*" | tee -a "${2:-/dev/stdout}" >/dev/null; }

# ── 1. Time Machine ───────────────────────────────────────────────────────────
tm_status() {
  echo "--- Time Machine (whole Mac, hourly once enabled) ---"
  tmutil destinationinfo 2>/dev/null | grep -E 'Name|Kind' | sed 's/^/  /' || echo "  (no destination configured)"
  echo "  Latest backup: $(tmutil latestbackup 2>/dev/null || echo 'unknown — is the Backups volume mounted?')"
  tmutil status 2>/dev/null | grep -E 'Running|Percent' | sed 's/^/  /'
}

tm_setup() {
  echo "Available volumes:"
  ls -d /Volumes/*/ 2>/dev/null | sed 's/^/  /'
  echo
  read -rp "Volume to back up to (e.g. /Volumes/MyBackup): " vol
  [ -d "$vol" ] || { echo "No such volume: $vol"; return 1; }
  echo "Setting Time Machine destination (sudo will prompt)..."
  sudo tmutil setdestination -a "$vol" && sudo tmutil enable
  echo "Destination set. Time Machine now runs hourly by itself — no job to install."
}

tm_exclusions() {
  echo "Adding fixed-path exclusions for dependency/build trees under ~/dev (sudo may prompt)..."
  local n=0 d
  while IFS= read -r d; do
    sudo tmutil addexclusion -p "$d" 2>/dev/null && n=$((n+1))
  done < <(find "$DEV_DIR" -maxdepth 3 \( -name .venv -o -name node_modules -o -name __pycache__ \) -type d 2>/dev/null | head -40)
  echo "  $n exclusions added."
}

tm_now() { tmutil startbackup && echo "Backup started (runs in background)."; }

# ── 2. Versioned rsync snapshots ──────────────────────────────────────────────
snap_dest() { cfg_get SNAP_DEST "$SNAP_DEST_DEFAULT"; }

do_snapshot() {
  local dest date_dir ex=()
  dest="$(snap_dest)"
  date_dir="$dest/$(date +%F)"
  mkdir -p "$dest" || { echo "cannot create $dest"; return 1; }
  for e in "${RSYNC_EXCLUDES[@]}"; do ex+=(--exclude "$e"); done
  case "$dest" in "$DEV_DIR"/*) ex+=(--exclude "${dest#"$DEV_DIR"/}") ;; esac

  echo "snapshot: $DEV_DIR -> $date_dir"
  if [ "$(df "$dest" | awk 'NR==2{print $1}')" = "$(df "$HOME" | awk 'NR==2{print $1}')" ]; then
    echo "  note: destination is on the SAME disk as ~/dev — protects against deletion/corruption,"
    echo "        not disk failure. Point SNAP_DEST at an external volume for full protection."
  fi
  local link=()
  [ -e "$dest/latest" ] && link=(--link-dest="$dest/latest")
  rsync -a --delete "${link[@]}" "${ex[@]}" "$DEV_DIR/" "$date_dir/" \
    && ln -sfn "$date_dir" "$dest/latest" \
    && log "snapshot ok: $date_dir" "$SNAP_LOG" \
    || { log "snapshot FAILED: $date_dir" "$SNAP_LOG"; return 1; }

  local keep cutoff d
  keep=$(cfg_get KEEP_DAYS "$KEEP_DAYS_DEFAULT")
  cutoff=$(date -v-"${keep}"d +%F)
  for d in "$dest"/20??-??-??; do
    [ -d "$d" ] || continue
    [[ "$(basename "$d")" < "$cutoff" ]] && { rm -rf "$d"; log "pruned $d" "$SNAP_LOG"; }
  done
  echo "done. Recover by copying files out of $date_dir"
}

snap_status() {
  local dest
  dest="$(snap_dest)"
  echo "--- Versioned snapshots (~/dev, browsable dated copies) ---"
  echo "  destination: $dest   keep: $(cfg_get KEEP_DAYS "$KEEP_DAYS_DEFAULT") days"
  if [ -d "$dest" ]; then
    echo "  snapshots:   $(ls -d "$dest"/20??-??-?? 2>/dev/null | wc -l | tr -d ' ') days on disk"
    echo "  latest:      $(readlink "$dest/latest" 2>/dev/null || echo none)"
    echo "  size:        $(du -sh "$dest" 2>/dev/null | cut -f1)"
  else
    echo "  (not created yet)"
  fi
  echo "  daily job:   $(launchctl print "gui/$(id -u)/$SNAP_LABEL" >/dev/null 2>&1 && echo INSTALLED 21:30 || echo not installed)"
}

# ── 3. GitHub backup ──────────────────────────────────────────────────────────
do_ghbackup() {
  local stamp repo branch pushed=0 committed=0 failed=0
  stamp="$(date '+%F %T')"
  echo "── github backup $stamp" | tee -a "$GH_LOG"
  while IFS= read -r gitdir; do
    repo="$(dirname "$gitdir")"
    git -C "$repo" rev-parse --git-dir >/dev/null 2>&1 || continue
    git -C "$repo" remote get-url origin >/dev/null 2>&1 || { echo "  skip (no origin): $repo" | tee -a "$GH_LOG"; continue; }
    branch="$(git -C "$repo" rev-parse --abbrev-ref HEAD 2>/dev/null)"
    [ -n "$branch" ] && [ "$branch" != "HEAD" ] || { echo "  skip (detached): $repo" | tee -a "$GH_LOG"; continue; }
    git -C "$repo" add -A 2>/dev/null
    if ! git -C "$repo" diff --cached --quiet 2>/dev/null; then
      git -C "$repo" commit -q -m "daily backup: $stamp" 2>/dev/null && committed=$((committed+1))
    fi
    if git -C "$repo" push -q origin "HEAD:$branch" 2>/dev/null; then
      pushed=$((pushed+1))
    else
      failed=$((failed+1)); echo "  PUSH FAILED: $repo" | tee -a "$GH_LOG"
    fi
  done < <(find "$DEV_DIR" -maxdepth 3 -name .git -type d 2>/dev/null)
  echo "── done: $committed committed, $pushed pushed, $failed failed" | tee -a "$GH_LOG"
}

gh_status() {
  echo "--- GitHub backup (~/dev repos → GitHub) ---"
  echo "  daily job: $(launchctl print "gui/$(id -u)/$GH_LABEL" >/dev/null 2>&1 && echo INSTALLED 21:45 || echo not installed)"
  echo "  last runs:"
  tail -4 "$GH_LOG" 2>/dev/null | sed 's/^/    /' || echo "    (never run)"
}

# ── 4. Restic encrypted cloud backup ─────────────────────────────────────────
restic_env() {  # load credentials; returns 1 if unconfigured
  local repo kid key
  repo=$(cfg_get RESTIC_REPO "")
  kid=$(cfg_get RESTIC_KEY_ID "")
  key=$(cfg_get RESTIC_KEY "")
  [ -n "$repo" ] && [ -n "$kid" ] && [ -n "$key" ] && [ -f "$RESTIC_PWFILE" ] || return 1
  export RESTIC_REPOSITORY="$repo" AWS_ACCESS_KEY_ID="$kid" AWS_SECRET_ACCESS_KEY="$key"
  export RESTIC_PASSWORD_FILE="$RESTIC_PWFILE"
}

restic_configure() {
  echo "--- Restic / Backblaze B2 setup ---"
  echo "You need: bucket name, S3 endpoint, keyID, applicationKey"
  echo "(B2 console → Buckets → your bucket → endpoint like s3.us-west-004.backblazeb2.com;"
  echo " App Keys → Add Application Key restricted to that bucket)"
  echo
  read -rp "Bucket name: " bucket
  read -rp "S3 endpoint (e.g. s3.us-west-004.backblazeb2.com): " endpoint
  read -rp "keyID: " kid
  read -rp "applicationKey: " key
  cfg_set RESTIC_REPO "s3:https://$endpoint/$bucket"
  cfg_set RESTIC_KEY_ID "$kid"
  cfg_set RESTIC_KEY "$key"
  mkdir -p "$RESTIC_DIR"
  if [ ! -f "$RESTIC_PWFILE" ]; then
    (umask 177; openssl rand -base64 32 > "$RESTIC_PWFILE")
    echo
    echo "Generated a random encryption password at $RESTIC_PWFILE (mode 600):"
    echo "  $(cat "$RESTIC_PWFILE")"
    echo ">>> Save this in your password manager NOW. Losing it = backups unreadable. <<<"
  fi
  if [ ! -f "$RESTIC_EXCLUDES" ]; then
    cat > "$RESTIC_EXCLUDES" <<'EXC'
Library/Caches
Library/Containers/*/Data/Library/Caches
Library/Logs
.Trash
.CFUserTextEncoding
**/.venv/**
**/venv/**
**/node_modules/**
**/__pycache__/**
**/.pytest_cache/**
**/dist/**
**/build/**
**/.DS_Store
dev-snapshots/**
EXC
  fi
  chmod 600 "$RESTIC_PWFILE"
  echo "Saved. Excludes file: $RESTIC_EXCLUDES (edit anytime)."
  echo "Next: menu option 'Restic: init repository'."
}

restic_init() {
  restic_env || { echo "Not configured — run 'Restic: configure' first."; return 1; }
  restic init 2>&1 | tail -2
}

do_restic_backup() {
  restic_env || { echo "restic not configured"; return 1; }
  echo "── restic backup $(date '+%F %T')" | tee -a "$RESTIC_LOG"
  restic backup "$HOME" --exclude-file "$RESTIC_EXCLUDES" --exclude-caches \
    --one-file-system 2>&1 | tail -4 | tee -a "$RESTIC_LOG"
  restic forget --prune --keep-daily 14 --keep-weekly 8 --keep-monthly 6 2>&1 | tail -2 | tee -a "$RESTIC_LOG"
  log "restic backup done" "$RESTIC_LOG"
}

restic_status() {
  echo "--- Restic cloud backup (home dir, encrypted, offsite) ---"
  if restic_env 2>/dev/null; then
    echo "  repo: $(cfg_get RESTIC_REPO '?')"
    echo "  snapshots: $(restic snapshots --compact 2>/dev/null | tail -1 || echo 'repo not initialized yet')"
  else
    echo "  (not configured — menu option 10)"
  fi
  echo "  daily job: $(launchctl print "gui/$(id -u)/$RESTIC_LABEL" >/dev/null 2>&1 && echo INSTALLED 22:15 || echo not installed)"
}

restic_restore() {
  restic_env || { echo "Not configured."; return 1; }
  echo "Recent snapshots:"; restic snapshots --compact 2>/dev/null | tail -6
  echo
  read -rp "Snapshot ID to restore (or 'latest'): " sid
  read -rp "Restore into folder: " target
  mkdir -p "$target"
  restic restore "$sid" --target "$target" && echo "Restored under $target"
}

# ── schedules ─────────────────────────────────────────────────────────────────
install_agent() {  # install_agent LABEL "command args" HOUR MINUTE
  local label="$1" cmd="$2" hour="$3" minute="$4" plist="$LA_DIR/$1.plist"
  mkdir -p "$LA_DIR" "$LOG_DIR"
  cat > "$plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$label</string>
  <key>ProgramArguments</key><array>
    <string>/bin/bash</string><string>$SELF</string><string>$cmd</string>
  </array>
  <key>StartCalendarInterval</key><dict><key>Hour</key><integer>$hour</integer><key>Minute</key><integer>$minute</integer></dict>
  <key>StandardOutPath</key><string>$LOG_DIR/$label.log</string>
  <key>StandardErrorPath</key><string>$LOG_DIR/$label-err.log</string>
</dict></plist>
PLIST
  launchctl bootout "gui/$(id -u)/$label" 2>/dev/null
  launchctl bootstrap "gui/$(id -u)" "$plist" && echo "installed: $label (daily $(printf '%02d:%02d' "$hour" "$minute"))"
}

install_all_schedules() {
  install_agent "$SNAP_LABEL" snapshot 21 30
  install_agent "$GH_LABEL" ghbackup 21 45
  install_agent "$RESTIC_LABEL" restic-backup 22 15
  echo
  echo "Time Machine needs no job — once a destination is set (option 2) it runs hourly on its own."
}

# ── status + restore help ─────────────────────────────────────────────────────
status_all() { tm_status; echo; snap_status; echo; gh_status; echo; restic_status; }

restore_help() {
  cat <<EOF

--- How to recover files ---

Time Machine (any hour today, any day this month — whole Mac):
  Open the folder in Finder → Control-click → "Browse Time Machine Backups"

Versioned snapshots (daily, browsable — ~/dev):
  open "$(snap_dest)"   → each 20XX-XX-XX folder is a complete copy of ~/dev

GitHub (offsite, per-repo history):
  gh repo clone evweath/<repo>   or in the repo:  git log / git checkout <sha> -- <file>

Restic (offsite, encrypted, point-in-time — home dir):
  Use menu option 14 (guided restore), or load credentials manually:
    export RESTIC_REPOSITORY=\$(grep ^RESTIC_REPO= ~/.dev-backup.conf | cut -d= -f2-)
    export AWS_ACCESS_KEY_ID=\$(grep ^RESTIC_KEY_ID= ~/.dev-backup.conf | cut -d= -f2-)
    export AWS_SECRET_ACCESS_KEY=\$(grep ^RESTIC_KEY= ~/.dev-backup.conf | cut -d= -f2-)
    export RESTIC_PASSWORD_FILE=~/.config/restic/password
  then:  restic snapshots            # list points in time
         restic restore latest --target ~/restore

EOF
}

# ── menu ──────────────────────────────────────────────────────────────────────
menu() {
  while true; do
    cat <<EOF

════════════════ dev backup control center ════════════════
  Time Machine (whole Mac, hourly, self-scheduling)
  1) status   2) set destination + enable   3) exclude venvs/caches   4) backup now

  Versioned snapshots (~/dev, browsable dated copies)
  5) snapshot now   6) set destination [$(snap_dest)]   7) install daily job (21:30)

  GitHub backup (all ~/dev repos)
  8) run now   9) install daily job (21:45)

  Restic cloud (home dir, encrypted, offsite — B2/S3)
  10) configure   11) init repo   12) backup now   13) install daily job (22:15)   14) restore

  a) Install ALL daily schedules at once
  s) Status overview      r) Restore help      q) Quit
EOF
    read -rp "> " choice
    case "$choice" in
      1) tm_status ;;
      2) tm_setup ;;
      3) tm_exclusions ;;
      4) tm_now ;;
      5) do_snapshot ;;
      6) read -rp "Snapshot destination: " d; cfg_set SNAP_DEST "$d"; echo "saved." ;;
      7) install_agent "$SNAP_LABEL" snapshot 21 30 ;;
      8) do_ghbackup ;;
      9) install_agent "$GH_LABEL" ghbackup 21 45 ;;
      10) restic_configure ;;
      11) restic_init ;;
      12) do_restic_backup ;;
      13) install_agent "$RESTIC_LABEL" restic-backup 22 15 ;;
      14) restic_restore ;;
      a) install_all_schedules ;;
      s) status_all ;;
      r) restore_help ;;
      q) break ;;
      *) echo "?" ;;
    esac
  done
}

case "${1:-}" in
  snapshot)       do_snapshot ;;
  ghbackup)       do_ghbackup ;;
  restic-backup)  do_restic_backup ;;
  status)         status_all ;;
  *)              menu ;;
esac
