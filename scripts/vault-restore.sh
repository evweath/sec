#!/bin/bash
# vault-restore.sh — list or restore versioned file snapshots from the vault.
#
#   vault-restore.sh /etc/hosts                 # list available versions
#   vault-restore.sh /etc/hosts 1788280000-change-hosts   # restore that version
#
# Vault written by com.evw.file-vault (evw-file-vault.py). Run as root for
# system files: sudo bash vault-restore.sh <path> [version]
set -uo pipefail
VAULT=/var/log/mac-sentinel/file-vault

[ $# -lt 1 ] && { echo "usage: $0 <original-path> [version-filename]"; exit 1; }
TARGET="$1"
KEY=$(printf '%s' "$TARGET" | shasum | cut -c1-16)
DIR="$VAULT/$KEY"

[ -d "$DIR" ] || { echo "no vault entries for $TARGET"; exit 1; }
SRC="$(cat "$DIR/SOURCE" 2>/dev/null || echo '?')"
[ "$SRC" = "$TARGET" ] || echo "NOTE: vault key maps to '$SRC'"

if [ $# -eq 1 ]; then
    echo "versions for $TARGET (newest last):"
    ls -1 "$DIR" | grep -v '^SOURCE$'
    exit 0
fi

VERSION="$2"
[ -f "$DIR/$VERSION" ] || { echo "no such version: $VERSION"; ls -1 "$DIR" | grep -v '^SOURCE$'; exit 1; }

cp -p "$DIR/$VERSION" "$TARGET" \
  && echo "restored $TARGET from vault version $VERSION" \
  || echo "restore failed (need sudo?)" >&2
