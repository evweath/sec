#!/bin/bash
echo "=== snapshot-probe3 $(date) ==="
[ "$(id -u)" -ne 0 ] && { echo "ERROR: must be root"; exit 1; }
MNT=/private/var/tmp/tm-mnt-test
mkdir -p "$MNT"
SNAP="com.apple.TimeMachine.2026-05-09-100913.backup"
if mount -t apfs -o -s="$SNAP" /dev/disk9s3 "$MNT" 2>&1; then
    echo "mount OK"; ls "$MNT" | head -5
    D=$(find "$MNT" -maxdepth 1 -type d -name "* - Data" | head -1)
    echo "data dir: $D"
    ls "$D/Users/" 2>&1
    probe=$(find "$D" -type f 2>/dev/null | head -1)
    head -c 10 "$probe" >/dev/null 2>&1 && echo "READ OK" || echo "READ FAILED ($probe)"
    umount "$MNT" && echo "unmounted clean"
else
    echo "MOUNT FAILED"
fi
echo "=== probe3 done ==="
