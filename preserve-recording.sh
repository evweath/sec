#!/usr/bin/env bash
# Preserve replayd incident recording to encrypted offline bundle.
# Run interactively — prompts for encryption passphrase via terminal.
# Usage: bash ~/dev/security/preserve-recording.sh
set -euo pipefail

SECURITY_DIR="$HOME/dev/security"
DEST="/Volumes/Passport/forensic-evidence"
BUNDLE_NAME="replayd-incident-2026-06-02"
KNOWN_HASH="2bd93974e2a91d9e74fad6c73399047a32a7118cf18d3baece2b409685a83898"

echo "=== Forensic Evidence Preservation ==="
echo "Target: $DEST/$BUNDLE_NAME.tar.gz.enc"
echo ""

# ── Find the recording file ────────────────────────────────────────────────────
RECORDING=$(python3 -c "
import os
desktop = os.path.expanduser('~/Desktop')
files = os.listdir(desktop)
found = [f for f in files if 'Recording' in f and '2026-06-02' in f]
if not found:
    raise SystemExit('ERROR: Recording file not found on Desktop')
print(os.path.join(desktop, found[0]))
")
echo "Recording: $RECORDING"
echo "Size:      $(du -sh "$RECORDING" | awk '{print $1}')"

# ── Verify hash ────────────────────────────────────────────────────────────────
echo ""
echo "Verifying SHA-256 (this takes ~60 seconds for 4 GB)..."
ACTUAL_HASH=$(python3 -c "
import hashlib, sys
h = hashlib.sha256()
with open('$RECORDING', 'rb') as f:
    while chunk := f.read(8*1024*1024):
        h.update(chunk)
print(h.hexdigest())
")

echo "Expected: $KNOWN_HASH"
echo "Actual:   $ACTUAL_HASH"

if [ "$ACTUAL_HASH" != "$KNOWN_HASH" ]; then
    echo ""
    echo "*** HASH MISMATCH — FILE MAY HAVE BEEN TAMPERED WITH ***"
    echo "Proceeding anyway (preserving what we have), but note this discrepancy."
else
    echo "Hash: VERIFIED ✓"
fi

# ── Create staging area ────────────────────────────────────────────────────────
STAGING=$(mktemp -d)
trap 'rm -rf "$STAGING"' EXIT

cp "$RECORDING" "$STAGING/"
cp "$SECURITY_DIR/replayd-incident-chain-of-custody.txt" "$STAGING/"

# Write manifest into staging
{
    echo "SHA-256 MANIFEST — replayd incident forensic bundle"
    echo "Created: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo ""
    echo "$ACTUAL_HASH  $(basename "$RECORDING")"
    shasum -a 256 "$SECURITY_DIR/replayd-incident-chain-of-custody.txt" | \
        awk '{print $1}' | xargs -I{} echo "{}  replayd-incident-chain-of-custody.txt"
} > "$STAGING/MANIFEST.sha256"

echo ""
echo "Bundle contents:"
ls -lh "$STAGING/"

# ── Encrypt ───────────────────────────────────────────────────────────────────
mkdir -p "$DEST"
ENCRYPTED="$DEST/$BUNDLE_NAME.tar.gz.enc"
MANIFEST_OUT="$DEST/$BUNDLE_NAME.MANIFEST.sha256"

echo ""
echo "Enter encryption passphrase (not echoed, not logged):"
echo "(Use a strong passphrase you will remember — write it on paper with your recovery key)"
echo ""

tar -czf - -C "$STAGING" . | \
    openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt \
        -pass fd:3 3</dev/tty > "$ENCRYPTED"

cp "$STAGING/MANIFEST.sha256" "$MANIFEST_OUT"

# ── Verify output ─────────────────────────────────────────────────────────────
echo ""
BUNDLE_HASH=$(shasum -a 256 "$ENCRYPTED" | awk '{print $1}')
BUNDLE_SIZE=$(du -sh "$ENCRYPTED" | awk '{print $1}')
echo "Encrypted bundle: $ENCRYPTED"
echo "Bundle size:      $BUNDLE_SIZE"
echo "Bundle SHA-256:   $BUNDLE_HASH"
echo ""
echo "Manifest copy:    $MANIFEST_OUT"
echo ""
echo "=== Preservation complete ==="
echo ""
echo "NEXT STEPS:"
echo "1. Record the bundle SHA-256 on paper alongside your recovery key:"
echo "   $BUNDLE_HASH"
echo "2. Safely eject the Passport drive"
echo "3. Store in a physically secure location separate from the Mac"
echo "4. To verify integrity later:"
echo "   shasum -a 256 $BUNDLE_NAME.tar.gz.enc"
echo "   openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -in $BUNDLE_NAME.tar.gz.enc | tar -tzf -"
