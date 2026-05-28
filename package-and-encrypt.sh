#!/usr/bin/env bash
# package-and-encrypt.sh
# Bundle the three hardening scripts + manifest into a single
# AES-256 encrypted file you can scatter to USB / email / cloud safely.
#
# Output: /Users/evw/dev/security/scripts-bundle.tar.gz.enc
#
# To decrypt later (on this or any other Mac/Linux with openssl):
#   openssl enc -d -aes-256-cbc -pbkdf2 -salt \
#       -in scripts-bundle.tar.gz.enc | tar xzv
#
# Notes:
#   • Uses OpenSSL's PBKDF2 KDF (do NOT remove -pbkdf2; the legacy default is weak).
#   • Passphrase is read interactively from /dev/tty — never stored on disk.
#   • Encrypted blob is safe to put anywhere; only your passphrase decrypts it.
#   • Caveat for a fully-compromised endpoint: your passphrase keystrokes can
#     theoretically be captured here. The encrypted blob is still useful for
#     transport — just treat the passphrase as exposed if you suspect the worst.

set -euo pipefail
cd "$(dirname "$0")"

FILES=(
    harden.sh
    lock-remote-access.sh
    run-with-ls-silent.sh
    little-snitch-triage.txt
    little-snitch-triage.pdf
    MANIFEST.sha256
    scripts-bundle.pdf
    PRESERVATION-GUIDE.md
    package-and-encrypt.sh
)
OUT="scripts-bundle.tar.gz.enc"

# Refresh manifest so it matches current file contents
shasum -a 256 harden.sh lock-remote-access.sh run-with-ls-silent.sh \
              little-snitch-triage.txt little-snitch-triage.pdf > MANIFEST.sha256
echo "Refreshed MANIFEST.sha256:"
cat MANIFEST.sha256
echo

echo "Bundling: ${FILES[*]}"
tar czf - "${FILES[@]}" \
    | openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt -out "$OUT"

echo
echo "Wrote: $(pwd)/$OUT  ($(wc -c < "$OUT" | tr -d ' ') bytes)"
echo "SHA-256 of encrypted blob: $(shasum -a 256 "$OUT" | awk '{print $1}')"
echo
echo "To verify it decrypts (sanity check before relying on it):"
echo "  openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -salt -in $OUT | tar tzv"
