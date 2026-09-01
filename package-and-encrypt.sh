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

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error-guard.sh)
_eg_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
while [ "$_eg_d" != "/" ] && [ ! -f "$_eg_d/lib/error-guard.sh" ]; do _eg_d="$(dirname "$_eg_d")"; done
[ -f "$_eg_d/lib/error-guard.sh" ] && . "$_eg_d/lib/error-guard.sh"; unset _eg_d
command -v guard_run >/dev/null 2>&1 || guard_run() { shift; "$@"; }
command -v guard_throw >/dev/null 2>&1 || guard_throw() { printf 'error-guard: throw: %s\n' "$*" >&2; return 1; }

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
guard_run "shasum-manifest" shasum -a 256 harden.sh lock-remote-access.sh run-with-ls-silent.sh \
              little-snitch-triage.txt little-snitch-triage.pdf > MANIFEST.sha256 || true
echo "Refreshed MANIFEST.sha256:"
cat MANIFEST.sha256
echo

# Verify every listed input exists first — a missing file must not yield a
# valid-looking but incomplete encrypted bundle.
missing=0
for f in "${FILES[@]}"; do
    [ -f "$f" ] || { echo "MISSING INPUT: $f" >&2; missing=1; }
done
[ "$missing" -eq 0 ] || { echo "Aborting — bundle inputs missing (see above)." >&2; exit 1; }

echo "Bundling: ${FILES[*]}"
# pipefail is on (set -euo pipefail above): a tar or openssl failure aborts nonzero.
guard_run "tar-bundle" tar czf - "${FILES[@]}" \
    | guard_run "openssl-encrypt" openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt -out "$OUT"

echo
echo "Wrote: $(pwd)/$OUT  ($(wc -c < "$OUT" | tr -d ' ') bytes)"
echo "SHA-256 of encrypted blob: $(shasum -a 256 "$OUT" | awk '{print $1}')"
echo
echo "To verify it decrypts (sanity check before relying on it):"
echo "  openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -salt -in $OUT | tar tzv"
