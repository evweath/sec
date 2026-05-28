# Preservation Guide

How to keep Claude-generated work recoverable across device loss, account compromise, and tampering. Apply when output spans multiple files or anything you'd hate to recreate from scratch.

## The three artifacts

| File | What it is | What it's for |
|---|---|---|
| `*-bundle.pdf` | Combined printable PDF with each source file's SHA-256 in its header | Paper backup — print and store off-site |
| `MANIFEST.sha256` | One SHA-256 hash per source file, plain text | Integrity check when restoring on a clean device |
| `*-bundle.tar.gz.enc` | AES-256-CBC encrypted tarball, PBKDF2 @ 600k iters | Scatter to USB / email / cloud — only the passphrase decrypts |

## Storage rules

1. **Paper copy of the PDF lives somewhere physical.** Locked desk, off-site safe, fireproof box — not in the same building as the original Mac if possible.
2. **Write the SHA-256 hashes by hand on the paper PDF** (first page is fine). Future-you needs to verify against these when restoring; the digital manifest can be tampered with, the handwritten one can't be (silently).
3. **Encrypted blob can go many places.** A USB stick in a drawer, a second cloud account on a different identity, attached to an email to yourself on a separate provider. Redundancy is fine — only the passphrase decrypts.
4. **Passphrase NEVER lives in the same place as the blob.** Memorize it, or write it on paper kept separate from the encrypted file. A passphrase manager works *only* if that manager lives in an account you fully trust.
5. **Never email the passphrase.** Never paste it into chat. A piece of paper in your wallet is fine; a sticky note on the monitor is not.

## Restoring on a clean device

1. Bring the encrypted blob to the new device via USB.
2. Decrypt:
   ```
   openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -salt \
       -in scripts-bundle.tar.gz.enc | tar xzv
   ```
3. Verify against the hand-written paper-copy hashes:
   ```
   shasum -a 256 -c MANIFEST.sha256
   ```
   Every line should say `OK`. If any says `FAILED`, the file was tampered with — don't run it. Re-type from the paper PDF.

## What NOT to do

- ❌ Don't push the source files to a git/cloud account you've flagged as compromised. An attacker with write access can rewrite history silently.
- ❌ Don't store the passphrase next to the encrypted blob (USB + sticky note = not encrypted).
- ❌ Don't trust an unverified copy. Always run the `shasum -c` check against your paper hashes before executing restored files.
- ❌ Don't rely on encryption alone. Paper is more durable than ciphertext you've forgotten the passphrase to.

## When to apply

| Situation | Apply? |
|---|---|
| Multi-file deliverable you'd hate to recreate | ✅ Yes |
| You suspect any account or device is observed | ✅ Yes |
| You want the work to survive your current machine | ✅ Yes |
| Single throwaway script, ephemeral output | ❌ No |
| Output is itself a secret (keys, credentials) | ❌ Different problem — this pattern is for integrity/availability, not confidentiality |

## How Claude knows to do this

Memory entries in `/Users/evw/.claude/projects/-Users-evw-dev-security/memory/` describe this pattern and the threat-model context. Future Claude sessions in this project directory will offer the preservation bundle proactively for substantial work. To apply this *across all projects* (not just this directory), add a short note to `~/.claude/CLAUDE.md` referencing this guide.
