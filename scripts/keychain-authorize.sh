#!/bin/bash
# keychain-authorize.sh — Grant silent script access to Keychain items.
#
# The macOS Keychain shows an access dialog the first time each script reads
# an item. Background LaunchAgents can't hold that dialog open, so it flashes
# and self-dismisses. This script sets the partition list for each migrated
# SECRET item (API keys, tokens, client secrets) to "apple:" — allowing any
# Apple-signed binary (bash, security, python) to read it without prompting.
#
# Account passwords (CHATGPT/GEMINI/GROK/PERPLEXITY/POE *_PASSWORD) and
# non-secret config values are deliberately NOT granted silent access —
# they keep prompting every time.
#
# Run this ONCE interactively (not via LaunchAgent):
#   bash ~/scripts/keychain-authorize.sh
#
# You will be prompted for your macOS login password once to unlock the
# login keychain so the ACLs can be updated. The password is fed to
# `security -i` over stdin — it never appears in process argv.

set -euo pipefail

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error-guard.sh)
_eg_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
while [ "$_eg_d" != "/" ] && [ ! -f "$_eg_d/lib/error-guard.sh" ]; do _eg_d="$(dirname "$_eg_d")"; done
[ -f "$_eg_d/lib/error-guard.sh" ] && . "$_eg_d/lib/error-guard.sh"; unset _eg_d
command -v guard_run >/dev/null 2>&1 || guard_run() { shift; "$@"; }
command -v guard_throw >/dev/null 2>&1 || guard_throw() { printf 'error-guard: throw: %s\n' "$*" >&2; return 1; }

ACCOUNT="$(whoami)"

KEYS=(
    # ── ai-orchestrator ────────────────────────────────────────
    # Only genuine secrets are granted silent reads. Account passwords
    # (CHATGPT/GEMINI/GROK/PERPLEXITY/POE *_PASSWORD + *_EMAIL) and
    # non-secret config values (DEBUG, OUTPUT_BASE_DIR, OLLAMA_BASE_URL,
    # CLAUDE_*_MODEL, EVALUATION_MODEL) were removed from this list:
    # silent access to full account credentials by any Apple-signed binary
    # is too much exposure, and granting non-secrets is pointless attack
    # surface. Those items keep prompting every time.
    DATABASE_URL
    REDIS_URL
    CELERY_BROKER_URL
    CELERY_RESULT_BACKEND
    ANTHROPIC_API_KEY
    OPENAI_API_KEY
    GEMINI_API_KEY
    GROK_API_KEY
    PERPLEXITY_API_KEY
    POE_API_KEY
    SECRET_KEY
    # ── shopify ────────────────────────────────────────────────
    # Tokens/client-secrets stay; shop names, URLs, API_VERSION,
    # REQUEST_DELAY and PUBLISH_PRODUCTS are non-secret config — removed.
    SOURCE_TOKEN
    SOURCE_ACCESS_TOKEN
    SOURCE_CLIENT_ID
    SOURCE_CLIENT_SECRET
    DEST_TOKEN
    DEST_ACCESS_TOKEN
    DEST_CLIENT_ID
    DEST_CLIENT_SECRET
    # ── google ─────────────────────────────────────────────────
    google-client-secrets
)

pass=0; skip=0; fail=0

ok()   { echo "  [OK]   $*"; pass=$((pass + 1)); }
warn() { echo "  [WARN] $*"; skip=$((skip + 1)); }
err()  { echo "  [FAIL] $*"; fail=$((fail + 1)); }

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║        Keychain ACL — Grant Silent Script Access         ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "  This grants SILENT read access to the API-key items listed"
echo "  above to ANY Apple-signed binary (via the 'apple:' partition"
echo "  list) so background scripts don't trigger disappearing dialogs."
echo ""
echo "  Account passwords and non-secret config values are NOT granted"
echo "  silent access — they keep prompting every time."
echo ""
echo "  You will be prompted for your macOS LOGIN password once."
echo ""

# Prompt for login keychain password securely
read -r -s -p "  Enter your macOS login password: " KEYCHAIN_PASS
echo ""
echo ""

# Password-bearing security(1) commands are fed to `security -i` over stdin:
# the password never appears in process argv (ps-visible to every user).
# They are wrapped in functions so guard_run's failure log — which records
# its argument list — only ever sees a bare function name, never the password.
kc_unlock() {
    printf '%s\n' "unlock-keychain -p \"${KEYCHAIN_PASS}\" \"${HOME}/Library/Keychains/login.keychain-db\"" | security -i
}
kc_set_partition() {  # $1 = keychain item (service) name
    printf '%s\n' "set-generic-password-partition-list -S apple: -a \"${ACCOUNT}\" -s \"$1\" -k \"${KEYCHAIN_PASS}\"" | security -i
}

# Verify the password unlocks the keychain before proceeding
if ! guard_run "keychain-unlock" kc_unlock 2>/dev/null; then
    echo "  [FAIL] Could not unlock login keychain — wrong password?"
    exit 1
fi
echo "  [OK]   Keychain unlocked"
echo ""
echo "── Setting partition lists ──────────────────────────────────"

for key in "${KEYS[@]}"; do
    # Check if item exists first
    if ! guard_run "keychain-find" security find-generic-password -a "$ACCOUNT" -s "$key" &>/dev/null; then
        warn "Not found: $key (skipped — may not be stored yet)"
        continue
    fi

    # apple: allows any Apple-signed binary (bash, security, python3) to read
    # without triggering a dialog
    if guard_run "keychain-set-partition" kc_set_partition "$key" 2>/dev/null; then
        ok "$key"
    else
        err "$key — failed to set partition list"
    fi
done

# Clear password from memory
KEYCHAIN_PASS=""
unset KEYCHAIN_PASS

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
printf  "║  Done: %3d authorized   %3d skipped   %3d failed        ║\n" $pass $skip $fail
echo    "╚══════════════════════════════════════════════════════════╝"
echo ""

if [[ $fail -gt 0 ]]; then
    echo "  Some items failed — re-run this script to retry."
    exit 1
fi

echo "  Background scripts can now read the granted API-key items silently."
echo "  No more flashing dialogs for those items."
echo ""
