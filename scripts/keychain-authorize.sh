#!/bin/bash
# keychain-authorize.sh — Grant silent script access to Keychain items.
#
# The macOS Keychain shows an access dialog the first time each script reads
# an item. Background LaunchAgents can't hold that dialog open, so it flashes
# and self-dismisses. This script sets the partition list for every migrated
# item to "apple:" — allowing any Apple-signed binary (bash, security, python)
# to read without prompting.
#
# Run this ONCE interactively (not via LaunchAgent):
#   bash ~/scripts/keychain-authorize.sh
#
# You will be prompted for your macOS login password once to unlock the
# login keychain so the ACLs can be updated.

set -euo pipefail

ACCOUNT="$(whoami)"

KEYS=(
    # ── ai-orchestrator ────────────────────────────────────────
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
    OLLAMA_BASE_URL
    CHATGPT_EMAIL
    CHATGPT_PASSWORD
    GEMINI_EMAIL
    GEMINI_PASSWORD
    GROK_EMAIL
    GROK_PASSWORD
    PERPLEXITY_EMAIL
    PERPLEXITY_PASSWORD
    POE_EMAIL
    POE_PASSWORD
    CLAUDE_DEFAULT_MODEL
    CLAUDE_FAST_MODEL
    EVALUATION_MODEL
    OUTPUT_BASE_DIR
    SECRET_KEY
    DEBUG
    # ── shopify ────────────────────────────────────────────────
    SOURCE_SHOP
    SOURCE_SHOP_URL
    SOURCE_TOKEN
    SOURCE_ACCESS_TOKEN
    SOURCE_CLIENT_ID
    SOURCE_CLIENT_SECRET
    DEST_SHOP
    DEST_SHOP_URL
    DEST_TOKEN
    DEST_ACCESS_TOKEN
    DEST_CLIENT_ID
    DEST_CLIENT_SECRET
    API_VERSION
    REQUEST_DELAY
    PUBLISH_PRODUCTS
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
echo "  This grants bash/python/security tool silent read access"
echo "  to your Keychain items so background scripts don't trigger"
echo "  disappearing dialogs."
echo ""
echo "  You will be prompted for your macOS LOGIN password once."
echo ""

# Prompt for login keychain password securely
read -r -s -p "  Enter your macOS login password: " KEYCHAIN_PASS
echo ""
echo ""

# Verify the password unlocks the keychain before proceeding
if ! security unlock-keychain -p "$KEYCHAIN_PASS" ~/Library/Keychains/login.keychain-db 2>/dev/null; then
    echo "  [FAIL] Could not unlock login keychain — wrong password?"
    exit 1
fi
echo "  [OK]   Keychain unlocked"
echo ""
echo "── Setting partition lists ──────────────────────────────────"

for key in "${KEYS[@]}"; do
    # Check if item exists first
    if ! security find-generic-password -a "$ACCOUNT" -s "$key" &>/dev/null; then
        warn "Not found: $key (skipped — may not be stored yet)"
        continue
    fi

    # apple: allows any Apple-signed binary (bash, security, python3) to read
    # without triggering a dialog
    if security set-generic-password-partition-list \
            -S "apple:" \
            -a "$ACCOUNT" \
            -s "$key" \
            -k "$KEYCHAIN_PASS" \
            2>/dev/null; then
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

echo "  Background scripts can now read Keychain items silently."
echo "  No more flashing dialogs."
echo ""
