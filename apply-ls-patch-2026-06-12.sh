#!/usr/bin/env bash
# Apply patched LS model + deploy fixed watchdog. Run: sudo bash ~/dev/security/apply-ls-patch-2026-06-12.sh
set -euo pipefail

LSCLI="/Applications/Little Snitch.app/Contents/Components/littlesnitch"

"$LSCLI" restore-model -t < /tmp/ls-model-2026-06-12-patched.json
echo "model imported"

cp /Users/eric/dev/security/evw-ls-watchdog.sh /usr/local/bin/evw-ls-watchdog.sh
chmod 755 /usr/local/bin/evw-ls-watchdog.sh
echo "watchdog deployed"

"$LSCLI" export-model /tmp/ls-model-verify.json
chown eric /tmp/ls-model-verify.json
chmod 600 /tmp/ls-model-verify.json
echo "IMPORT-AND-DEPLOY-OK"
