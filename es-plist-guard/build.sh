#!/bin/bash
# build.sh — compile es-plist-guard.
#
# Compiling always works. RUNNING it requires a signature carrying the
# restricted entitlement com.apple.developer.endpoint-security.client
# (paid Apple Developer account + Apple-approved Endpoint Security
# capability — see README.md). Until then the binary starts and
# es_new_client() is refused; that refusal is the expected self-test.
set -euo pipefail
cd "$(dirname "$0")"

clang -O2 -fblocks -Wall -Wextra -o es-plist-guard es-plist-guard.c -lEndpointSecurity -lbsm

# Ad-hoc signature so the loader accepts the binary. ES will still refuse it
# at runtime without the real entitlement:
codesign --force --sign - es-plist-guard

# Once the capability is approved, sign for real instead:
#   codesign --force --options runtime --timestamp \
#     --sign "Apple Development: <your name> (<team id>)" \
#     --entitlements entitlements.plist es-plist-guard

echo "built ./es-plist-guard (adhoc-signed; run it — es_new_client refusal is expected pre-entitlement)"
