#!/bin/bash
# ls-remove-terminal-any.sh
# Removes the Terminal→any/any/any allow rule (V-001) in one atomic operation.
# Must run as root: sudo bash /Users/evw/dev/security/ls-remove-terminal-any.sh

set -euo pipefail

LSCLI="/Applications/Little Snitch.app/Contents/Components/littlesnitch"
FRESH="/var/tmp/ls-remove-$(date +%s).json"
CLEAN="/var/tmp/ls-clean-$(date +%s).json"

echo "[1/3] Exporting current LS model..."
"$LSCLI" export-model "$FRESH" || true   # LS CLI returns non-zero even on success
if [ ! -f "$FRESH" ]; then
  echo "ERROR: export produced no file at $FRESH"
  exit 1
fi
echo "      Exported $(wc -c < "$FRESH") bytes to $FRESH"

echo "[2/3] Removing Terminal->any rule..."
python3 << PYEOF
import json, sys

src  = "$FRESH"
dst  = "$CLEAN"

d = json.load(open(src))
before = len(d["rules"])

d["rules"] = [r for r in d["rules"] if not (
    r.get("process", "") == "identifier.APPLE/com.apple.Terminal"
    and r.get("remote") == "any"
    and r.get("origin") == "monitor"
)]

after = len(d["rules"])
if before == after:
    print("  Rule not found — already removed or different state")
    sys.exit(0)

open(dst, "w").write(json.dumps(d, indent=2, separators=(",", " : ")) + "\n")
print(f"  Removed {before - after} rule(s)  ({before} → {after})")
PYEOF

if [ ! -f "$CLEAN" ]; then
  echo "      Rule already absent — nothing to do"
  exit 0
fi
echo "      Clean model: $(wc -c < "$CLEAN") bytes"

echo "[3/3] Importing clean model..."
"$LSCLI" restore-model "$CLEAN"
echo "SUCCESS — Terminal->any rule removed"

rm -f "$FRESH" "$CLEAN"
