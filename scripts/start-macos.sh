#!/usr/bin/env bash
# scripts/start-macos.sh
# Starts Next.js dev server + BullMQ worker in separate Terminal tabs
# Usage: bash scripts/start-macos.sh

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Ensure Homebrew services are running
if ! brew services list | grep postgresql@16 | grep -q started 2>/dev/null; then
  echo "[start] Starting PostgreSQL…"
  brew services start postgresql@16
  sleep 2
fi

if ! brew services list | grep redis | grep -q started 2>/dev/null; then
  echo "[start] Starting Redis…"
  brew services start redis
  sleep 1
fi

echo "[start] Infrastructure running"

# Open two Terminal tabs
osascript <<EOF
tell application "Terminal"
  activate

  -- Tab 1: Next.js dev server
  do script "cd '${ROOT_DIR}' && echo '=== Next.js Dev Server ===' && npm run dev"

  -- Tab 2: BullMQ worker
  tell application "System Events" to keystroke "t" using command down
  do script "cd '${ROOT_DIR}' && echo '=== BullMQ Worker ===' && npm run worker" in front window
end tell
EOF

echo "[start] Opened Terminal with two tabs (Next.js + Worker)"
echo "[start] App will be at http://localhost:3000"
