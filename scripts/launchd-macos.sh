#!/usr/bin/env bash
# scripts/launchd-macos.sh
# Install or uninstall AI Task Manager as macOS launch agents
# Usage: bash scripts/launchd-macos.sh [install|uninstall|logs]

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
USERNAME="$(whoami)"
AGENTS_DIR="$HOME/Library/LaunchAgents"
PLIST_APP="$AGENTS_DIR/com.aitaskmanager.app.plist"
PLIST_WORKER="$AGENTS_DIR/com.aitaskmanager.worker.plist"

ACTION="${1:-install}"

patch_plist() {
  local src="$1"
  local dst="$2"
  # Replace placeholder path with actual project path and username
  sed "s|/Users/YOUR_USERNAME/aitaskmanager|${ROOT_DIR}|g" "$src" > "$dst"
  # Patch node path for Intel Macs
  if [[ "$(uname -m)" == "x86_64" ]]; then
    sed -i '' 's|/opt/homebrew/bin/node|/usr/local/bin/node|g' "$dst"
    sed -i '' 's|/opt/homebrew/bin:/usr/local/bin|/usr/local/bin|g' "$dst"
  fi
}

case "$ACTION" in
  install)
    mkdir -p "$AGENTS_DIR"

    echo "Patching and installing launch agents for user: $USERNAME"
    echo "Project path: $ROOT_DIR"
    echo ""

    patch_plist "$ROOT_DIR/launchd/com.aitaskmanager.app.plist" "$PLIST_APP"
    patch_plist "$ROOT_DIR/launchd/com.aitaskmanager.worker.plist" "$PLIST_WORKER"

    # Build the app first
    echo "Building Next.js app (required for production)…"
    cd "$ROOT_DIR" && npm run build

    launchctl load "$PLIST_APP"
    launchctl load "$PLIST_WORKER"

    echo ""
    echo "✓ Launch agents installed."
    echo "  App will start at login and restart on crash."
    echo ""
    echo "  Check status:  bash scripts/launchd-macos.sh status"
    echo "  View logs:     bash scripts/launchd-macos.sh logs"
    echo "  Uninstall:     bash scripts/launchd-macos.sh uninstall"
    ;;

  uninstall)
    echo "Uninstalling launch agents…"
    launchctl unload "$PLIST_APP" 2>/dev/null && echo "  App unloaded" || echo "  App was not loaded"
    launchctl unload "$PLIST_WORKER" 2>/dev/null && echo "  Worker unloaded" || echo "  Worker was not loaded"
    rm -f "$PLIST_APP" "$PLIST_WORKER"
    echo "✓ Uninstalled."
    ;;

  status)
    echo ""
    echo "LaunchAgent status:"
    launchctl list | grep aitaskmanager || echo "  (no aitaskmanager agents loaded)"
    echo ""
    echo "Process check:"
    lsof -i :3000 &>/dev/null && echo "  Next.js: running on :3000" || echo "  Next.js: not running"
    pgrep -f "tsx.*worker/index" &>/dev/null && echo "  Worker:  running" || echo "  Worker:  not running"
    echo ""
    ;;

  logs)
    echo "=== App log (Ctrl+C to stop) ==="
    tail -f /tmp/aitaskmanager-app.log /tmp/aitaskmanager-worker.log
    ;;

  *)
    echo "Usage: $0 [install|uninstall|status|logs]"
    exit 1
    ;;
esac
