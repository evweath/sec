#!/usr/bin/env bash
# scripts/services-macos.sh
# Manage Homebrew background services
# Usage: bash scripts/services-macos.sh [start|stop|status|restart]

ACTION="${1:-status}"

case "$ACTION" in
  start)
    echo "Starting PostgreSQL and Redis…"
    brew services start postgresql@16
    brew services start redis
    echo "Done."
    ;;
  stop)
    echo "Stopping PostgreSQL and Redis…"
    brew services stop postgresql@16
    brew services stop redis
    echo "Done."
    ;;
  restart)
    echo "Restarting PostgreSQL and Redis…"
    brew services restart postgresql@16
    brew services restart redis
    echo "Done."
    ;;
  status|*)
    echo ""
    echo "Service Status:"
    brew services list | grep -E "(postgresql|redis)"
    echo ""
    # Check if Next.js is running
    if lsof -i :3000 &>/dev/null; then
      echo "  Next.js:  running on :3000"
    else
      echo "  Next.js:  not running"
    fi
    # Check if worker is running
    if pgrep -f "tsx.*worker/index" &>/dev/null; then
      echo "  Worker:   running (PID $(pgrep -f 'tsx.*worker/index'))"
    else
      echo "  Worker:   not running"
    fi
    echo ""
    ;;
esac
