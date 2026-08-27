#!/usr/bin/env bash
# =============================================================================
#  run_migration.sh  —  Shopify Migration Tool Launcher
#
#  Automatically creates a Python virtual environment, installs dependencies,
#  and runs shopify_migrate.py.  Works on macOS and Linux.
#
#  IMPORTANT: Always run this launcher — never call python3 directly.
#  The venv inside .venv/ has the required packages; system Python does not.
#
#  Usage:
#    chmod +x run_migration.sh
#    ./run_migration.sh                   # interactive group selector
#    ./run_migration.sh --all             # migrate everything
#    ./run_migration.sh --groups products customers
#    ./run_migration.sh --dry-run         # preview, no writes
#    ./run_migration.sh --resume          # resume interrupted run
#    ./run_migration.sh --validate        # QA report only
#    ./run_migration.sh --list            # list all groups
#    ./run_migration.sh --rebuild-venv    # force-rebuild the virtual environment
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"
MIGRATE_SCRIPT="$SCRIPT_DIR/shopify_migrate.py"

# ── Colour helpers ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${BLUE}[setup]${RESET} $*"; }
success() { echo -e "${GREEN}[setup]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[warn] ${RESET} $*"; }
error()   { echo -e "${RED}[error]${RESET} $*" >&2; }

# ── Detect OS ─────────────────────────────────────────────────────────────────
OS="unknown"
if [[ "$(uname)" == "Darwin" ]]; then
    OS="macos"
elif [[ "$(uname)" == "Linux" ]]; then
    OS="linux"
fi

# ── Check shopify_migrate.py exists ───────────────────────────────────────────
if [[ ! -f "$MIGRATE_SCRIPT" ]]; then
    error "shopify_migrate.py not found at: $MIGRATE_SCRIPT"
    error "Both files must be in the same directory."
    exit 1
fi

# ── Find Python 3.8+ ──────────────────────────────────────────────────────────
find_python() {
    local py=""
    for cmd in python3 python3.13 python3.12 python3.11 python3.10 python3.9 python3.8 python; do
        if command -v "$cmd" &>/dev/null; then
            # Verify it is actually Python 3.8+
            local ok
            ok=$("$cmd" -c "
import sys
ok = sys.version_info >= (3, 8)
print('yes' if ok else 'no')
" 2>/dev/null || echo "no")
            if [[ "$ok" == "yes" ]]; then
                py="$cmd"; break
            fi
        fi
    done

    if [[ -z "$py" ]]; then
        error "Python 3.8 or higher not found."
        if [[ "$OS" == "macos" ]]; then
            error "Install Python on macOS:"
            error "  Option 1 (recommended): https://www.python.org/downloads/macos/"
            error "  Option 2 (Homebrew):    brew install python3"
        else
            error "Install Python on Linux:"
            error "  sudo apt install python3 python3-venv python3-full"
        fi
        exit 1
    fi
    echo "$py"
}

# ── Ensure venv module is available ───────────────────────────────────────────
ensure_venv() {
    local py="$1"
    if ! "$py" -c "import venv" &>/dev/null; then
        warn "venv module not available for $py"
        if [[ "$OS" == "linux" ]] && command -v apt-get &>/dev/null; then
            warn "Attempting: sudo apt-get install python3-venv python3-full ..."
            sudo apt-get install -y python3-venv python3-full 2>/dev/null || {
                error "Could not install python3-venv. Run manually:"
                error "  sudo apt install python3-venv python3-full"
                exit 1
            }
        elif [[ "$OS" == "macos" ]]; then
            error "venv is missing from your Python installation."
            error "Re-install Python from https://www.python.org/downloads/macos/"
            exit 1
        else
            error "venv module missing. Install python3-venv for your OS."
            exit 1
        fi
    fi
}

# ── Create virtual environment ─────────────────────────────────────────────────
create_venv() {
    local py="$1"
    info "Creating virtual environment at $VENV_DIR ..."
    "$py" -m venv "$VENV_DIR"
    success "Virtual environment created"
}

# ── Install dependencies ───────────────────────────────────────────────────────
install_deps() {
    local pip="$VENV_DIR/bin/pip"
    info "Installing dependencies (requests, certifi) ..."
    "$pip" install --quiet --upgrade pip
    "$pip" install --quiet requests certifi
    local ver
    ver=$("$VENV_DIR/bin/python" -c 'import requests; print(requests.__version__)')
    success "Installed: requests $ver"
}

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}  Shopify Migration Tool — Environment Setup${RESET}"
echo -e "${BOLD}  OS: $OS${RESET}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""

# ── Force rebuild if requested ────────────────────────────────────────────────
if [[ "${1:-}" == "--rebuild-venv" ]]; then
    warn "Removing existing .venv for rebuild ..."
    rm -rf "$VENV_DIR"
    shift
fi

# ── Find Python ───────────────────────────────────────────────────────────────
PYTHON=$(find_python)
PYVER=$("$PYTHON" --version 2>&1)
info "Using: $PYTHON ($PYVER)"

# ── Remove broken venv (exists but python binary missing) ─────────────────────
if [[ -d "$VENV_DIR" ]] && [[ ! -f "$VENV_DIR/bin/python" ]]; then
    warn "Existing .venv is broken — removing and rebuilding ..."
    rm -rf "$VENV_DIR"
fi

# ── Create venv if needed ─────────────────────────────────────────────────────
if [[ ! -d "$VENV_DIR" ]]; then
    ensure_venv "$PYTHON"
    create_venv "$PYTHON"
    install_deps
else
    # Venv exists — just check requests is installed
    if ! "$VENV_DIR/bin/python" -c "import requests" &>/dev/null; then
        info "Reinstalling missing dependencies ..."
        install_deps
    else
        RVER=$("$VENV_DIR/bin/python" -c 'import requests; print(requests.__version__)')
        success "Virtual environment ready (requests $RVER)"
    fi
fi

# ── Credentials reminder if SOURCE_SHOP not set ───────────────────────────────
if [[ -z "${SOURCE_SHOP:-}" ]]; then
    echo ""
    echo -e "${YELLOW}[warn]  SOURCE_SHOP is not set. Export credentials before running:${RESET}"
    echo ""
    echo "  export SOURCE_SHOP=\"bakery-wholesalers.myshopify.com\""
    echo "  export SOURCE_CLIENT_ID=\"...\""
    echo "  export SOURCE_CLIENT_SECRET=\"...\""
    echo "  export DEST_SHOP=\"donut-equipment.myshopify.com\""
    echo "  export DEST_CLIENT_ID=\"...\""
    echo "  export DEST_CLIENT_SECRET=\"...\""
    echo ""
fi

echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}  Running Migration${RESET}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""

# Launch the migration script using the venv python (has all dependencies)
exec "$VENV_DIR/bin/python" "$MIGRATE_SCRIPT" "$@"
