#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#  MarketOS — Full Install Script
#  Usage:  bash install.sh [--dev] [--port <port>]
#
#  Place this file next to marketos-complete-build.zip and run it.
#  It will unzip, install dependencies, and start the app.
# ═══════════════════════════════════════════════════════════════════

set -e

# ── Colours ──────────────────────────────────────────────────────────
RESET='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'
CYAN='\033[38;5;51m'
GREEN='\033[38;5;120m'
AMBER='\033[38;5;215m'
RED='\033[38;5;203m'

ok()   { echo -e "  ${GREEN}✓${RESET}  $1"; }
info() { echo -e "  ${CYAN}→${RESET}  $1"; }
warn() { echo -e "  ${AMBER}⚠${RESET}  $1"; }
fail() { echo -e "\n  ${RED}✗  $1${RESET}\n"; exit 1; }
step() { echo -e "\n${BOLD}${CYAN}$1${RESET}"; echo -e "${DIM}$(printf '─%.0s' {1..52})${RESET}"; }

# ── Banner ────────────────────────────────────────────────────────────
clear
echo ""
echo -e "${BOLD}${CYAN}"
echo "  ███╗   ███╗ █████╗ ██████╗ ██╗  ██╗███████╗████████╗ ██████╗ ███████╗"
echo "  ████╗ ████║██╔══██╗██╔══██╗██║ ██╔╝██╔════╝╚══██╔══╝██╔═══██╗██╔════╝"
echo "  ██╔████╔██║███████║██████╔╝█████╔╝ █████╗     ██║   ██║   ██║███████╗"
echo "  ██║╚██╔╝██║██╔══██║██╔══██╗██╔═██╗ ██╔══╝     ██║   ██║   ██║╚════██║"
echo "  ██║ ╚═╝ ██║██║  ██║██║  ██║██║  ██╗███████╗   ██║   ╚██████╔╝███████║"
echo "  ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝    ╚═════╝ ╚══════╝"
echo -e "${RESET}"
echo -e "  ${DIM}Unified Marketing Automation Platform — v1.0${RESET}"
echo ""

# ── Parse flags ───────────────────────────────────────────────────────
START_DEV=false
PORT=3001

for arg in "$@"; do
  case $arg in
    --dev)        START_DEV=true ;;
    --port)       shift; PORT="$1" ;;
    --port=*)     PORT="${arg#*=}" ;;
  esac
done

# ── Locate script directory (where the zip should live) ──────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZIP_FILE="$SCRIPT_DIR/marketos-complete-build.zip"
INSTALL_DIR="$SCRIPT_DIR/marketos"

# ── Step 1: Prerequisites ─────────────────────────────────────────────
step "1/4  Checking prerequisites"

if ! command -v node &>/dev/null; then
  fail "Node.js is not installed. Download from https://nodejs.org (v18+ required)"
fi
NODE_VER=$(node -e "process.stdout.write(process.version.slice(1).split('.')[0])")
if [ "$NODE_VER" -lt 18 ]; then
  fail "Node.js v18+ required (found v${NODE_VER}). Download from https://nodejs.org"
fi
ok "Node.js $(node --version)"

if ! command -v npm &>/dev/null; then
  fail "npm is not installed"
fi
ok "npm $(npm --version)"

if ! command -v unzip &>/dev/null; then
  fail "'unzip' is not installed. Install via: brew install unzip  or  apt install unzip"
fi
ok "unzip $(unzip -v | head -1 | awk '{print $2}')"

# ── Step 2: Unzip ─────────────────────────────────────────────────────
step "2/4  Extracting application"

if [ ! -f "$ZIP_FILE" ]; then
  fail "marketos-complete-build.zip not found next to this script.\nExpected: $ZIP_FILE"
fi

if [ -d "$INSTALL_DIR" ]; then
  warn "Directory '$INSTALL_DIR' already exists"
  read -rp "  Overwrite it? [y/N] " OVERWRITE
  OVERWRITE=${OVERWRITE:-N}
  if [[ "$OVERWRITE" =~ ^[Yy]$ ]]; then
    rm -rf "$INSTALL_DIR"
    ok "Removed existing directory"
  else
    info "Using existing directory — skipping extraction"
    goto_install=true
  fi
fi

if [ "${goto_install:-false}" = false ]; then
  mkdir -p "$INSTALL_DIR"
  unzip -q "$ZIP_FILE" -d "$INSTALL_DIR"
  # zip extracts into marketing-app/ subfolder — flatten one level if present
  if [ -d "$INSTALL_DIR/marketing-app" ] && [ ! -f "$INSTALL_DIR/package.json" ]; then
    mv "$INSTALL_DIR/marketing-app/"* "$INSTALL_DIR/" 2>/dev/null || true
    mv "$INSTALL_DIR/marketing-app/".* "$INSTALL_DIR/" 2>/dev/null || true
    rmdir "$INSTALL_DIR/marketing-app" 2>/dev/null || true
  fi
  ok "Extracted to $INSTALL_DIR"
fi

cd "$INSTALL_DIR"

if [ ! -f "package.json" ]; then
  fail "Extraction failed — package.json not found in $INSTALL_DIR"
fi

# ── Step 3: Environment ───────────────────────────────────────────────
step "3/4  Setting up environment"

if [ -f "env.example" ] && [ ! -f ".env.local" ]; then
  cp env.example .env.local
  ok "Created .env.local from env.example"
  info "Edit .env.local to connect your Shopify / API credentials"
elif [ -f ".env.local" ]; then
  ok ".env.local already present — skipping"
else
  warn "No env.example found — .env.local not created"
fi

# ── Step 4: Install dependencies ─────────────────────────────────────
step "4/4  Installing dependencies"

npm install --prefer-offline 2>&1 | tail -3
ok "Dependencies installed ($(node -e "const p=require('./package.json'); const n=Object.keys({...p.dependencies,...p.devDependencies}).length; process.stdout.write(n+' packages')"))"

# ── Done ──────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}  ✓  MarketOS is ready!${RESET}"
echo ""
echo -e "  ${DIM}App directory:${RESET}  ${BOLD}$INSTALL_DIR${RESET}"
echo ""

if [ "$START_DEV" = true ]; then
  echo -e "  ${CYAN}→${RESET}  Starting development server on port ${BOLD}$PORT${RESET}…"
  echo ""
  npm run dev -- --port "$PORT"
else
  echo -e "  ${DIM}To start:${RESET}"
  echo -e "  ${BOLD}  cd $INSTALL_DIR${RESET}"
  echo -e "  ${BOLD}  npm run dev${RESET}"
  echo ""
  echo -e "  ${DIM}Or start immediately:${RESET}"
  echo -e "  ${BOLD}  bash install.sh --dev${RESET}"
  echo -e "  ${BOLD}  bash install.sh --dev --port 8080${RESET}"
  echo ""
  echo -e "  ${DIM}Once running, open:${RESET}  ${CYAN}http://localhost:$PORT${RESET}"
  echo ""
fi
