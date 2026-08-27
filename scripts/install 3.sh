#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════
#  MarketOS — Install Script
#  Usage: bash install.sh [--skip-wizard] [--dev]
# ═══════════════════════════════════════════════════════════

set -e

# ── Colours ─────────────────────────────────────────────────
RESET='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'
CYAN='\033[38;5;51m'
GREEN='\033[38;5;120m'
AMBER='\033[38;5;215m'
RED='\033[38;5;203m'
PURPLE='\033[38;5;141m'
BG_DARK='\033[48;5;234m'

# ── Helpers ──────────────────────────────────────────────────
ok()   { echo -e "  ${GREEN}✓${RESET}  $1"; }
info() { echo -e "  ${CYAN}→${RESET}  $1"; }
warn() { echo -e "  ${AMBER}⚠${RESET}  $1"; }
fail() { echo -e "  ${RED}✗${RESET}  $1"; exit 1; }
step() { echo -e "\n${BOLD}${CYAN}$1${RESET}"; echo -e "${DIM}$(printf '─%.0s' {1..52})${RESET}"; }

# ── Banner ───────────────────────────────────────────────────
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
echo -e "  ${DIM}Unified Marketing Automation Platform${RESET}"
echo -e "  ${DIM}v1.0 — Shopify + 14 Integrations${RESET}"
echo ""

# ── Parse flags ──────────────────────────────────────────────
SKIP_WIZARD=false
START_DEV=false

for arg in "$@"; do
  case $arg in
    --skip-wizard) SKIP_WIZARD=true ;;
    --dev)         START_DEV=true   ;;
  esac
done

# ── Check prerequisites ───────────────────────────────────────
step "1/4  Checking prerequisites"

# Node.js
if ! command -v node &>/dev/null; then
  fail "Node.js is not installed. Download from https://nodejs.org (v18 or higher required)"
fi
NODE_VER=$(node -e "process.stdout.write(process.version.slice(1).split('.')[0])")
if [ "$NODE_VER" -lt 18 ]; then
  fail "Node.js v18+ required (found v${NODE_VER}). Download from https://nodejs.org"
fi
ok "Node.js $(node --version)"

# npm
if ! command -v npm &>/dev/null; then
  fail "npm is not installed"
fi
ok "npm $(npm --version)"

# git (optional)
if command -v git &>/dev/null; then
  ok "git $(git --version | awk '{print $3}')"
else
  warn "git not found — version control unavailable"
fi

# ── Environment file ─────────────────────────────────────────
step "2/4  Setting up environment"

ENV_FILE=".env.local"
TEMPLATE="env.example"

if [ ! -f "$TEMPLATE" ]; then
  fail "env.example not found. Make sure you are in the marketing-app directory."
fi

if [ -f "$ENV_FILE" ]; then
  warn ".env.local already exists — skipping copy"
  warn "Delete .env.local and re-run install.sh to reset credentials"
else
  cp "$TEMPLATE" "$ENV_FILE"
  ok "Created .env.local from env.example"
  info "Edit .env.local to add your API credentials (or run the wizard below)"
fi

# ── Install dependencies ──────────────────────────────────────
step "3/4  Installing dependencies"

if [ -d "node_modules" ] && [ -f "node_modules/.package-lock.json" ]; then
  info "node_modules already present — running npm install to sync"
fi

npm install --prefer-offline 2>&1 | tail -3
ok "Dependencies installed"

# ── Configuration wizard ──────────────────────────────────────
step "4/4  Configuration"

if [ "$SKIP_WIZARD" = true ]; then
  info "Skipping wizard (--skip-wizard flag set)"
  info "Run  node scripts/wizard.js  at any time to configure integrations"
else
  echo ""
  echo -e "  ${BOLD}Would you like to run the API configuration wizard now?${RESET}"
  echo -e "  ${DIM}The wizard walks through connecting all your integrations.${RESET}"
  echo -e "  ${DIM}You can also skip and configure via the in-app Settings page.${RESET}"
  echo ""
  read -rp "  Run wizard? [Y/n] " RUN_WIZ
  RUN_WIZ=${RUN_WIZ:-Y}

  if [[ "$RUN_WIZ" =~ ^[Yy]$ ]]; then
    echo ""
    node scripts/wizard.js
  else
    info "Skipped. Run  node scripts/wizard.js  whenever you're ready."
    info "Or open  http://localhost:3001/setup  after starting the app."
  fi
fi

# ── Done ─────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}  ✓  Installation complete!${RESET}"
echo ""
echo -e "  ${DIM}Start the development server:${RESET}"
echo -e "  ${BOLD}  npm run dev${RESET}"
echo ""
echo -e "  ${DIM}Or run everything now:${RESET}"
echo -e "  ${BOLD}  npm run dev -- --port 3001${RESET}"
echo ""
echo -e "  ${DIM}In-app setup wizard:${RESET}"
echo -e "  ${CYAN}  http://localhost:3001/setup${RESET}"
echo ""

# ── Auto-start dev server if --dev flag passed ────────────────
if [ "$START_DEV" = true ]; then
  info "Starting development server..."
  npm run dev -- --port 3001
fi
