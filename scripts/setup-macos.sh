#!/usr/bin/env bash
# scripts/setup-macos.sh
# One-shot setup for AI Task Manager on macOS using Homebrew
# Usage: bash scripts/setup-macos.sh

set -euo pipefail

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()    { echo -e "${CYAN}[setup]${NC} $1"; }
success() { echo -e "${GREEN}[✓]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[✗]${NC} $1"; exit 1; }

echo ""
echo "  AI Task Manager — macOS Setup"
echo "  ================================"
echo ""

# ─── Check macOS ─────────────────────────────────────────
[[ "$(uname)" == "Darwin" ]] || error "This script is for macOS only."

# ─── Homebrew ────────────────────────────────────────────
if ! command -v brew &>/dev/null; then
  info "Installing Homebrew…"
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  # Add brew to PATH for Apple Silicon
  if [[ -f "/opt/homebrew/bin/brew" ]]; then
    eval "$(/opt/homebrew/bin/brew shellenv)"
  fi
else
  success "Homebrew already installed"
fi

# ─── Node.js ─────────────────────────────────────────────
if ! command -v node &>/dev/null; then
  info "Installing Node.js 20 via Homebrew…"
  brew install node@20
  # Add to PATH
  echo 'export PATH="/opt/homebrew/opt/node@20/bin:$PATH"' >> ~/.zshrc
  export PATH="/opt/homebrew/opt/node@20/bin:$PATH"
else
  NODE_VER=$(node --version | cut -d. -f1 | tr -d 'v')
  if [[ "$NODE_VER" -lt 18 ]]; then
    warn "Node.js $NODE_VER detected — version 18+ required. Installing node@20…"
    brew install node@20
    brew link node@20 --force
  else
    success "Node.js $(node --version) already installed"
  fi
fi

# ─── PostgreSQL ───────────────────────────────────────────
if ! brew list postgresql@16 &>/dev/null; then
  info "Installing PostgreSQL 16…"
  brew install postgresql@16
else
  success "PostgreSQL 16 already installed"
fi

# Start PostgreSQL
if ! brew services list | grep postgresql@16 | grep -q started; then
  info "Starting PostgreSQL…"
  brew services start postgresql@16
  sleep 2
fi
success "PostgreSQL running"

# Create DB user and database
info "Configuring database…"
PGUSER="${POSTGRES_USER:-aitm}"
PGPASS="${POSTGRES_PASSWORD:-change_me_in_prod}"
PGDB="${POSTGRES_DB:-aitaskmanager}"

# Create role (ignore error if exists)
psql postgres -c "CREATE USER ${PGUSER} WITH PASSWORD '${PGPASS}';" 2>/dev/null || true
psql postgres -c "CREATE DATABASE ${PGDB} OWNER ${PGUSER};" 2>/dev/null || true
psql postgres -c "GRANT ALL PRIVILEGES ON DATABASE ${PGDB} TO ${PGUSER};" 2>/dev/null || true
success "Database '${PGDB}' ready (user: ${PGUSER})"

# ─── Redis ───────────────────────────────────────────────
if ! brew list redis &>/dev/null; then
  info "Installing Redis…"
  brew install redis
else
  success "Redis already installed"
fi

if ! brew services list | grep redis | grep -q started; then
  info "Starting Redis…"
  brew services start redis
  sleep 1
fi
success "Redis running"

# ─── .env ────────────────────────────────────────────────
if [[ ! -f ".env" ]]; then
  info "Creating .env from .env.example…"
  cp .env.example .env

  # Update DATABASE_URL for local Homebrew Postgres (no password socket auth)
  SOCKET_DIR=$(psql postgres -t -c "SHOW unix_socket_directories;" 2>/dev/null | tr -d ' ' | head -1)
  if [[ -n "$SOCKET_DIR" ]]; then
    sed -i '' "s|DATABASE_URL=.*|DATABASE_URL=\"postgresql://${PGUSER}:${PGPASS}@localhost:5432/${PGDB}\"|" .env
  fi

  # Update REDIS_URL (local Redis, no password by default)
  sed -i '' 's|REDIS_URL=.*|REDIS_URL="redis://localhost:6379"|' .env

  # Generate NEXTAUTH_SECRET
  SECRET=$(openssl rand -base64 32)
  sed -i '' "s|NEXTAUTH_SECRET=.*|NEXTAUTH_SECRET=${SECRET}|" .env

  success ".env created — add your AI provider API keys"
  warn "Edit .env and add: ANTHROPIC_API_KEY, OPENAI_API_KEY, etc."
else
  success ".env already exists"
fi

# ─── npm install ─────────────────────────────────────────
info "Installing npm dependencies…"
npm install
success "Dependencies installed"

# ─── Prisma ──────────────────────────────────────────────
info "Generating Prisma client…"
npm run db:generate

info "Running database migrations…"
npm run db:migrate

info "Seeding database…"
npm run db:seed
success "Database migrated and seeded"

# ─── Done ────────────────────────────────────────────────
echo ""
echo -e "${GREEN}Setup complete!${NC}"
echo ""
echo "  Start development:"
echo ""
echo "    Terminal 1:  npm run dev"
echo "    Terminal 2:  npm run worker"
echo ""
echo "  Or use the convenience script:"
echo ""
echo "    bash scripts/start-macos.sh"
echo ""
echo "  Open http://localhost:3000"
echo "  Login: admin@example.com / Admin1234!"
echo ""
