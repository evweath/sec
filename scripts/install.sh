#!/usr/bin/env bash
# install.sh — AI Orchestrator VM setup
# Tested on Ubuntu 22.04 / Debian 12
# Run as your normal user (not root). Will prompt for sudo when needed.
set -euo pipefail

# ── Config — edit these if needed ────────────────────────────────────────────
APP_DIR="$(cd "$(dirname "$0")" && pwd)"   # defaults to the folder this script is in
APP_USER="$(whoami)"
VENV="$APP_DIR/venv"
PYTHON="python3"

echo "============================================"
echo " AI Orchestrator Install"
echo " App dir : $APP_DIR"
echo " User    : $APP_USER"
echo "============================================"

# ── 1. System packages ────────────────────────────────────────────────────────
echo "[1/7] Installing system packages..."
sudo apt-get update -qq
sudo apt-get install -y -qq \
    python3 python3-venv python3-pip \
    libpq-dev gcc \
    nginx \
    docker.io docker-compose-plugin \
    curl

# Ensure Docker is running (for postgres + redis)
sudo systemctl enable docker
sudo systemctl start docker
# Add current user to docker group so we don't need sudo for docker commands
sudo usermod -aG docker "$APP_USER"

# ── 2. Python virtualenv ──────────────────────────────────────────────────────
echo "[2/7] Creating Python virtualenv..."
$PYTHON -m venv "$VENV"
"$VENV/bin/pip" install --upgrade pip -q

# ── 3. Python dependencies ────────────────────────────────────────────────────
echo "[3/7] Installing Python dependencies..."
"$VENV/bin/pip" install -r "$APP_DIR/backend/requirements.txt" -q

# ── 4. Playwright chromium ────────────────────────────────────────────────────
echo "[4/7] Installing Playwright + Chromium..."
"$VENV/bin/playwright" install chromium
"$VENV/bin/playwright" install-deps chromium

# ── 5. Start databases (postgres + redis in Docker) ───────────────────────────
echo "[5/7] Starting PostgreSQL + Redis..."
# Need docker group — use newgrp trick or sg
sg docker -c "docker compose -f '$APP_DIR/docker-compose.db.yml' up -d"

echo "Waiting for PostgreSQL to be ready..."
for i in $(seq 1 30); do
    if sg docker -c "docker compose -f '$APP_DIR/docker-compose.db.yml' exec -T postgres pg_isready -U orchestrator" &>/dev/null; then
        echo "PostgreSQL is ready."
        break
    fi
    sleep 2
done

# ── 6. Setup .env if it doesn't exist ────────────────────────────────────────
if [ ! -f "$APP_DIR/.env" ]; then
    echo "[6/7] Creating .env from example..."
    cp "$APP_DIR/.env.example" "$APP_DIR/.env"
    echo ""
    echo "  ⚠️  .env created. You MUST edit it and add your credentials:"
    echo "     nano $APP_DIR/.env"
    echo ""
    echo "  At minimum set:"
    echo "     CLAUDE_EMAIL and CLAUDE_PASSWORD (primary — claude.ai account)"
    echo "     ANTHROPIC_API_KEY (backup only)"
    echo ""
    read -p "Press Enter after editing .env to continue..." _
else
    echo "[6/7] .env already exists — skipping."
fi

# ── 7. Run Alembic migrations ─────────────────────────────────────────────────
echo "[7/7] Running database migrations..."
cd "$APP_DIR/backend"
"$VENV/bin/alembic" upgrade head

# ── 8. Install systemd services ───────────────────────────────────────────────
echo "Installing systemd services..."
for svc in api worker beat; do
    src="$APP_DIR/systemd/ai-orchestrator-${svc}.service"
    dst="/etc/systemd/system/ai-orchestrator-${svc}.service"
    sed -e "s|__APP_DIR__|$APP_DIR|g" \
        -e "s|__APP_USER__|$APP_USER|g" \
        "$src" | sudo tee "$dst" > /dev/null
done

sudo systemctl daemon-reload
sudo systemctl enable ai-orchestrator-api ai-orchestrator-worker ai-orchestrator-beat
sudo systemctl start  ai-orchestrator-api ai-orchestrator-worker ai-orchestrator-beat

# ── 9. Nginx config ────────────────────────────────────────────────────────────
echo "Configuring Nginx..."
sudo tee /etc/nginx/sites-available/ai-orchestrator > /dev/null << 'NGINXEOF'
server {
    listen 80;
    server_name _;

    # Frontend static files (served by FastAPI or a separate static build)
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 300;
        proxy_send_timeout 300;
    }

    # WebSocket support (for streaming output, future use)
    location /ws {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
NGINXEOF

sudo ln -sf /etc/nginx/sites-available/ai-orchestrator /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx

echo ""
echo "============================================"
echo " Install complete!"
echo ""
echo " Check service status:"
echo "   sudo systemctl status ai-orchestrator-api"
echo "   sudo systemctl status ai-orchestrator-worker"
echo "   sudo systemctl status ai-orchestrator-beat"
echo ""
echo " View logs:"
echo "   journalctl -u ai-orchestrator-api -f"
echo "   journalctl -u ai-orchestrator-worker -f"
echo ""
echo " Test the API:"
echo "   curl http://localhost/api/v1/providers"
echo ""
echo " First-run Gemini session setup (if using Gemini):"
echo "   cd $APP_DIR/backend"
echo "   $VENV/bin/python -c 'import asyncio; from services.gemini_browser import gemini_browser; asyncio.run(gemini_browser.setup_session())'"
echo "============================================"
