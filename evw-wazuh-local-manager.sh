#!/usr/bin/env bash
# =============================================================================
# evw-wazuh-local-manager.sh — Wazuh MANAGER on this Mac (single-node docker
# stack in colima), so the local agent (10.0.0.2 was never reachable) has a
# real manager. All ports bind to 127.0.0.1 — nothing is exposed to the LAN.
#
# Deploy lessons encoded here (2026-10-01):
#   - v4.14.7 cert generator omits root-ca-manager.pem — copy root-ca.pem.
#   - the indexer takes NO password env: admin/kibanaserver live as bcrypt
#     hashes in config/wazuh_indexer/internal_users.yml — regenerate them with
#     the image's hash.sh. INDEXER_PASSWORD/DASHBOARD_PASSWORD only tell the
#     manager/dashboard how to CONNECT.
#   - the security index is initialized from internal_users.yml only on a
#     FRESH wazuh-indexer-data volume (down -v to reinitialize).
#
# Usage:
#   bash evw-wazuh-local-manager.sh setup     # one-time: passwords, certs, up
#   bash evw-wazuh-local-manager.sh start|stop|status
#   sudo bash evw-wazuh-setup.sh 127.0.0.1    # then point the agent here
#
# Stack: /Users/evw/dev/security/wazuh-stack (wazuh-docker v4.14.7 single-node,
# matches agent 4.14.7). Dashboard: https://127.0.0.1 (admin / generated).
# =============================================================================
set -euo pipefail

_eg_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
while [ "$_eg_d" != "/" ] && [ ! -f "$_eg_d/lib/error-guard.sh" ]; do _eg_d="$(dirname "$_eg_d")"; done
[ -f "$_eg_d/lib/error-guard.sh" ] && . "$_eg_d/lib/error-guard.sh"; unset _eg_d
command -v guard_run >/dev/null 2>&1 || guard_run() { shift; "$@"; }

STACK="/Users/evw/dev/security/wazuh-stack"
CREDS="$STACK/.credentials"   # 600, gitignored
COMPOSE="docker compose -f $STACK/docker-compose.yml"

gen_pw() { openssl rand -hex 12; }   # 24 hex chars; avoids tr|head SIGPIPE under pipefail

need() { command -v "$1" >/dev/null 2>&1 || { echo "[!] missing: $1 (brew install $1)" >&2; exit 1; }; }

wait_api() {
    echo "[*] waiting for manager API on 127.0.0.1:55000 ..."
    for i in $(seq 1 60); do
        code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 https://127.0.0.1:55000/ 2>/dev/null || echo 000)
        case "$code" in
            200|401) echo "    API up (http $code) after ~$((i*5))s"; return 0 ;;
        esac
        sleep 5
    done
    echo "[!] API did not come up in 5 min — check: $COMPOSE logs wazuh.manager" >&2
    return 1
}

cmd_setup() {
    need colima; need docker
    colima status >/dev/null 2>&1 || { echo "[!] colima not running — start it: colima start"; exit 1; }

    if [ ! -f "$STACK/docker-compose.yml" ]; then
        echo "[0/4] Fetching wazuh-docker v4.14.7 single-node (matches agent)..."
        rm -rf /tmp/wazuh-docker.$$  # shallow clone, keep only single-node
        guard_run "wazuh-clone" git clone --depth 1 --branch v4.14.7 \
            https://github.com/wazuh/wazuh-docker.git /tmp/wazuh-docker.$$
        mkdir -p "$STACK"
        cp -R /tmp/wazuh-docker.$$/single-node/. "$STACK/"
        rm -rf /tmp/wazuh-docker.$$
        # bind every published port to loopback — nothing on the LAN
        sed -i '' \
            -e 's|- "1514:1514"|- "127.0.0.1:1514:1514"|' \
            -e 's|- "1515:1515"|- "127.0.0.1:1515:1515"|' \
            -e 's|- "514:514/udp"|- "127.0.0.1:514:514/udp"|' \
            -e 's|- "55000:55000"|- "127.0.0.1:55000:55000"|' \
            -e 's|- "9200:9200"|- "127.0.0.1:9200:9200"|' \
            -e 's|- 443:5601|- 127.0.0.1:443:5601|' \
            "$STACK/docker-compose.yml"
    fi

    if grep -q "INDEXER_PASSWORD=SecretPassword" "$STACK/docker-compose.yml"; then
        echo "[1/4] Generating strong passwords (replacing stock defaults)..."
        IW=$(gen_pw); KB=$(gen_pw)
        sed -i '' -e "s/INDEXER_PASSWORD=SecretPassword/INDEXER_PASSWORD=$IW/g" \
                  -e "s/DASHBOARD_PASSWORD=kibanaserver/DASHBOARD_PASSWORD=$KB/g" \
                  "$STACK/docker-compose.yml"
        { echo "# wazuh local stack credentials — $(date -Iseconds)  (chmod 600, gitignored)"
          echo "dashboard: https://127.0.0.1  user=admin  password=$IW"
          echo "dashboard service account (kibanaserver): $KB"
          echo "wazuh API: https://127.0.0.1:55000  user=wazuh-wui  password=$IW  (default stock: wazuh-wui/MyS3cr37P450r14- — change in Dashboard → Server management → API)"
        } > "$CREDS"
        chmod 600 "$CREDS"
        echo "    credentials written to $CREDS (600)"

        echo "    hashing passwords into internal_users.yml (indexer reads"
        echo "    bcrypt hashes from that file — it takes no password env)..."
        IUSERS="$STACK/config/wazuh_indexer/internal_users.yml"
        [ -f "$IUSERS.bak" ] || cp "$IUSERS" "$IUSERS.bak"
        H1=$(docker run --rm wazuh/wazuh-indexer:4.14.7 bash \
            /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$IW" \
            2>/dev/null | grep -oE '\$2[ayb]\$[0-9]+\$[./A-Za-z0-9]+')
        H2=$(docker run --rm wazuh/wazuh-indexer:4.14.7 bash \
            /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$KB" \
            2>/dev/null | grep -oE '\$2[ayb]\$[0-9]+\$[./A-Za-z0-9]+')
        [ -n "$H1" ] && [ -n "$H2" ] || { echo "[!] hash generation failed" >&2; exit 1; }
        H1="$H1" H2="$H2" IUSERS="$IUSERS" python3 << 'PYEOF'
import os
p = os.environ['IUSERS']
lines = open(p).readlines()
assert lines[12].strip() == 'admin:', lines[12]
assert lines[19].strip() == 'kibanaserver:', lines[19]
lines[13] = '  hash: "%s"\n' % os.environ['H1']
lines[20] = '  hash: "%s"\n' % os.environ['H2']
open(p, 'w').writelines(lines)
print('    internal_users.yml updated (admin + kibanaserver)')
PYEOF
    else
        echo "[1/4] passwords already set — keeping existing"
    fi

    # v4.14.7 generator omits root-ca-manager.pem; the manager mounts it
    CERTS="$STACK/config/wazuh_indexer_ssl_certs"
    if [ -d "$CERTS" ] && [ ! -f "$CERTS/root-ca-manager.pem" ]; then
        chmod u+w "$CERTS" 2>/dev/null || true
        cp "$CERTS/root-ca.pem" "$CERTS/root-ca-manager.pem"
        chmod 400 "$CERTS/root-ca-manager.pem"
        echo "    created root-ca-manager.pem from root-ca.pem"
    fi

    echo "[2/4] Generating indexer TLS certs (first run only)..."
    if [ ! -d "$STACK/config/wazuh_indexer_ssl_certs" ]; then
        guard_run "wazuh-certs" docker compose -f "$STACK/generate-indexer-certs.yml" run --rm generator
    else
        echo "    certs already present — skipping"
    fi

    echo "[3/4] Pulling images + starting stack..."
    guard_run "wazuh-up" $COMPOSE up -d

    echo "[4/4] Health check..."
    wait_api
    echo ""
    echo "[✓] Local Wazuh manager is up. Next:"
    echo "    sudo bash /Users/evw/dev/security/evw-wazuh-setup.sh 127.0.0.1   # point the agent here"
    echo "    dashboard: https://127.0.0.1  (credentials: $CREDS)"
}

cmd_start() {
    colima status >/dev/null 2>&1 || colima start
    guard_run "wazuh-up" $COMPOSE up -d
    wait_api
}

cmd_stop() {
    $COMPOSE stop
}

cmd_status() {
    colima status 2>&1 | head -2 || echo "colima: not running"
    $COMPOSE ps 2>/dev/null || true
    code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 https://127.0.0.1:55000/ 2>/dev/null || echo 000)
    echo "manager API (127.0.0.1:55000): http $code"
    code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 https://127.0.0.1/ 2>/dev/null || echo 000)
    echo "dashboard   (https://127.0.0.1): http $code"
}

case "${1:-}" in
    setup)  cmd_setup ;;
    start)  cmd_start ;;
    stop)   cmd_stop ;;
    status) cmd_status ;;
    *)      sed -n '2,16p' "$0"; exit 2 ;;
esac
