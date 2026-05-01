#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
# setup_two_nodes.sh — Start two Hokora nodes connected via RNS TCP transport.
# Usage: ./tests/live/setup_two_nodes.sh
# Press Enter to tear everything down.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

NODE_A_DIR="/tmp/hokora_node_a"
NODE_B_DIR="/tmp/hokora_node_b"
RNS_A_DIR="$SCRIPT_DIR/rns_a"
RNS_B_DIR="$SCRIPT_DIR/rns_b"
# Daemon observability ports — each daemon owns its own loopback listener
# (same surface the production daemon exposes for /health/live + /api/metrics/).
OBS_PORT_A=8430
OBS_PORT_B=8431

PIDS=()

cleanup() {
    echo ""
    echo "Shutting down..."
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null || true
        fi
    done
    sleep 2
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
    done
    echo "All processes stopped."
}

trap cleanup EXIT INT TERM

# --- Clean up old state ---
rm -rf "$NODE_A_DIR" "$NODE_B_DIR"

# --- Write TOML configs ---
write_config() {
    local dir="$1" name="$2" rns_dir="$3" obs_port="$4"
    cat > "$dir/hokora.toml" <<TOML
node_name = "$name"
data_dir = "$dir"
log_level = "DEBUG"
db_encrypt = false
rns_config_dir = "$rns_dir"
announce_interval = 15
rate_limit_tokens = 10
rate_limit_refill = 1.0
max_upload_bytes = 5242880
max_storage_bytes = 1073741824
retention_days = 0
enable_fts = true
observability_enabled = true
observability_port = $obs_port
TOML
}

# --- Init Node A ---
echo "=== Initializing Node A ==="
export HOKORA_DATA_DIR="$NODE_A_DIR"
hokora init --node-name "NodeA" --data-dir "$NODE_A_DIR" --no-db-encrypt --skip-luks-check
write_config "$NODE_A_DIR" "NodeA" "$RNS_A_DIR" "$OBS_PORT_A"

# --- Init Node B ---
echo "=== Initializing Node B ==="
export HOKORA_DATA_DIR="$NODE_B_DIR"
hokora init --node-name "NodeB" --data-dir "$NODE_B_DIR" --no-db-encrypt --skip-luks-check
write_config "$NODE_B_DIR" "NodeB" "$RNS_B_DIR" "$OBS_PORT_B"

# --- Start RNS instances ---
echo "=== Starting RNS instances ==="
rnsd --config "$RNS_A_DIR" &
PIDS+=($!)
echo "  rnsd A started (PID: ${PIDS[-1]})"

rnsd --config "$RNS_B_DIR" &
PIDS+=($!)
echo "  rnsd B started (PID: ${PIDS[-1]})"

sleep 2

# --- Start daemons ---
echo "=== Starting Hokora daemons ==="
HOKORA_CONFIG="$NODE_A_DIR/hokora.toml" python -m hokora &
PIDS+=($!)
echo "  hokorad A started (PID: ${PIDS[-1]})"

HOKORA_CONFIG="$NODE_B_DIR/hokora.toml" python -m hokora &
PIDS+=($!)
echo "  hokorad B started (PID: ${PIDS[-1]})"

sleep 5

# --- Verify against the daemon listeners ---
echo ""
echo "=== Verification ==="
API_KEY_A=$(cat "$NODE_A_DIR/api_key" 2>/dev/null || echo "none")
API_KEY_B=$(cat "$NODE_B_DIR/api_key" 2>/dev/null || echo "none")

echo "Node A /health/live:"
curl -s "http://127.0.0.1:$OBS_PORT_A/health/live" | python -m json.tool 2>/dev/null || echo "  (not responding yet)"

echo "Node B /health/live:"
curl -s "http://127.0.0.1:$OBS_PORT_B/health/live" | python -m json.tool 2>/dev/null || echo "  (not responding yet)"

echo ""
echo "Node A /api/metrics/ (head):"
curl -s -H "X-API-Key: $API_KEY_A" "http://127.0.0.1:$OBS_PORT_A/api/metrics/" | head -8 || echo "  (not responding)"

echo ""
echo "Node A channels (DB):"
sqlite3 "$NODE_A_DIR/hokora.db" "SELECT id, name, access_mode FROM channels;" 2>/dev/null || echo "  (sqlite3 not available)"

echo ""
echo "=== Both nodes running ==="
echo "  Node A obs: http://127.0.0.1:$OBS_PORT_A  (API key: $API_KEY_A)"
echo "  Node B obs: http://127.0.0.1:$OBS_PORT_B  (API key: $API_KEY_B)"
echo "  Node A data: $NODE_A_DIR"
echo "  Node B data: $NODE_B_DIR"
echo ""
echo "Press Enter to shut down..."
read -r
