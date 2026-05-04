#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
# docker-entrypoint.sh — Start RNS and the Hokora daemon.
set -euo pipefail

DATA_DIR="${HOKORA_DATA_DIR:-/data/hokora}"
# Default RNS config to the data volume so `hokora init` (run on first
# start) and the daemon agree on one path. Operators who want managed
# RNS can override RNS_CONFIG_DIR and bind-mount the directory in.
RNS_DIR="${RNS_CONFIG_DIR:-$DATA_DIR/rns}"
DB_ENCRYPT="${HOKORA_DB_ENCRYPT:-true}"
RELAY_ONLY="${HOKORA_RELAY_ONLY:-false}"
ENABLE_I2P="${HOKORA_ENABLE_I2P:-false}"
if [ "$RELAY_ONLY" = "true" ]; then
    NODE_TYPE="relay"
else
    NODE_TYPE="${HOKORA_NODE_TYPE:-community}"
fi

# Init node if no config exists yet. ``hokora init`` writes the
# canonical hokora.toml; runtime tuning happens via HOKORA_* env vars
# at daemon load time (config.load_config). Avoid rewriting the file
# here — the env overlay covers operator-driven changes without
# binding any defaults to disk.
if [ ! -f "$DATA_DIR/hokora.toml" ]; then
    echo "No config found — initializing node..."
    INIT_ARGS="--node-name ${HOKORA_NODE_NAME:-Hokora} --node-type ${NODE_TYPE} --data-dir $DATA_DIR --skip-luks-check"
    if [ "$DB_ENCRYPT" = "false" ]; then
        INIT_ARGS="$INIT_ARGS --no-db-encrypt"
    fi
    hokora init ${INIT_ARGS} || { echo "ERROR: hokora init failed"; exit 1; }
fi

export HOKORA_CONFIG="$DATA_DIR/hokora.toml"
# Map RNS_CONFIG_DIR (operator-facing knob) to the canonical
# HOKORA_RNS_CONFIG_DIR env var so the load-time overlay points the
# daemon at a managed/bind-mounted RNS config when one is supplied.
export HOKORA_RNS_CONFIG_DIR="$RNS_DIR"

# Forward signals to background processes for clean shutdown (H4: graceful)
cleanup() {
    echo "Shutting down..."
    [ -n "${I2PD_PID:-}" ] && kill "$I2PD_PID" 2>/dev/null
    sleep 5
    [ -n "${I2PD_PID:-}" ] && kill -9 "$I2PD_PID" 2>/dev/null
    wait
}
trap cleanup SIGTERM SIGINT

# Optional I2P sidecar — RNS's I2PInterface speaks SAMv3 to a local i2pd.
# Gated on HOKORA_ENABLE_I2P so non-I2P deployments pay zero runtime cost
# (i2pd is installed in the image but never launched unless requested).
# Cooperates with `network_mode: host` setups: if a SAM bridge is already
# listening on 127.0.0.1:7656 (host-side i2pd), reuse it instead of
# spawning a duplicate that would fight for the same port.
if [ "$ENABLE_I2P" = "true" ]; then
    if python3 -c "import socket; s=socket.socket(); s.settimeout(1); s.connect(('127.0.0.1',7656)); s.close()" 2>/dev/null; then
        echo "i2pd SAM bridge already listening on 127.0.0.1:7656 — reusing existing instance"
    else
        I2PD_DATA_DIR="$DATA_DIR/i2pd"
        mkdir -p "$I2PD_DATA_DIR"
        echo "Starting i2pd (SAM bridge for RNS I2PInterface)..."
        i2pd \
            --datadir="$I2PD_DATA_DIR" \
            --sam.enabled=true \
            --sam.address=127.0.0.1 \
            --sam.port=7656 \
            --log=stdout \
            --loglevel=warn &
        I2PD_PID=$!
        # Poll the SAM port until i2pd is ready (router bootstrap is fast,
        # tunnel-build for actual destinations happens lazily when RNS
        # opens the first I2P interface).
        for i in $(seq 1 60); do
            if ! kill -0 "$I2PD_PID" 2>/dev/null; then
                echo "ERROR: i2pd exited during startup"
                exit 1
            fi
            if python3 -c "import socket; s=socket.socket(); s.settimeout(1); s.connect(('127.0.0.1',7656)); s.close()" 2>/dev/null; then
                echo "i2pd SAM bridge ready on 127.0.0.1:7656 (PID: $I2PD_PID)"
                break
            fi
            sleep 0.5
        done
    fi
fi

# The daemon owns the RNS instance directly (no separate rnsd needed).
# RNS config at $RNS_DIR/config must have share_instance = Yes so clients
# (TUI) can connect as shared instance clients.
if [ -f "$RNS_DIR/config" ]; then
    echo "RNS config found at $RNS_DIR/config — daemon will own RNS instance"
else
    echo "WARNING: No RNS config at $RNS_DIR/config — daemon will use RNS defaults"
fi

if [ "$RELAY_ONLY" = "true" ]; then
    echo "Starting Hokora relay node (transport + propagation)..."
    exec python -m hokora --relay-only
fi

# Community mode: daemon is the container's main process.
echo "Starting Hokora daemon..."
exec python -m hokora
