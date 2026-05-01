# 01 — Installation

This runbook covers a fresh install of Hokora on Linux. For container deployment see [07-deployment-docker.md](07-deployment-docker.md); for production daemon management see [08-deployment-systemd.md](08-deployment-systemd.md).

## Prerequisites

| Requirement | Notes |
|---|---|
| Linux x86_64 or arm64 | Debian 12, Ubuntu 22.04+, Fedora 38+, Arch all tested |
| Python **3.10 or newer** | `python3 --version` |
| `build-essential`, `pkg-config` | For compiling extensions |
| `libsqlcipher-dev` (Debian/Ubuntu) or equivalent | Required for SQLCipher database encryption |
| `git` | To clone the repository |
| (Optional) an RNode for LoRa transport | Heltec V3 or equivalent |

Install system packages on Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip build-essential \
    pkg-config libsqlcipher-dev git
```

Fedora equivalent:

```bash
sudo dnf install -y python3 python3-pip python3-devel gcc pkgconfig \
    sqlcipher-devel git
```

Arch equivalent:

```bash
sudo pacman -S --needed python python-pip base-devel pkgconf sqlcipher git
```

## Install from source

```bash
git clone https://github.com/4ntenna/hokora.git
cd hokora

python3 -m venv .venv
source .venv/bin/activate

# Community node (with TUI)
pip install -e ".[tui]"

# Relay node (no TUI)
pip install -e .

# Full dev install
pip install -e ".[dev,tui]"
```

The `-e` (editable) install makes local code changes take effect immediately. For production you may prefer a non-editable install or a wheel build.

## Entry points

After install the virtualenv provides three commands:

| Command | Purpose |
|---|---|
| `hokora` | Administrative CLI (init, channel, role, invite, db, audit, mirror, seed, node, daemon, identity, config) |
| `hokorad` | Daemon (node server). Loopback `/health/live` + `/api/metrics/` on `127.0.0.1:8421`. |
| `hokora-tui` | Terminal client |

## Initialise a node

```bash
hokora init
```

The init command is interactive. Non-interactive use:

```bash
# Community node with SQLCipher (recommended)
hokora init --node-name "My Node" --node-type community

# Relay node (no database)
hokora init --node-name "My Relay" --node-type relay

# Community node without SQLCipher (development only)
hokora init --node-name "Dev Node" --node-type community --no-db-encrypt

# Use a non-default data directory
hokora init --data-dir /opt/hokora/node-a --node-name "Node A" --node-type community
```

### What `hokora init` creates

Under `$DATA_DIR` (default `~/.hokora`):

| Path | Mode | Purpose |
|---|---|---|
| `hokora.toml` | 0o600 | Configuration file (atomic write, contains `db_key` — back up securely) |
| `hokora.db` | 0o600 | SQLCipher database (community only) |
| `identities/` | 0o700 | RNS identity directory |
| `identities/node_identity` | 0o600 | Node's RNS identity key |
| `media/` | 0o755 | Media storage (community only) |
| `rns/config` | 0o644 | Generated Reticulum config with commented interface examples |
| `systemd/hokorad.service` | 0o644 | Pre-filled, hardened systemd unit for this data dir |
| `api_key` | 0o600 | API key for the daemon's loopback `/api/metrics/` endpoint. Written by `hokora init` (atomic O_EXCL). Required for Prometheus scrape; the route returns 404 if missing. |

Two files appear at runtime once the daemon starts:

| Path | Mode | Purpose |
|---|---|---|
| `hokorad.pid` | 0o600 | Daemon PID file, atomic replace on boot |
| `heartbeat` | 0o644 | Atomic msgpack liveness file, 30 s cadence |
| `hokorad.log` | 0o644 | Rotating log, 10 MB × 5 backups |

### `db_key` is critical

If `db_encrypt = true` (the default), the database is encrypted with AES-256 via SQLCipher. The key lives in `hokora.toml`. **Losing the key means losing the database.** Back it up immediately, out of band, before starting the daemon.

```bash
umask 077
grep '^db_key' ~/.hokora/hokora.toml > /path/to/secure/backup/hokora.db_key.$(date +%Y%m%d)
```

See [10-database-operations.md § Backup and restore](10-database-operations.md#backup-and-restore) for a production-grade backup procedure.

## First run

### Self-hoster

```bash
hokorad           # foreground; Ctrl+C to stop

# Or as a background process managed by the CLI
hokora daemon start
hokora daemon status
hokora daemon stop
```

In another terminal, start the TUI:

```bash
hokora-tui
```

The TUI auto-discovers a local daemon by scanning `~/.hokora*/hokorad.pid` and reading the daemon's `hokora.toml`. If you set `HOKORA_CONFIG=/path/to/hokora.toml` it uses that directly.

### Fleet operator

Skip the foreground run and go straight to systemd ([08-deployment-systemd.md](08-deployment-systemd.md)) or Docker ([07-deployment-docker.md](07-deployment-docker.md)).

## Verify the install

```bash
# PID file written
ls -l ~/.hokora/hokorad.pid

# Heartbeat file fresh (mtime within last 90 s)
stat ~/.hokora/heartbeat

# Liveness endpoint
curl -sf http://127.0.0.1:8421/health/live

# Readiness (requires RNS up and maintenance loop warm)
curl -sf http://127.0.0.1:8421/health/ready

# Default channel exists (community only)
hokora channel list
```

## Relay node

Relay nodes are used as seed / transport nodes on a public network. They do not store community data, require no SQLCipher, and have a small memory footprint.

```bash
hokora init --node-name "seed-1" --node-type relay
hokorad --relay-only
```

Relay-mode daemons still expose `/health/live` and `/health/ready`, still write a heartbeat file, but skip database init, channel management, and federation subsystems.

See [02-configuration.md § Relay propagation](02-configuration.md#relay-propagation) for the LXMF propagation tunables.

## Uninstall

```bash
# Stop the daemon
hokora daemon stop

# (Back up your data dir first if you have community data you need)
tar -czf ~/hokora-backup-$(date +%Y%m%d).tar.gz ~/.hokora

# Remove the data directory
rm -rf ~/.hokora

# Remove the virtualenv and source tree
deactivate
rm -rf ~/path/to/hokora
```

If you installed a systemd unit, remove that too:

```bash
sudo systemctl disable --now hokorad
sudo rm /etc/systemd/system/hokorad.service
sudo systemctl daemon-reload
```

## Troubleshooting

- **`sqlcipher3` build fails**: install the `libsqlcipher-dev` package (or equivalent) before `pip install`.
- **`hokorad` exits with "database locked"**: another daemon is still running. Check `hokora daemon status` and `ps -ef | grep hokorad`.
- **`hokora-tui` hangs on startup**: a previous TUI may own the RNS shared-instance socket. See [11-incident-response.md § Shared-instance inversion](11-incident-response.md#shared-instance-inversion).
- **`/health/live` returns 503**: heartbeat is stale. See [11-incident-response.md § Stale heartbeat](11-incident-response.md#stale-heartbeat).
