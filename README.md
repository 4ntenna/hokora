# Hokora

**Federated, encrypted messaging with channels, threads, and roles for off-grid and low-bandwidth networks.**

<img width="1366" height="679" alt="Screenshot_2026-04-30_20_54_00" src="https://github.com/user-attachments/assets/32ab6efe-a4b8-4abe-9fa4-6a1426a8f0ad" />


[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: AGPL-3.0-only](https://img.shields.io/badge/license-AGPL--3.0--only-blue.svg)](LICENSE)
[![Reticulum](https://img.shields.io/badge/transport-Reticulum%20%E2%89%A51.1.9-orange.svg)](https://reticulum.network/)

Hokora runs over the [Reticulum](https://reticulum.network/) network stack and the [LXMF](https://github.com/markqvist/lxmf) message layer. It delivers channels, threads, roles, reactions, media, direct messages, and end-to-end encrypted sealed channels over any transport Reticulum supports. Currently itegrated and tested transports are currently: LoRa radio, TCP and I2P, with more coming soon!

---

## What it is

<img width="1366" height="684" alt="Screenshot_2026-04-30_20_53_40" src="https://github.com/user-attachments/assets/23fa3ee7-2ab6-467d-8e61-923945bc133a" />



- **Federated.** Each node is self-contained. Nodes peer and mirror channels across the mesh.
- **Offline-first.** LXMF delivers messages even when the recipient is temporarily unreachable.
- **Encrypted by default.** SQLCipher at rest, Ed25519 on every LXMF message, AES-256-GCM per sealed channel, forward-secret X25519 + XChaCha20-Poly1305 on federation links.
- **Bandwidth-adaptive.** Client-Declared Sync Profiles (FULL, PRIORITIZED, MINIMAL, BATCHED) match client capabilities to the transport.
- **Operable.** PID-based daemon, atomic heartbeat, loopback-only health + Prometheus endpoint, Alembic migrations, systemd-hardened service unit.

---

## How it works

```
                    ┌────────────────┐
                    │   TUI Client   │
                    │  (hokora-tui)  │
                    └───────┬────────┘
                            │
                            │  RNS Link / LXMF
                            ▼
        ┌──────────────────────────────────────────┐
        │              Hokora Daemon               │
        │                (hokorad)                 │
        │                                          │
        │  SQLCipher DB · LXMF Bridge · Channels   │
        │  Permissions · Sealed Keys · CDSP        │
        │  Federation · Mirror Push · Epoch Crypto │
        │  Loopback /health/live + /api/metrics/   │
        └────────────┬─────────────────┬───────────┘
                     │                 │
                     │ Reticulum       │
                     │ Transport       │
                     ▼                 ▼
            ┌──────────────┐    ┌────────────────┐
            │ Peer Node(s) │    │  Relay Node(s) │
            │ (federation) │    │  (transport +  │
            │              │    │   LXMF propag.)│
            └──────────────┘    └────────────────┘
```

A **node** is either a *community node* (full daemon with channels, permissions, federation) or a *relay node* (transport + LXMF store-and-forward only, no database). Clients connect over an RNS Link for real-time sync and send messages via LXMF. Nodes discover each other through Reticulum announces and mirror channels across the federation. Operational health and Prometheus metrics are exposed by the daemon itself on a loopback HTTP listener — no separate dashboard process.

---

## Status

| Item | Value |
|---|---|
| Version | 0.1.0 |
| Python | 3.10, 3.11, 3.12, 3.13 |
| Reticulum | ≥ 1.1.9, < 2.0 |
| LXMF | ≥ 0.9.6, < 1.0 |
| Database | SQLCipher (default), or SQLite when initialised with `hokora init --no-db-encrypt` |
| Platforms | Linux (primary), macOS (dev), Docker, systemd-managed bare-metal |

---

## Components

| Component | Command | Purpose |
|---|---|---|
| Daemon | `hokorad` | Node server — owns a Reticulum instance, manages channels, processes messages, runs federation, serves loopback `/health/live` + `/api/metrics/` |
| CLI | `hokora` | Management — init, channel/role/invite/identity/mirror/audit CRUD, db migrations, daemon lifecycle |
| TUI | `hokora-tui` | Terminal client (urwid) — six-tab interface with channels, DMs, search, threads |

---

## Requirements

- Linux (Debian/Ubuntu tested; Fedora/Arch supported)
- Python **3.10 or newer**
- System libraries: `libsqlcipher-dev` (or equivalent), `build-essential`, `pkg-config`
- Optional: an RNode (Heltec V3 or equivalent) for LoRa transport

Dependency versions are pinned in `pyproject.toml` and locked in `requirements-lock.txt` (generated via `pip-compile --generate-hashes`).

---

## Quickstart

Hokora supports several roles: connect as a **user** through the TUI, run your own **community node** for others to join, **federate** with any compatible Reticulum-based mesh you can reach, or **build a private network** end-to-end. The three paths below cover the common starting points — pick the one that matches your situation.

### A. Local single-node (self-host)

```bash
git clone https://github.com/4ntenna/hokora.git
cd hokora

python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,tui]"

# Initialise a community node (prompts for node name and type)
hokora init

# Start the daemon in the foreground
hokorad

# In a second terminal: open the TUI
hokora-tui
```

The daemon owns its own Reticulum instance; no separate `rnsd` is required. `hokora init` creates `~/.hokora/` with an encrypted database, an RNS identity, a generated `hokora.toml`, a `db_keyfile` (the SQLCipher master key, 0o600), an `api_key` for the loopback `/api/metrics/` endpoint (0o600), and a hardened systemd unit template.

### B. Docker (single-node production)

```bash
git clone https://github.com/4ntenna/hokora.git
cd hokora

docker compose up -d
sleep 15

# Container health (the daemon's loopback /health/live on :8421).
docker compose ps
docker exec hokorad curl -sf http://127.0.0.1:8421/health/live
```

This brings up a single Hokora community daemon. On first start the entrypoint runs `hokora init`, which generates the encrypted DB, identity, `db_keyfile`, `api_key`, and an RNS config (with commented examples for TCP / I2P / RNode). All of it lives in the named `hokora-data` volume; the observability listener binds `127.0.0.1:8421` on the host. To add a TCP seed or another transport, edit the RNS config inside the volume and restart:

```bash
docker compose exec hokorad sh -c 'vi "$HOKORA_DATA_DIR/rns/config"'
docker compose restart hokorad
```

See [docs/runbooks/07-deployment-docker.md](docs/runbooks/07-deployment-docker.md) for upgrade, rollback, and fleet operations.

For a local two-node federation lab (build verification of cross-node Reticulum transport), use the example stack:

```bash
docker compose -f examples/two-node-federation/docker-compose.yml up -d
```

See [examples/two-node-federation/README.md](examples/two-node-federation/README.md).

### C. Join an existing mesh

```bash
pip install -e ".[tui]"

# Add a TCP seed (writes to the RNS config; restart any running daemon to pick it up).
hokora seed add "<name>" <host>:<port>

hokora-tui

# Inside the TUI, redeem the invite the operator gave you:
/invite redeem <token:dest:pubkey:channel>
```

Replace `<host>:<port>` above with the seed an operator gives you, or copy an RNS config from them into `~/.reticulum/config` (TCP / I2P / LoRa examples in [docs/runbooks/04-transport-setup.md](docs/runbooks/04-transport-setup.md)) and start the TUI — it will auto-discover local daemons and surface announced peers. Any Reticulum-based network you can reach (other Hokora deployments, propagation-only relays, your own private mesh) is reachable through the same RNS configuration.

---

## Core concepts

**Nodes.** Community nodes run the full daemon (DB, channels, permissions, federation). Relay nodes run transport + LXMF propagation only. Relays need no database and have a much smaller resource footprint.

**Channels.** Persistent named spaces with `public`, `write_restricted`, or `private` access modes. Messages are addressed to channels; each channel has its own RNS destination. A channel can additionally be marked `sealed` for end-to-end encryption.

**Federation.** Nodes peer over authenticated RNS Links via a 3-step Ed25519 challenge-response handshake followed by a 3-step X25519 forward-secrecy epoch-key exchange (TOFU by default). Peered nodes mirror channels in either direction, with per-peer cursors, at-least-once delivery, and loop prevention via `origin_node`.

**Sealed channels.** AES-256-GCM per-channel group keys. Ciphertext at rest, plaintext only on the Link-encrypted wire to authenticated subscribers. The invariant is structural: every Message-write path routes through `security/sealed_invariant.py`, which exposes two fail-closed entry points (`seal_for_origin` for locally-originated writes, `validate_mirror_payload` for federation-pushed rows). See [docs/runbooks/06-sealed-channels.md](docs/runbooks/06-sealed-channels.md).

**CDSP.** Client-Declared Sync Profiles — FULL, PRIORITIZED, MINIMAL, BATCHED — let a client announce its capabilities so the daemon can scale responses to the transport. LoRa clients get small paginated syncs; TCP clients get immediate live push.

**Forward-secret federation.** X25519 ephemeral key exchange, HKDF-SHA256 key derivation, XChaCha20-Poly1305 per epoch. Epoch keys rotate on a configurable interval (default one hour) and are wrapped at rest with a KEK derived from the node identity.

**Reticulum / LXMF primer.** Reticulum is a cryptographic networking stack that runs over any byte-oriented transport. LXMF is a store-and-forward message format built on it. Hokora layers its own sync protocol on Reticulum Links and uses LXMF for direct messages and offline message propagation.

---

## Install

```bash
# Core (daemon only)
pip install -e .

# Daemon + TUI + dev tools
pip install -e ".[dev,tui]"
```

Optional extras:

| Extra | Packages | Purpose |
|---|---|---|
| `tui` | urwid | Terminal UI client |
| `i2p` | i2plib | I2P transport via i2pd SAM bridge |
| `dev` | pytest, pytest-asyncio, ruff, alembic, httpx | Testing and linting |

SQLCipher (`sqlcipher3`) is a **core** dependency — database encryption is the default. Use `hokora init --no-db-encrypt` only for relay nodes (which hold no community data) or for development; never for a production community node.

---

## Documentation

The runbooks under `docs/runbooks/` are the operator manual. Read them in order for a full install, or jump to the one that matches your task.

| Runbook | Audience |
|---|---|
| [00-overview.md](docs/runbooks/00-overview.md) | Map of the docs, terminology, support scope |
| [01-installation.md](docs/runbooks/01-installation.md) | Bare-metal install, `hokora init`, data-dir layout, file modes |
| [02-configuration.md](docs/runbooks/02-configuration.md) | Canonical `hokora.toml` reference — every field |
| [03-cli-reference.md](docs/runbooks/03-cli-reference.md) | Every `hokora` subcommand with flags and side effects |
| [04-transport-setup.md](docs/runbooks/04-transport-setup.md) | TCP, I2P, LoRa/RNode RNS config snippets |
| [05-federation.md](docs/runbooks/05-federation.md) | Peering, handshake, mirroring, FS epochs |
| [06-sealed-channels.md](docs/runbooks/06-sealed-channels.md) | Sealed-invariant model, key rotation, recovery |
| [07-deployment-docker.md](docs/runbooks/07-deployment-docker.md) | Docker images, compose, entrypoint, volumes |
| [08-deployment-systemd.md](docs/runbooks/08-deployment-systemd.md) | Production systemd install with hardening |
| [09-monitoring-observability.md](docs/runbooks/09-monitoring-observability.md) | Heartbeat, `/health/*`, Prometheus metric catalogue |
| [10-database-operations.md](docs/runbooks/10-database-operations.md) | Alembic workflow, SQLCipher keys, backup/restore |
| [11-incident-response.md](docs/runbooks/11-incident-response.md) | Triage playbooks for common failures |
| [12-upgrade-guide.md](docs/runbooks/12-upgrade-guide.md) | Version-to-version notes |
| [13-permissions-and-roles.md](docs/runbooks/13-permissions-and-roles.md) | Permission flags, built-in roles, resolution model, channel overrides |
| [14-member-management.md](docs/runbooks/14-member-management.md) | Inviting, onboarding, removing, auditing users |

Security reporting and design summary lives in [SECURITY.md](SECURITY.md). Wire-protocol opcodes and constants are canonical in [src/hokora/constants.py](src/hokora/constants.py); ORM schema in [src/hokora/db/models.py](src/hokora/db/models.py).

---

## Testing

```bash
source .venv/bin/activate

# Unit + integration tests (no network required)
PYTHONPATH=src python -m pytest tests/unit/ tests/integration/ -v

# Multi-node federation tests (auto-skip without rnsd on PATH)
PYTHONPATH=src python -m pytest tests/multinode/ -v -s

# Load tests (manual, -m load)
PYTHONPATH=src python -m pytest tests/load/ -m load -v
```

The CI pipeline runs ruff lint, ruff format, mypy (on an 18-file perimeter), and the full unit + integration matrix across Python 3.10–3.13.

---

## Security

- Report vulnerabilities privately — see [SECURITY.md](SECURITY.md). Do not open public GitHub issues for security reports.
- SQLCipher encryption is the default; back up your `db_key` out-of-band.
- TOFU is enforced by default on federation peer keys (`reject_key_change=True`).
- Observability HTTP listener is loopback-only in source (`127.0.0.1`). Expose it only behind an authenticated reverse proxy if you need remote scraping.

---

## Contributing

1. Fork, branch, install dev extras: `pip install -e ".[dev,tui]"`.
2. Make changes with tests.
3. Run the full gate: `ruff check . && ruff format --check . && PYTHONPATH=src python -m pytest tests/unit/ tests/integration/`.
4. Submit a PR.

Style: `ruff` with `line-length=100`, `target-version=py310`. Type hints encouraged; the strict perimeter in `pyproject.toml [tool.mypy]` is extended incrementally as modules are refactored.

---

## Acknowledgements

Hokora is built on:

- [Reticulum](https://reticulum.network/) — the cryptographic networking stack that makes all of this possible.
- [LXMF](https://github.com/markqvist/lxmf) — the resilient message format layered on Reticulum.
- [SQLCipher](https://www.zetetic.net/sqlcipher/) — encrypted SQLite.
- [libsodium](https://doc.libsodium.org/) via PyNaCl — XChaCha20-Poly1305 AEAD.

---

## License

[GNU Affero General Public License v3.0 only](LICENSE) © 2026 4ntenna and The Hokora Project.

Hokora is free software: you can redistribute it and/or modify it under the terms of version 3 of the GNU Affero General Public License as published by the Free Software Foundation. Distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the LICENSE file or <https://www.gnu.org/licenses/agpl-3.0.html> for details.
