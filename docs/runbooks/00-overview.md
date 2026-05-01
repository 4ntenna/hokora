# 00 — Runbook Overview

---

## Reading order

| Order | When to read |
|---|---|
| [01-installation.md](01-installation.md) | First install, or provisioning a new node |
| [02-configuration.md](02-configuration.md) | Before editing `hokora.toml` |
| [04-transport-setup.md](04-transport-setup.md) | Before joining a mesh over TCP / I2P / LoRa |
| [03-cli-reference.md](03-cli-reference.md) | Day-to-day administration |
| [05-federation.md](05-federation.md) | Peering two or more nodes |
| [06-sealed-channels.md](06-sealed-channels.md) | Deploying encrypted-at-rest channels |
| [13-permissions-and-roles.md](13-permissions-and-roles.md) | Designing permissions, roles, channel overrides |
| [14-member-management.md](14-member-management.md) | Inviting, onboarding, removing, auditing users |
| [07-deployment-docker.md](07-deployment-docker.md) | Containerised deployment |
| [08-deployment-systemd.md](08-deployment-systemd.md) | Bare-metal production deployment |
| [09-monitoring-observability.md](09-monitoring-observability.md) | SRE / on-call setup |
| [10-database-operations.md](10-database-operations.md) | Migrations, backup, restore, key rotation |
| [11-incident-response.md](11-incident-response.md) | When something breaks |
| [12-upgrade-guide.md](12-upgrade-guide.md) | Upgrading an installation |

The README at the repo root is the public-facing project page. Wire-protocol constants are canonical in `src/hokora/constants.py`; ORM schema in `src/hokora/db/models.py`.

---

## Terminology

| Term | Meaning |
|---|---|
| **Node** | A running `hokorad` process with its own RNS identity and (for community nodes) a SQLCipher database. |
| **Community node** | Full daemon. Owns channels, permissions, federation. Exposes loopback `/health/live` + `/api/metrics/` on `127.0.0.1:8421`. |
| **Relay node** | Transport + LXMF propagation only. No database. Started with `--relay-only` or `relay_only = true`. |
| **Client** | A TUI (`hokora-tui`) connecting to a daemon. |
| **Channel** | A named message space with its own RNS destination. Access mode: `public`, `write_restricted`, `private`. |
| **Sealed channel** | A channel with AES-256-GCM encryption at rest. Plaintext only on the authenticated wire. |
| **Peer** | Another node the local node has peered with for federation. |
| **Mirror** | A per-(peer, channel) replication relationship. |
| **LXMF** | Lightweight Extensible Message Format — the store-and-forward layer above Reticulum. |
| **RNS** | Reticulum Network Stack — the cryptographic transport Hokora runs on. |
| **CDSP** | Client-Declared Sync Profile — a client's declared bandwidth/storage posture (FULL, PRIORITIZED, MINIMAL, BATCHED). |
| **Epoch** | A forward-secret time slice. Keys derived for one epoch do not decrypt traffic from another. |
| **TOFU** | Trust On First Use. The default for federation peer keys; subsequent key changes are rejected unless manually updated. |

---

## Operator quick map

| Task | Starting point |
|---|---|
| Install a community node from scratch | [01-installation.md § Self-hoster](01-installation.md#self-hoster) |
| Install a relay/seed node | [01-installation.md § Relay node](01-installation.md#relay-node) |
| Configure LoRa (868 MHz / 915 MHz) | [04-transport-setup.md § RNode / LoRa](04-transport-setup.md#rnode--lora) |
| Run the full stack in Docker | [07-deployment-docker.md](07-deployment-docker.md) |
| Harden a systemd install | [08-deployment-systemd.md § Hardened unit](08-deployment-systemd.md#hardened-unit) |
| Wire Prometheus scraping | [09-monitoring-observability.md § Scraping](09-monitoring-observability.md#scraping) |
| Peer two community nodes | [05-federation.md § Adding a peer](05-federation.md#adding-a-peer) |
| Rotate a sealed channel key | [06-sealed-channels.md § Rotating the group key](06-sealed-channels.md#rotating-the-group-key) |
| Set up channel permissions | [13-permissions-and-roles.md § Worked examples](13-permissions-and-roles.md#worked-examples) |
| Invite a new user | [14-member-management.md § Inviting a user](14-member-management.md#inviting-a-user) |
| Remove a user from a channel | [14-member-management.md § Removing a member](14-member-management.md#removing-a-member) |
| Read the audit log | [14-member-management.md § Reading the audit log](14-member-management.md#reading-the-audit-log) |
| Apply a database migration | [10-database-operations.md § Applying migrations](10-database-operations.md#applying-migrations) |
| Recover from a stale heartbeat | [11-incident-response.md § Stale heartbeat](11-incident-response.md#stale-heartbeat) |

---

## Support scope

Hokora is pre-1.0 software. The APIs and protocols are stable enough to federate across releases within the 0.1.x line. Breaking changes may be introduced in major version bumps when the design improves from doing so.

- Issues, bug reports, feature requests: GitHub issues.
- Security vulnerabilities: see [SECURITY.md](../../SECURITY.md). Do not disclose publicly.
- Commercial support: not currently offered.

---

## Conventions used in the runbooks

- Shell blocks assume Linux, `bash` or `zsh`, and a Python 3.10+ virtualenv activated where relevant.
- `$DATA_DIR` defaults to `~/.hokora` unless overridden with `HOKORA_DATA_DIR` or `hokora init --data-dir`.
- File-mode callouts use octal notation (`0o600` = owner read/write only).
- Commands prefixed with `#` require root; `$` does not.
- Placeholders are `<angle-bracketed>` and must be replaced before execution.
