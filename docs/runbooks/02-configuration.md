# 02 — Configuration Reference

This is the canonical reference for `hokora.toml`. Every field below is read by `src/hokora/config.py`. Defaults match current code at head.

## File location and precedence

Load order (highest priority first):

1. Environment variables — every field has an overlay `HOKORA_<FIELD_NAME_UPPER>`.
2. TOML file at `$HOKORA_CONFIG`, or `$DATA_DIR/hokora.toml`, or `~/.hokora/hokora.toml`.
3. In-code defaults.

The file is written with mode `0o600` (owner read/write only) by `hokora init`. Preserve that mode after manual edits:

```bash
chmod 0600 ~/.hokora/hokora.toml
```

## Minimal community node

```toml
node_name = "My Node"
data_dir  = "~/.hokora"
db_encrypt = true
db_keyfile = "/home/<user>/.hokora/db_key"
announce_enabled = true
announce_interval = 600
```

`hokora init` writes the keyfile and sets `db_keyfile` for you; this snippet shows the resulting shape. Legacy installs may still carry an inline `db_key = "..."` instead of `db_keyfile`; migrate via `hokora db migrate-key` (see [10-database-operations.md § SQLCipher key management](10-database-operations.md#sqlcipher-key-management)).

## Hardened community node

The minimum-viable settings for a community node intended for public use. Each non-default field is annotated.

```toml
node_name  = "My Node"
data_dir   = "/var/lib/hokora"

# Database — encrypted, key in a separate 0o600 file.
db_encrypt = true
db_keyfile = "/var/lib/hokora/db_key"

# Federation — refuse unauthenticated peers; do not auto-trust.
require_signed_federation = true
federation_auto_trust     = false

# Forward secrecy — keep enabled with the default 1 h epoch rotation.
fs_enabled        = true
fs_epoch_duration = 3600

# Logging — structured JSON to stdout for journald / docker logs / log shippers.
log_level     = "INFO"
log_json      = true
log_to_stdout = true

# Privacy — null sender_hash on messages older than 30 days.
metadata_scrub_days = 30

# Liveness + observability — heartbeat and loopback HTTP both on.
heartbeat_enabled    = true
observability_enabled = true

# Announces — public discovery on; tune the interval to your traffic.
announce_enabled  = true
announce_interval = 600
```

Do not run a public community node with `federation_auto_trust = true` or `require_signed_federation = false`; either flag relaxes the federation peer-handshake guarantees. They exist for closed-mesh and lab deployments.

## Minimal relay node

```toml
node_name = "seed-1"
data_dir  = "~/.hokora"
relay_only = true
db_encrypt = false
propagation_enabled       = true
propagation_storage_mb    = 500
propagation_autopeer      = true
propagation_autopeer_maxdepth = 4
propagation_max_peers     = 20
announce_enabled          = true
announce_interval         = 600
```

## Full reference

All fields applicable to community and relay nodes unless noted.

### Node identity and transport

| Field | Type | Default | Env | Purpose |
|---|---|---|---|---|
| `node_name` | string | `"Hokora Node"` | `HOKORA_NODE_NAME` | Human-readable label, announced to peers |
| `node_description` | string | `""` | `HOKORA_NODE_DESCRIPTION` | Extended metadata |
| `data_dir` | path | `~/.hokora` | `HOKORA_DATA_DIR` | Root for all node state |
| `identity_dir` | path | `$DATA_DIR/identities` | `HOKORA_IDENTITY_DIR` | RNS identity directory |
| `rns_config_dir` | path | `None` (uses `~/.reticulum`) | `HOKORA_RNS_CONFIG_DIR` | Custom Reticulum config directory |

### Database and media

| Field | Type | Default | Env | Purpose |
|---|---|---|---|---|
| `db_path` | path | `$DATA_DIR/hokora.db` | `HOKORA_DB_PATH` | SQLCipher file |
| `db_encrypt` | bool | `true` | `HOKORA_DB_ENCRYPT` | SQLCipher on/off. Always `true` for community nodes in production |
| `db_key` | string | generated | `HOKORA_DB_KEY` | 64 hex chars (256 bits). Required if `db_encrypt=true` |
| `media_dir` | path | `$DATA_DIR/media` | `HOKORA_MEDIA_DIR` | Media attachment storage |
| `max_upload_bytes` | int | `5242880` (5 MB) | `HOKORA_MAX_UPLOAD_BYTES` | Per-file upload limit |
| `max_storage_bytes` | int | `1073741824` (1 GB) | `HOKORA_MAX_STORAGE_BYTES` | Per-channel storage quota |
| `max_global_storage_bytes` | int | `10737418240` (10 GB) | `HOKORA_MAX_GLOBAL_STORAGE_BYTES` | Total node storage quota |

### Logging

| Field | Type | Default | Env | Purpose |
|---|---|---|---|---|
| `log_level` | string | `"INFO"` | `HOKORA_LOG_LEVEL` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |
| `log_json` | bool | `false` | `HOKORA_LOG_JSON` | Emit structured JSON (recommended for fleet aggregators) |
| `log_to_stdout` | bool | `false` | `HOKORA_LOG_TO_STDOUT` | Also emit to stdout alongside the file handler |

The default log handler is a `RotatingFileHandler` writing `$DATA_DIR/hokorad.log` with 10 MB × 5 backups. When running under systemd, prefer `log_to_stdout=true` and let journald capture output.

### Announce, retention, UI

| Field | Type | Default | Env | Purpose |
|---|---|---|---|---|
| `announce_enabled` | bool | `true` | `HOKORA_ANNOUNCE_ENABLED` | Set `false` for silent / invite-only nodes |
| `announce_interval` | int | `600` (10 min) | `HOKORA_ANNOUNCE_INTERVAL` | Seconds between channel announces |
| `default_channel_name` | string | `"general"` | `HOKORA_DEFAULT_CHANNEL_NAME` | Created on `hokora init` |
| `retention_days` | int | `0` (unlimited) | `HOKORA_RETENTION_DAYS` | Message TTL; 0 disables pruning |
| `metadata_scrub_days` | int | `0` (disabled) | `HOKORA_METADATA_SCRUB_DAYS` | Null `sender_hash` on messages older than N days |
| `enable_fts` | bool | `true` | `HOKORA_ENABLE_FTS` | SQLite FTS5 full-text search |
| `max_sync_limit` | int | `100` | `HOKORA_MAX_SYNC_LIMIT` | Cap on `sync_history` page size |
| `show_private_channels` | bool | `true` | `HOKORA_SHOW_PRIVATE_CHANNELS` | Show private channel names in listings to non-members (membership still gates content access) |

### Rate limiting

| Field | Type | Default | Env | Purpose |
|---|---|---|---|---|
| `rate_limit_tokens` | int | `10` | `HOKORA_RATE_LIMIT_TOKENS` | Token-bucket burst capacity per identity |
| `rate_limit_refill` | float | `1.0` | `HOKORA_RATE_LIMIT_REFILL` | Tokens per second refill |

Per-channel slowmode is managed via `hokora channel edit <id> --slowmode <seconds>` and does not have a TOML field.

### Federation and trust

| Field | Type | Default | Env | Purpose |
|---|---|---|---|---|
| `require_signed_federation` | bool | `true` | `HOKORA_REQUIRE_SIGNED_FEDERATION` | Enforce Ed25519 challenge-response on peer handshakes |
| `federation_auto_trust` | bool | `false` | `HOKORA_FEDERATION_AUTO_TRUST` | Auto-accept new peers (dangerous outside trusted environments) |
| `federation_push_retry_interval` | int | `60` | `HOKORA_FEDERATION_PUSH_RETRY_INTERVAL` | Sweep interval for failed pushes |
| `federation_push_max_backoff` | int | `600` | `HOKORA_FEDERATION_PUSH_MAX_BACKOFF` | Max delay for exponential backoff |

### Forward secrecy (federation link encryption)

| Field | Type | Default | Env | Purpose |
|---|---|---|---|---|
| `fs_enabled` | bool | `true` | `HOKORA_FS_ENABLED` | Enable X25519 + XChaCha20-Poly1305 epoch protocol |
| `fs_epoch_duration` | int | `3600` (1 h) | `HOKORA_FS_EPOCH_DURATION` | Epoch rotation period |
| `fs_min_epoch_duration` | int | `300` (5 min) | `HOKORA_FS_MIN_EPOCH_DURATION` | Minimum accepted from a peer |
| `fs_max_epoch_duration` | int | `86400` (24 h) | `HOKORA_FS_MAX_EPOCH_DURATION` | Maximum accepted from a peer |
| `fs_rotation_max_retries` | int | `3` | `HOKORA_FS_ROTATION_MAX_RETRIES` | Retries on key distribution failure |
| `fs_rotation_initial_backoff` | int | `30` | `HOKORA_FS_ROTATION_INITIAL_BACKOFF` | Initial retry delay (seconds) |

Config load validates `fs_min_epoch_duration < fs_epoch_duration < fs_max_epoch_duration` and refuses to start otherwise.

### CDSP (Client-Declared Sync Profiles)

| Field | Type | Default | Env | Purpose |
|---|---|---|---|---|
| `cdsp_enabled` | bool | `true` | `HOKORA_CDSP_ENABLED` | Enable bandwidth-adaptive sync profile negotiation |
| `cdsp_session_timeout` | int | `3600` | `HOKORA_CDSP_SESSION_TIMEOUT` | Session idle timeout (seconds) |
| `cdsp_init_timeout` | int | `5` | `HOKORA_CDSP_INIT_TIMEOUT` | Grace period before defaulting pre-CDSP clients |
| `cdsp_deferred_queue_limit` | int | `1000` | `HOKORA_CDSP_DEFERRED_QUEUE_LIMIT` | Max queued live-push events per session |
| `cdsp_default_profile` | int | `1` (FULL) | `HOKORA_CDSP_DEFAULT_PROFILE` | `1`=FULL, `2`=PRIORITIZED, `3`=MINIMAL, `4`=BATCHED |

### Observability and heartbeat

| Field | Type | Default | Env | Purpose |
|---|---|---|---|---|
| `heartbeat_enabled` | bool | `true` | `HOKORA_HEARTBEAT_ENABLED` | Write `$DATA_DIR/heartbeat` periodically |
| `heartbeat_interval_s` | float | `30.0` | `HOKORA_HEARTBEAT_INTERVAL_S` | Seconds between writes |
| `observability_enabled` | bool | `true` | `HOKORA_OBSERVABILITY_ENABLED` | Start loopback HTTP listener |
| `observability_port` | int | `8421` | `HOKORA_OBSERVABILITY_PORT` | Port for `/health/*` and `/api/metrics/` |

The observability listener's bind address is **hard-coded to `127.0.0.1`** in source and is not a config field. To expose metrics externally, use an authenticated reverse proxy. See [09-monitoring-observability.md § External exposure](09-monitoring-observability.md#external-exposure).

### Relay propagation (relay nodes only)

| Field | Type | Default | Env | Purpose |
|---|---|---|---|---|
| `relay_only` | bool | `false` | `HOKORA_RELAY_ONLY` | Skip community subsystems at boot |
| `propagation_enabled` | bool | `false` | `HOKORA_PROPAGATION_ENABLED` | Enable LXMF store-and-forward |
| `propagation_storage_mb` | int | `500` | `HOKORA_PROPAGATION_STORAGE_MB` | Max message store size |
| `propagation_static_peers` | list[string] | `[]` | `HOKORA_PROPAGATION_STATIC_PEERS` | Destination hashes of peers to always carry for |
| `propagation_autopeer` | bool | `true` | `HOKORA_PROPAGATION_AUTOPEER` | Discover peers from announces |
| `propagation_autopeer_maxdepth` | int | `4` | `HOKORA_PROPAGATION_AUTOPEER_MAXDEPTH` | Hop limit for auto-discovery |
| `propagation_max_peers` | int | `20` | `HOKORA_PROPAGATION_MAX_PEERS` | Concurrent peer cap |

## Environment variable overlay

Every field can be set via `HOKORA_<FIELD_NAME_UPPER>`. Type coercion:

- Booleans: `true` / `false`, `1` / `0`, `yes` / `no` (case-insensitive).
- Integers / floats: standard parsing.
- Lists: comma-separated strings.

Example:

```bash
HOKORA_LOG_LEVEL=DEBUG \
HOKORA_LOG_JSON=true \
HOKORA_ANNOUNCE_INTERVAL=300 \
hokorad
```

Environment overlay is convenient for containerised deployments. See [07-deployment-docker.md § Environment variables](07-deployment-docker.md#environment-variables).

## Config validation

On startup the daemon validates:

- `db_encrypt=true` requires either `db_keyfile` (path to a 64-hex-character file at mode 0o600) or, on legacy nodes, an inline `db_key` of 64 hex characters. Resolution order is documented in [10-database-operations.md § SQLCipher key management](10-database-operations.md#sqlcipher-key-management).
- `fs_min_epoch_duration < fs_epoch_duration < fs_max_epoch_duration`.
- `federation_auto_trust=true` with `require_signed_federation=false` emits a loud warning; it is a legitimate pattern only in lab / closed-mesh deployments.
- `observability_port` is in range.

Validation failures cause the daemon to exit before any subsystem starts. Fix the config and restart.

## Applying changes

Configuration changes require a daemon restart. There is no SIGHUP reload. After editing `hokora.toml` (or changing `HOKORA_*` environment variables on a containerised deployment), restart the daemon to pick them up:

```bash
sudo systemctl restart hokorad        # systemd
docker compose restart hokorad        # docker
hokora daemon stop && hokora daemon start    # bare metal dev runs
```

Trust-state toggles (`hokora mirror trust` / `untrust`) and per-channel slowmode edits are exceptions — they take effect immediately without a restart. Anything that changes a TOML field or env var does not.

## See also

- [01-installation.md](01-installation.md) for initial `hokora init`.
- [09-monitoring-observability.md](09-monitoring-observability.md) for observability + heartbeat operational behaviour.
- [05-federation.md](05-federation.md) for the federation trust model and epoch protocol.
