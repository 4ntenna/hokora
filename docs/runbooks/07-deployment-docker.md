# 07 — Docker Deployment

Hokora ships a single `Dockerfile.full`, a top-level `docker-compose.yml` that brings up one community node (the deployable template), and a relocated two-node lab under `examples/two-node-federation/`. This runbook covers operating the image, volume and environment-variable layout, healthchecks, and upgrade/rollback.

## Image

`Dockerfile.full` is the only image — it bundles the daemon, the TUI tooling, and (optionally) i2pd. Entry point is `docker-entrypoint.sh`. The image:

- Bases on `python:3.12-slim`.
- Installs `libsqlcipher-dev`, `gcc`, `pkg-config`, and `i2pd` at build time.
- Runs as a non-root `hokora` user inside the container.
- Exposes port 4242 (RNS TCP) and 8421 (loopback observability — daemon's `/health/live` + `/api/metrics/`).
- Writes to `/data/hokora` (node data) and `/etc/rns` (Reticulum config).

## Building

```bash
docker build -f Dockerfile.full -t hokora:latest .
```

For air-gapped or offline fleets, push to your internal registry:

```bash
docker build -f Dockerfile.full -t registry.internal/hokora:$(git rev-parse --short HEAD) .
docker push registry.internal/hokora:$(git rev-parse --short HEAD)
```

## `docker-entrypoint.sh`

The entrypoint performs init-on-first-run, then `exec`s the daemon as PID 1. Behaviour:

1. Reads `HOKORA_DATA_DIR` (default `/data/hokora`), `RNS_CONFIG_DIR` (default `$HOKORA_DATA_DIR/rns`), and all `HOKORA_*` env vars.
2. If `$DATA_DIR/hokora.toml` does not exist, runs `hokora init` with the right `--node-type`, preserving any operator-supplied `HOKORA_DB_KEY` and merging other env vars into the generated TOML. `hokora init` also writes `<data_dir>/api_key` (atomic 0o600) for the loopback `/api/metrics/` endpoint, and a default `<data_dir>/rns/config` with commented examples for TCP / I2P / RNode.
3. Optionally launches `i2pd` (when `HOKORA_ENABLE_I2P=true`) and waits for its SAM bridge on `127.0.0.1:7656`.
4. Relay mode (`HOKORA_RELAY_ONLY=true` or `HOKORA_NODE_TYPE=relay`): `exec python -m hokora --relay-only`.
5. Community mode: `exec python -m hokora`. The daemon's own service-registry handles SIGTERM cleanup; the entrypoint trap forwards SIGTERM to any sidecar processes (e.g. i2pd).

The entrypoint is not fully idempotent for config drifts — re-running it against an existing data dir will overwrite non-key fields from the environment. This is a deliberate design choice to let `docker compose up` re-apply environment changes without manual intervention. The `db_key` is always preserved.

## Environment variables

All `hokora.toml` fields can be set via `HOKORA_<FIELD_NAME_UPPER>` (see [02-configuration.md § Environment variable overlay](02-configuration.md#environment-variable-overlay)). The most common ones in Docker:

| Variable | Default | Purpose |
|---|---|---|
| `HOKORA_DATA_DIR` | `/data/hokora` | Container data dir (mount a volume here) |
| `RNS_CONFIG_DIR` | `$HOKORA_DATA_DIR/rns` | Reticulum config; override + bind-mount for managed-config setups |
| `HOKORA_NODE_NAME` | `"Hokora Node"` | Label announced to peers |
| `HOKORA_NODE_TYPE` | `community` | `community` or `relay` |
| `HOKORA_RELAY_ONLY` | `false` | Force relay mode |
| `HOKORA_DB_ENCRYPT` | `true` | SQLCipher on/off |
| `HOKORA_DB_KEY` | — | Pass a known key for reproducible builds |
| `HOKORA_LOG_LEVEL` | `INFO` | Daemon log level |
| `HOKORA_LOG_JSON` | `false` | Structured JSON logs (recommended for fleets) |
| `HOKORA_LOG_TO_STDOUT` | `false` | Emit to stdout too (lets `docker logs` capture output) |
| `HOKORA_ANNOUNCE_INTERVAL` | `600` | Seconds between announces |

## Volumes

| Container path | Purpose | Typical host binding |
|---|---|---|
| `/data/hokora` | Node data (DB, identities, logs, heartbeat, pid, api_key) | Named volume or bind to host path |
| `/etc/rns` | Reticulum config (read-only) | Bind-mount from host config dir |

Always use a named volume or bind-mount for `/data/hokora` — losing it means losing the database key, identity, and all community data.

## Healthcheck

The Docker `HEALTHCHECK` in `Dockerfile.full` targets the loopback observability endpoint:

```
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=20s \
  CMD curl -sf http://127.0.0.1:8421/health/live || exit 1
```

This endpoint is unauthenticated and minimal. It returns 200 when the heartbeat file mtime is fresh (within 3× `heartbeat_interval_s`, i.e. 90 s by default). See [09-monitoring-observability.md § Health endpoints](09-monitoring-observability.md#health-endpoints) for the full semantics.

Healthcheck semantics follow the liveness contract documented in [09-monitoring-observability.md § The three-layer liveness contract](09-monitoring-observability.md#the-three-layer-liveness-contract): external probes are alert-only. A failing healthcheck does NOT restart the container — that is Docker's job — but it does mark the container unhealthy so the orchestrator can route around it.

## `docker-compose.yml` (single-node)

The repo-root `docker-compose.yml` brings up one community node and is what `docker compose up -d` runs from a fresh clone. It builds `Dockerfile.full`, persists `/data/hokora` in a named volume, and binds the observability listener to `127.0.0.1:8421` on the host. There is no second bind-mount — on first start the entrypoint calls `hokora init`, which generates the RNS config under `<volume>/rns/config` alongside the database, identity, `db_keyfile`, and `api_key`.

```yaml
services:
  hokorad:
    build:
      context: .
      dockerfile: Dockerfile.full
    image: hokora:latest
    container_name: hokorad
    restart: unless-stopped
    environment:
      HOKORA_NODE_NAME: "Hokora Node"
      HOKORA_NODE_TYPE: "community"
      HOKORA_DB_ENCRYPT: "${HOKORA_DB_ENCRYPT:-true}"
      HOKORA_LOG_LEVEL: "${HOKORA_LOG_LEVEL:-INFO}"
      HOKORA_LOG_JSON: "${HOKORA_LOG_JSON:-true}"
      HOKORA_LOG_TO_STDOUT: "${HOKORA_LOG_TO_STDOUT:-true}"
      HOKORA_ANNOUNCE_INTERVAL: "${HOKORA_ANNOUNCE_INTERVAL:-600}"
    volumes:
      - hokora-data:/data/hokora
    ports:
      - "127.0.0.1:8421:8421"
    mem_limit: 1g
    cpus: "2.0"
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8421/health/live')"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 20s

volumes:
  hokora-data:
```

Run:

```bash
docker compose up -d
sleep 20
docker compose ps                                              # should be "healthy"
docker exec hokorad curl -sf http://127.0.0.1:8421/health/live
```

Teardown:

```bash
docker compose down         # preserves the data volume
docker compose down -v      # deletes the data volume (destructive)
```

To add a TCP seed or another transport after first run:

```bash
docker compose exec hokorad sh -c 'vi "$HOKORA_DATA_DIR/rns/config"'
docker compose restart hokorad
```

Operators who want managed RNS config (config-management ownership of `/etc/rns`, no in-volume edits) can bind-mount their config directory and override the path:

```yaml
    volumes:
      - hokora-data:/data/hokora
      - /srv/hokora/rns:/etc/rns:ro
    environment:
      RNS_CONFIG_DIR: /etc/rns
```

Port 8421 binds to loopback only; expose externally via your reverse proxy, not Docker's port forwarding.

## Two-node federation lab

For local build verification of cross-node Reticulum transport, an opt-in two-node stack lives under `examples/two-node-federation/`:

```bash
docker compose -f examples/two-node-federation/docker-compose.yml up -d
sleep 15
docker compose -f examples/two-node-federation/docker-compose.yml ps

docker exec hokora-node-a curl -sf http://127.0.0.1:8421/health/live
docker exec hokora-node-b curl -sf http://127.0.0.1:8421/health/live
```

Both daemons sit on a private bridge with no published ports; RNS configs are bind-mounted from `tests/live/docker_rns_a/` and `docker_rns_b/`. The stack verifies both nodes come up healthy on a shared Reticulum bridge — it does not assert mirror sync or end-to-end message flow. For those, run the multinode pytest suite under `tests/multinode/`. See `examples/two-node-federation/README.md` for details.

## Relay node

A relay seed in Docker:

```yaml
services:
  relay:
    image: registry.internal/hokora:v0.1.0
    restart: unless-stopped
    environment:
      HOKORA_NODE_NAME: "seed-a"
      HOKORA_NODE_TYPE: "relay"
      HOKORA_RELAY_ONLY: "true"
      HOKORA_PROPAGATION_ENABLED: "true"
      HOKORA_PROPAGATION_STORAGE_MB: "2000"
    volumes:
      - /srv/relay/data:/data/hokora
      - /srv/relay/rns:/etc/rns:ro
    ports:
      - "4242:4242/tcp"     # public TCP seed
      - "127.0.0.1:8421:8421"
    mem_limit: 256m
    cpus: "0.5"
```

The relay still writes a heartbeat and exposes `/health/live` on 8421.

## Upgrading

```bash
# Pull or build the new image with a unique tag
docker build -f Dockerfile.full -t registry.internal/hokora:v0.1.1 .
docker push registry.internal/hokora:v0.1.1

# Tag the currently-running image as a rollback point
docker tag registry.internal/hokora:v0.1.0 registry.internal/hokora:rollback-$(date +%Y%m%d-%H%M%S)
docker push registry.internal/hokora:rollback-...

# Apply migrations (in a one-shot container against the same data volume)
docker run --rm \
  -v /srv/hokora/data:/data/hokora \
  registry.internal/hokora:v0.1.1 \
  hokora db upgrade

# Update compose to the new tag and recreate
sed -i 's|hokora:v0.1.0|hokora:v0.1.1|' docker-compose.yml
docker compose up -d --force-recreate
```

Verify:

```bash
docker inspect <container> --format '{{.State.Health.Status}} restarts={{.RestartCount}}'
docker exec <container> hokora db current
```

## Rollback

```bash
# Point compose back at the rollback tag
sed -i 's|hokora:v0.1.1|hokora:rollback-YYYYMMDD-HHMMSS|' docker-compose.yml
docker compose up -d --force-recreate
```

If the new version ran a migration that cannot be downgraded, restore the DB from backup before rolling back; see [10-database-operations.md § Backup and restore](10-database-operations.md#backup-and-restore).

## Fleet operator notes

- Tag images with the git short SHA in addition to semantic versions. Always keep the previous prod tag as a `rollback-` pointer.
- Prefer named volumes over bind-mounts unless your config management owns the host paths. Named volumes are easier to back up with `docker run --rm -v ... alpine tar`.
- Run the observability listener port (8421) bound to loopback only (`127.0.0.1:8421:8421`). Front with authenticated scraping (see [09-monitoring-observability.md](09-monitoring-observability.md)).
- For Kubernetes, translate the compose file into a StatefulSet with a PVC for `/data/hokora`, a ConfigMap for `/etc/rns`, a `livenessProbe` hitting `/health/live`, and a `readinessProbe` hitting `/health/ready`.

## See also

- [08-deployment-systemd.md](08-deployment-systemd.md) for bare-metal deployment.
- [09-monitoring-observability.md](09-monitoring-observability.md) for scraping the container.
- [10-database-operations.md](10-database-operations.md) for migrations under Docker.
