# 09 — Monitoring and Observability

Hokora implements a three-layer liveness contract and a Prometheus-scrapeable metrics endpoint. This runbook covers each layer, the endpoints they expose, the auth model, metric families, and recommended alerts.

## The three-layer liveness contract

The contract was designed so that each layer can fail independently without cascading:

| Layer | Owner | Semantics |
|---|---|---|
| **L1 — Process liveness** | systemd / Docker / Kubernetes | `Restart=on-failure`, `restart: unless-stopped`. Bounces the process if it exits. |
| **L2 — Heartbeat file** | Daemon (`HeartbeatWriter`) | Atomic msgpack write every 30 s. Write is *gated* on inline invariants: `rns_alive` and `maintenance_fresh`. If invariants fail, mtime goes stale — a signal to L3 without killing the process. |
| **L3 — HTTP endpoints** | Daemon (`ObservabilityListener`, loopback only) | `/health/live` (mtime-freshness), `/health/ready` (live + RNS up + maintenance fresh), `/api/metrics/` (Prometheus). |

Destructive lifecycle actions (kills, restarts) are owned exclusively by L1. L2 and L3 are *alert-only*. External probes that cycle the daemon process based on health-endpoint responses can produce sustained kill loops on a healthy container; do not configure them to do so.

## Health endpoints

The observability listener binds to `127.0.0.1:<observability_port>` (default 8421). Bind address is **hard-coded** in source, not a config field. For external exposure, use a reverse proxy — see [External exposure](#external-exposure).

### `GET /health/live`

- **Auth:** none
- **Purpose:** Is the process up and writing its heartbeat?
- **Returns:**
  - `200 {"status": "live"}` when heartbeat mtime is within `3 × heartbeat_interval_s` (90 s by default).
  - `503 {"status": "stale"}` otherwise.
- **Consumers:** Docker HEALTHCHECK, systemd watchdog sidecar, kubelet `livenessProbe`.

### `GET /health/ready`

- **Auth:** none
- **Purpose:** Is the node ready to accept traffic?
- **Conditions for 200:**
  - `/health/live` conditions are met, AND
  - RNS reports ≥1 active interface, AND
  - Maintenance loop ran within `5 × announce_interval` (50 min by default).
- **Returns 503 with a reason** (`rns_down`, `maintenance_stale`, etc.) otherwise.
- **Consumers:** fleet dashboards distinguishing "dead" from "degraded"; kubelet `readinessProbe`.

### `GET /api/metrics/`

- **Auth:** `X-API-Key` header, or `?key=<key>` query parameter, constant-time compared against the contents of `$DATA_DIR/api_key` (mode 0o600).
- **Returns:**
  - `404` if the api_key file does not exist (metrics disabled — unconfigured).
  - `401` if the key is missing or wrong.
  - `200` with Prometheus text format (v0.0.4) otherwise.
- **Consumers:** Prometheus scrapers. Always proxy through an authenticated front end.

## Heartbeat file

Path: `$DATA_DIR/heartbeat`. Mode 0o644 (contents are public — just identity hash and timestamp). Written atomically via tempfile + `os.replace`.

| Field | Meaning |
|---|---|
| `v` | Schema version (currently 1) |
| `ts` | Unix timestamp of the write |
| `role` | `community` or `relay` |
| `node_identity_hash` | Hex-encoded RNS identity hash |
| `pid` | Daemon PID |

A stale heartbeat means **one of** the following: the daemon crashed (L1 will restart it), RNS has no active interface (`rns_alive` false), or maintenance hasn't run recently (`maintenance_fresh` false). The distinction matters for triage — see [11-incident-response.md § Stale heartbeat](11-incident-response.md#stale-heartbeat).

Relay nodes check `rns_alive` but not `maintenance_fresh` (there's no community maintenance loop to be fresh or stale).

## Metrics catalogue

Sixteen metric families in total. Emitted by `src/hokora/core/prometheus_exporter.py::render_metrics`.

### Core counts

| Metric | Labels | Purpose |
|---|---|---|
| `hokora_messages_total` | `channel` | Per-channel message count |
| `hokora_channels_total` | — | Total channels |
| `hokora_messages_total_all` | — | All messages |
| `hokora_identities_total` | — | Cached identities |
| `hokora_peers_discovered` | — | Peer count |
| `hokora_daemon_uptime_seconds` | — | Uptime since daemon start |

### RNS interface

| Metric | Labels | Purpose |
|---|---|---|
| `hokora_rns_interface_bytes_rx_total` | `interface`, `type` | Per-interface receive bytes |
| `hokora_rns_interface_bytes_tx_total` | `interface`, `type` | Per-interface transmit bytes |
| `hokora_rns_interface_up` | `interface`, `type` | 1 if online, 0 if not |

### Federation and sync

| Metric | Labels | Purpose |
|---|---|---|
| `hokora_channel_latest_seq_ingested` | `channel` | Latest seq number accepted by this node per channel |
| `hokora_peer_sync_cursor_seq` | `peer`, `channel` | Where each peer's push cursor is |
| `hokora_cdsp_sessions` | `profile`, `state` | Session counts split by profile and state |
| `hokora_deferred_sync_items` | `channel` | Queued events awaiting CDSP session resume |
| `hokora_federation_peers` | `trusted` | Peer counts by trust status |

### Sealed channels

| Metric | Labels | Purpose |
|---|---|---|
| `hokora_sealed_channels_total` | — | Count of sealed channels |
| `hokora_sealed_key_age_seconds` | `channel` | Age of the newest epoch key |

All label values are sanitised against `"`, `\`, and newline characters before emission.

## Scraping

### Prometheus config

```yaml
scrape_configs:
  - job_name: 'hokora'
    scrape_interval: 30s
    metrics_path: '/api/metrics/'
    static_configs:
      - targets: ['127.0.0.1:8421']
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/hokora_api_key
    scheme: http
```

Note: Prometheus `authorization` adds an `Authorization: Bearer <key>` header; our endpoint reads `X-API-Key` or `?key=`. If using `Bearer`, you'll need either a metrics router change or a proxy that translates headers. The simplest option is:

```yaml
    params:
      key: ['<your-api-key>']
```

...which passes the key as a query parameter. Or front with a reverse proxy that inserts `X-API-Key`.

The api_key file is written by `hokora init` (atomic 0o600). For legacy data dirs predating init-time generation, create one manually before the daemon starts:

```bash
python3 -c 'import secrets; print(secrets.token_hex(32))' > $DATA_DIR/api_key
chmod 0600 $DATA_DIR/api_key
chown hokora:hokora $DATA_DIR/api_key
```

If the file is missing the daemon's `/api/metrics/` endpoint returns 404 (the route is hidden so probers can't distinguish "not configured" from "wrong auth"). The daemon will not generate the file at startup — keep it as an explicit operator artefact.

### External exposure

`ObservabilityListener` binds to `127.0.0.1` and refuses to start on any other address. To scrape from outside the host:

**Option A — SSH tunnel for a fleet Prometheus:**

```bash
ssh -L 18421:127.0.0.1:8421 node-a.example
# Prometheus scrapes localhost:18421
```

**Option B — reverse proxy with authentication:**

```nginx
location /api/metrics/ {
    proxy_pass http://127.0.0.1:8421/api/metrics/;
    proxy_set_header X-API-Key $http_authorization;
    # Add auth_basic or mtls in front
}
```

**Option C — Prometheus agent on the same host.** Run a local Prometheus agent that scrapes `127.0.0.1:8421` and remote-writes to the central aggregator.

For Kubernetes, scrape through a sidecar container or a sidecar Prometheus pod sharing the pod network.

## Recommended alerts

### Critical alerts (page)

- `hokora_daemon_uptime_seconds == 0` or target absent for > 2 min → daemon is down.
- Heartbeat mtime > 180 s → L2 failure.
- `/health/live` returning 503 for > 3 min → heartbeat stale and recovery has not kicked in.

### Warning alerts (ticket)

- `/health/ready` returning 503 for > 10 min → a subsystem is not ready.
- `hokora_rns_interface_up == 0` for any `interface` for > 5 min → transport offline.
- `rate(hokora_messages_total_all[5m]) == 0` during expected-active hours → processing has stalled.

### Informational dashboards

- `hokora_peer_sync_cursor_seq` falling steadily behind `hokora_channel_latest_seq_ingested` for the same channel → push is lagging.
- `hokora_deferred_sync_items` spike → clients disconnecting before flush.
- `hokora_sealed_key_age_seconds` above the operator's rotation SLA → time to rotate the group key.
- `hokora_cdsp_sessions{state="failed"}` non-zero → CDSP negotiation failing.

## Structured logs

Set `HOKORA_LOG_JSON=true` and the daemon emits one JSON object per log line, suitable for direct ingestion by vector, fluent-bit, Loki, or similar. Enable `HOKORA_LOG_TO_STDOUT=true` when running under systemd/Docker so log shippers can capture it.

Log fields:

| Field | Purpose |
|---|---|
| `ts` | ISO 8601 timestamp |
| `level` | Log level |
| `logger` | Python logger name |
| `msg` | Message |
| `extra.*` | Any structured context the call site attached |

Hokora's `TransportLogSanitizer` strips RNS interface class names from log output so transport types do not leak into aggregated logs. If raw RNS diagnostics are needed, drop the sanitizer at the DEBUG level on a specific host.

## Fleet operator notes

- One Prometheus job per node works well up to a few hundred nodes. Beyond that, use service-discovery (file_sd or Consul) so adding nodes doesn't require re-templating scrape configs.
- Put the api_key into your secrets manager (Vault, SOPS, external-secrets). Rotate by writing a new file atomically and `systemctl restart hokorad`.
- Alert on `count(hokora_rns_interface_up == 0) by (node) > 0` across the whole fleet to spot transport issues that aren't node-local.
- Dashboards worth building: message throughput per channel, peer-sync-cursor lag, CDSP session state distribution, heartbeat mtime per node.

## See also

- [02-configuration.md § Observability and heartbeat](02-configuration.md#observability-and-heartbeat)
- [08-deployment-systemd.md § Watchdog integration](08-deployment-systemd.md#watchdog-integration)
- [11-incident-response.md § Stale heartbeat](11-incident-response.md#stale-heartbeat)
