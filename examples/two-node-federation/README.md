# Two-node federation lab

A local Docker stack that brings up two Hokora daemons on a private bridge network and connects them over RNS TCP.

## Run

From the repo root:

```bash
docker compose -f examples/two-node-federation/docker-compose.yml up -d
sleep 15
docker compose -f examples/two-node-federation/docker-compose.yml ps

docker exec hokora-node-a curl -sf http://127.0.0.1:8421/health/live
docker exec hokora-node-b curl -sf http://127.0.0.1:8421/health/live
```

## What it verifies

- Both daemons start and become healthy on a shared Reticulum bridge.
- Each daemon owns its own RNS instance, isolated from the host's transport via per-config `instance_name`.
- The image's healthcheck wired to `/health/live` reports green within 20 s.

## What it does not verify

Federation peering, mirror sync, and end-to-end message flow are not exercised by this stack. Use the multinode pytest suite for those:

```bash
PYTHONPATH=src python -m pytest tests/multinode/ -v -s
```

## Files

- `docker-compose.yml` — the stack definition. Build context is the repo root, so it picks up the same `Dockerfile.full` as the production single-node compose.
- RNS configs are read from `tests/live/docker_rns_a/` and `docker_rns_b/` at the repo root.

## Teardown

```bash
docker compose -f examples/two-node-federation/docker-compose.yml down -v
```

`-v` deletes the per-node data volumes (destructive — only run if you don't care about the lab's accumulated state).
