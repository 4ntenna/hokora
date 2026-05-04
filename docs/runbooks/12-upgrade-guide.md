# 12 — Upgrade Guide

This runbook covers upgrading a Hokora installation from one release to another. It is organised by version and by deployment mode.

## General upgrade principles

1. **Back up first.** Always. See [10-database-operations.md § Backup and restore](10-database-operations.md#backup-and-restore).
2. **Tag the currently-running image or commit** as a rollback point.
3. **Apply migrations before starting the new daemon version.** A new daemon refuses to start against an older-schema DB.
4. **Roll fleets staggered, one host at a time**, verifying health after each.
5. **Keep the previous working copy available for at least 7 days** before you delete it.

## Pre-flight checklist

```bash
# 1. Back up data
sudo systemctl stop hokorad
tar -czf /backups/hokora-pre-upgrade-$(date +%Y%m%d-%H%M%S).tar.gz \
    -C / var/lib/hokora
sudo systemctl start hokorad

# 2. Capture the current revision
hokora db current                          # note the output

# 3. Capture the current version
hokora --version                           # note the output

# 4. Confirm health
curl -sf http://127.0.0.1:8421/health/ready
```

## Bare-metal upgrade

```bash
# Stop service
sudo systemctl stop hokorad

# Update source
cd /opt/hokora
git fetch --tags
git checkout <new-tag-or-sha>

# Update dependencies
source .venv/bin/activate
pip install -e ".[tui,web]"              # or the extras you use
pip install -r requirements-lock.txt     # if you are pinning to the lock file

# Apply schema migrations
hokora db upgrade

# Confirm head
hokora db current

# Start and verify
sudo systemctl start hokorad
sleep 10
curl -sf http://127.0.0.1:8421/health/ready
hokora node status
```

Rollback on failure:

```bash
sudo systemctl stop hokorad
cd /opt/hokora
git checkout <previous-tag>
pip install -e ".[tui,web]"

# If the new version ran a migration that you need to revert:
hokora db downgrade --revision <prev_head>

sudo systemctl start hokorad
```

Some migrations are not safely reversible; see [10-database-operations.md § Downgrades](10-database-operations.md#downgrades). If downgrade isn't an option, restore from the backup you took in pre-flight.

## Docker upgrade

```bash
# Build or pull the new image
docker pull registry.internal/hokora:v0.1.1

# Tag the currently running image as a rollback point
RUNNING=$(docker inspect --format '{{.Image}}' hokorad)
docker tag $RUNNING registry.internal/hokora:rollback-$(date +%Y%m%d-%H%M%S)

# Apply migrations in a one-shot container against the live data volume
docker run --rm \
  -v /srv/hokora/data:/data/hokora \
  -e HOKORA_DATA_DIR=/data/hokora \
  registry.internal/hokora:v0.1.1 \
  hokora db upgrade

# Recreate with the new image
sed -i 's|hokora:v0.1.0|hokora:v0.1.1|' docker-compose.yml
docker compose up -d --force-recreate

# Verify
docker inspect hokorad --format '{{.State.Health.Status}} restarts={{.RestartCount}}'
curl -sf http://127.0.0.1:8421/health/ready
```

Rollback: edit compose back to the `rollback-*` tag and `docker compose up -d --force-recreate`.

See [07-deployment-docker.md § Upgrading](07-deployment-docker.md#upgrading) for image-tagging discipline.

## Fleet upgrade

For fleets above ~5 nodes, stagger the rollout:

```bash
for host in node-a node-b node-c node-d; do
  echo "=== $host ==="
  ssh $host 'sudo systemctl stop hokorad'
  ssh $host 'cd /opt/hokora && git pull && pip install -e ".[tui,web]" && hokora db upgrade'
  ssh $host 'sudo systemctl start hokorad'

  # Wait for ready
  until ssh $host 'curl -sf http://127.0.0.1:8421/health/ready'; do sleep 5; done

  # Smoke
  ssh $host 'hokora node status'

  # Pause before the next host
  sleep 60
done
```

Do one host at a time. If any host fails verify, stop the loop and investigate before continuing. Federation tolerates a mixed-version fleet during a rollout; it does not tolerate half a fleet silently broken.

## Version-to-version notes

### 0.1.0 → 0.1.x (within the 0.1 series)

No breaking changes planned within 0.1.x. Migrations will be additive. Config fields may be added; existing fields retain their semantics.

Standard upgrade procedure:

```bash
hokora db upgrade
sudo systemctl restart hokorad
```

### 0.1.x → 0.2 (future)

When 0.2 ships, this section will detail any breaking changes. Expect at least one around the `db_key` storage location (moving from `hokora.toml` to a separate `db_key` file). A migration tool will be provided.

## Post-upgrade verification

After any upgrade, work through this checklist:

- [ ] `hokora db current` reports the expected revision.
- [ ] `hokora --version` reports the expected version.
- [ ] `curl -sf http://127.0.0.1:8421/health/ready` returns 200.
- [ ] `hokora node status` runs clean.
- [ ] `hokora channel list` lists the expected channels.
- [ ] For federated nodes: `hokora node peers` shows trusted peers; `hokora_peer_sync_cursor_seq` advances.
- [ ] For sealed channels: send a test message, confirm `body IS NULL` at rest (see [06-sealed-channels.md § Operator smoke test](06-sealed-channels.md#operator-smoke-test)).
- [ ] For each TUI user: confirm they can connect and see channels.

If any step fails, roll back.

## What to do with stale copies

After an upgrade, you will likely have:

- `$DATA_DIR/hokora.db.pre-upgrade` from your warm backup (if you made one).
- A `rollback-YYYYMMDD-HHMMSS` Docker tag.
- A local git branch or tag at the previous release.

Keep these for a minimum of 7 days. Once the new version has run stably across your whole fleet for a week, delete the warm-backup files and the rollback Docker tag; keep the cold backups per your retention policy.

## See also

- [07-deployment-docker.md § Upgrading](07-deployment-docker.md#upgrading)
- [10-database-operations.md § Applying migrations](10-database-operations.md#applying-migrations)
- [11-incident-response.md](11-incident-response.md) if something goes wrong during upgrade.
