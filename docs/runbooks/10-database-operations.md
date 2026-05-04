# 10 — Database Operations

Hokora uses SQLCipher for encrypted SQLite, with Alembic for schema migrations. This runbook covers migrations, FTS maintenance, key management, and backup/restore procedures.

## Schema overview

Community nodes maintain 16 ORM models. Relay nodes have no database. The canonical schema is `src/hokora/db/models.py`; Alembic migrations live under `alembic/versions/`. The `0.1.0` initial release ships a single baseline migration; future releases will add additive revisions on top of it.

Client cache (`~/.hokora-client/tui.db`) is an unrelated SQLite database owned by the TUI at schema v8. Operator procedures on it are trivial (safe to delete for a fresh client cache) and aren't covered here.

## Applying migrations

```bash
# Show current revision
hokora db current

# Apply all pending migrations
hokora db upgrade

# Apply to a specific revision
hokora db upgrade --revision <target>
```

The `hokora db` group is cwd-independent — it walks up from the CLI package to find `alembic/env.py` and sets an absolute `script_location`, so migrations run from any directory.

### Migrations under Docker

Run a one-shot container against the same data volume:

```bash
docker run --rm \
  -v /srv/hokora/data:/data/hokora \
  -e HOKORA_DATA_DIR=/data/hokora \
  registry.internal/hokora:latest \
  hokora db upgrade
```

Do this *before* starting the new daemon version. If you bring up the new daemon first and it finds a DB at an older revision than it expects, it refuses to start. This is a safety feature — it stops a node with mismatched code and schema from corrupting data.

### Downgrades

```bash
# Revert the most recent migration
hokora db downgrade

# Revert to a specific revision
hokora db downgrade --revision <target>
```

**Not every migration is safely reversible.** Data-destructive migrations lose information on downgrade. Always back up before a downgrade, and test on a staging copy first.

### The `env.py` DML-commit fix

`alembic/env.py` uses `connectable.begin()` (not `.connect()`). This matters because SQLAlchemy 2.x's `connect()` does not auto-commit, so INSERT/UPDATE/DELETE inside a migration would silently roll back. The `.begin()` context manager wraps the whole migration in one transaction that commits on clean exit. Migrations can safely mix DDL and DML.

## Full-text search

FTS5 is maintained by triggers: INSERT/UPDATE/DELETE on `messages` → `messages_fts`. The trigger includes a guard so sealed-channel rows (where `body IS NULL` and `encrypted_body IS NOT NULL`) are never indexed.

### Rebuilding the FTS index

If the FTS index gets out of sync (rare, usually after a manual DB operation), rebuild it:

```bash
hokora db rebuild-fts
```

This runs `INSERT INTO messages_fts(messages_fts) VALUES ('rebuild')` under the covers. Takes a few seconds per thousand messages on typical hardware.

## SQLCipher key management

### Where the key lives

`hokora init` generates a 64-hex-char (256-bit) key and writes it to `$DATA_DIR/db_key` with mode 0o600. The path is recorded in `hokora.toml` as `db_keyfile = "..."`. The TOML config no longer carries the key itself.

```toml
# hokora.toml fragment
db_encrypt = true
db_keyfile = "/var/lib/hokora/db_key"
```

This separation means an operator can rsync, commit, or share `hokora.toml` for support without leaking the database master key. The key lives in exactly one file, on disk, owned by the daemon user.

**Backwards compatibility.** Legacy nodes still carry an inline `db_key = "..."` in `hokora.toml`. The daemon honours this for one release with a `DeprecationWarning` at startup. Migrate with `hokora db migrate-key` (see below).

### Discovery order

`NodeConfig.resolve_db_key()` is the single chokepoint that supplies the SQLCipher master key to `create_db_engine(...)`. Resolution order:

1. `db_encrypt = false` — return `None` (relay/lab path).
2. `db_keyfile` set in TOML — read the file, strip whitespace, validate `^[0-9a-fA-F]{64}$`, return.
3. Auto-discovery — neither field set, but `$DATA_DIR/db_key` exists → adopt it as `db_keyfile` (lets a "drop the file" install work without editing TOML).
4. Inline `db_key` set — return it and emit a one-shot `DeprecationWarning` (legacy path).
5. Encryption on but no key source — fail at config-load time with a clear message.

If `db_keyfile` exists with mode looser than 0o600, the daemon logs a warning but does not auto-tighten — that is an explicit operator decision (the file might be group-readable for a documented reason).

### Migrating from inline `db_key` to a keyfile

For existing nodes carrying the inline form:

```bash
sudo -u hokora hokora db migrate-key
sudo systemctl restart hokorad          # restart picks up the new path
```

The command:

1. Reads the inline `db_key` from `hokora.toml`.
2. Writes it to `$DATA_DIR/db_key` (atomic, 0o600).
3. Verifies the resolver recovers the same bytes.
4. Backs up the original to `hokora.toml.prev` (0o600).
5. Rewrites `hokora.toml` to replace `db_key = "..."` with `db_keyfile = "$DATA_DIR/db_key"`.

`migrate-key` is idempotent and refuses to overwrite an existing keyfile. To migrate to a non-default path:

```bash
sudo -u hokora hokora db migrate-key --to-file /etc/hokora/db_key
```

After a successful migrate, verify before deleting the backup:

```bash
sudo -u hokora hokora node status         # exits 0, prints node identity hash
sudo rm $DATA_DIR/hokora.toml.prev      # only after status verifies
```

### Backing up the DB key

The keyfile is the single point of failure for decrypting the database. Without it, the SQLCipher database is cryptographically unrecoverable.

Practical patterns:

- **Offline copy on removable media** — write the 64 hex chars to paper, USB, or an air-gapped device. Single most reliable option.
- **Password manager** — paste the contents into a vault entry tagged with the node identity hash.
- **QR code** — `qrencode -o key.png "$(cat $DATA_DIR/db_key)"` produces a scannable backup.
- **Split secret** — split the hex key into shares (e.g. via `ssss-split`) and distribute to multiple holders for high-value deployments.

Do **not** commit the keyfile to a code repository. Do **not** include it in a `tar` of `$DATA_DIR` that you intend to share for support — exclude it explicitly with `--exclude=db_key`.

### Future-proofing: systemd `LoadCredential`

The `db_keyfile` path can point at a credential delivered by systemd at unit-start time, removing the on-disk copy entirely. Outline (not yet wired into the generated unit file — file an issue if you need this):

```ini
# /etc/systemd/system/hokorad.service.d/credentials.conf
[Service]
LoadCredential=db_key:/etc/credstore.encrypted/hokorad-db-key
Environment=HOKORA_DB_KEYFILE=%d/db_key
```

systemd materialises the credential at `${CREDENTIALS_DIRECTORY}/db_key` only for the daemon's lifetime; the path is namespaced and group-readable to no one but the unit. The Hokora daemon reads it like any other file.

### Rotating the DB key

There is no built-in CLI for full key rotation yet (re-encrypts the entire DB). Procedure:

```bash
# 1. Stop the daemon and back up.
sudo systemctl stop hokorad
cp $DATA_DIR/hokora.db $DATA_DIR/hokora.db.pre-rotation
cp $DATA_DIR/db_key $DATA_DIR/db_key.pre-rotation

# 2. Re-encrypt with a new key via sqlcipher CLI.
OLD_KEY=$(cat $DATA_DIR/db_key)
NEW_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')

sqlcipher $DATA_DIR/hokora.db.pre-rotation <<EOF
PRAGMA key = "$OLD_KEY";
ATTACH DATABASE '$DATA_DIR/hokora.db.new' AS new KEY '$NEW_KEY';
SELECT sqlcipher_export('new');
DETACH DATABASE new;
EOF

# 3. Swap DB files and write the new key.
mv $DATA_DIR/hokora.db.new $DATA_DIR/hokora.db
chmod 0600 $DATA_DIR/hokora.db
printf '%s\n' "$NEW_KEY" | sudo -u hokora tee $DATA_DIR/db_key.new > /dev/null
chmod 0600 $DATA_DIR/db_key.new
mv $DATA_DIR/db_key.new $DATA_DIR/db_key

# 4. Restart and verify.
sudo systemctl start hokorad
sleep 10
hokora node status                      # should succeed, printing node hash
```

**Keep `hokora.db.pre-rotation` and `db_key.pre-rotation` until you have confirmed multiple round-trips on the new key.** Anything that goes wrong leaves you needing the old pair to recover.

## Backup and restore

A clean backup requires the daemon to be either fully stopped or quiesced. SQLite WAL mode tolerates hot copies but produces inconsistent backups if a write happens mid-copy.

### Cold backup (recommended)

```bash
sudo systemctl stop hokorad

# Capture everything needed to restore
tar --numeric-owner -czf /backups/hokora-$(date +%Y%m%d-%H%M%S).tar.gz \
    -C / \
    var/lib/hokora/hokora.db \
    var/lib/hokora/hokora.toml \
    var/lib/hokora/identities \
    var/lib/hokora/media

sudo systemctl start hokorad

# Verify the backup
tar -tzf /backups/hokora-*.tar.gz | head
```

### Warm backup (WAL-safe)

If downtime is unacceptable, use SQLite's online backup API via `sqlcipher`:

```bash
DB_KEY=$(sudo grep '^db_key' /var/lib/hokora/hokora.toml | cut -d'"' -f2)

sudo -u hokora sqlcipher /var/lib/hokora/hokora.db <<EOF
PRAGMA key = "$DB_KEY";
PRAGMA cipher_compatibility = 4;
ATTACH DATABASE '/tmp/hokora-backup.db' AS bkp KEY "$DB_KEY";
SELECT sqlcipher_export('bkp');
DETACH DATABASE bkp;
EOF

# Move to final location
mv /tmp/hokora-backup.db /backups/hokora-$(date +%Y%m%d-%H%M%S).db
```

This produces a consistent encrypted copy with the same `db_key` as the original.

### Restore

```bash
sudo systemctl stop hokorad

tar -xzf /backups/hokora-YYYYMMDD-HHMMSS.tar.gz -C /

sudo chmod 0600 /var/lib/hokora/hokora.db
sudo chmod 0600 /var/lib/hokora/hokora.toml
sudo chmod 0700 /var/lib/hokora/identities
sudo chmod 0600 /var/lib/hokora/identities/*
sudo chown -R hokora:hokora /var/lib/hokora

sudo systemctl start hokorad

# Check the restored DB is at an expected revision
hokora db current
```

If the restored DB is at an older revision than the installed code, run `hokora db upgrade` before starting the daemon.

## Backup retention and automation

A workable schedule for self-hosters:

- Hourly WAL-safe warm backups, retained for 48 h.
- Daily cold backups, retained for 30 d.
- Monthly cold backups, retained for 12 months.

Off-site at least one of the daily backups every week. An example `/etc/cron.d/hokora-backup` for hourly warm:

```
0 * * * * hokora /usr/local/bin/hokora-warm-backup.sh >>/var/log/hokora-backup.log 2>&1
```

Fleet operators should drive backup from their config-management/orchestration layer (e.g. `backup.sh` container on a scheduled job, or a Kubernetes CronJob) rather than per-host cron.

## Media and identity files

`$DATA_DIR/media/` and `$DATA_DIR/identities/` are not in the database but ARE on the critical recovery path. The backup procedure above includes them. Media files are referenced from the `messages` table; missing media will surface as broken attachments but will not corrupt the DB.

## Integrity checks

```bash
sudo -u hokora sqlcipher $DATA_DIR/hokora.db <<EOF
PRAGMA key = "$(grep ^db_key $DATA_DIR/hokora.toml | cut -d'"' -f2)";
PRAGMA integrity_check;
PRAGMA foreign_key_check;
EOF
```

`integrity_check` should return `ok`. `foreign_key_check` should return nothing. Run after any forced shutdown or suspected corruption.

## Known issue — backup escrow for legacy nodes

On legacy nodes that still carry an inline `db_key` inside `hokora.toml`, the file serves as both the config and the key store, which complicates independent key backup. Treat such a `hokora.toml` as a secrets file and include it in the secrets backup, not the config backup. New nodes use a separate `db_keyfile`; migrate via `hokora db migrate-key` to remove this concern.

## See also

- [02-configuration.md § Database and media](02-configuration.md#database-and-media) — config fields relevant to DB layout.
- [06-sealed-channels.md § Recovery limits](06-sealed-channels.md#recovery-limits) — member-key backup policy.
- [11-incident-response.md § Database errors](11-incident-response.md#database-errors) — triage.
