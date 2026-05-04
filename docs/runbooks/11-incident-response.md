# 11 — Incident Response

Triage playbooks for the common Hokora failure modes. Every playbook follows the same shape: **Symptom → Triage → Diagnosis → Fix → Verify**.

Diagnose process-level state before network-level state. The most common root causes — daemon not running, stale PID file, RNS shared-instance socket owned by an unexpected process — are visible from `pgrep` and `lsof` and do not require any transport diagnostics.

## Triage first-pass

Run these five commands before diagnosing anything:

```bash
pgrep -af "hokora"                      # who is alive
lsof -U 2>/dev/null | grep rns/default           # who owns the RNS shared-instance socket
cat ~/.hokora*/hokorad.pid 2>/dev/null         # is PID file consistent with a live process
stat ~/.hokora*/heartbeat 2>/dev/null        # is the heartbeat recent
journalctl -u hokorad -n 100 --no-pager            # what did the daemon say last
```

If something obvious falls out — no daemon, no heartbeat, inverted socket ownership — jump directly to the matching playbook below. Otherwise continue to the next layer of diagnosis.

---

## Daemon won't start

**Symptom.** `hokorad` exits immediately or `systemctl start hokorad` reports `(code=exited, status=1/FAILURE)`.

**Triage.**

```bash
journalctl -u hokorad -n 50 --no-pager
# Or foreground: /path/to/python -m hokora
```

**Common causes and fixes.**

| Error fragment | Cause | Fix |
|---|---|---|
| `sqlcipher3` `ImportError` | SQLCipher missing | `pip install -e .` with `libsqlcipher-dev` installed |
| `db_key must be 64 hex characters` | Mis-set config | Regenerate: `python3 -c 'import secrets; print(secrets.token_hex(32))'`; write to `hokora.toml`; `chmod 0600` |
| `Database is at revision X, expected Y` | DB is behind code | `hokora db upgrade` |
| `[Errno 98] Address already in use` on 8421 | Another daemon is running | `pgrep -af hokorad`, stop duplicates |
| `Permission denied` on `hokorad.pid` | Data dir ownership | `chown -R hokora:hokora $DATA_DIR` |
| `fs_min_epoch_duration >= fs_epoch_duration` | Config validation | Fix `hokora.toml`; see [02-configuration.md § Forward secrecy](02-configuration.md#forward-secrecy-federation-link-encryption) |

**Verify.** `hokora daemon status` returns running; `/health/live` returns 200.

---

## Shared-instance inversion

**Symptom.** Channel announces from the local daemon propagate fine, but profile announces (display name, status text) from the TUI don't reach remote peers. Or: remote TUIs don't see newly-announced peers for long periods.

**Triage.**

```bash
lsof -U | grep rns/default
```

**Diagnosis.** The first process to bind the `@rns/default` UNIX socket becomes the shared-instance owner. If the TUI won that race (e.g. it was running before the daemon restarted, or the daemon briefly died), the daemon attaches as a client. Daemon channel announces go via IPC to the TUI's transport — fine. But profile announces that originate from the TUI's own destinations skip the IPC layer and go through the TUI's owner-transport directly, where RNS's announce rate limiting sometimes drops them.

A clear tell in daemon logs:

```
Socket for LocalInterface[rns/default] was closed, attempting to reconnect...
```

Only clients print this. Owners never do.

**Fix.** Restart in the correct order:

```bash
# Kill both
pkill -f hokora-tui
sudo systemctl stop hokorad
sleep 3                                  # let the abstract socket release

# Daemon first
sudo systemctl start hokorad
sleep 2

# Verify ownership
lsof -U | grep rns/default               # should show daemon PID with (LISTEN) only

# Then TUI
hokora-tui                                  # its lsof rows should be (CONNECTED)
```

**Verify.** `lsof -U | grep rns/default` shows the daemon PID as `(LISTEN)` and any TUI PIDs as `(CONNECTED)`. Remote peers see profile announces within one announce interval (600 s by default, configurable).

---

## Peer announces not propagating

**Symptom.** A remote operator says "I can't see your channel". You haven't changed anything.

**Triage.**

```bash
# Is the remote's destination hash in your path table
rnpath -t                    | head -20
# Are YOUR announces reaching their seed?
ssh <seed-operator> 'rnpath -t' | grep <your-dest-hash>
```

**Common causes.**

1. **Shared-instance inversion on your side.** Covered above.
2. **Your RNS has no route to the remote.** `rnpath` shows no entry for the remote. Check your interface config; if you rely on a seed, is the seed reachable (`nc -z <seed-host> 4242`)?
3. **The seed's path table has stale entries.** Some seeds discard announces after their expiration window. Force a fresh announce from your side: `hokora daemon stop && hokora daemon start`.
4. **`announce_enabled=false`**. Silent/invite-only mode. You won't be discovered via announce at all — redemption is via invite only.

**Fix.** Depends on the cause. If 2 or 3, restarting your daemon usually re-propagates an announce immediately. If 4, that's working as configured.

**Verify.** `rnpath -t` on the remote shows your destination with a fresh expiration.

---

## Stale heartbeat

**Symptom.** `/health/live` returns 503, or your Docker/systemd healthcheck flaps. `stat $DATA_DIR/heartbeat` shows mtime older than 90 s despite the daemon process being up.

**Triage.** The heartbeat is gated on two invariants. Which one failed?

```bash
# RNS alive?
journalctl -u hokorad -n 200 | grep -i 'rns\|interface'

# Maintenance fresh?
journalctl -u hokorad -n 200 | grep -i 'maintenance'

# Both?
curl -sf http://127.0.0.1:8421/health/ready   # returns JSON with a reason code
```

**Common causes.**

| Reason | Meaning | Fix |
|---|---|---|
| `rns_down` | No RNS interface reports `online=True` | Check `hokora_rns_interface_up` metric; check physical layer (USB for RNode, routing for TCP, i2pd for I2P). Restart daemon once transport is back. |
| `maintenance_stale` | Maintenance loop hasn't run within 5× announce_interval | Check for blocking SQL (`journalctl -u hokorad | grep -i 'lock\|busy'`); check DB integrity; potentially an FTS5 corruption |

**Fix.** If `rns_down`: fix the transport, no daemon restart needed — heartbeat recovers as soon as RNS comes back. If `maintenance_stale`: inspect the logs to find what blocked maintenance, restart if needed. **Do not** kill the daemon unless you have diagnosed the cause — a kill masks the underlying fault.

**Verify.** `curl -sf http://127.0.0.1:8421/health/ready` returns 200. `stat $DATA_DIR/heartbeat` shows mtime within 30 s.

---

## Federation stalled

**Symptom.** A freshly-added mirror is not receiving messages. `hokora node peers` shows the peer but `hokora_peer_sync_cursor_seq` isn't advancing.

**Triage.**

```bash
# 1. Is the peer still in the path table?
rnpath -t | grep <peer-hash>

# 2. Is it trusted?
hokora node peers | grep <peer-hash>

# 3. Did the handshake complete?
journalctl -u hokorad | grep -i 'handshake\|federation' | tail -40

# 4. Is our cursor actually advancing
curl -sf http://127.0.0.1:8421/api/metrics/?key=$(cat $DATA_DIR/api_key) \
  | grep hokora_peer_sync_cursor_seq
```

**Common causes.**

1. **Mirror was added but daemon not restarted.** `MirrorLifecycleManager` loads mirrors at startup. Restart: `sudo systemctl restart hokorad`.
2. **Peer not trusted.** `hokora mirror trust <peer_hash>`. No restart required.
3. **TOFU mismatch — peer's key changed.** Handshake fails silently. See [05-federation.md § Key changes](05-federation.md#key-changes-tofu).
4. **Cold-start stall.** RNS Link establishment to a peer can fail silently for up to ~5 minutes after boot. Known issue. Workaround: restart once both sides are up and `rnpath` shows a fresh entry for the peer.

**Verify.** Send a test message on the mirrored channel from the remote end; confirm it appears locally within a minute.

---

## Sealed channel "access denied"

**Symptom.** A user can't post to or read a sealed channel they should have access to.

**Triage.**

```bash
# Do they have a role scoped to that channel?
hokora role list    # check roles
# There is no "list assignments" CLI yet — query the DB directly:

sudo -u hokora sqlcipher $DATA_DIR/hokora.db <<EOF
PRAGMA key = "$DB_KEY";
SELECT r.name, ra.channel_id, ra.identity_hash
FROM role_assignments ra JOIN roles r ON r.id=ra.role_id
WHERE ra.identity_hash = '<hex>';
EOF

# Do they have a SealedKey row?
SELECT channel_id, epoch, identity_hash FROM sealed_keys WHERE identity_hash = '<hex>';
```

**Diagnosis.**

- If no role assignment at the channel scope, **this is an access-control denial, not a bug.** Issue a channel-scoped role assignment: `hokora role assign member <identity_hash> --channel <channel_id>`.
- If a role assignment exists but no `SealedKey` row, key distribution failed during `hokora role assign`. Re-run the assignment — it is idempotent.
- If a `SealedKey` row exists for an old epoch but not the current epoch, the user missed a key rotation. Re-assign to redistribute.

**Fix.** Assignment via CLI:

```bash
hokora role assign member <identity_hash> --channel <channel_id>
```

**Verify.** The user's TUI reconnects and renders the channel's message history. `hokora_sealed_key_age_seconds{channel="..."}` reflects the most recent epoch.

---

## Database errors

**Symptom.** Daemon logs show `database is locked`, `no such column`, `FOREIGN KEY constraint failed`, or SQLCipher errors.

**Triage.** Always run integrity checks before anything destructive:

```bash
sudo systemctl stop hokorad
DB_KEY=$(sudo grep '^db_key' $DATA_DIR/hokora.toml | cut -d'"' -f2)
sudo -u hokora sqlcipher $DATA_DIR/hokora.db <<EOF
PRAGMA key = "$DB_KEY";
PRAGMA integrity_check;
PRAGMA foreign_key_check;
EOF
```

**Common causes.**

| Error | Cause | Fix |
|---|---|---|
| `database is locked` | Two daemons racing for the DB | `pgrep hokorad`, kill duplicates |
| `no such column` | Schema/code mismatch | `hokora db current` vs expected head; `hokora db upgrade` |
| `FOREIGN KEY constraint failed` | Orphan row, usually after a manual DB edit | Restore from backup; investigate the edit |
| `file is not a database` | Wrong key or corrupted file | Wrong key: recover from `hokora.toml` backup. Corrupted: restore from backup. |

**Fix.** Depends on cause. Never `DELETE` rows to "fix" FK violations without understanding the root cause — you will usually lose more data than you save.

**Verify.** `PRAGMA integrity_check` returns `ok`. `hokora db current` matches the expected head. Daemon starts clean.

---

## `/api/metrics/` returns 404 or 401

**Symptom.** Prometheus scrape fails, or `curl -H "X-API-Key: …" http://127.0.0.1:8421/api/metrics/` returns 404 / 401.

**Triage.**

```bash
# Is the api_key file present and readable by the daemon user?
ls -l $DATA_DIR/api_key

# Is the daemon's observability listener up at all?
curl -sf http://127.0.0.1:8421/health/live
```

**Common causes.**

- `api_key` missing — route returns 404 by design (so probers cannot distinguish "not configured" from "wrong auth"). Recreate per [09-monitoring-observability.md § Scraping](09-monitoring-observability.md#scraping).
- `api_key` present but wrong mode (must be `0o600` and owned by the daemon user).
- Wrong key supplied — 401. Compare bytes, not characters; `secrets.compare_digest` is constant-time.
- Daemon hasn't started its observability listener yet (early startup, or `observability_enabled = false`).

**Fix.** Regenerate the key if missing or unreadable, then restart the daemon. The route is hidden when no key is configured — generate one even on relay nodes if you want Prometheus scrape.

**Verify.** `curl -sf -H "X-API-Key: $(cat $DATA_DIR/api_key)" http://127.0.0.1:8421/api/metrics/ | head` returns Prometheus text.

---

## When nothing matches

1. Capture state:

   ```bash
   mkdir -p /tmp/hokora-incident-$(date +%Y%m%d-%H%M%S)
   cd /tmp/hokora-incident-*

   pgrep -af "hokora"            > ps.txt
   lsof -U 2>/dev/null | grep rns/default > rns-socket.txt
   ls -la ~/.hokora*/                  > data-dir.txt
   stat ~/.hokora*/heartbeat           > heartbeat.txt
   curl -sf http://127.0.0.1:8421/health/ready > health-ready.txt 2>&1
   journalctl -u hokorad -n 500 --no-pager   > hokorad.log
   rnpath -t                               > rnpath.txt
   ```

2. Open a GitHub issue with the captured state (redact `identity_hash`, `destination_hash`, and anything sender-identifying).

3. Do not apply destructive actions — `systemctl reset-failed`, `rm -rf $DATA_DIR`, `pkill -9` — without exhausting the non-destructive path first.

## See also

- [09-monitoring-observability.md](09-monitoring-observability.md) for alerts that should catch most of these before users do.
- [05-federation.md](05-federation.md) for peer-handshake diagnostics.
- [06-sealed-channels.md](06-sealed-channels.md) for sealed-invariant verification.
- [10-database-operations.md](10-database-operations.md) for DB-integrity and backup procedures.
