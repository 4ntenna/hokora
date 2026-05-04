# 14 — Member Management

This runbook covers the day-2 operator workflows: inviting users, assigning roles, removing members, and reading the audit log. The CLI surface lives at `hokora invite`, `hokora role`, and `hokora audit`. For the underlying permission model see [13-permissions-and-roles.md](13-permissions-and-roles.md).

## Inviting a user

Invites are the supported way to onboard a new identity onto the node. Invite tokens are 16 random bytes, SHA-256-hashed at rest, and returned to the operator as a colon-separated composite that embeds the destination hash and (for channel-scoped invites) the channel's public key. The pubkey embed lets the recipient redeem the invite without first observing the channel's announce, which matters for silent and invite-only nodes.

### Issuing an invite

```bash
# Channel-scoped invite, single use, 72-hour expiry (defaults).
hokora invite create --channel <channel_id>

# Channel-scoped, 5 uses, 24-hour expiry.
hokora invite create --channel <channel_id> --max-uses 5 --expiry-hours 24

# Node-scoped invite (no --channel) — grants no channel access by itself; the
# redeemer becomes a known identity but still needs role assignments.
hokora invite create
```

The command prints the composite token. Hand it to the recipient out of band (Signal, email, etc.). The composite format is:

```
<token>:<destination_hash>:<channel_pubkey>:<channel_id>
```

Fields after the token are present only on channel-scoped invites. The token alone is enough for the daemon to look up the invite row; the trailing fields let the recipient's TUI bypass the announce wait.

### Listing and filtering

```bash
hokora invite list                          # all active invites
hokora invite list --channel <channel_id>   # filter to one channel
```

The output shows each invite's token hash (16-byte hex prefix), `uses / max_uses`, status (`active`, `revoked`, `expired`, `exhausted`), and expiry. Operators identify a specific invite by its hash for revocation.

### Redemption

The recipient runs the redemption inside their TUI:

```
/invite redeem <composite_token>
```

The daemon validates the token, checks `max_uses` and `expires_at` under an async lock to prevent a TOCTOU race on concurrent redemption, increments `uses`, and creates the channel-scoped `member` role assignment if the invite is channel-scoped. Sealed-channel invites also trigger sealed-key distribution to the redeemer (queued via `pending_sealed_distributions` if the recipient's RNS identity is not yet known).

Redemption is rate-limited per identity: 5 attempts per 10 minutes; 3 failures within the window blocks that identity for 1 hour. Limits are bucketed by the identity hash carried in the redemption packet.

### Revoking

```bash
hokora invite revoke <token_hash>
```

Revocation flips `revoked = true` on the row. Future redemptions return `Invite has been revoked`. Revocation does **not** retroactively undo prior successful redemptions or strip role assignments that were granted by the invite — those persist until removed manually with `hokora role revoke`.

### Lifecycle states

| State | Cause | Operator action to recover |
|---|---|---|
| `active` | Created and not yet revoked, expired, or exhausted. | None. |
| `revoked` | `hokora invite revoke` was called. | Issue a new invite. |
| `expired` | `expires_at < now`. | Issue a new invite. |
| `exhausted` | `uses >= max_uses` (when `max_uses > 0`). | Issue a new invite or extend `max_uses` via DB edit. |

Set `--max-uses 0` for an unlimited invite. Use sparingly — unlimited invites accumulate redemptions silently and have no rate-limit recourse if the token leaks.

## Assigning roles

Role assignment is the day-2 mechanism for changing what a user can do on the node. The CLI surface is in [03-cli-reference.md § `hokora role`](03-cli-reference.md#hokora-role); the resolver behaviour is in [13-permissions-and-roles.md § Resolution model](13-permissions-and-roles.md#resolution-model).

```bash
# Channel-scoped: grant moderator on one channel
hokora role assign moderator <identity_hash> --channel <channel_id>

# Node-scoped: grant a role across the node
hokora role assign moderator <identity_hash>
```

On sealed channels, channel-scoped role assignment also envelope-encrypts the channel's group key for the recipient's RNS public key. If the recipient's identity has not been observed by the daemon yet, the distribution is queued in `pending_sealed_distributions` and drains when the recipient announces:

```bash
hokora role pending --channel <channel_id>     # see queued distributions
```

Pending entries auto-clear when the recipient comes online; an unmet pending entry that persists for hours usually means the recipient's identity is unreachable on RNS or the channel was created on a different node. Inspect `rnpath -t | grep <identity_hash>` to verify reachability.

### Re-running assignment is idempotent

`hokora role assign` is safe to re-run. If the assignment row already exists it is a no-op; if a sealed-key row is missing for the current epoch it is created. Use re-assign as the standard recovery path for "user can't decrypt the sealed channel" — it heals a missing or stale `sealed_keys` row without side effects.

## Removing a member

There is no single "remove user" command today; the operator composes it from existing primitives.

### Revoke their roles

```bash
# Channel-scoped revoke — strips this channel's role assignment
hokora role revoke moderator <identity_hash> --channel <channel_id>

# Node-scoped revoke — strips the node-level role
hokora role revoke moderator <identity_hash>
```

Revoking the last role on a sealed channel does not delete the recipient's `sealed_keys` row (historical messages need the old key to decrypt for any current member). To rotate the group key after a revoke so the leaver cannot decrypt new traffic, run:

```bash
hokora channel rotate-key <channel_id>
```

Rotation generates a new AES-256-GCM group key, increments the channel epoch, and re-distributes envelope-encrypted blobs to every *current* role-holder. The leaver no longer holds a current `sealed_keys` row and cannot decrypt anything from the new epoch onward.

### Effect on prior content

Role revocation does **not** delete the user's prior messages. To remove their content as well, an operator with `PERM_DELETE_OTHERS` can delete messages individually from the TUI. There is no bulk-sweep CLI today; operators with high-volume needs run a SQL form against the DB:

```bash
sudo systemctl stop hokorad

DB_KEY=$(cat $DATA_DIR/db_keyfile)
sqlcipher $DATA_DIR/hokora.db <<EOF
PRAGMA key = "$DB_KEY";

-- Soft-delete: replace body, keep row for FK integrity
UPDATE messages
SET body = '[deleted]', encrypted_body = NULL, edited = 1
WHERE sender_hash = '<identity_hex>';

-- Optional: drop FTS5 entries for the soft-deleted rows
INSERT INTO messages_fts(messages_fts) VALUES ('rebuild');
EOF

sudo systemctl start hokorad
```

A bulk-sweep CLI (`hokora moderate sweep --identity <hex>`) is a planned enhancement; until it lands, treat the SQL form as the supported path and document the run in your operations log.

## Banning an identity

Hokora's persistent ban surface is `hokora ban`. It mutates `Identity.blocked` and is enforced at every chokepoint a banned identity might touch: local message ingest, sync read paths (history, threads, search, pins, member list, channel metadata, fetch media, subscribe-live), federation push receive (per-message, even from a trusted relay), the federation pusher (banned senders are filtered outbound), and invite redemption.

DMs in Hokora are TUI-to-TUI peer-to-peer over LXMF transport; the daemon never ingests DMs, so the ban surface does not extend to direct messages. A banned identity can still send DMs to other operators if the recipient TUI accepts them — recipients should manage that at the client layer (block in the conversations tab).

### CLI

```bash
# Ban an identity
hokora ban add <identity_hash> --reason "spam in #general"

# List currently banned identities
hokora ban list

# Lift a ban
hokora ban remove <identity_hash> --reason "appeal granted"
```

Every `add` / `remove` writes an `audit_log` row (`identity_ban` / `identity_unban`) carrying the actor (node-owner identity hash), target, reason, and the count of any pending sealed-key distributions dropped. Read it back with `hokora audit list`.

The CLI refuses to ban the node-owner identity. The permission resolver short-circuits the node-owner to `PERM_ALL` (see [13-permissions-and-roles.md § Layer 1](13-permissions-and-roles.md#layer-1--node-owner)); a banned-but-still-omnipotent owner row would leave the daemon in an inconsistent state, so the refusal lives at the mutation boundary.

### Sealed channels

When the banned identity was a member of any sealed channels, `hokora ban add` lists them and prints the rotate-key commands you should run next. Rotation is **not automatic** — operator decision, mirroring how `hokora role revoke` defers rotation. Without rotation the banned identity still holds the AES key for the current epoch and can decrypt sealed-channel ciphertext they had cached locally; for new traffic, rotate:

```bash
hokora channel rotate-key <sealed_channel_id>
```

`hokora ban add` also drops any rows in `pending_sealed_distributions` queued for the target so a future announce cannot trigger a key envelope being materialised after the ban.

### What the ban does not do

- **Existing messages from the banned identity stay in the channel store.** Bans are forward-looking. To soft-delete past content, use the SQL form documented earlier in this runbook (`UPDATE messages SET body = '[deleted]' WHERE sender_hash = ...`).
- **Active invites the banned identity could redeem are not auto-revoked.** Run `hokora invite list` and revoke any that look unsafe; the redemption gate would refuse them anyway, but explicit revocation is cleaner. (For the same reason, ban before sending fresh invites someone might phish.)
- **DMs to and from the banned identity are not affected** — see the DM caveat above.
- **`PERM_BAN_IDENTITIES = 0x2000` is reserved.** It is defined and assignable to roles, but no protocol handler currently issues bans over the wire — bans are CLI-only by the operator. The flag is held in reserve for a future remote-ban surface; today it has no runtime effect.

## Reading the audit log

The audit log is a single table (`audit_log`) keyed by `(actor, action_type, target, channel_id, timestamp)`. Today the daemon writes only `message_delete` events automatically. Other administrative actions (role assign, role revoke, channel create, invite revoke) are not audited at write time; this is a known gap.

### CLI

```bash
# Last 50 entries (default)
hokora audit list

# Filter by channel
hokora audit list --channel <channel_id>

# Bulk export as JSON
hokora audit list --limit 1000 --json > audit-$(date +%Y%m%d).json
```

The text mode prints one entry per line: timestamp, actor (truncated identity hash), action type, target, channel ID. JSON mode emits the full record including the `details` blob.

### What to expect

- `message_delete` events carry the deleting actor's identity hash, the deleted message hash in `target`, and the reason (`reason`) in `details`.
- Other event types may appear if added in future releases. The CLI is forward-compatible — it prints whatever `action_type` the row carries.

### Retention

There is no automatic retention policy on the audit log today. Rows accumulate indefinitely. For high-volume nodes, prune periodically with a SQL form:

```bash
DB_KEY=$(cat $DATA_DIR/db_keyfile)
sqlcipher $DATA_DIR/hokora.db <<EOF
PRAGMA key = "$DB_KEY";
DELETE FROM audit_log WHERE timestamp < strftime('%s', 'now', '-180 days');
EOF
```

Run during a maintenance window or when the daemon is stopped to avoid lock contention.

## Channel governance

Day-2 channel-level operator controls live on `hokora channel`:

| Action | Command |
|---|---|
| Throttle posting | `hokora channel edit <channel_id> --slowmode <seconds>` (per-identity post interval) |
| Lock down a channel to a single role | `--access write_restricted` + override per [13-permissions-and-roles.md § Worked examples](13-permissions-and-roles.md#make-announcements-write-restricted-only-publisher-can-post). |
| Re-key a sealed channel | `hokora channel rotate-key <channel_id>` |
| Rotate the channel's RNS destination | `hokora channel rotate-rns-key <channel_id> --yes` (48 h grace; daemon restart required) |
| Take a channel offline | `hokora channel edit <channel_id> --access private` (existing members keep access; non-members lose visibility) |
| Delete a channel | `hokora channel delete <channel_id>` |

Slowmode and access-mode edits take effect immediately. RNS identity rotation requires a daemon restart to bind the new destination; the prior identity remains valid for 48 h via the recorded grace window so old clients can still reach the channel during the cutover.

## See also

- [03-cli-reference.md](03-cli-reference.md) — full CLI surface for `role`, `invite`, `audit`, `channel`.
- [13-permissions-and-roles.md](13-permissions-and-roles.md) — permission flags, built-in roles, resolution model.
- [06-sealed-channels.md](06-sealed-channels.md) — sealed-key lifecycle on assign / revoke / rotate.
- [10-database-operations.md](10-database-operations.md) — backup before bulk SQL operations on the DB.
- [11-incident-response.md § Sealed channel "access denied"](11-incident-response.md#sealed-channel-access-denied) — triage for missing sealed-key rows after assignment.
