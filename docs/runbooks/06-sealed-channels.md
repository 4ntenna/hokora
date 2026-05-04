# 06 — Sealed Channels

A sealed channel is a channel whose message bodies are encrypted at rest with AES-256-GCM. The plaintext never touches disk. Subscribed clients see plaintext on the Link-encrypted wire; unauthorised parties see ciphertext only.

This runbook covers the invariant, the operator surface (create, rotate, recover), and the recovery limits.

## The invariant

Every Message-write path routes through `src/hokora/security/sealed_invariant.py`, which exposes two fail-closed entry points sharing one `_channel_is_sealed` predicate:

`seal_for_origin(channel, plaintext, sealed_manager)` — locally-originated writes; encrypts plaintext.

| Input | Output |
|---|---|
| Sealed channel + non-empty plaintext | `(None, ciphertext, nonce, epoch)` — body column is `NULL`; ciphertext in `encrypted_body` |
| Sealed channel + empty body | `(None, None, None, None)` |
| Non-sealed channel | `(plaintext, None, None, None)` |
| Sealed channel, no group key available | `PermissionDenied` raised (never falls back to plaintext) |

`validate_mirror_payload(channel, body, encrypted_body, nonce, epoch)` — federation-pushed rows; never re-encrypts. Sealed channels require ciphertext on the wire and reject any payload carrying plaintext (raises `SealedChannelError`, which the mirror caller maps to drop+log without consuming a sequence number).

Write sites:

1. `MessageProcessor.ingest()` — normal inbound messages → `seal_for_origin`.
2. `MessageProcessor.process_edit()` — edit row and original body overwrite → `seal_for_origin`.
3. `MessageProcessor.process_pin()` — system messages → `seal_for_origin`.
4. `federation/mirror_ingestor.py` — peer-pushed messages → `validate_mirror_payload`.

This is enforced structurally, not by per-site inspection. If a sealed-channel plaintext ever appears in the `body` column at rest, the invariant has been violated — that is a bug and should be reported.

## FTS guard

The FTS5 insert trigger is gated:

```sql
WHEN new.body IS NOT NULL AND new.encrypted_body IS NULL
```

Sealed rows have `body IS NULL`, so they are never indexed. Full-text search (`/search` in the TUI) returns zero results for sealed content by design.

## Creating a sealed channel

```bash
hokora channel create --name ops --sealed
```

This creates the channel with `sealed=true`, generates an AES-256-GCM group key for the current epoch, wraps it for the node owner's identity, and stores the wrapped blob in the `sealed_keys` table. Plaintext keys never touch disk.

To seal an existing unsealed channel:

```bash
hokora channel seal <channel_id>
```

Note that existing plaintext messages in the channel remain in `body` until a purge is run (see [Plaintext purge](#plaintext-purge) below). New messages from this point on are encrypted.

## Granting access

Only identities with a `SealedKey` row for a channel can decrypt it. Keys are distributed automatically on role-assign:

```bash
hokora role assign member <identity_hash> --channel <channel_id>
```

The CLI envelope-encrypts the group key for the new member's RNS public key and writes the blob to `sealed_keys`. If the recipient's RNS identity is not yet known to the daemon, the distribution is queued in `pending_sealed_distributions` and drains on the next announce — see [14-member-management.md § Assigning roles](14-member-management.md#assigning-roles).

The role-assignment surface and the underlying permission model are documented in [13-permissions-and-roles.md](13-permissions-and-roles.md).

## Rotating the group key

Rotate the key whenever a member leaves, when keys are suspected to have leaked, or on a scheduled cadence (quarterly or annually for long-lived sealed channels).

```bash
hokora channel rotate-key <channel_id>
```

This:

1. Generates a new AES-256-GCM key.
2. Increments the channel's epoch.
3. Envelope-encrypts the new key for every current member.
4. Writes new `SealedKey` rows; the old rows remain so that historical ciphertext can still be decrypted.

Historical messages encrypted under the old epoch continue to decrypt cleanly because their `epoch` column references the old `SealedKey`.

## Rotating the channel's RNS identity

Separate from the group key, a channel's RNS identity can be rotated. This is useful if the destination hash has been burned (public spam, misconfigured peer) or on a periodic schedule.

```bash
hokora channel rotate-rns-key <channel_id> --yes
```

This:

1. Generates a new RNS identity.
2. Emits a dual-signed announce (old key signs the new key).
3. Backs up the old identity file to `identities/<channel>.pre-rotation-<timestamp>`.
4. Stores a 48-hour grace window on the channel row so old clients can still reach it during the cutover.
5. **Requires a daemon restart** for the new identity to become the active destination.

## Plaintext purge

If you sealed an existing channel that had prior plaintext, or if a bug ever left co-populated rows, run a plaintext purge. This is idempotent.

On daemon startup the `sealed_bootstrap.purge_plaintext_from_sealed_channels` routine runs automatically and performs two passes:

1. **Plaintext-only rows.** Sealed-channel rows that have *only* plaintext (`encrypted_body IS NULL`) and no ciphertext are deleted. These are pre-invariant leftovers from a channel that was sealed after it already held messages.
2. **Co-populated rows.** Rows that have both plaintext and ciphertext have their `body` and `media_path` nullified. Explicit FTS5 deletes are then issued because the FTS trigger does not fire on `UPDATE ... SET body=NULL`.

No operator action is required; the purge runs on every boot. To force a re-run without a restart, restart the daemon.

## Recovery limits

**If every member loses their identity file, the sealed channel's content cannot be recovered.** The group key is only stored envelope-encrypted to member identities — there is no escrow key, no centralised decryptor, no passphrase fallback.

Mitigations:

- Back up member identity files (`identities/*` with mode 0o600) alongside `hokora.toml`.
- For critical sealed channels, maintain a dedicated "escrow member" whose identity file is stored in a cold backup.
- Document your escrow policy as part of your node's operating procedure.

## Federation behaviour

Sealed channels can be mirrored across federation. Ciphertext traverses the wire verbatim — peer daemons cannot decrypt it. The receiving daemon writes the ciphertext directly into its own `messages` table; a local member with the group key can then decrypt via the standard read path.

If a peer pushes a plaintext body for a sealed channel, the push is rejected at `mirror_ingestor.py` before any DB write happens.

## Operator smoke test

To verify the invariant on your node:

```bash
# Create a throwaway sealed channel
hokora channel create --name sealed-smoke --sealed

# From a TUI as the node owner, send a message, e.g. "hello world"

# Inspect the database
sqlcipher $DATA_DIR/hokora.db
PRAGMA key = "<your_db_key>";

SELECT msg_hash, body, length(encrypted_body), nonce, epoch
FROM messages
WHERE channel_id = (SELECT id FROM channels WHERE name='sealed-smoke')
ORDER BY seq DESC
LIMIT 1;
```

Expected:

- `body` is `NULL`.
- `length(encrypted_body)` is `20 + 16 = 36` for "hello world" (20 bytes plaintext plus the 16-byte GCM tag).
- `nonce` is 12 bytes.
- `epoch` is a positive integer.

If `body` is non-null, the invariant has been violated — collect a repro and report.

## See also

- [05-federation.md](05-federation.md) for federation-side mirror semantics on sealed channels.
- [10-database-operations.md § Backup and restore](10-database-operations.md#backup-and-restore) — key material must be backed up alongside the DB.
- [SECURITY.md](../../SECURITY.md) for the threat model. Sealed-channel implementation lives at `src/hokora/security/sealed.py` (key management) and `src/hokora/security/sealed_invariant.py` (write-path chokepoint).
