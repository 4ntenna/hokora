# 03 — CLI Reference

The `hokora` CLI is a Click application. Groups are laid out in `src/hokora/cli/`. All commands run from any working directory, including `hokora db` migrations.

```bash
hokora --help                      # top-level help
hokora <group> --help              # group help
hokora <group> <command> --help    # per-command help
```

## Global options

| Option | Purpose |
|---|---|
| `--version` | Print version and exit |
| `--help` | Show help |

## Command groups

| Group | Purpose |
|---|---|
| `hokora init` | Initialise a node (standalone, not a group) |
| `hokora channel` | Channel CRUD, overrides, key rotation |
| `hokora role` | Role CRUD, role assignment, pending sealed-key distributions |
| `hokora identity` | RNS identity import/export/list |
| `hokora invite` | Invite token issuance and revocation |
| `hokora node` | Node status, config dump, peer listing |
| `hokora mirror` | Federation mirror management |
| `hokora seed` | RNS seed-node CRUD (filesystem-gated config edits) |
| `hokora db` | Alembic migrations and FTS rebuild |
| `hokora daemon` | Daemon lifecycle (start / stop / status) |
| `hokora audit` | Query the audit log |
| `hokora ban` | Ban / unban identities at the node level |
| `hokora config` | Configuration helpers (e.g. `validate-rns`) |

---

## `hokora init`

Initialises a new node. Interactive by default; accepts all fields as flags for unattended provisioning.

```bash
hokora init [--data-dir PATH]
          [--node-name NAME]
          [--node-type {community,relay}]
          [--no-db-encrypt]
          [--skip-luks-check]
```

| Flag | Default | Purpose |
|---|---|---|
| `--data-dir` | `~/.hokora` | Root of node state |
| `--node-name` | prompted | Human-readable label |
| `--node-type` | prompted | `community` or `relay` |
| `--no-db-encrypt` | off | Disable SQLCipher (not recommended for community) |
| `--skip-luks-check` | off | Skip the LUKS volume warning |

Side effects and file modes are documented in [01-installation.md § What `hokora init` creates](01-installation.md#what-hokora-init-creates).

---

## `hokora channel`

Channel IDs can be either a 16-character hex ID or a channel name with optional `#` prefix. Both resolve via `_resolve_channel_id`.

| Command | Args | Notable flags | Effect |
|---|---|---|---|
| `create` | `name` | `--description`, `--access {public,write_restricted,private}`, `--category ID`, `--sealed` | Creates Channel row. `--sealed` eagerly provisions a group key. |
| `list` | — | — | Lists all channels with sealed/access markers. |
| `info` | `channel_id` or `#name` | — | Shows metadata, slowmode, identity hash, destination hash, seal state. |
| `edit` | `channel_id` or `#name` | `--name`, `--description`, `--access`, `--slowmode SECONDS` | Updates the channel row. |
| `delete` | `channel_id` or `#name` | (prompts) | Deletes channel and associated messages. |
| `seal` | `channel_id` or `#name` | — | Sets `sealed=true`; provisions initial key. |
| `unseal` | `channel_id` or `#name` | (prompts) | Sets `sealed=false`; deletes `SealedKey` rows. |
| `rotate-key` | `channel_id` or `#name` | — | Rotates sealed group key; increments epoch; redistributes to members. |
| `rotate-rns-key` | `channel_id` or `#name` | `--yes` | Rotates the channel's RNS identity with a dual-signed announce. 48 h grace window recorded on the channel row. **Requires daemon restart.** |
| `override` | `channel_id` or `#name` | `--role ID-OR-NAME`, `--allow PERMS`, `--deny PERMS` | Upserts a `ChannelOverride`. Deny beats allow. |

Examples:

```bash
hokora channel create --name announcements --access write_restricted
hokora channel create --name ops --sealed
hokora channel edit #general --slowmode 5
hokora channel override #ops --role everyone --deny 0x0003   # strip send perms
hokora channel rotate-key ops
```

---

## `hokora role`

| Command | Args | Notable flags | Effect |
|---|---|---|---|
| `create` | `name` | `--permissions BITS`, `--position INT`, `--colour HEX`, `--mentionable` | Creates a role. Bitmask accepts decimal or `0x` hex. |
| `assign` | `role_name` `identity_hash` | `--channel CHANNEL_ID` (optional for node-scope) | Creates `RoleAssignment`. On sealed channels, distributes the group key. |
| `revoke` | `role_name` `identity_hash` | `--channel CHANNEL_ID` | Removes a role assignment. |
| `list` | — | — | Shows roles with permissions (hex), position, builtin flag. |
| `pending` | — | `--channel CHANNEL_ID` | Shows sealed-key distributions deferred at assign time (recipient identity not yet resolved by RNS). Drains automatically when the recipient announces. |

Permission bitmask reference — canonical in `src/hokora/constants.py` (the `PERM_*` constants). Summary:

```
0x0001 SEND_MESSAGES       0x0080 DELETE_OWN
0x0002 SEND_MEDIA          0x0100 DELETE_OTHERS
0x0004 CREATE_THREADS      0x0200 PIN_MESSAGES
0x0008 USE_MENTIONS        0x0400 MANAGE_CHANNELS
0x0010 MENTION_EVERYONE    0x0800 MANAGE_ROLES
0x0020 ADD_REACTIONS       0x1000 MANAGE_MEMBERS
0x0040 READ_HISTORY        0x2000 BAN_IDENTITIES
                           0x4000 VIEW_AUDIT_LOG
                           0x8000 EDIT_OWN
PERM_ALL = 0xFFFF
```

Built-in roles `node_owner` (0xFFFF, pos=1000), `channel_owner` (0xFFFF, pos=999), `member` and `everyone` (baseline) are seeded on first run and refreshed on every daemon start if their default permissions change in code.

For the resolution model, channel-override semantics, worked examples, and common patterns, see [13-permissions-and-roles.md](13-permissions-and-roles.md). For day-2 workflows (invite, onboard, remove, audit), see [14-member-management.md](14-member-management.md).

---

## `hokora identity`

| Command | Args | Effect |
|---|---|---|
| `create` | `name` | Writes `identities/custom_<name>` (mode 0o600) |
| `list` | — | Lists identity files; flags invalid ones |
| `export` | `name` `output_path` | Copies identity file to `output_path` |
| `import` | `input_path` `name` | Copies into `identities/custom_<name>` (0o600); validates format |

---

## `hokora invite`

| Command | Args | Notable flags | Effect |
|---|---|---|---|
| `create` | — | `--channel CHANNEL_ID`, `--max-uses INT`, `--expiry-hours INT` | Issues a token. Channel-scoped invites embed a public key hint. Prints composite `token:dest:pubkey:channel`. |
| `list` | — | `--channel CHANNEL_ID` | Shows token hashes, uses, status. |
| `revoke` | `token_hash` | — | Marks the invite revoked. |

Invite redemption happens in the TUI via `/invite redeem <token>`; see [TUI slash commands](#tui-slash-commands) below. The full lifecycle (token format, rate limits, revocation semantics) is in [14-member-management.md § Inviting a user](14-member-management.md#inviting-a-user).

---

## `hokora node`

| Command | Args | Effect |
|---|---|---|
| `status` | — | Prints node identity hash, channel count, message count |
| `config` | — | Dumps effective config (db_key masked) |
| `peers` | — | Reads the `Peer` table and shows federation-trusted peers with last-seen timestamps |

---

## `hokora mirror`

| Command | Args | Effect |
|---|---|---|
| `add` | `remote_dest_hash` `channel_id` | Adds a channel to the peer's mirror list. **Requires daemon restart to take effect.** |
| `remove` | `remote_dest_hash` `channel_id` | Removes a channel from the peer's mirror list |
| `list` | — | Shows all mirrors across peers |
| `trust` | `remote_dest_hash` | Marks the peer `federation_trusted=true` |
| `untrust` | `remote_dest_hash` | Marks the peer untrusted |

See [05-federation.md](05-federation.md) for handshake semantics and trust policy.

---

## `hokora seed`

Filesystem-gated CRUD on the RNS config's outbound seed entries. The TUI Network tab and this CLI share one atomic-write helper, so operators can mix the two paths.

| Command | Args | Notable flags | Effect |
|---|---|---|---|
| `list` | — | — | Lists seed entries currently in the RNS config. |
| `add` | `name` `target` | — | Appends a `[[<name>]]` interface block. `target` is `host:port` for TCP or a `.b32.i2p` address for I2P. Atomic write; prior file backed up to `config.prev`. |
| `remove` | `name` | — | Removes the named interface block. |
| `apply` | — | `--restart` | Prints the supervisor command appropriate for the deployment, or (with `--restart`) respawns the daemon via the `hokorad.argv` sibling file on bare-metal dev runs. |

Adding or removing a seed mutates the RNS config but does not signal the running daemon; restart to pick up the new transport. See [04-transport-setup.md § Managing seeds](04-transport-setup.md#managing-seeds--hokora-seed-recommended) for resolution order and topology-aware behaviour.

---

## `hokora config`

Configuration helpers that don't write state.

| Command | Args | Effect |
|---|---|---|
| `validate-rns` | — | Dry-run parse of the RNS config the daemon would load. Reports interface blocks, syntax errors, and unrecognised keys without restarting anything. |

---

## `hokora audit`

Inspect the local audit log.

| Command | Args | Notable flags | Effect |
|---|---|---|---|
| `list` | — | `--limit INT` (default 50), `--channel CHANNEL_ID`, `--json` | Prints recent audit-log entries newest first. JSON mode emits the full record including the `details` blob. |

The set of action types written today is limited (see [14-member-management.md § Reading the audit log](14-member-management.md#reading-the-audit-log)). The CLI is forward-compatible — it prints whatever rows the daemon has recorded.

---

## `hokora ban`

Persistent identity ban surface. Mutates `Identity.blocked` and writes `audit_log` rows; enforced at every daemon-side chokepoint a banned identity might touch (sync read, federation push receive + send, invite redemption, local message ingest). See [14-member-management.md § Banning an identity](14-member-management.md#banning-an-identity) for the full workflow.

| Command | Args | Notable flags | Effect |
|---|---|---|---|
| `add` | `IDENTITY_HASH` | `--reason TEXT` | Marks identity blocked, writes `identity_ban` audit row, drops any pending sealed-key distributions, and lists sealed channels needing key rotation. Refuses node-owner. |
| `remove` | `IDENTITY_HASH` | `--reason TEXT` | Clears block state, writes `identity_unban` audit row. No-op when target was not banned. |
| `list` | — | — | Prints every currently-banned identity with `blocked_at` age and `blocked_by` actor. |

`hokora ban add` does not auto-rotate sealed-channel keys — operator decision. The output of `add` lists the sealed channels and the `hokora channel rotate-key <id>` commands to run if you want to revoke the banned identity's access to future sealed-channel traffic.

---

## `hokora db`

All Alembic migrations are accessed through this group. Works from any cwd.

| Command | Args | Effect |
|---|---|---|
| `upgrade` | `--revision TARGET` (default `head`) | Apply migrations to target |
| `downgrade` | `--revision TARGET` (default `-1`) | Revert N revisions |
| `current` | — | Show active revision |
| `history` | — | List all revisions |
| `rebuild-fts` | — | Rebuild the FTS5 index from `messages` |
| `migrate-key` | `--to-file PATH` (default `$DATA_DIR/db_key`) | Move the SQLCipher master key from inline `db_key` to a separate 0o600 keyfile. Idempotent. Restart required. |

Migration application, downgrade caveats, and the `env.py` DML-commit invariant are documented in [10-database-operations.md § Applying migrations](10-database-operations.md#applying-migrations). DB-key handling, including the keyfile/inline split, is in [10-database-operations.md § SQLCipher key management](10-database-operations.md#sqlcipher-key-management).

---

## `hokora daemon`

| Command | Args | Notable flags | Effect |
|---|---|---|---|
| `start` | — | `--foreground` / `-f`, `--relay-only` | Starts daemon. Foreground for debugging; otherwise detaches and writes `hokorad.pid`. |
| `stop` | — | — | Reads `hokorad.pid`, sends SIGTERM, removes the PID file |
| `status` | — | — | Checks PID file and process health |

Prefer systemd (see [08-deployment-systemd.md](08-deployment-systemd.md)) for production. `hokora daemon start` is a convenience for development and single-user deployments.

---

## `hokorad` direct

The daemon entry point accepts a single runtime flag:

| Flag | Purpose |
|---|---|
| `--relay-only` | Run in relay mode (transport + LXMF only). Equivalent to `relay_only = true` in `hokora.toml`. |

Configuration is otherwise taken from `$HOKORA_CONFIG`, `$DATA_DIR/hokora.toml`, or the default location.

---

## TUI slash commands

All commands run inside the running TUI. Arguments are positional.

| Command | Args | Purpose |
|---|---|---|
| `/help` | — | Show all registered commands |
| `/local` | — | Auto-connect to a local daemon via PID-file discovery |
| `/connect` | `dest_hash [channel_id]` | Open an RNS Link to a remote node by destination hash. To add a TCP seed by `host:port`, use `hokora seed add` (see [04-transport-setup.md](04-transport-setup.md)) and restart the daemon. |
| `/disconnect` | — | Tear down all channel links and clear UI connection state |
| `/name` | `name` | Set display name |
| `/status` | `text` | Set status text |
| `/dm` | `peer_hash [message]` | Open a DM conversation; send `message` if supplied |
| `/dms` | — | Switch to the Conversations tab |
| `/search` | — | Open the search overlay on the Channels tab |
| `/thread` | `msg_hash` | Open a thread for the given parent message |
| `/members` | — | Show the current channel's members |
| `/invite` | `[create [N] \| redeem <code> \| list]` | Manage invites for the current channel |
| `/sync` | — | Re-sync the current channel's message history |
| `/upload` | `path` | Upload a media file to the current channel |
| `/download` | `filename [save_path]` | Fetch a media file from the daemon |
| `/clear` | — | Clear the current channel's message view |
| `/quit` | — | Exit the TUI (alias `/q`) |

### TUI keybindings

Global:

| Binding | Action |
|---|---|
| `F1`–`F6` or `Alt+1`–`Alt+6` | Switch to tab N |
| `Tab` / `Shift+Tab` | Next / previous tab |
| `Ctrl+S` | Search overlay (Channels tab) |
| `Ctrl+I` | Invite dialog |
| `Ctrl+A` | Trigger profile announce |
| `Ctrl+B` | Show bookmarks in status |
| `Ctrl+Q` | Quit |
| `?` | Toggle help overlay |
| `Esc` | Close modal / cancel mode |

Channels tab (when a message is focused and the compose line is empty):

| Binding | Action |
|---|---|
| `r` | Reply to the focused message |
| `e` | Edit the focused message (own messages only) |
| `d` | Delete the focused message |
| `t` | Open the thread for the focused message |
| `p` | Pin / unpin the focused message |
| `+` | React to the focused message |
| `f` | Download the focused message's media attachment |

Discovery tab:

| Binding | Action |
|---|---|
| `i` | Open the info panel for the focused node / peer / favourite |
| `b` | Toggle the bookmark on the focused entry |

---

## See also

- [02-configuration.md](02-configuration.md) for config fields referenced by CLI defaults.
- [06-sealed-channels.md](06-sealed-channels.md) for the sealed-channel lifecycle.
- [10-database-operations.md](10-database-operations.md) for migration procedures.
