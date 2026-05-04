# 13 — Permissions and Roles

This runbook explains Hokora's permission model: what flags exist, what built-in roles grant, how the resolver combines them, and how an operator changes any of it. Source of truth for the bits is `src/hokora/constants.py`; for resolution logic, `src/hokora/security/permissions.py`; for built-in role defaults, `src/hokora/security/roles.py`.

## Concepts

| Term | Meaning |
|---|---|
| **Identity** | An RNS identity hash. Identifies a user across the mesh. |
| **Role** | A named bundle of permission flags, with a hex colour, position, and mentionable flag. Stored in the `roles` table. |
| **Role assignment** | A `(role, identity, channel?)` row in the `role_assignments` table. Assignments may be **node-scoped** (`channel = NULL`) or **channel-scoped**. |
| **Channel override** | A `(channel, role)` row in `channel_overrides` carrying `allow` and `deny` bitmasks. Overrides specialise a role's permissions for one channel. |
| **Permission flag** | A single bit in the 16-bit permission bitfield. The full set is `PERM_ALL = 0xFFFF`. |

## Permission flags

Every permission is a single bit. Combine with bitwise OR. The full set fits in a 16-bit integer.

| Flag | Bit | Operator meaning |
|---|---|---|
| `PERM_SEND_MESSAGES` | `0x0001` | Post text messages |
| `PERM_SEND_MEDIA` | `0x0002` | Upload media (images, files) |
| `PERM_CREATE_THREADS` | `0x0004` | Open thread replies on a parent message |
| `PERM_USE_MENTIONS` | `0x0008` | Mention specific users in a message |
| `PERM_MENTION_EVERYONE` | `0x0010` | Use `@everyone` to broadcast a notification |
| `PERM_ADD_REACTIONS` | `0x0020` | React to messages with emoji |
| `PERM_READ_HISTORY` | `0x0040` | Read prior messages in the channel |
| `PERM_DELETE_OWN` | `0x0080` | Delete one's own messages |
| `PERM_DELETE_OTHERS` | `0x0100` | Delete other users' messages (moderation) |
| `PERM_PIN_MESSAGES` | `0x0200` | Pin / unpin messages in the channel |
| `PERM_MANAGE_CHANNELS` | `0x0400` | Edit channel metadata, slowmode, access mode |
| `PERM_MANAGE_ROLES` | `0x0800` | Create, edit, assign, revoke roles |
| `PERM_MANAGE_MEMBERS` | `0x1000` | Manage member-level metadata |
| `PERM_BAN_IDENTITIES` | `0x2000` | Reserved. Banning is CLI-only today via `hokora ban`; no protocol surface checks this bit. See [14-member-management.md § Banning an identity](14-member-management.md#banning-an-identity). |
| `PERM_VIEW_AUDIT_LOG` | `0x4000` | Read the audit log via `hokora audit list` |
| `PERM_EDIT_OWN` | `0x8000` | Edit one's own messages |

`PERM_ALL = 0xFFFF` is every flag set. `PERM_EVERYONE_DEFAULT` (the baseline assigned to `@everyone` and `member`) is `0x80EF` — `SEND_MESSAGES | SEND_MEDIA | CREATE_THREADS | USE_MENTIONS | ADD_REACTIONS | READ_HISTORY | DELETE_OWN | EDIT_OWN`.

The CLI accepts both decimal and `0x...` hex when creating a role:

```bash
hokora role create publisher --permissions 0x0003     # SEND_MESSAGES | SEND_MEDIA
hokora role create moderator --permissions 0x01F0     # DELETE_OTHERS | PIN_MESSAGES
                                                       # | MANAGE_CHANNELS | MANAGE_ROLES
                                                       # | MANAGE_MEMBERS
```

## Built-in roles

Four roles are seeded on first run and refreshed on every daemon restart. If the default permission mask changes in code, a restart propagates the new bits to existing nodes.

| Role | Default permissions | Position | Notes |
|---|---|---|---|
| `node_owner` | `PERM_ALL` (`0xFFFF`) | 1000 | Held only by the identity that ran `hokora init`. Implicit — not stored as a role assignment; the resolver short-circuits on `identity_hash == node_owner_hash`. |
| `channel_owner` | `PERM_ALL` (`0xFFFF`) | 999 | Held by the creator of a channel. The resolver short-circuits to `PERM_ALL` if any of the identity's roles for the channel is `channel_owner`. |
| `member` | `PERM_EVERYONE_DEFAULT` (`0x80EF`) | 1 | Apply explicitly with `hokora role assign member <hash> --channel <id>`. Required as the carrier for sealed-channel key distribution — sealed-key envelopes are pushed on assignment of any channel-scoped role, and `member` is the canonical default. |
| `everyone` | `PERM_EVERYONE_DEFAULT` (`0x80EF`) | 0 | Implicit baseline for *every* identity, including identities with no role assignments. The resolver always starts from this floor before adding role permissions. |

You cannot delete a built-in role. You *can* change `everyone`'s permissions — the resolver re-fetches `everyone` on every check, so changes take effect on the next request. To strip the default media-upload right across the whole node, for example:

```bash
hokora role list                              # find @everyone's id
sqlcipher $DATA_DIR/hokora.db \
    "PRAGMA key='$DB_KEY'; \
     UPDATE roles SET permissions = permissions & ~0x0002 \
     WHERE name='everyone';"
```

There is no CLI to edit `@everyone` directly today; use the SQL form above or a channel-scoped override (see [Channel overrides](#channel-overrides)).

## Resolution model

Permission checks run through `PermissionResolver.get_effective_permissions`. The resolver walks five layers and returns a single 16-bit bitfield. Each layer's effect is summarised below, in priority order.

### Layer 1 — Node owner

If the identity hash matches the node's owner hash, return `PERM_ALL`. The check is constant-time and unconditional. Node ownership is set at `hokora init` time and stored in the daemon's identity file, not as a role assignment.

### Layer 2 — Channel owner

Fetch the identity's roles for the channel. If any role is named `channel_owner`, return `PERM_ALL`. The owner of a channel has every permission *for that channel*, regardless of node-level role state.

### Layer 3 — Role union

Start with the `@everyone` baseline. For every role assigned to the identity (node-scoped or channel-scoped), bitwise-OR the role's permissions onto the running mask:

```
perms = everyone.permissions
for role in identity.roles:
    perms |= role.permissions
```

Roles are additive. There is no "deny" at the role level itself — denial happens in layer 4.

### Layer 4 — Channel overrides

Fetch every `channel_override` row for the channel where the role is one the identity holds. Aggregate the `allow` and `deny` bitmasks across all matching overrides, then apply once:

```
perms = (perms | all_allow) & ~all_deny
```

Overrides are **order-independent**. Within a single check, every applicable override's `allow` bits are ORed together, and every applicable override's `deny` bits are ORed together; the result is then `(perms | all_allow) & ~all_deny`. **Deny beats allow** when the same bit is set on both sides — clearing happens last.

This means an override on the `everyone` role that denies `SEND_MESSAGES`, plus an override on the `publisher` role that allows `SEND_MESSAGES`, **denies the bit for users with the `publisher` role** — because `deny` from one applicable override is OR'd into the aggregate deny mask. To let `publisher` post in a channel where `everyone` is silenced, do not deny on `everyone`; set the channel's access mode to `write_restricted` instead and grant the `publisher` role its own `SEND_MESSAGES` allow.

### Layer 5 — Write-restricted floor

If the channel's `access_mode == write_restricted` and the identity has *no* roles for that channel, the resolver clears `SEND_MESSAGES` and `SEND_MEDIA` from the result regardless of the `everyone` baseline. Identities with at least one role for the channel are unaffected by this layer; they fall back to layers 1-4.

### Final value

The resolver returns the bitfield. A specific permission check (`resolve(...)`) is `bool(effective_perms & required_permission)`.

## Channel overrides

Overrides are how operators specialise a role's permissions for one channel without touching the role's global permissions. Each override carries two bitmasks:

| Mask | Effect |
|---|---|
| `allow` | Bits added to the role's permissions for this channel. |
| `deny`  | Bits removed from the role's permissions for this channel. |

Set with `hokora channel override`:

```bash
# Strip @everyone's send rights on #announcements
hokora channel override #announcements --role everyone --deny 0x0003

# Let publisher post text + media on #announcements
hokora channel override #announcements --role publisher --allow 0x0003

# Remove an override (no flags required)
hokora channel override #announcements --role publisher
```

Per-role overrides accumulate. Re-issuing `--allow` / `--deny` for the same `(channel, role)` pair upserts the row. The aggregate-allow / aggregate-deny semantics in layer 4 mean operators should design overrides as additive grants rather than corrective denials wherever possible.

## Worked examples

### Make `#announcements` write-restricted, only `publisher` can post

```bash
# 1. Set the channel access mode
hokora channel edit #announcements --access write_restricted

# 2. Create the publisher role
hokora role create publisher --permissions 0x0003 --colour "#FF8800"

# 3. Override on the channel: publisher gets explicit send rights
hokora channel override #announcements --role publisher --allow 0x0003

# 4. Assign publisher to the user(s) you want posting
hokora role assign publisher <identity_hash> --channel <announcements_id>
```

A user without the `publisher` role on `#announcements` falls into layer 5 (no roles → write-restricted floor strips send bits). A user with `publisher` falls into layer 4 with `allow=0x0003`; layer 5 does not apply because they have a role.

### Let `member` post text but not media on `#general`

```bash
# Override on the channel: member loses media-upload bit
hokora channel override #general --role member --deny 0x0002
```

Identities assigned the `member` role on `#general` keep `SEND_MESSAGES` (from `everyone` baseline + `member` permissions) but lose `SEND_MEDIA` via the override's `deny` mask. Other channels are unaffected.

### Restrict one specific identity on one channel

There is no per-identity override today; overrides are role-keyed. The pattern is:

```bash
# 1. Create a single-identity role with no permissions
hokora role create restricted --permissions 0x0000

# 2. Override on the channel: restricted role loses send + react bits
hokora channel override #general --role restricted --deny 0x0023

# 3. Assign the restricted role to the identity, channel-scoped
hokora role assign restricted <identity_hash> --channel <general_id>
```

The restricted role contributes nothing in layer 3 (`permissions = 0`), but the layer-4 deny mask applies because the identity holds the role. Their effective permissions become `everyone.permissions & ~0x0023` for that channel.

### Sealed channel: assign role and auto-distribute the key

```bash
# Sealed channel pre-exists; the operator wants to onboard a new member.
hokora role assign member <identity_hash> --channel <sealed_channel_id>
```

`hokora role assign` on a sealed channel does two things: writes the `RoleAssignment` row and envelope-encrypts the channel's group key for the recipient's RNS public key. If the recipient's RNS identity is not yet known to the daemon (no announce seen), the distribution is queued in `pending_sealed_distributions` and drains when the recipient announces. Inspect the queue:

```bash
hokora role pending --channel <sealed_channel_id>
```

See [06-sealed-channels.md § Granting access](06-sealed-channels.md#granting-access) for the full sealed-channel lifecycle.

## Common patterns

| Goal | Pattern |
|---|---|
| Read-only public announcements channel | `channel edit --access write_restricted` + role + override per [Worked examples](#make-announcements-write-restricted-only-publisher-can-post). |
| Mute one user across all channels | Create a no-permission role, override every channel to deny that role's send bits, assign it node-scoped. |
| Promote a moderator | `role create moderator --permissions 0x4FE0` (delete-others + pin + manage-channels + manage-roles + manage-members + audit) and assign node-scoped. |
| Quiet a chatty role on one channel | `channel override <channel> --role <name> --deny 0x0001`. |
| Demote a user | `role revoke <role> <identity>` — node-scoped or channel-scoped, mirrors the assign call. |
| Audit an identity's effective permissions | No CLI today. Read `roles`, `role_assignments`, `channel_overrides` directly via SQLCipher; replay the resolver mentally. A `hokora role effective <hash> --channel <id>` command is on the roadmap. |

## Pitfalls

- **Aggregate-deny is order-independent.** Adding an `allow` override on a higher-priority role does not "win over" a `deny` override on a lower-priority role. Both contribute to the same aggregate deny mask. Design grants as `allow` on a role no one else holds, not as competing allow/deny on shared roles.
- **Built-in role permissions are refreshed at restart.** If you tune `@everyone` via raw SQL, the resolver picks up the change on the next request, but a daemon restart will *re-apply the code-level default* if `is_builtin = true` and the row's permissions differ from the constants. To make `@everyone` changes durable, edit `PERM_EVERYONE_DEFAULT` in `src/hokora/constants.py` and rebuild, or use channel overrides instead.
- **"No role" is not "no permissions".** The resolver always starts from the `@everyone` baseline. An identity with zero role assignments still gets `PERM_EVERYONE_DEFAULT` minus any layer-5 stripping. To deny a default permission everywhere, narrow `@everyone` itself.
- **Channel-owner short-circuit ignores layers 3-5.** A `channel_owner` role assignment grants `PERM_ALL` on the channel before any override or write-restricted check runs. Reserve `channel_owner` for trusted operators; do not use it as a moderator role.
- **Node-scoped vs. channel-scoped role assignments are disjoint.** Assigning `member` node-scoped does not grant `member` permissions on a specific channel for the override pass; channel-keyed override lookups only consult channel-scoped role assignments. Assign at the channel scope when an override is involved.

## See also

- [03-cli-reference.md § `hokora role`](03-cli-reference.md#hokora-role) — full CLI surface for role CRUD and assignment.
- [03-cli-reference.md § `hokora channel`](03-cli-reference.md#hokora-channel) — channel access mode, slowmode, override CLI.
- [06-sealed-channels.md](06-sealed-channels.md) — sealed-channel access, sealed-key distribution on role assign.
- [14-member-management.md](14-member-management.md) — invite, onboarding, banning, audit log.
- `src/hokora/constants.py` — canonical permission flag values.
- `src/hokora/security/permissions.py` — resolver implementation.
- `src/hokora/security/roles.py` — built-in role defaults.
