# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""hokora channel: create, list, info, edit, delete."""

import asyncio
import re
import uuid

import click


def _run(coro):
    return asyncio.run(coro)


async def _resolve_channel_id(session, channel_ref: str) -> str:
    """Resolve a user-provided ``channel_ref`` to a canonical channel ID.

    Accepts either a 16-char hex ID (returned as-is) or a channel name with
    an optional leading ``#``. Falls back to the raw input so the caller's
    ``repo.get_by_id`` still produces a useful "not found" message.
    """
    ref = (channel_ref or "").lstrip("#")
    # A 16-char hex string is treated as an ID — matches how UUID-hex slices
    # are produced by ``hokora channel create``.
    if len(ref) == 16 and re.fullmatch(r"[0-9a-fA-F]{16}", ref):
        return ref

    from hokora.db.queries import ChannelRepo

    for ch in await ChannelRepo(session).list_all():
        if ch.name == ref:
            return ch.id
    # Unresolved — let the caller surface "not found" with the original input.
    return ref


@click.group("channel")
def channel_group():
    """Manage channels."""
    pass


@channel_group.command("create")
@click.argument("name")
@click.option("--description", "-d", default="")
@click.option(
    "--access", type=click.Choice(["public", "write_restricted", "private"]), default="public"
)
@click.option("--category", default=None)
@click.option("--sealed", is_flag=True, default=False, help="Create as sealed (encrypted) channel")
def create(name, description, access, category, sealed):
    """Create a new channel."""
    _run(_create_channel(name, description, access, category, sealed))


async def _create_channel(name, description, access, category_id, sealed=False):
    from hokora.constants import MAX_CHANNEL_NAME_LENGTH, MAX_CHANNEL_DESCRIPTION_LENGTH
    from hokora.db.models import Channel
    from hokora.db.queries import ChannelRepo
    from hokora.cli._helpers import db_session

    name = name.strip()
    if not name:
        click.echo("Error: Channel name cannot be empty.")
        return
    if len(name) > MAX_CHANNEL_NAME_LENGTH:
        click.echo(f"Error: Channel name exceeds {MAX_CHANNEL_NAME_LENGTH} characters.")
        return
    if re.search(r"[<>&\"']", name):
        click.echo("Error: Channel name contains invalid characters (<, >, &, \", ').")
        return
    if len(description) > MAX_CHANNEL_DESCRIPTION_LENGTH:
        click.echo(f"Error: Description exceeds {MAX_CHANNEL_DESCRIPTION_LENGTH} characters.")
        return

    async with db_session() as session:
        repo = ChannelRepo(session)
        existing = await repo.list_all()
        if any(ch.name == name for ch in existing):
            click.echo(f"Error: A channel named '{name}' already exists.")
            return
        channel = Channel(
            id=uuid.uuid4().hex[:16],
            name=name,
            description=description,
            access_mode=access,
            category_id=category_id,
            sealed=sealed,
        )
        await repo.create(channel)
        seal_label = ""
        if sealed:
            # Generate + persist the initial group key immediately so the
            # channel is usable from t=0. Previously this was deferred to
            # daemon restart, leaving a window where messages would land
            # plaintext in a channel marked sealed (invariant violation).
            try:
                await _provision_sealed_key(session, channel.id)
                seal_label = " [SEALED — key provisioned]"
            except Exception as exc:
                seal_label = f" [SEALED — key provisioning FAILED: {exc}]"
        click.echo(f"Created channel #{name} ({channel.id}) [{access}]{seal_label}")


@channel_group.command("list")
def list_channels():
    """List all channels."""
    _run(_list_channels())


async def _list_channels():
    from hokora.db.queries import ChannelRepo
    from hokora.cli._helpers import db_session

    async with db_session() as session:
        repo = ChannelRepo(session)
        channels = await repo.list_all()
        if not channels:
            click.echo("No channels found.")
            return
        for ch in channels:
            seal_label = " [SEALED]" if ch.sealed else ""
            click.echo(
                f"  #{ch.name:<20} id={ch.id}  mode={ch.access_mode}  seq={ch.latest_seq}{seal_label}"
            )


@channel_group.command("info")
@click.argument("channel_id")
def info(channel_id):
    """Show channel details."""
    _run(_channel_info(channel_id))


async def _channel_info(channel_id):
    from hokora.db.queries import ChannelRepo
    from hokora.cli._helpers import db_session

    async with db_session() as session:
        channel_id = await _resolve_channel_id(session, channel_id)
        repo = ChannelRepo(session)
        ch = await repo.get_by_id(channel_id)
        if not ch:
            click.echo(f"Channel {channel_id} not found.")
            return
        click.echo(f"Channel: #{ch.name}")
        click.echo(f"  ID:          {ch.id}")
        click.echo(f"  Description: {ch.description}")
        click.echo(f"  Access:      {ch.access_mode}")
        click.echo(f"  Category:    {ch.category_id or 'none'}")
        click.echo(f"  Latest Seq:  {ch.latest_seq}")
        click.echo(f"  Identity:    {ch.identity_hash or 'not assigned'}")
        click.echo(f"  Slowmode:    {ch.slowmode}s" if ch.slowmode else "  Slowmode:    off")
        click.echo(f"  Sealed:      {'yes' if ch.sealed else 'no'}")


@channel_group.command("edit")
@click.argument("channel_id")
@click.option("--name", default=None)
@click.option("--description", default=None)
@click.option(
    "--access", type=click.Choice(["public", "write_restricted", "private"]), default=None
)
@click.option("--slowmode", type=int, default=None)
def edit(channel_id, name, description, access, slowmode):
    """Edit channel settings."""
    _run(_edit_channel(channel_id, name, description, access, slowmode))


async def _edit_channel(channel_id, name, description, access, slowmode):
    from hokora.db.queries import ChannelRepo
    from hokora.cli._helpers import db_session

    kwargs = {}
    if name is not None:
        if re.search(r"[<>&\"']", name):
            click.echo("Error: Channel name contains invalid characters (<, >, &, \", ').")
            return
        kwargs["name"] = name
    if description is not None:
        from hokora.constants import MAX_CHANNEL_DESCRIPTION_LENGTH

        if len(description) > MAX_CHANNEL_DESCRIPTION_LENGTH:
            click.echo(f"Error: Description exceeds {MAX_CHANNEL_DESCRIPTION_LENGTH} characters.")
            return
        kwargs["description"] = description
    if access is not None:
        kwargs["access_mode"] = access
    if slowmode is not None:
        kwargs["slowmode"] = slowmode

    if not kwargs:
        click.echo("No changes specified.")
        return

    async with db_session() as session:
        channel_id = await _resolve_channel_id(session, channel_id)
        repo = ChannelRepo(session)
        ch = await repo.update_channel(channel_id, **kwargs)
        if ch:
            click.echo(f"Updated channel #{ch.name}")
        else:
            click.echo(f"Channel {channel_id} not found.")


@channel_group.command("delete")
@click.argument("channel_id")
@click.confirmation_option(prompt="Are you sure you want to delete this channel?")
def delete(channel_id):
    """Delete a channel."""
    _run(_delete_channel(channel_id))


async def _delete_channel(channel_id):
    from hokora.db.queries import ChannelRepo
    from hokora.cli._helpers import db_session

    async with db_session() as session:
        channel_id = await _resolve_channel_id(session, channel_id)
        repo = ChannelRepo(session)
        if await repo.delete_channel(channel_id):
            click.echo(f"Deleted channel {channel_id}")
        else:
            click.echo(f"Channel {channel_id} not found.")


@channel_group.command("seal")
@click.argument("channel_id")
def seal(channel_id):
    """Seal a channel (enable end-to-end encryption)."""
    _run(_seal_channel(channel_id, True))


@channel_group.command("unseal")
@click.argument("channel_id")
@click.confirmation_option(prompt="Unseal will remove encryption. Are you sure?")
def unseal(channel_id):
    """Unseal a channel (disable end-to-end encryption)."""
    _run(_seal_channel(channel_id, False))


@channel_group.command("rotate-key")
@click.argument("channel_id")
def rotate_key(channel_id):
    """Rotate the encryption key for a sealed channel."""
    _run(_rotate_channel_key(channel_id))


@channel_group.command("rotate-rns-key")
@click.argument("channel_id")
@click.option(
    "--yes",
    is_flag=True,
    default=False,
    help="Skip confirmation prompt.",
)
def rotate_rns_key(channel_id, yes):
    """Rotate the RNS identity key for a channel.

    Generates a new RNS identity, emits a dual-signed key-rotation announce via
    the OLD destination so federated peers can verify the handover, then swaps
    the on-disk identity file and updates the channel's identity_hash +
    destination_hash in the DB. Federation peers accept signatures from either
    old or new identity for a 48h grace window. The operator must restart the
    daemon after this command so the new destination becomes served.
    """
    if not yes:
        click.confirm(
            f"Rotate RNS identity key for channel {channel_id}? "
            "The daemon must be restarted afterwards.",
            abort=True,
        )
    _run(_rotate_channel_rns_key(channel_id))


async def _rotate_channel_rns_key(channel_id):
    import binascii
    import os
    import time
    from pathlib import Path

    import RNS

    from hokora.cli._helpers import db_session
    from hokora.config import load_config
    from hokora.constants import DESTINATION_ASPECT
    from hokora.db.models import Channel
    from hokora.federation.key_rotation import (
        KEY_ROTATION_GRACE_PERIOD,
        KeyRotationManager,
    )
    from hokora.security.fs import write_identity_secure
    from sqlalchemy import select

    config = load_config()

    # Open DB session first — cheap, fails fast if the channel row is missing.
    # Also resolves a channel name to its canonical ID.
    async with db_session() as session:
        channel_id = await _resolve_channel_id(session, channel_id)
        row = await session.execute(select(Channel).where(Channel.id == channel_id))
        channel = row.scalar_one_or_none()
        if channel is None:
            click.echo(f"Error: Channel {channel_id} not found in DB.")
            return
        channel_name = channel.name
        old_identity_hash = channel.identity_hash

    id_path = config.identity_dir / f"channel_{channel_id}"
    if not id_path.exists():
        click.echo(
            f"Error: Channel {channel_id} has not been registered with the "
            f"network yet (no identity file at {id_path}). Start the daemon "
            f"at least once so the channel's RNS identity is provisioned, "
            f"then retry rotation."
        )
        return

    # Initialise RNS so we can instantiate the old destination and announce
    # through the shared instance (attaches to the daemon's socket if it's
    # running, otherwise briefly owns it). The identity file is read *after*
    # Reticulum is up so crypto primitives are already configured.
    try:
        RNS.Reticulum(configdir=str(config.rns_config_dir) if config.rns_config_dir else None)
    except Exception as e:
        click.echo(f"Error: failed to initialise RNS: {e}")
        return

    old_identity = RNS.Identity.from_file(str(id_path))
    new_identity = RNS.Identity()

    old_destination = RNS.Destination(
        old_identity,
        RNS.Destination.IN,
        RNS.Destination.SINGLE,
        DESTINATION_ASPECT,
        channel_id,
    )
    new_destination_probe = RNS.Destination(
        new_identity,
        RNS.Destination.IN,
        RNS.Destination.SINGLE,
        DESTINATION_ASPECT,
        channel_id,
    )
    new_dest_hash_hex = binascii.hexlify(new_destination_probe.hash).decode()

    # Send dual-signed announce. The in-memory grace-tracker inside this
    # local KeyRotationManager instance is discarded on process exit — the
    # durable grace state lives on the channel row (see below).
    mgr = KeyRotationManager()
    mgr.initiate_rotation(channel_id, old_identity, new_identity, old_destination)

    # Atomic identity-file rollover:
    # 1. write new identity to a sibling `.next` path at 0o600,
    # 2. rename the old file to a timestamped backup,
    # 3. rename `.next` into place.
    next_path = id_path.with_name(id_path.name + ".next")
    backup_path = id_path.with_name(id_path.name + f".pre-rotation-{int(time.time())}")
    write_identity_secure(new_identity, next_path)
    os.replace(id_path, backup_path)
    os.replace(next_path, id_path)

    # Persist the rotation state on the channel row so the daemon can enforce
    # the 48h federation signature grace window across restarts.
    grace_end = time.time() + KEY_ROTATION_GRACE_PERIOD
    async with db_session() as session:
        row = await session.execute(select(Channel).where(Channel.id == channel_id))
        channel = row.scalar_one_or_none()
        if channel is None:
            click.echo(f"Error: Channel {channel_id} vanished mid-rotation.")
            return
        channel.identity_hash = new_identity.hexhash
        channel.destination_hash = new_dest_hash_hex
        channel.rotation_old_hash = old_identity_hash
        channel.rotation_grace_end = grace_end
        await session.commit()

    click.echo(
        f"Rotated RNS identity for #{channel_name}: "
        f"{old_identity_hash[:12]}… → {new_identity.hexhash[:12]}…\n"
        f"  Old identity file backed up to: {Path(backup_path).name}\n"
        f"  Grace window ends: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(grace_end))}\n"
        f"  NEXT STEP: restart the daemon so it serves the new destination."
    )


async def _rotate_channel_key(channel_id):
    from hokora.db.models import Channel
    from hokora.security.sealed import SealedChannelManager
    from hokora.db.queries import RoleRepo
    from hokora.cli._helpers import db_session
    from sqlalchemy import select
    import RNS

    from hokora.config import load_config

    config = load_config()
    identity_path = config.identity_dir / "node_identity"
    node_identity = RNS.Identity.from_file(str(identity_path))

    async with db_session() as session:
        channel_id = await _resolve_channel_id(session, channel_id)
        result = await session.execute(select(Channel).where(Channel.id == channel_id))
        ch = result.scalar_one_or_none()
        if not ch:
            click.echo(f"Channel {channel_id} not found.")
            return
        if not ch.sealed:
            click.echo(f"Channel #{ch.name} is not sealed.")
            return

        mgr = SealedChannelManager()
        await mgr.load_keys(session, node_identity)

        if not mgr.get_key(channel_id):
            click.echo(
                f"No existing key for channel #{ch.name}. Generate one by sealing the channel."
            )
            return

        role_repo = RoleRepo(session)
        members = await role_repo.get_channel_member_hashes(channel_id)

        old_epoch = mgr.get_epoch(channel_id)
        mgr.rotate_key(channel_id)
        new_epoch = mgr.get_epoch(channel_id)
        await mgr.persist_key(session, channel_id, node_identity)

        click.echo(
            f"Rotated key for #{ch.name}: epoch {old_epoch} → {new_epoch} ({len(members)} members)"
        )


async def _seal_channel(channel_id, seal):
    from hokora.db.models import Channel, SealedKey
    from hokora.cli._helpers import db_session
    from sqlalchemy import select, delete

    async with db_session() as session:
        channel_id = await _resolve_channel_id(session, channel_id)
        result = await session.execute(select(Channel).where(Channel.id == channel_id))
        ch = result.scalar_one_or_none()
        if not ch:
            click.echo(f"Channel {channel_id} not found.")
            return

        ch.sealed = seal
        if seal:
            # Provision the initial key now so the channel is encrypt-ready
            # before the next daemon restart. Idempotent — startup bootstrap
            # would also cover this, but doing it here closes the window.
            try:
                await _provision_sealed_key(session, channel_id)
                click.echo(f"Sealed channel #{ch.name}. Initial key provisioned.")
            except Exception as exc:
                click.echo(
                    f"Sealed channel #{ch.name}, but key provisioning failed: {exc}. "
                    f"Will retry on next daemon restart."
                )
        else:
            # Delete sealed keys
            await session.execute(delete(SealedKey).where(SealedKey.channel_id == channel_id))
            click.echo(f"Unsealed channel #{ch.name}. Keys deleted.")


async def _provision_sealed_key(session, channel_id: str) -> None:
    """Generate a group key for a sealed channel and persist it for the
    node owner. Used by both ``_create_channel`` (sealed=True) and
    ``_seal_channel``. Reads node identity from the configured identity_dir.
    """
    import RNS
    from hokora.config import load_config
    from hokora.security.sealed import SealedChannelManager

    cfg = load_config()
    id_path = cfg.identity_dir / "node_identity"
    if not id_path.exists():
        raise FileNotFoundError(f"Node identity missing at {id_path}; run 'hokora init' first")
    node_identity = RNS.Identity.from_file(str(id_path))
    mgr = SealedChannelManager()
    mgr.generate_key(channel_id)
    await mgr.persist_key(session, channel_id, node_identity)


_PERM_NAMES = {
    "SEND_MESSAGES": 0x0001,
    "SEND_MEDIA": 0x0002,
    "CREATE_THREADS": 0x0004,
    "USE_MENTIONS": 0x0008,
    "MENTION_EVERYONE": 0x0010,
    "ADD_REACTIONS": 0x0020,
    "READ_HISTORY": 0x0040,
    "DELETE_OWN": 0x0080,
    "DELETE_OTHERS": 0x0100,
    "PIN_MESSAGES": 0x0200,
    "MANAGE_CHANNELS": 0x0400,
    "MANAGE_ROLES": 0x0800,
    "MANAGE_MEMBERS": 0x1000,
    "BAN_IDENTITIES": 0x2000,
    "VIEW_AUDIT_LOG": 0x4000,
    "EDIT_OWN": 0x8000,
}


def _parse_perm_bitmask(perm_csv: str) -> int:
    """Parse a comma-separated list of permission names into a bitmask.

    Raises ``click.BadParameter`` on unknown names so bad input surfaces
    immediately rather than silently collapsing to 0.
    """
    if not perm_csv:
        return 0
    total = 0
    for name in (p.strip().upper() for p in perm_csv.split(",") if p.strip()):
        if name not in _PERM_NAMES:
            raise click.BadParameter(
                f"Unknown permission {name!r}. Valid names: " + ", ".join(sorted(_PERM_NAMES))
            )
        total |= _PERM_NAMES[name]
    return total


@channel_group.command("override")
@click.argument("channel_id")
@click.option("--role", "role_ref", required=True, help="Role name or role ID")
@click.option("--allow", default="", help="Comma-separated permission names to explicitly allow")
@click.option("--deny", default="", help="Comma-separated permission names to explicitly deny")
def override(channel_id, role_ref, allow, deny):
    """Set a per-channel permission override for a role.

    Deny bits override allow bits and the role's baseline. Use this to make
    a write_restricted ``announcements`` channel truly read-only for the
    member role:

        hokora channel override <id> --role member --deny SEND_MESSAGES,SEND_MEDIA
    """
    _run(_set_channel_override(channel_id, role_ref, allow, deny))


async def _set_channel_override(channel_id, role_ref, allow_csv, deny_csv):
    from hokora.db.models import Channel, ChannelOverride, Role
    from hokora.cli._helpers import db_session
    from sqlalchemy import select

    allow_bits = _parse_perm_bitmask(allow_csv)
    deny_bits = _parse_perm_bitmask(deny_csv)

    async with db_session() as session:
        channel_id = await _resolve_channel_id(session, channel_id)
        ch = (
            await session.execute(select(Channel).where(Channel.id == channel_id))
        ).scalar_one_or_none()
        if ch is None:
            click.echo(f"Channel {channel_id} not found.")
            return

        role = (await session.execute(select(Role).where(Role.id == role_ref))).scalar_one_or_none()
        if role is None:
            role = (
                await session.execute(select(Role).where(Role.name == role_ref))
            ).scalar_one_or_none()
        if role is None:
            click.echo(f"Role {role_ref!r} not found.")
            return

        existing = (
            await session.execute(
                select(ChannelOverride)
                .where(ChannelOverride.channel_id == channel_id)
                .where(ChannelOverride.role_id == role.id)
            )
        ).scalar_one_or_none()

        if existing is None:
            session.add(
                ChannelOverride(
                    channel_id=channel_id,
                    role_id=role.id,
                    allow=allow_bits,
                    deny=deny_bits,
                )
            )
            action = "created"
        else:
            existing.allow = allow_bits
            existing.deny = deny_bits
            action = "updated"

        click.echo(
            f"Override {action}: channel=#{ch.name} role={role.name} "
            f"allow=0x{allow_bits:04x} deny=0x{deny_bits:04x}"
        )
