# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""hokora role: create, assign, revoke, list."""

import asyncio

import click


def _run(coro):
    return asyncio.run(coro)


@click.group("role")
def role_group():
    """Manage roles and permissions."""
    pass


def _parse_permissions(value: str) -> int:
    """Parse permissions as decimal or hex (0x prefix)."""
    value = value.strip()
    if value.startswith("0x") or value.startswith("0X"):
        return int(value, 16)
    return int(value)


@role_group.command("create")
@click.argument("name")
@click.option(
    "--permissions", "-p", default="0", help="Permission bitfield (decimal or hex with 0x prefix)"
)
@click.option("--position", type=int, default=1)
@click.option("--colour", default="#FFFFFF", help="Role colour hex (e.g. #FF0000)")
@click.option("--mentionable", is_flag=True, default=False, help="Whether role is mentionable")
def create(name, permissions, position, colour, mentionable):
    """Create a new role."""
    try:
        perm_int = _parse_permissions(permissions)
    except ValueError:
        click.echo(f"Invalid permissions value: {permissions}")
        return
    if perm_int < 0:
        click.echo("Error: Permissions value must be non-negative.")
        return
    _run(_create_role(name, perm_int, position, colour, mentionable))


async def _create_role(name, permissions, position, colour, mentionable):
    from hokora.security.roles import RoleManager
    from hokora.cli._helpers import db_session

    async with db_session() as session:
        mgr = RoleManager()
        try:
            role = await mgr.create_role(session, name, permissions, position)
        except Exception as e:
            if "UNIQUE" in str(e).upper():
                click.echo(f"Error: A role named '{name}' already exists.")
                return
            raise
        role.colour = colour
        role.mentionable = mentionable
        await session.flush()
        click.echo(
            f"Created role '{role.name}' (id={role.id}, perms={role.permissions:#06x}, colour={role.colour})"
        )


@role_group.command("assign")
@click.argument("role_name")
@click.argument("identity_hash")
@click.option("--channel", default=None)
def assign(role_name, identity_hash, channel):
    """Assign a role to an identity."""
    _run(_assign_role(role_name, identity_hash, channel))


async def _assign_role(role_name, identity_hash, channel_id):
    from hokora.db.queries import RoleRepo, IdentityRepo
    from hokora.db.models import Channel, SealedKey
    from hokora.security.roles import RoleManager
    from hokora.cli._helpers import db_session
    from sqlalchemy import select

    # Initialise RNS so ``security.sealed.load_peer_rns_identity`` can recall
    # the recipient's full identity from ``Identity.known_destinations``.
    # Without this, the CLI process has an empty path cache and every
    # sealed-key distribution defers — even when the daemon has a perfectly
    # good live cache. With ``share_instance = Yes`` in the RNS config (the
    # default for community-node deployments) we attach as a client of the
    # running daemon's RNS instance and inherit its disk-persisted path
    # state; ``request_path`` calls forward to the daemon for live lookups.
    import RNS
    from hokora.config import load_config

    if not getattr(RNS.Reticulum, "_hokora_cli_initialised", False):
        try:
            cfg_outer = load_config()
            RNS.Reticulum(configdir=str(cfg_outer.rns_config_dir))
            RNS.Reticulum._hokora_cli_initialised = True
        except Exception:
            # Best-effort: if RNS init fails (e.g. daemon down, no rns
            # config), the deferred path will still produce an honest error
            # rather than silent corruption.
            pass

    async with db_session() as session:
        repo = RoleRepo(session)
        role = await repo.get_by_name(role_name)
        if not role:
            click.echo(f"Role '{role_name}' not found.")
            return

        ident_repo = IdentityRepo(session)
        await ident_repo.upsert(identity_hash)

        mgr = RoleManager()
        await mgr.assign_role(session, role.id, identity_hash, channel_id)
        click.echo(f"Assigned '{role_name}' to {identity_hash[:16]}...")

        # Channel-scoped grant on a sealed channel → distribute the group key
        # so the new member can encrypt/decrypt. Idempotent: skips if the
        # identity already has a SealedKey row for the latest epoch.
        if channel_id:
            ch = (
                await session.execute(select(Channel).where(Channel.id == channel_id))
            ).scalar_one_or_none()
            if ch and ch.sealed:
                existing = (
                    await session.execute(
                        select(SealedKey)
                        .where(SealedKey.channel_id == channel_id)
                        .where(SealedKey.identity_hash == identity_hash)
                    )
                ).scalar_one_or_none()
                if existing is None:
                    from hokora.db.queries import PendingSealedDistributionRepo
                    from hokora.exceptions import SealedKeyDistributionDeferred
                    from hokora.security.sealed import distribute_sealed_key_to_identity

                    try:
                        await distribute_sealed_key_to_identity(session, channel_id, identity_hash)
                        click.echo(
                            f"Distributed sealed key for #{ch.name} to {identity_hash[:16]}..."
                        )
                    except SealedKeyDistributionDeferred as exc:
                        # Recipient not in RNS path cache. Persist the
                        # intent so the daemon's announce handler can
                        # drain it the moment the peer next announces
                        # (typically: connects via TUI).
                        await PendingSealedDistributionRepo(session).enqueue(
                            channel_id, identity_hash, role.id
                        )
                        click.echo(
                            f"Role assigned. Sealed-key distribution queued; will deliver "
                            f"automatically when {identity_hash[:16]}... next announces. "
                            f"({exc})"
                        )
                    except Exception as exc:
                        click.echo(
                            f"WARNING: role assigned but sealed-key distribution failed: {exc}"
                        )


@role_group.command("revoke")
@click.argument("role_name")
@click.argument("identity_hash")
@click.option("--channel", default=None, help="Channel ID to revoke from (omit for global)")
def revoke(role_name, identity_hash, channel):
    """Revoke a role from an identity."""
    _run(_revoke_role(role_name, identity_hash, channel))


async def _revoke_role(role_name, identity_hash, channel_id=None):
    from hokora.db.queries import RoleRepo
    from hokora.db.models import RoleAssignment
    from hokora.cli._helpers import db_session
    from sqlalchemy import select, and_

    async with db_session() as session:
        repo = RoleRepo(session)
        role = await repo.get_by_name(role_name)
        if not role:
            click.echo(f"Role '{role_name}' not found.")
            return

        conditions = [
            RoleAssignment.role_id == role.id,
            RoleAssignment.identity_hash == identity_hash,
        ]
        if channel_id:
            conditions.append(RoleAssignment.channel_id == channel_id)
        else:
            conditions.append(RoleAssignment.channel_id.is_(None))

        result = await session.execute(select(RoleAssignment).where(and_(*conditions)))
        assignments = list(result.scalars().all())
        for a in assignments:
            await session.delete(a)

        # Revoke takes priority over any queued sealed-key distribution.
        # Drop matching pending rows so ``hokora role pending`` reflects
        # operator intent immediately rather than waiting for the peer's
        # next announce to trigger the drain-time revoke guard.
        from hokora.db.models import PendingSealedDistribution
        from sqlalchemy import delete

        pending_conditions = [
            PendingSealedDistribution.role_id == role.id,
            PendingSealedDistribution.identity_hash == identity_hash,
        ]
        if channel_id:
            pending_conditions.append(PendingSealedDistribution.channel_id == channel_id)
        await session.execute(delete(PendingSealedDistribution).where(and_(*pending_conditions)))

        scope = f"channel {channel_id}" if channel_id else "global"
        click.echo(
            f"Revoked '{role_name}' from {identity_hash[:16]}... "
            f"({len(assignments)} removed, scope={scope})"
        )


@role_group.command("list")
def list_roles():
    """List all roles."""
    _run(_list_roles())


async def _list_roles():
    from hokora.db.queries import RoleRepo
    from hokora.cli._helpers import db_session

    async with db_session() as session:
        repo = RoleRepo(session)
        roles = await repo.list_all()
        for r in roles:
            builtin = " [builtin]" if r.is_builtin else ""
            click.echo(f"  {r.name:<20} pos={r.position}  perms={r.permissions:#06x}{builtin}")


@role_group.command("pending")
@click.option("--channel", default=None, help="Filter by channel ID.")
def pending(channel):
    """List pending sealed-key distributions awaiting recipient announce."""
    _run(_list_pending(channel))


async def _list_pending(channel_id):
    import time as _time

    from hokora.cli._helpers import db_session
    from hokora.db.models import Channel, Role
    from hokora.db.queries import PendingSealedDistributionRepo
    from sqlalchemy import select

    async with db_session() as session:
        repo = PendingSealedDistributionRepo(session)
        entries = await repo.list_all(channel_id=channel_id)
        if not entries:
            click.echo("(no pending sealed-key distributions)")
            return

        now = _time.time()
        for e in entries:
            ch = (
                await session.execute(select(Channel).where(Channel.id == e.channel_id))
            ).scalar_one_or_none()
            ch_name = f"#{ch.name}" if ch else f"channel={e.channel_id[:16]}"
            role = (
                await session.execute(select(Role).where(Role.id == e.role_id))
            ).scalar_one_or_none()
            role_name = role.name if role else e.role_id[:16]
            age = int(now - e.queued_at)
            tail = f" last_error={e.last_error}" if e.last_error else ""
            click.echo(
                f"  {ch_name:<20} {e.identity_hash[:16]}... role={role_name:<12} "
                f"queued {age}s ago retries={e.retry_count}{tail}"
            )
