# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""hokora ban: persistent identity ban / unban / list.

CLI-only operator surface. The ban gate itself runs at every protocol
chokepoint (sync read, federation push receive, federation push send
filter, invite redeem, local message ingest); this command writes the
state row + audit-log entry. See ``security.ban.BanManager``.
"""

import asyncio
import time

import click


def _run(coro):
    return asyncio.run(coro)


@click.group("ban")
def ban_group():
    """Ban / unban identities at the node level."""
    pass


@ban_group.command("add")
@click.argument("identity_hash")
@click.option("--reason", default=None, help="Free-text reason recorded in the audit log.")
def add(identity_hash, reason):
    """Ban an identity from the node."""
    _run(_add_ban(identity_hash, reason))


async def _add_ban(target, reason):
    import RNS

    from hokora.cli._helpers import db_session
    from hokora.config import load_config
    from hokora.security.ban import BanError, BanManager

    config = load_config()
    identity_path = config.identity_dir / "node_identity"
    actor_identity = RNS.Identity.from_file(str(identity_path))
    actor_hash = actor_identity.hexhash

    mgr = BanManager(node_owner_hash=actor_hash)

    async with db_session() as session:
        try:
            result = await mgr.ban(session, target, actor=actor_hash, reason=reason)
        except BanError as exc:
            click.echo(f"Refused: {exc}")
            raise SystemExit(1)

    if result.already_blocked:
        click.echo(f"Identity {target[:16]}... was already banned (provenance refreshed).")
    else:
        click.echo(f"Banned {target[:16]}...")

    if result.pending_dropped:
        click.echo(f"  Dropped {result.pending_dropped} pending sealed-key distribution(s).")

    if result.sealed_channels:
        click.echo("")
        click.echo("Sealed channels the banned identity was a member of:")
        for ch_id, ch_name in result.sealed_channels:
            click.echo(f"  #{ch_name}  ({ch_id})")
        click.echo("")
        click.echo(
            "Rotate keys on each sealed channel to revoke the banned "
            "identity's access to future messages:"
        )
        for ch_id, _ in result.sealed_channels:
            click.echo(f"  hokora channel rotate-key {ch_id}")


@ban_group.command("remove")
@click.argument("identity_hash")
@click.option("--reason", default=None, help="Free-text reason recorded in the audit log.")
def remove(identity_hash, reason):
    """Unban an identity."""
    _run(_remove_ban(identity_hash, reason))


async def _remove_ban(target, reason):
    import RNS

    from hokora.cli._helpers import db_session
    from hokora.config import load_config
    from hokora.security.ban import BanError, BanManager

    config = load_config()
    identity_path = config.identity_dir / "node_identity"
    actor_identity = RNS.Identity.from_file(str(identity_path))
    actor_hash = actor_identity.hexhash

    mgr = BanManager(node_owner_hash=actor_hash)

    async with db_session() as session:
        try:
            result = await mgr.unban(session, target, actor=actor_hash, reason=reason)
        except BanError as exc:
            click.echo(f"Refused: {exc}")
            raise SystemExit(1)

    if not result.was_blocked:
        click.echo(f"Identity {target[:16]}... was not banned (no-op).")
    else:
        click.echo(f"Unbanned {target[:16]}...")


@ban_group.command("list")
def list_banned():
    """List every currently banned identity."""
    _run(_list_banned())


async def _list_banned():
    from hokora.cli._helpers import db_session
    from hokora.security.ban import BanManager

    async with db_session() as session:
        mgr = BanManager()
        rows = await mgr.list_banned(session)

    if not rows:
        click.echo("(no banned identities)")
        return

    now = time.time()
    for ident in rows:
        age = ""
        if ident.blocked_at:
            secs = int(now - ident.blocked_at)
            age = f"  banned {secs}s ago"
        actor = f"  by {ident.blocked_by[:16]}..." if ident.blocked_by else "  by <unknown>"
        name = f" ({ident.display_name})" if ident.display_name else ""
        click.echo(f"  {ident.hash}{name}{age}{actor}")
