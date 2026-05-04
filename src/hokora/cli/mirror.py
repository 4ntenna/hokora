# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""hokora mirror: add, remove, list channel mirrors."""

import asyncio

import click


def _run(coro):
    return asyncio.run(coro)


@click.group("mirror")
def mirror_group():
    """Manage channel mirrors (federation)."""
    pass


@mirror_group.command("add")
@click.argument("remote_dest_hash")
@click.argument("channel_id")
def add(remote_dest_hash, channel_id):
    """Add a channel mirror: hokora mirror add <remote_dest_hash> <channel_id>."""
    _run(_add_mirror(remote_dest_hash, channel_id))


async def _add_mirror(remote_dest_hash, channel_id):
    from hokora.db.models import Peer
    from hokora.cli._helpers import db_session
    from sqlalchemy import select

    async with db_session() as session:
        result = await session.execute(select(Peer).where(Peer.identity_hash == remote_dest_hash))
        peer = result.scalar_one_or_none()
        if not peer:
            peer = Peer(
                identity_hash=remote_dest_hash,
                channels_mirrored=[channel_id],
            )
            session.add(peer)
        else:
            mirrored = list(peer.channels_mirrored or [])
            if channel_id not in mirrored:
                mirrored.append(channel_id)
                peer.channels_mirrored = mirrored
            else:
                click.echo(f"Mirror already configured for {channel_id}")
                return

    click.echo(f"Added mirror: {remote_dest_hash[:16]}... -> channel {channel_id}")
    click.echo("Restart the daemon for the mirror to take effect.")


@mirror_group.command("remove")
@click.argument("remote_dest_hash")
@click.argument("channel_id")
def remove(remote_dest_hash, channel_id):
    """Remove a channel mirror."""
    _run(_remove_mirror(remote_dest_hash, channel_id))


async def _remove_mirror(remote_dest_hash, channel_id):
    from hokora.db.models import Peer
    from hokora.cli._helpers import db_session
    from sqlalchemy import select

    async with db_session() as session:
        result = await session.execute(select(Peer).where(Peer.identity_hash == remote_dest_hash))
        peer = result.scalar_one_or_none()
        if peer and peer.channels_mirrored:
            mirrored = list(peer.channels_mirrored)
            if channel_id in mirrored:
                mirrored.remove(channel_id)
                peer.channels_mirrored = mirrored
                click.echo(f"Removed mirror for channel {channel_id}")
            else:
                click.echo("Mirror not found.")
        else:
            click.echo("Mirror not found.")


@mirror_group.command("list")
def list_mirrors():
    """List configured channel mirrors."""
    _run(_list_mirrors())


@mirror_group.command("trust")
@click.argument("remote_dest_hash")
def trust(remote_dest_hash):
    """Trust a federation peer: hokora mirror trust <remote_dest_hash>."""
    _run(_trust_peer(remote_dest_hash, True))


@mirror_group.command("untrust")
@click.argument("remote_dest_hash")
def untrust(remote_dest_hash):
    """Untrust a federation peer: hokora mirror untrust <remote_dest_hash>."""
    _run(_trust_peer(remote_dest_hash, False))


async def _trust_peer(remote_dest_hash, trusted):
    from hokora.db.models import Peer
    from hokora.cli._helpers import db_session
    from sqlalchemy import select

    async with db_session() as session:
        result = await session.execute(select(Peer).where(Peer.identity_hash == remote_dest_hash))
        peer = result.scalar_one_or_none()
        if not peer:
            peer = Peer(
                identity_hash=remote_dest_hash,
                federation_trusted=trusted,
            )
            session.add(peer)
        else:
            peer.federation_trusted = trusted

    action = "Trusted" if trusted else "Untrusted"
    click.echo(f"{action} peer {remote_dest_hash[:16]}...")


async def _list_mirrors():
    from hokora.db.models import Peer
    from hokora.cli._helpers import db_session
    from sqlalchemy import select

    async with db_session() as session:
        result = await session.execute(select(Peer))
        peers = result.scalars().all()
        found = False
        for peer in peers:
            for ch_id in peer.channels_mirrored or []:
                found = True
                click.echo(
                    f"  {peer.identity_hash[:16]}... -> channel {ch_id}"
                    f"  (node: {peer.node_name or 'unknown'})"
                )
        if not found:
            click.echo("No mirrors configured.")
