# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""hokora node: status, peers, config."""

import asyncio

import click

from hokora.config import load_config


def _run(coro):
    return asyncio.run(coro)


@click.group("node")
def node_group():
    """Node management."""
    pass


@node_group.command("status")
def status():
    """Show node status."""
    _run(_node_status())


async def _node_status():
    from hokora.db.engine import create_db_engine, create_session_factory
    from hokora.db.queries import ChannelRepo
    from sqlalchemy import select, func
    from hokora.db.models import Message

    config = load_config()
    engine = create_db_engine(
        config.db_path, encrypt=config.db_encrypt, db_key=config.resolve_db_key()
    )
    session_factory = create_session_factory(engine)

    click.echo(f"Node: {config.node_name}")
    click.echo(f"Data: {config.data_dir}")
    click.echo(f"DB:   {config.db_path}")

    async with session_factory() as session:
        async with session.begin():
            repo = ChannelRepo(session)
            channels = await repo.list_all()
            click.echo(f"Channels: {len(channels)}")

            result = await session.execute(select(func.count()).select_from(Message))
            msg_count = result.scalar()
            click.echo(f"Messages: {msg_count}")

    # Check identity
    identity_path = config.identity_dir / "node_identity"
    if identity_path.exists():
        import RNS

        identity = RNS.Identity.from_file(str(identity_path))
        click.echo(f"Identity: {identity.hexhash}")
    else:
        click.echo("Identity: not created")

    await engine.dispose()


@node_group.command("config")
def show_config():
    """Show current configuration."""
    config = load_config()
    for field_name, field_info in config.model_fields.items():
        value = getattr(config, field_name)
        if field_name == "db_key" and value:
            value = "***"
        click.echo(f"  {field_name}: {value}")


@node_group.command("peers")
def peers():
    """List known peers discovered via announces or federation handshakes."""
    _run(_peers())


async def _peers():
    """Read the ``peers`` table directly.

    Peers are persisted on announce receipt and on federation handshake
    ack, so this works whether or not the daemon is currently running.
    The daemon still uses the same table as its in-memory source of
    truth — keeping the CLI as a pure reader avoids any coordination
    with the daemon process.
    """
    import datetime

    from sqlalchemy import select

    from hokora.db.engine import create_db_engine, create_session_factory
    from hokora.db.models import Peer

    config = load_config()
    engine = create_db_engine(
        config.db_path, encrypt=config.db_encrypt, db_key=config.resolve_db_key()
    )
    session_factory = create_session_factory(engine)

    try:
        async with session_factory() as session:
            result = await session.execute(select(Peer).order_by(Peer.last_seen.desc()))
            rows = list(result.scalars().all())
    finally:
        await engine.dispose()

    if not rows:
        click.echo("No peers discovered.")
        return

    for p in rows:
        trust = "TRUSTED" if p.federation_trusted else "untrusted"
        if p.last_seen:
            last = datetime.datetime.fromtimestamp(p.last_seen).isoformat(timespec="seconds")
        else:
            last = "never"
        name = (p.node_name or "<unnamed>")[:24]
        click.echo(f"  {p.identity_hash[:16]}  {name:24s}  last_seen={last}  [{trust}]")
