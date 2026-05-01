# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""hokora invite: create, list, revoke."""

import asyncio

import click


def _run(coro):
    return asyncio.run(coro)


@click.group("invite")
def invite_group():
    """Manage invite tokens."""
    pass


@invite_group.command("create")
@click.option("--channel", default=None, help="Channel ID to invite to")
@click.option("--max-uses", type=int, default=1)
@click.option("--expiry-hours", type=int, default=72)
def create(channel, max_uses, expiry_hours):
    """Create a new invite token."""
    _run(_create_invite(channel, max_uses, expiry_hours))


async def _create_invite(channel_id, max_uses, expiry_hours):
    from hokora.db.models import Channel
    from hokora.security.invites import InviteManager
    from hokora.config import load_config
    from hokora.cli._helpers import db_session
    from sqlalchemy import select
    import RNS

    config = load_config()
    identity_path = config.identity_dir / "node_identity"
    identity = RNS.Identity.from_file(str(identity_path))

    async with db_session() as session:
        # Determine destination hash to bundle in the invite.
        # Must be an RNS destination hash (not identity hash) so the
        # TUI can connect via connect_channel().
        destination_hash = None
        if channel_id:
            result = await session.execute(select(Channel).where(Channel.id == channel_id))
            ch = result.scalar_one_or_none()
            if ch and ch.destination_hash:
                destination_hash = ch.destination_hash
        else:
            # Node-level invite: use the first channel's destination hash
            # as the connection entry point. node_meta will reveal all channels.
            result = await session.execute(select(Channel).order_by(Channel.created_at).limit(1))
            first_ch = result.scalar_one_or_none()
            if first_ch and first_ch.destination_hash:
                destination_hash = first_ch.destination_hash
                channel_id = first_ch.id  # Include channel_id for TUI connect

        # Load the channel's identity public key so the recipient can
        # construct the Identity locally without waiting for an announce.
        # Falls back to no-pubkey (3-field format) if the identity file
        # is missing for any reason. Channel identities are stored as
        # ``channel_<id>`` under ``identity_dir``.
        destination_pubkey = None
        if channel_id:
            ch_id_path = config.identity_dir / f"channel_{channel_id}"
            if ch_id_path.exists():
                try:
                    ch_identity = RNS.Identity.from_file(str(ch_id_path))
                    destination_pubkey = ch_identity.get_public_key().hex()
                except Exception:
                    destination_pubkey = None

        mgr = InviteManager()
        raw_token, token_hash = await mgr.create_invite(
            session,
            identity.hexhash,
            None,  # Node-level: no channel scope for the role
            max_uses,
            expiry_hours,
            destination_hash=destination_hash,
            destination_pubkey=destination_pubkey,
        )
        # Append channel_id to composite token for TUI connect_channel()
        if channel_id and ":" in raw_token:
            raw_token = f"{raw_token}:{channel_id}"
        click.echo(f"Invite token: {raw_token}")
        click.echo(f"  Hash:    {token_hash[:16]}...")
        click.echo(f"  Uses:    0/{max_uses}")
        click.echo(f"  Expires: {expiry_hours}h")
        if channel_id:
            click.echo(f"  Channel: {channel_id}")

        # Also output short invite code
        try:
            from hokora.security.invite_codes import encode_invite

            # raw_token is "token_hex:dest_hash_hex"
            if ":" in raw_token and destination_hash:
                token_hex = raw_token.split(":")[0]
                short_code = encode_invite(token_hex, destination_hash)
                click.echo(f"  Short code: {short_code}")
        except Exception:
            pass  # Short codes are optional


@invite_group.command("list")
@click.option("--channel", default=None)
def list_invites(channel):
    """List invite tokens."""
    _run(_list_invites(channel))


async def _list_invites(channel_id):
    from hokora.security.invites import InviteManager
    from hokora.cli._helpers import db_session
    import time

    async with db_session() as session:
        mgr = InviteManager()
        invites = await mgr.list_invites(session, channel_id)
        if not invites:
            click.echo("No invites found.")
            return
        for inv in invites:
            status = (
                "revoked"
                if inv.revoked
                else ("expired" if inv.expires_at and inv.expires_at < time.time() else "active")
            )
            click.echo(
                f"  {inv.token_hash}  uses={inv.uses}/{inv.max_uses}  "
                f"status={status}  channel={inv.channel_id or 'node'}"
            )


@invite_group.command("revoke")
@click.argument("token_hash")
def revoke(token_hash):
    """Revoke an invite token."""
    _run(_revoke_invite(token_hash))


async def _revoke_invite(token_hash):
    from hokora.security.invites import InviteManager
    from hokora.cli._helpers import db_session

    async with db_session() as session:
        mgr = InviteManager()
        if await mgr.revoke_invite(session, token_hash):
            click.echo(f"Revoked invite {token_hash[:16]}...")
        else:
            click.echo("Invite not found.")
