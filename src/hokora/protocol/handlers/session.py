# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Session sync handlers: CDSP, invites, sealed keys."""

import logging
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from hokora.db.models import SealedKey
from hokora.db.queries import RoleRepo
from hokora.exceptions import SyncError, PermissionDenied, InviteError, RateLimitExceeded
from hokora.protocol.sync_utils import SessionContext

logger = logging.getLogger(__name__)


async def handle_redeem_invite(
    ctx: SessionContext,
    session: AsyncSession,
    nonce: bytes,
    payload: dict,
    channel_id: Optional[str],
    requester_hash: Optional[str] = None,
    link=None,
) -> dict:
    """Handle redeem_invite (0x0A): redeem an invite token over the sync protocol."""
    # Fallback to link identity if requester_hash not yet set (identify race)
    if not requester_hash and link:
        try:
            remote_identity = link.get_remote_identity()
            if remote_identity:
                requester_hash = remote_identity.hexhash
        except Exception:
            logger.debug("link identity fallback lookup failed", exc_info=True)
    if not requester_hash:
        raise SyncError("Authentication required to redeem an invite")

    raw_token = payload.get("token")
    if not raw_token:
        raise SyncError("No token provided for redeem_invite")

    try:
        invite = await ctx.invite_manager.redeem_invite(
            session,
            raw_token,
            requester_hash,
        )
    except InviteError as e:
        raise SyncError(f"Invite redemption failed: {e}")
    except RateLimitExceeded as e:
        raise SyncError(f"Rate limited: {e}")

    # Distribute sealed key if the channel is sealed
    sealed_key_epoch = None
    if invite.channel_id and ctx.sealed_manager:
        channel = ctx.channel_manager.get_channel(invite.channel_id)
        if channel and channel.sealed:
            key_data = ctx.sealed_manager._keys.get(invite.channel_id)
            if key_data and link:
                try:
                    # Encrypt the group key for the new member's identity
                    peer_identity = link.get_remote_identity()
                    if peer_identity:
                        encrypted_blob = peer_identity.encrypt(key_data["key"])
                        sealed_key_record = SealedKey(
                            channel_id=invite.channel_id,
                            identity_hash=requester_hash,
                            epoch=key_data["epoch"],
                            encrypted_key_blob=encrypted_blob,
                        )
                        session.add(sealed_key_record)
                        sealed_key_epoch = key_data["epoch"]
                        logger.info(
                            f"Distributed sealed key for channel "
                            f"{invite.channel_id} to {requester_hash[:16]}"
                        )
                except Exception:
                    logger.exception(f"Failed to distribute sealed key for {invite.channel_id}")

    result = {
        "action": "invite_redeemed",
        "channel_id": invite.channel_id,
        "identity_hash": requester_hash,
    }
    if sealed_key_epoch is not None:
        result["sealed_key_epoch"] = sealed_key_epoch
    return result


async def handle_request_sealed_key(
    ctx: SessionContext,
    session: AsyncSession,
    nonce: bytes,
    payload: dict,
    channel_id: Optional[str],
    requester_hash: Optional[str] = None,
    link=None,
) -> dict:
    """Handle request_sealed_key (0x0D): serve sealed channel key to authorized member."""
    ch_id = payload.get("channel_id", channel_id)
    if not ch_id:
        raise SyncError("No channel_id for request_sealed_key")

    if not requester_hash:
        raise SyncError("Authentication required for sealed key request")

    # Short-circuit for non-sealed channels: clients that advertise
    # ``supports_sealed_at_rest`` request a key for every channel on
    # link establishment (they don't track which are sealed at request
    # time). Returning an empty response keeps the daemon log quiet
    # and the TUI handler treats null blob as "nothing to persist".
    if ctx.channel_manager:
        channel = ctx.channel_manager.get_channel(ch_id)
        if channel is not None and not getattr(channel, "sealed", False):
            return {
                "action": "sealed_key",
                "channel_id": ch_id,
                "epoch": None,
                "encrypted_key_blob": None,
            }

    # Rate limit sealed key requests to prevent abuse
    if ctx.rate_limiter:
        try:
            ctx.rate_limiter.check_rate_limit(requester_hash)
        except RateLimitExceeded as e:
            raise SyncError(f"Rate limited: {e}")

    # Verify requester has a channel-scoped role. Sealed-key requests are
    # gated strictly — node-scoped roles never satisfy the check.
    role_repo = RoleRepo(session)
    roles = await role_repo.get_identity_roles(requester_hash, ch_id, strict_channel_scope=True)
    if not roles:
        raise PermissionDenied("Not a member of this channel")

    # Look up latest sealed key for the requester
    result = await session.execute(
        select(SealedKey)
        .where(SealedKey.channel_id == ch_id)
        .where(SealedKey.identity_hash == requester_hash)
        .order_by(SealedKey.epoch.desc())
        .limit(1)
    )
    sealed_key = result.scalar_one_or_none()

    if not sealed_key:
        raise SyncError("No sealed key available for this member")

    return {
        "action": "sealed_key",
        "channel_id": ch_id,
        "epoch": sealed_key.epoch,
        "encrypted_key_blob": sealed_key.encrypted_key_blob,
    }


async def handle_cdsp_session_init(
    ctx: SessionContext,
    session: AsyncSession,
    nonce: bytes,
    payload: dict,
    channel_id: Optional[str],
    requester_hash: Optional[str] = None,
    link=None,
) -> dict:
    """Handle CDSP Session Init (0x0E): establish sync profile session."""
    if not ctx.cdsp_manager:
        raise SyncError("CDSP not enabled on this node")
    if not requester_hash:
        raise SyncError("Authentication required for CDSP session")

    result = await ctx.cdsp_manager.handle_session_init(session, requester_hash, payload)

    if result.get("rejected"):
        return {
            "action": "cdsp_session_reject",
            "error_code": result.get("error_code"),
            "cdsp_version": result.get("cdsp_version"),
        }

    ack: dict = {
        "action": "cdsp_session_ack",
        "session_id": result["session_id"],
        "accepted_profile": result["accepted_profile"],
        "cdsp_version": result["cdsp_version"],
        "deferred_count": result.get("deferred_count", 0),
        "resume_token": result.get("resume_token"),
    }
    # On resume, propagate any flushed items (live events that were queued
    # while the client was disconnected) so the client can replay them in
    # FIFO order as if they had arrived live.
    if result.get("resumed"):
        ack["resumed"] = True
        ack["flushed_count"] = result.get("flushed_count", 0)
        ack["flushed_items"] = result.get("flushed_items", [])
    return ack


async def handle_cdsp_profile_update(
    ctx: SessionContext,
    session: AsyncSession,
    nonce: bytes,
    payload: dict,
    channel_id: Optional[str],
    requester_hash: Optional[str] = None,
    link=None,
) -> dict:
    """Handle CDSP Profile Update (0x10): change sync profile mid-session."""
    if not ctx.cdsp_manager:
        raise SyncError("CDSP not enabled on this node")

    session_id = payload.get("session_id")
    new_profile = payload.get("sync_profile")
    if not session_id or new_profile is None:
        raise SyncError("session_id and sync_profile required for profile update")

    result = await ctx.cdsp_manager.handle_profile_update(session, session_id, new_profile)

    if result.get("rejected"):
        return {
            "action": "cdsp_session_reject",
            "error_code": result.get("error_code"),
        }

    return {
        "action": "cdsp_profile_ack",
        "session_id": result["session_id"],
        "accepted_profile": result["accepted_profile"],
        "cdsp_version": result["cdsp_version"],
        "deferred_count": result.get("deferred_count", 0),
        "flushed_count": result.get("flushed_count", 0),
        "flushed_items": result.get("flushed_items", []),
    }


async def handle_create_invite(
    ctx: SessionContext,
    session: AsyncSession,
    nonce: bytes,
    payload: dict,
    channel_id: Optional[str],
    requester_hash: Optional[str] = None,
    link=None,
) -> dict:
    """Handle create_invite: create an invite token (requires PERM_MANAGE_MEMBERS)."""
    from hokora.constants import PERM_MANAGE_MEMBERS

    if not requester_hash:
        raise PermissionDenied("Authentication required to create invites")

    if not ctx.invite_manager:
        raise SyncError("Invite system not available")

    # Permission check: node_owner or PERM_MANAGE_MEMBERS
    is_owner = requester_hash == ctx.node_identity
    if not is_owner and ctx.permission_resolver:
        # Check global permission (any channel with manage members)
        ch_id = payload.get("channel_id", channel_id)
        if ch_id:
            ch = ctx.channel_manager.get_channel(ch_id) if ctx.channel_manager else None
            if ch:
                perms = await ctx.permission_resolver.get_effective_permissions(
                    session,
                    requester_hash,
                    ch,
                )
                if not (perms & PERM_MANAGE_MEMBERS):
                    raise PermissionDenied("Requires MANAGE_MEMBERS permission")
            else:
                raise SyncError(f"Channel {ch_id} not found")
        else:
            raise PermissionDenied("Node-level invites require node_owner")

    ch_id = payload.get("channel_id", channel_id)
    max_uses = payload.get("max_uses", 1)
    expiry_hours = payload.get("expiry_hours", 72)

    # Get destination hash for the composite token
    destination_hash = None
    if ch_id and ctx.channel_manager:
        ch = ctx.channel_manager.get_channel(ch_id)
        if ch and ch.destination_hash:
            destination_hash = ch.destination_hash
    elif ctx.channel_manager:
        channels = ctx.channel_manager.get_all_channels()
        if channels:
            first = channels[0]
            destination_hash = first.destination_hash
            if not ch_id:
                ch_id = first.id

    raw_token, token_hash = await ctx.invite_manager.create_invite(
        session,
        requester_hash,
        ch_id,
        max_uses,
        expiry_hours,
        destination_hash=destination_hash,
    )

    # Append channel_id to composite token for TUI connect
    if ch_id and ":" in raw_token:
        raw_token = f"{raw_token}:{ch_id}"

    logger.info(f"Invite created by {requester_hash[:8]} hash={token_hash[:8]}")

    return {
        "action": "invite_created",
        "token": raw_token,
        "token_hash": token_hash,
        "max_uses": max_uses,
        "expiry_hours": expiry_hours,
        "channel_id": ch_id,
    }


async def handle_list_invites(
    ctx: SessionContext,
    session: AsyncSession,
    nonce: bytes,
    payload: dict,
    channel_id: Optional[str],
    requester_hash: Optional[str] = None,
    link=None,
) -> dict:
    """Handle list_invites: list active invites (requires PERM_MANAGE_MEMBERS)."""

    if not requester_hash:
        raise PermissionDenied("Authentication required to list invites")

    if not ctx.invite_manager:
        raise SyncError("Invite system not available")

    # Permission check: node_owner bypasses, others need PERM_MANAGE_MEMBERS
    is_owner = requester_hash == ctx.node_identity
    if not is_owner:
        raise PermissionDenied("Invite listing requires node_owner")

    ch_id = payload.get("channel_id", channel_id)
    invites = await ctx.invite_manager.list_invites(session, ch_id)

    invite_list = []
    for inv in invites:
        invite_list.append(
            {
                "token_hash": inv.token_hash[:12],
                "channel_id": inv.channel_id,
                "max_uses": inv.max_uses,
                "uses": inv.uses,
                "expires_at": inv.expires_at,
                "revoked": inv.revoked,
            }
        )

    return {
        "action": "invite_list",
        "invites": invite_list,
        "channel_id": ch_id,
    }
