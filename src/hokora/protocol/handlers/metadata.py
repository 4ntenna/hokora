# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Metadata sync handlers: node_meta, members, threads, pins."""

import binascii
import logging
import time
from typing import Optional

import RNS

from sqlalchemy import select, func, distinct
from sqlalchemy.ext.asyncio import AsyncSession

from hokora.constants import (
    ACCESS_PRIVATE,
    ACCESS_WRITE_RESTRICTED,
    PERM_MANAGE_MEMBERS,
    PERM_SEND_MESSAGES,
)
from hokora.db.models import Message, Role, RoleAssignment, Identity
from hokora.db.queries import MessageRepo, CategoryRepo, RoleRepo
from hokora.exceptions import SyncError, PermissionDenied
from hokora.protocol.sync_utils import (
    MetadataContext,
    check_channel_read,
    encode_messages_with_keys,
    get_session_profile,
)

logger = logging.getLogger(__name__)


async def handle_node_meta(
    ctx: MetadataContext,
    session: AsyncSession,
    nonce: bytes,
    payload: dict,
    channel_id: Optional[str],
    requester_hash: Optional[str] = None,
    link=None,
) -> dict:
    """Handle sync_node_meta: return node info + channel list + categories + roles."""
    all_channels = ctx.channel_manager.list_channels()

    # Filter private channels based on requester access and node config.
    # show_private_channels config allows node owners to choose whether
    # non-members can see that private channels exist.
    show_private = getattr(ctx.config, "show_private_channels", True) if ctx.config else True

    is_node_owner = (
        ctx.permission_resolver
        and requester_hash
        and requester_hash == ctx.permission_resolver.node_owner_hash
    )
    if is_node_owner or show_private:
        channels = list(all_channels)
    elif requester_hash:
        ra_result = await session.execute(
            select(RoleAssignment.channel_id)
            .where(RoleAssignment.identity_hash == requester_hash)
            .where(RoleAssignment.channel_id.isnot(None))
        )
        accessible_channel_ids = {row[0] for row in ra_result.all()}
        channels = [
            ch
            for ch in all_channels
            if ch.access_mode != ACCESS_PRIVATE or ch.id in accessible_channel_ids
        ]
    else:
        channels = [ch for ch in all_channels if ch.access_mode != ACCESS_PRIVATE]

    # Build channel summaries with member_count and last_activity (single query)
    stats = await session.execute(
        select(
            Message.channel_id,
            func.count(distinct(Message.sender_hash)),
            func.max(Message.timestamp),
        ).group_by(Message.channel_id)
    )
    channel_stats = {row[0]: (row[1], row[2]) for row in stats.all()}

    channel_list = []
    for ch in channels:
        member_count, last_activity = channel_stats.get(ch.id, (0, None))

        # Compute LXMF delivery destination hash for this channel
        lxmf_dest_hash = None
        ch_identity = None
        try:
            ch_identity = ctx.channel_manager.identity_manager.get_identity(ch.id)
            if ch_identity:
                lxmf_hash_bytes = RNS.Destination.hash_from_name_and_identity(
                    "lxmf.delivery", ch_identity
                )
                lxmf_dest_hash = binascii.hexlify(lxmf_hash_bytes).decode()
        except Exception:
            logger.debug(
                "LXMF destination hash derivation failed for channel %s", ch.id, exc_info=True
            )

        # Resolve write permission for requester
        can_write = True
        if requester_hash and ctx.permission_resolver:
            try:
                perms = await ctx.permission_resolver.get_effective_permissions(
                    session,
                    requester_hash,
                    ch,
                )
                can_write = bool(perms & PERM_SEND_MESSAGES)
            except Exception:
                can_write = False
        elif not requester_hash:
            # Anonymous: can't write to restricted/private/sealed
            can_write = ch.access_mode not in (ACCESS_PRIVATE, ACCESS_WRITE_RESTRICTED)

        channel_list.append(
            {
                "id": ch.id,
                "name": ch.name,
                "description": ch.description,
                "access_mode": ch.access_mode,
                "category_id": ch.category_id,
                "position": ch.position,
                "identity_hash": ch.identity_hash,
                "destination_hash": ch.destination_hash,
                "lxmf_destination_hash": lxmf_dest_hash,
                "identity_public_key": ch_identity.get_public_key() if ch_identity else None,
                "sealed": bool(getattr(ch, "sealed", False)),
                "can_write": can_write,
                "latest_seq": ch.latest_seq,
                "member_count": member_count,
                "last_activity": last_activity,
            }
        )

    # Categories with collapsed_default
    cat_repo = CategoryRepo(session)
    categories = await cat_repo.list_all()
    category_list = [
        {
            "id": cat.id,
            "name": cat.name,
            "position": cat.position,
            "collapsed_default": cat.collapsed_default,
        }
        for cat in categories
    ]

    # Roles
    role_repo = RoleRepo(session)
    roles = await role_repo.list_all()
    role_list = [
        {
            "role_id": r.id,
            "name": r.name,
            "permissions": r.permissions,
            "colour": r.colour,
            "position": r.position,
            "mentionable": r.mentionable,
        }
        for r in roles
    ]

    # CDSP: check profile for metadata inclusion
    profile = await get_session_profile(ctx, session, requester_hash)

    # node_identity_hash = the daemon's RNS identity hexhash. Distinct from
    # ``node_identity`` (which carries the node-owner admin hash). Lets the
    # TUI tag cached channel rows so the Channels view can disambiguate
    # same-named channels from different nodes.
    node_identity_hash = None
    if ctx.node_rns_identity is not None:
        try:
            node_identity_hash = ctx.node_rns_identity.hexhash
        except Exception:
            node_identity_hash = None

    result = {
        "action": "node_meta",
        "node_name": ctx.node_name,
        "node_description": ctx.node_description,
        "node_identity": ctx.node_identity,
        "node_identity_hash": node_identity_hash,
        "channels": channel_list,
        "node_time": time.time(),
    }

    if profile["include_metadata"]:
        result["categories"] = category_list
        result["roles"] = role_list
    else:
        result["categories"] = []
        result["roles"] = []
        result["metadata_partial"] = True

    return result


async def handle_get_pins(
    ctx: MetadataContext,
    session: AsyncSession,
    nonce: bytes,
    payload: dict,
    channel_id: Optional[str],
    requester_hash: Optional[str] = None,
    link=None,
) -> dict:
    """Handle get_pins: return pinned messages for a channel."""
    ch_id = payload.get("channel_id", channel_id)
    if not ch_id:
        raise SyncError("No channel_id for get_pins")

    await check_channel_read(ctx, session, ch_id, requester_hash)

    repo = MessageRepo(session)
    pinned = await repo.get_pinned(ch_id)

    return {
        "action": "pins",
        "channel_id": ch_id,
        "messages": await encode_messages_with_keys(
            session, pinned, sealed_manager=ctx.sealed_manager
        ),
    }


async def handle_thread(
    ctx: MetadataContext,
    session: AsyncSession,
    nonce: bytes,
    payload: dict,
    channel_id: Optional[str],
    requester_hash: Optional[str] = None,
    link=None,
) -> dict:
    """Handle sync_thread: retrieve thread messages ordered by thread_seq."""
    root_hash = payload.get("root_hash")
    if not root_hash:
        raise SyncError("root_hash required for sync_thread")

    # Look up root message to find its channel for access control
    repo = MessageRepo(session)
    root_msg = await repo.get_by_hash(root_hash)
    if not root_msg:
        raise SyncError("Thread root message not found")
    if root_msg.channel_id:
        await check_channel_read(ctx, session, root_msg.channel_id, requester_hash)

    profile = await get_session_profile(ctx, session, requester_hash)
    limit = min(
        payload.get("limit", profile["default_sync_limit"]),
        profile["max_sync_limit"],
    )
    messages = await repo.get_thread_messages(root_hash, limit)

    return {
        "action": "thread",
        "root_hash": root_hash,
        "messages": await encode_messages_with_keys(
            session, messages, sealed_manager=ctx.sealed_manager
        ),
    }


async def handle_member_list(
    ctx: MetadataContext,
    session: AsyncSession,
    nonce: bytes,
    payload: dict,
    channel_id: Optional[str],
    requester_hash: Optional[str] = None,
    link=None,
) -> dict:
    """Handle get_member_list (0x08): return channel members with roles."""
    ch_id = payload.get("channel_id", channel_id)
    if not ch_id:
        raise SyncError("No channel_id for get_member_list")

    # Auth check — enforce permission based on channel access mode
    channel = ctx.channel_manager.get_channel(ch_id)
    if channel and ctx.permission_resolver and requester_hash:
        if channel.access_mode == ACCESS_PRIVATE:
            # Private channels: requester must have a channel-scoped role
            role_repo = RoleRepo(session)
            roles = await role_repo.get_identity_roles(
                requester_hash, ch_id, strict_channel_scope=True
            )
            if not roles:
                raise PermissionDenied("Private channel member list requires membership")
        else:
            # Non-private: require MANAGE_MEMBERS permission
            has_perm = await ctx.permission_resolver.resolve(
                session,
                requester_hash,
                channel,
                PERM_MANAGE_MEMBERS,
            )
            if not has_perm:
                raise PermissionDenied("Member list requires MANAGE_MEMBERS permission")

    # Query role assignments for this channel (or global)
    result = await session.execute(
        select(RoleAssignment, Identity, Role)
        .join(Identity, RoleAssignment.identity_hash == Identity.hash)
        .join(Role, RoleAssignment.role_id == Role.id)
        .where((RoleAssignment.channel_id == ch_id) | (RoleAssignment.channel_id.is_(None)))
    )
    rows = result.all()

    # Group by identity
    members = {}
    for assignment, identity, role in rows:
        ih = identity.hash
        if ih not in members:
            members[ih] = {
                "identity_hash": ih,
                "display_name": identity.display_name,
                "roles": [],
            }
        members[ih]["roles"].append(
            {
                "role_id": role.id,
                "name": role.name,
            }
        )

    # Paginate member list — CDSP: apply profile limits
    profile = await get_session_profile(ctx, session, requester_hash)
    all_members = list(members.values())
    total = len(all_members)
    limit = min(payload.get("limit", 50), profile["max_sync_limit"], 200)
    offset = max(0, int(payload.get("offset", 0)))
    page = all_members[offset : offset + limit]

    return {
        "action": "member_list",
        "channel_id": ch_id,
        "members": page,
        "total": total,
        "has_more": (offset + limit) < total,
    }
