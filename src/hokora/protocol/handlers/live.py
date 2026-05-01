# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Live subscription and media fetch sync handlers."""

import logging
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from hokora.constants import CDSP_PROFILE_FULL
from hokora.db.queries import SessionRepo
from hokora.exceptions import SyncError
from hokora.protocol.sync_utils import (
    LiveContext,
    check_channel_read,
    get_session_profile,
    defer_sync_item,
)

logger = logging.getLogger(__name__)


async def handle_subscribe_live(
    ctx: LiveContext,
    session: AsyncSession,
    nonce: bytes,
    payload: dict,
    channel_id: Optional[str],
    requester_hash: Optional[str] = None,
    link=None,
) -> dict:
    """Handle subscribe_live (0x02): subscribe a link to live channel updates."""
    ch_id = payload.get("channel_id", channel_id)
    if not ch_id:
        raise SyncError("No channel_id for subscribe_live")

    await check_channel_read(ctx, session, ch_id, requester_hash)

    # CDSP: check if live push is allowed under current profile
    profile = await get_session_profile(ctx, session, requester_hash)
    if not profile["live_push"]:
        raise SyncError("Live subscriptions not available under current sync profile")

    if not ctx.live_manager:
        raise SyncError("Live subscriptions not available")

    if not link:
        raise SyncError("No link provided for subscribe_live")

    # Pass sync_profile to live_manager for per-subscriber filtering
    sess = await SessionRepo(session).get_active_session(requester_hash) if requester_hash else None
    sync_profile = sess.sync_profile if sess else CDSP_PROFILE_FULL
    if not ctx.live_manager.subscribe(
        ch_id,
        link,
        sync_profile=sync_profile,
        identity_hash=requester_hash,
        supports_sealed_at_rest=bool(payload.get("supports_sealed_at_rest", False)),
    ):
        raise SyncError("Subscription limit reached")
    logger.info(f"Live subscription added for channel {ch_id}")

    return {
        "action": "subscribed",
        "channel_id": ch_id,
    }


async def handle_unsubscribe(
    ctx: LiveContext,
    session: AsyncSession,
    nonce: bytes,
    payload: dict,
    channel_id: Optional[str],
    requester_hash: Optional[str] = None,
    link=None,
) -> dict:
    """Handle unsubscribe (0x03): unsubscribe a link from live channel updates."""
    ch_id = payload.get("channel_id", channel_id)

    if not ctx.live_manager:
        raise SyncError("Live subscriptions not available")

    if not link:
        raise SyncError("No link provided for unsubscribe")

    if ch_id:
        ctx.live_manager.unsubscribe(ch_id, link)
    else:
        ctx.live_manager.unsubscribe_all(link)

    return {
        "action": "unsubscribed",
        "channel_id": ch_id,
    }


async def handle_fetch_media(
    ctx: LiveContext,
    session: AsyncSession,
    nonce: bytes,
    payload: dict,
    channel_id: Optional[str],
    requester_hash: Optional[str] = None,
    link=None,
) -> dict:
    """Handle fetch_media (0x09): serve a media file via RNS.Resource."""
    # CDSP: check if media fetch is allowed under current profile
    profile = await get_session_profile(ctx, session, requester_hash)
    if not profile["media_fetch"]:
        if requester_hash:
            await defer_sync_item(
                ctx,
                session,
                requester_hash,
                payload.get("channel_id", channel_id),
                0x09,
                payload,
            )
        return {"action": "media_deferred", "deferred": True}

    # Access control: require channel_id for private channel media
    media_channel_id = payload.get("channel_id", channel_id)
    if media_channel_id:
        await check_channel_read(ctx, session, media_channel_id, requester_hash)

    relative_path = payload.get("path")
    if not relative_path:
        raise SyncError("No path provided for fetch_media")

    if not ctx.media_transfer:
        raise SyncError("Media transfer not available")

    if not link:
        raise SyncError("No link provided for fetch_media")

    success = ctx.media_transfer.serve_media(link, relative_path)
    if not success:
        raise SyncError(f"Media not found: {relative_path}")

    return {
        "action": "media_serving",
        "path": relative_path,
    }
