# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""History and search sync handlers."""

import logging
import time
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from hokora.constants import MSG_THREAD_REPLY
from hokora.db.queries import MessageRepo
from hokora.exceptions import SyncError
from hokora.protocol.wire import encode_message_for_sync
from hokora.protocol.sync_utils import (
    HistoryContext,
    check_channel_read,
    encode_messages_with_keys,
    get_session_profile,
    defer_sync_item,
)

logger = logging.getLogger(__name__)


async def handle_history(
    ctx: HistoryContext,
    session: AsyncSession,
    nonce: bytes,
    payload: dict,
    channel_id: Optional[str],
    requester_hash: Optional[str] = None,
    link=None,
) -> dict:
    """Handle sync_history: return messages since a sequence number."""
    ch_id = payload.get("channel_id", channel_id)
    if not ch_id:
        raise SyncError("No channel_id provided for sync_history")

    await check_channel_read(ctx, session, ch_id, requester_hash)

    # CDSP: apply profile-aware limits
    profile = await get_session_profile(ctx, session, requester_hash)
    since_seq = payload.get("since_seq", 0)
    limit = min(
        payload.get("limit", profile["default_sync_limit"]),
        profile["max_sync_limit"],
    )
    direction = payload.get("direction", "forward")

    # PRIORITIZED profile: default to newest-first unless client explicitly chose forward
    if profile.get("history_direction") == "backward" and "direction" not in payload:
        direction = "backward"

    repo = MessageRepo(session)
    raw_messages = await repo.get_history(
        ch_id,
        since_seq=since_seq,
        limit=limit,
        direction=direction,
    )

    # Check has_more BEFORE filtering thread replies
    has_more = len(raw_messages) == limit
    gap_explanation = None

    # Filter out thread replies from main timeline
    messages = [m for m in raw_messages if m.type != MSG_THREAD_REPLY]

    result = {
        "action": "history",
        "channel_id": ch_id,
        "messages": await encode_messages_with_keys(
            session,
            messages,
            sealed_manager=ctx.sealed_manager,
            subscriber_supports_sealed_at_rest=bool(payload.get("supports_sealed_at_rest", False)),
        ),
        "latest_seq": ctx.sequencer.get_cached_seq(ch_id),
        "has_more": has_more,
        "gap_explanation": gap_explanation,
        "node_time": time.time(),
        "sync_profile": profile.get("max_sync_limit"),
    }
    return result


async def handle_search(
    ctx: HistoryContext,
    session: AsyncSession,
    nonce: bytes,
    payload: dict,
    channel_id: Optional[str],
    requester_hash: Optional[str] = None,
    link=None,
) -> dict:
    """Handle search: FTS5 or fallback search."""
    ch_id = payload.get("channel_id", channel_id)
    query = payload.get("query", "")

    # CDSP: apply profile-aware search limits
    profile = await get_session_profile(ctx, session, requester_hash)
    if profile["search_limit"] == 0:
        # MINIMAL profile: defer search
        if requester_hash:
            await defer_sync_item(ctx, session, requester_hash, ch_id, 0x07, payload)
        return {"action": "search", "results": [], "deferred": True}

    limit = min(payload.get("limit", 20), profile["search_limit"])
    if not ch_id or not query:
        raise SyncError("channel_id and query required for search")

    # Cap query length to prevent abuse
    max_query_len = 500
    query_truncated = False
    if len(query) > max_query_len:
        query = query[:max_query_len]
        query_truncated = True

    # Access control check
    channel = await check_channel_read(ctx, session, ch_id, requester_hash)

    # Check if channel is sealed (no search allowed)
    if channel and channel.sealed:
        raise SyncError("Search not available for sealed channels")

    if ctx.fts_manager:
        results = await ctx.fts_manager.search(ch_id, query, limit)
        # Add context for FTS results
        repo = MessageRepo(session)
        enriched = []
        for r in results:
            context = await _get_search_context(repo, ch_id, r.get("msg_hash"))
            r.update(context)
            enriched.append(r)
        return {
            "action": "search",
            "channel_id": ch_id,
            "results": enriched,
            "query_truncated": query_truncated,
        }

    # Fallback to LIKE search
    repo = MessageRepo(session)
    messages = await repo.search(ch_id, query, limit)
    results = []
    for m in messages:
        entry = encode_message_for_sync(m)
        context = await _get_search_context(repo, ch_id, m.msg_hash)
        entry.update(context)
        results.append(entry)

    return {
        "action": "search",
        "channel_id": ch_id,
        "results": results,
        "query_truncated": query_truncated,
    }


async def _get_search_context(repo: MessageRepo, channel_id: str, msg_hash: str) -> dict:
    """Fetch 1-2 messages before/after a search result by seq."""
    msg = await repo.get_by_hash(msg_hash) if msg_hash else None
    if not msg or msg.seq is None:
        return {"context_before": [], "context_after": []}

    before = await repo.get_history(
        channel_id,
        direction="backward",
        before_seq=msg.seq,
        limit=2,
    )
    after = await repo.get_history(
        channel_id,
        since_seq=msg.seq,
        limit=2,
    )
    return {
        "context_before": [encode_message_for_sync(m) for m in before],
        "context_after": [encode_message_for_sync(m) for m in after],
    }
