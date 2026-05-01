# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Per-channel monotonic sequence assignment."""

import asyncio
import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from hokora.constants import MAX_LOCK_ENTRIES
from hokora.db.queries import ChannelRepo

logger = logging.getLogger(__name__)


class SequenceManager:
    """Assigns monotonically increasing sequence numbers per channel.

    Maintains an in-memory cache backed by atomic DB updates.
    """

    def __init__(self):
        self._locks: dict[str, asyncio.Lock] = {}
        self._cache: dict[str, int] = {}
        self._thread_locks: dict[str, asyncio.Lock] = {}
        self._thread_cache: dict[str, int] = {}

    def _get_lock(self, key: str, lock_dict: dict) -> asyncio.Lock:
        if key not in lock_dict:
            # Evict oldest entries if dict has grown too large
            if len(lock_dict) >= MAX_LOCK_ENTRIES:
                for old_key in list(lock_dict)[:100]:
                    lock = lock_dict[old_key]
                    if not lock.locked():
                        del lock_dict[old_key]
            lock_dict[key] = asyncio.Lock()
        return lock_dict[key]

    async def load_from_db(self, session: AsyncSession, channel_id: str) -> int:
        """Load current sequence from DB into cache."""
        repo = ChannelRepo(session)
        channel = await repo.get_by_id(channel_id)
        if channel:
            self._cache[channel_id] = channel.latest_seq
            return channel.latest_seq
        return 0

    async def next_seq(self, session: AsyncSession, channel_id: str) -> int:
        """Atomically increment and return next sequence number."""
        lock = self._get_lock(channel_id, self._locks)
        async with lock:
            repo = ChannelRepo(session)
            seq = await repo.increment_seq(channel_id)
            self._cache[channel_id] = seq
            return seq

    async def next_thread_seq(
        self,
        session: AsyncSession,
        root_hash: str,
        channel_id: str = "",
    ) -> int:
        """Atomically increment and return next thread sequence number."""
        from hokora.db.models import Thread

        lock = self._get_lock(root_hash, self._thread_locks)
        async with lock:
            result = await session.execute(select(Thread).where(Thread.root_msg_hash == root_hash))
            thread = result.scalar_one_or_none()
            if thread:
                thread.latest_thread_seq += 1
                seq = thread.latest_thread_seq
            else:
                thread = Thread(
                    root_msg_hash=root_hash,
                    channel_id=channel_id,
                    latest_thread_seq=1,
                )
                session.add(thread)
                seq = 1
            self._thread_cache[root_hash] = seq
            await session.flush()
            return seq

    def get_cached_seq(self, channel_id: str) -> int:
        """Get the cached latest sequence (non-authoritative)."""
        return self._cache.get(channel_id, 0)
