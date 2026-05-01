# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Database maintenance: retention pruning, TTL expiry, VACUUM, secure deletion."""

import logging
import os
import time
from pathlib import Path

from sqlalchemy import delete, func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession, AsyncEngine

from hokora.db.models import Message, Channel, Invite

logger = logging.getLogger(__name__)


class MaintenanceManager:
    def __init__(self, engine: AsyncEngine, media_dir: Path):
        self.engine = engine
        self.media_dir = media_dir

    async def prune_expired_messages(self, session: AsyncSession) -> int:
        """Delete messages past their TTL using batched queries."""
        now = time.time()
        count = 0
        batch_size = 500
        while True:
            result = await session.execute(
                select(Message)
                .where(
                    Message.ttl.is_not(None),
                    Message.timestamp + Message.ttl < now,
                )
                .limit(batch_size)
            )
            batch = list(result.scalars().all())
            if not batch:
                break
            for msg in batch:
                if msg.media_path:
                    self._secure_delete_file(msg.media_path)
                await session.delete(msg)
                count += 1
            await session.flush()
        if count:
            logger.info(f"Pruned {count} expired messages")
        return count

    async def prune_old_messages(self, session: AsyncSession, retention_days: int) -> int:
        """Delete messages older than retention period using batched queries."""
        if retention_days <= 0:
            return 0
        cutoff = time.time() - (retention_days * 86400)
        # First handle messages with media (need secure delete)
        count = 0
        batch_size = 500
        while True:
            result = await session.execute(
                select(Message)
                .where(
                    Message.timestamp < cutoff,
                    Message.media_path.is_not(None),
                )
                .limit(batch_size)
            )
            batch = list(result.scalars().all())
            if not batch:
                break
            for msg in batch:
                self._secure_delete_file(msg.media_path)
                await session.delete(msg)
                count += 1
            await session.flush()
        # Bulk delete remaining messages without media
        result = await session.execute(
            delete(Message).where(
                Message.timestamp < cutoff,
            )
        )
        count += result.rowcount
        if count:
            await session.flush()
            logger.info(f"Pruned {count} messages older than {retention_days} days")
        return count

    async def prune_retention(self, session: AsyncSession) -> int:
        """Enforce per-channel max_retention by pruning oldest messages."""
        result = await session.execute(select(Channel))
        channels = list(result.scalars().all())
        total = 0
        for ch in channels:
            if ch.max_retention <= 0:
                continue
            count_result = await session.execute(
                select(func.count(Message.msg_hash)).where(Message.channel_id == ch.id)
            )
            count = count_result.scalar() or 0
            if count <= ch.max_retention:
                continue
            excess = count - ch.max_retention
            oldest = await session.execute(
                select(Message)
                .where(Message.channel_id == ch.id)
                .order_by(Message.seq.asc())
                .limit(excess)
            )
            for msg in oldest.scalars().all():
                if msg.media_path:
                    self._secure_delete_file(msg.media_path)
                await session.delete(msg)
                total += 1
        if total:
            await session.flush()
            logger.info(f"Pruned {total} messages for retention limits")
        return total

    async def prune_expired_invites(self, session: AsyncSession) -> int:
        """Delete expired and fully-used invites."""
        now = time.time()
        result = await session.execute(
            delete(Invite).where(
                (Invite.expires_at.is_not(None)) & (Invite.expires_at < now)
                | ((Invite.max_uses > 0) & (Invite.uses >= Invite.max_uses))
            )
        )
        count = result.rowcount
        if count:
            await session.flush()
            logger.info(f"Pruned {count} expired/exhausted invites")
        return count

    async def vacuum(self):
        """VACUUM database for secure deletion of freed pages."""
        async with self.engine.begin() as conn:
            await conn.execute(text("VACUUM"))
        logger.info("Database vacuumed")

    async def scrub_metadata(self, session: AsyncSession, days: int) -> int:
        """Null out sender_hash on messages older than `days` for privacy.

        Designed for whistleblowing/activist nodes (metadata_scrub_days config).
        """
        if days <= 0:
            return 0
        cutoff = time.time() - (days * 86400)
        result = await session.execute(
            update(Message)
            .where(Message.timestamp < cutoff, Message.sender_hash.is_not(None))
            .values(sender_hash=None)
        )
        count = result.rowcount
        if count:
            await session.flush()
            logger.info(f"Scrubbed sender metadata from {count} messages older than {days} days")
        return count

    def _secure_delete_file(self, filepath: str):
        """Overwrite file with zeros before unlinking."""
        path = Path(filepath).resolve()
        if not path.is_relative_to(self.media_dir.resolve()):
            logger.warning(f"Refusing to delete file outside media dir: {path}")
            return
        if path.exists():
            try:
                size = path.stat().st_size
                with open(path, "wb") as f:
                    f.write(b"\x00" * size)
                    f.flush()
                    os.fsync(f.fileno())
                path.unlink()
            except OSError as e:
                logger.warning(f"Failed to securely delete {path}: {e}")
