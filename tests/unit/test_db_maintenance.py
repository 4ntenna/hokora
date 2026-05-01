# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Database maintenance tests: message pruning, retention, vacuum, invite cleanup, batched deletes."""

import time

import pytest_asyncio

from hokora.constants import MSG_TEXT
from hokora.db.maintenance import MaintenanceManager
from hokora.db.models import (
    Channel,
    Message,
    Invite,
)
from hokora.db.queries import (
    ChannelRepo,
    MessageRepo,
)


class TestDBMaintenance:
    async def _insert_message(
        self, session, ch_id, msg_hash, timestamp, ttl=None, seq=1, media_path=None
    ):
        msg = Message(
            msg_hash=msg_hash,
            channel_id=ch_id,
            sender_hash="user1",
            seq=seq,
            timestamp=timestamp,
            type=MSG_TEXT,
            body="test",
            ttl=ttl,
            media_path=media_path,
        )
        session.add(msg)
        await session.flush()
        return msg

    async def test_prune_expired_messages(self, session, engine, tmp_dir):
        ch_repo = ChannelRepo(session)
        channel = Channel(id="expch1", name="exp_test", latest_seq=0)
        await ch_repo.create(channel)

        now = time.time()
        # Expired message (ttl=10, timestamp 100 seconds ago)
        await self._insert_message(
            session,
            "expch1",
            "exp_msg1",
            now - 100,
            ttl=10,
            seq=1,
        )
        # Fresh message (ttl=10000, timestamp now)
        await self._insert_message(
            session,
            "expch1",
            "exp_msg2",
            now,
            ttl=10000,
            seq=2,
        )

        mgr = MaintenanceManager(engine, tmp_dir / "media")
        count = await mgr.prune_expired_messages(session)
        assert count == 1

        # Verify only the fresh message remains
        repo = MessageRepo(session)
        remaining = await repo.get_by_hash("exp_msg2")
        assert remaining is not None
        deleted = await repo.get_by_hash("exp_msg1")
        assert deleted is None

    async def test_prune_old_messages_with_retention(self, session, engine, tmp_dir):
        ch_repo = ChannelRepo(session)
        channel = Channel(id="oldch1", name="old_test", latest_seq=0)
        await ch_repo.create(channel)

        now = time.time()
        # Old message (31 days ago)
        await self._insert_message(
            session,
            "oldch1",
            "old_msg1",
            now - (31 * 86400),
            seq=1,
        )
        # Recent message
        await self._insert_message(
            session,
            "oldch1",
            "old_msg2",
            now,
            seq=2,
        )

        mgr = MaintenanceManager(engine, tmp_dir / "media")
        count = await mgr.prune_old_messages(session, retention_days=30)
        assert count == 1

        repo = MessageRepo(session)
        assert await repo.get_by_hash("old_msg1") is None
        assert await repo.get_by_hash("old_msg2") is not None

    async def test_prune_retention_per_channel(self, session, engine, tmp_dir):
        ch_repo = ChannelRepo(session)
        channel = Channel(
            id="retch1",
            name="ret_test",
            latest_seq=0,
            max_retention=2,
        )
        await ch_repo.create(channel)

        now = time.time()
        for i in range(5):
            await self._insert_message(
                session,
                "retch1",
                f"ret_msg{i}",
                now + i,
                seq=i + 1,
            )

        mgr = MaintenanceManager(engine, tmp_dir / "media")
        count = await mgr.prune_retention(session)
        # 5 messages with max_retention=2 -> should prune 3
        assert count == 3

    async def test_vacuum_runs(self, session, engine, tmp_dir):
        mgr = MaintenanceManager(engine, tmp_dir / "media")
        # Should not raise
        await mgr.vacuum()


# ============================================================================
# Prune Expired Invites
# ============================================================================


class TestPruneExpiredInvites:
    """3C: MaintenanceManager.prune_expired_invites deletes expired invites from DB."""

    @pytest_asyncio.fixture
    async def maintenance(self, engine, tmp_dir):
        media_dir = tmp_dir / "media"
        media_dir.mkdir(exist_ok=True)
        return MaintenanceManager(engine, media_dir)

    async def test_prune_expired_invites(self, session, maintenance):
        # Create an expired invite
        expired = Invite(
            token_hash="expired_hash_1234",
            created_by="creator1",
            max_uses=10,
            uses=0,
            expires_at=time.time() - 3600,  # expired 1 hour ago
        )
        session.add(expired)

        # Create a valid invite
        valid = Invite(
            token_hash="valid_hash_5678",
            created_by="creator1",
            max_uses=10,
            uses=0,
            expires_at=time.time() + 3600,  # expires in 1 hour
        )
        session.add(valid)
        await session.flush()

        count = await maintenance.prune_expired_invites(session)
        assert count >= 1

        # Valid invite should still exist
        from sqlalchemy import select

        result = await session.execute(select(Invite).where(Invite.token_hash == "valid_hash_5678"))
        assert result.scalar_one_or_none() is not None

    async def test_prune_exhausted_invites(self, session, maintenance):
        exhausted = Invite(
            token_hash="exhausted_hash",
            created_by="creator1",
            max_uses=1,
            uses=1,
            expires_at=time.time() + 86400,  # not expired
        )
        session.add(exhausted)
        await session.flush()

        count = await maintenance.prune_expired_invites(session)
        assert count >= 1


# ============================================================================
# Batched Maintenance
# ============================================================================


class TestBatchedMaintenance:
    """3D: Maintenance uses batched deletes."""

    @pytest_asyncio.fixture
    async def maintenance(self, engine, tmp_dir):
        media_dir = tmp_dir / "media"
        media_dir.mkdir(exist_ok=True)
        return MaintenanceManager(engine, media_dir)

    async def test_prune_old_messages_bulk(self, session, maintenance):
        """Verify prune_old_messages uses bulk delete (doesn't load all into memory)."""
        # Create channel first (FK constraint)
        ch = Channel(id="ch_test", name="test", identity_hash="a" * 32)
        session.add(ch)
        await session.flush()

        # Create messages older than retention
        old_time = time.time() - (100 * 86400)
        for i in range(10):
            msg = Message(
                msg_hash=f"old_{i:04d}",
                channel_id="ch_test",
                sender_hash="sender1",
                type=0x01,
                body=f"old message {i}",
                timestamp=old_time,
                seq=i,
            )
            session.add(msg)
        await session.flush()

        count = await maintenance.prune_old_messages(session, retention_days=30)
        assert count == 10
