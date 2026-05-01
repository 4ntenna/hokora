# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for CDSP deferred sync item management."""

import time

import pytest_asyncio

from hokora.constants import (
    CDSP_PROFILE_FULL,
    CDSP_PROFILE_MINIMAL,
)
from hokora.db.models import Base
from hokora.db.queries import SessionRepo, DeferredSyncItemRepo

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker


@pytest_asyncio.fixture
async def db_session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        async with session.begin():
            yield session
    await engine.dispose()


async def _create_session(db_session, session_id="sess_1", identity_hash="id_1"):
    repo = SessionRepo(db_session)
    return await repo.create_session(
        session_id=session_id,
        identity_hash=identity_hash,
        sync_profile=CDSP_PROFILE_MINIMAL,
        expires_at=time.time() + 3600,
    )


class TestDeferredEnqueue:
    async def test_enqueue_increments_count(self, db_session):
        sess = await _create_session(db_session)
        repo = DeferredSyncItemRepo(db_session)

        await repo.enqueue(sess.session_id, "ch1", 0x07, {"query": "hello"})
        count = await repo.count_for_session(sess.session_id)
        assert count == 1

        await repo.enqueue(sess.session_id, "ch1", 0x09, {"path": "img.jpg"})
        count = await repo.count_for_session(sess.session_id)
        assert count == 2


class TestDeferredEviction:
    async def test_evict_oldest_when_at_limit(self, db_session):
        sess = await _create_session(db_session)
        repo = DeferredSyncItemRepo(db_session)

        # Enqueue 5 items
        for i in range(5):
            await repo.enqueue(sess.session_id, "ch1", 0x07, {"n": i})

        # Evict to keep only 3
        evicted = await repo.evict_oldest(sess.session_id, keep_limit=3)
        assert evicted == 2

        count = await repo.count_for_session(sess.session_id)
        assert count == 3


class TestDeferredFlush:
    async def test_flush_on_profile_upgrade(self, db_session):
        sess = await _create_session(db_session)
        repo = DeferredSyncItemRepo(db_session)

        await repo.enqueue(sess.session_id, "ch1", 0x07, {"query": "test"})
        await repo.enqueue(sess.session_id, "ch1", 0x09, {"path": "file.jpg"})

        flushed = await repo.flush_for_session(sess.session_id, CDSP_PROFILE_FULL)
        assert len(flushed) == 2

        # Queue should be empty now
        count = await repo.count_for_session(sess.session_id)
        assert count == 0


class TestDeferredExpiry:
    async def test_expired_items_cleaned_up(self, db_session):
        sess = await _create_session(db_session)
        repo = DeferredSyncItemRepo(db_session)

        # Enqueue with already-expired TTL
        await repo.enqueue(
            sess.session_id,
            "ch1",
            0x07,
            {"query": "old"},
            ttl=time.time() - 100,
        )
        # Enqueue with future TTL
        await repo.enqueue(
            sess.session_id,
            "ch1",
            0x07,
            {"query": "fresh"},
            ttl=time.time() + 3600,
        )

        cleaned = await repo.cleanup_expired()
        assert cleaned == 1

        count = await repo.count_for_session(sess.session_id)
        assert count == 1


class TestDeferredCountAccuracy:
    async def test_deferred_count_matches_reality(self, db_session):
        sess = await _create_session(db_session)
        repo = DeferredSyncItemRepo(db_session)

        for i in range(7):
            await repo.enqueue(sess.session_id, "ch1", 0x07, {"n": i})

        count = await repo.count_for_session(sess.session_id)
        assert count == 7

        # Flush 3
        await repo.evict_oldest(sess.session_id, keep_limit=4)
        count = await repo.count_for_session(sess.session_id)
        assert count == 4
