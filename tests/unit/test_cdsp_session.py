# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for CDSP session lifecycle: init, ack, reject, resume, profile update, expiry."""

import asyncio
import time

import pytest
import pytest_asyncio

from hokora.constants import (
    CDSP_VERSION,
    CDSP_PROFILE_FULL,
    CDSP_PROFILE_PRIORITIZED,
    CDSP_PROFILE_MINIMAL,
    CDSP_PROFILE_BATCHED,
)
from hokora.config import NodeConfig
from hokora.protocol.session import CDSPSessionManager
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


@pytest.fixture
def config():
    return NodeConfig(
        db_encrypt=False,
        cdsp_enabled=True,
        cdsp_session_timeout=3600,
        cdsp_init_timeout=5,
        cdsp_deferred_queue_limit=1000,
    )


@pytest.fixture
def manager(config):
    return CDSPSessionManager(config)


class TestSessionInit:
    async def test_valid_full_profile(self, manager, db_session):
        result = await manager.handle_session_init(
            db_session,
            "identity_abc",
            {"cdsp_version": 1, "sync_profile": CDSP_PROFILE_FULL},
        )
        assert result["rejected"] is False
        assert result["accepted_profile"] == CDSP_PROFILE_FULL
        assert result["cdsp_version"] == CDSP_VERSION
        assert result["session_id"]
        assert result["deferred_count"] == 0

    async def test_valid_prioritized_profile(self, manager, db_session):
        result = await manager.handle_session_init(
            db_session,
            "identity_abc",
            {"cdsp_version": 1, "sync_profile": CDSP_PROFILE_PRIORITIZED},
        )
        assert result["rejected"] is False
        assert result["accepted_profile"] == CDSP_PROFILE_PRIORITIZED

    async def test_valid_minimal_profile(self, manager, db_session):
        result = await manager.handle_session_init(
            db_session,
            "identity_abc",
            {"cdsp_version": 1, "sync_profile": CDSP_PROFILE_MINIMAL},
        )
        assert result["rejected"] is False
        assert result["accepted_profile"] == CDSP_PROFILE_MINIMAL

    async def test_valid_batched_profile(self, manager, db_session):
        result = await manager.handle_session_init(
            db_session,
            "identity_abc",
            {"cdsp_version": 1, "sync_profile": CDSP_PROFILE_BATCHED},
        )
        assert result["rejected"] is False
        assert result["accepted_profile"] == CDSP_PROFILE_BATCHED

    async def test_invalid_profile_zero(self, manager, db_session):
        result = await manager.handle_session_init(
            db_session,
            "identity_abc",
            {"cdsp_version": 1, "sync_profile": 0x00},
        )
        assert result["rejected"] is True
        assert result["error_code"] == 2

    async def test_invalid_profile_high(self, manager, db_session):
        result = await manager.handle_session_init(
            db_session,
            "identity_abc",
            {"cdsp_version": 1, "sync_profile": 0x05},
        )
        assert result["rejected"] is True
        assert result["error_code"] == 2

    async def test_invalid_profile_0xff(self, manager, db_session):
        result = await manager.handle_session_init(
            db_session,
            "identity_abc",
            {"cdsp_version": 1, "sync_profile": 0xFF},
        )
        assert result["rejected"] is True
        assert result["error_code"] == 2

    async def test_future_version_rejected(self, manager, db_session):
        result = await manager.handle_session_init(
            db_session,
            "identity_abc",
            {"cdsp_version": 99, "sync_profile": CDSP_PROFILE_FULL},
        )
        assert result["rejected"] is True
        assert result["error_code"] == 1
        assert result["cdsp_version"] == CDSP_VERSION

    async def test_version_v1_accepted(self, manager, db_session):
        result = await manager.handle_session_init(
            db_session,
            "identity_abc",
            {"cdsp_version": 1, "sync_profile": CDSP_PROFILE_FULL},
        )
        assert result["rejected"] is False
        assert result["cdsp_version"] == 1


class TestSessionResume:
    async def test_resume_with_valid_token(self, manager, db_session):
        # Create initial session
        result1 = await manager.handle_session_init(
            db_session,
            "identity_abc",
            {"cdsp_version": 1, "sync_profile": CDSP_PROFILE_FULL},
        )
        resume_token = result1["resume_token"]

        # Resume session
        result2 = await manager.handle_session_init(
            db_session,
            "identity_abc",
            {
                "cdsp_version": 1,
                "sync_profile": CDSP_PROFILE_PRIORITIZED,
                "resume_token": resume_token,
            },
        )
        assert result2["rejected"] is False
        assert result2.get("resumed") is True
        assert result2["accepted_profile"] == CDSP_PROFILE_PRIORITIZED


class TestProfileUpdate:
    async def test_upgrade_minimal_to_full(self, manager, db_session):
        # Create MINIMAL session
        init = await manager.handle_session_init(
            db_session,
            "identity_abc",
            {"cdsp_version": 1, "sync_profile": CDSP_PROFILE_MINIMAL},
        )
        session_id = init["session_id"]

        # Enqueue a deferred item
        repo = DeferredSyncItemRepo(db_session)
        await repo.enqueue(session_id, "ch1", 0x07, {"query": "test"})

        # Upgrade to FULL
        result = await manager.handle_profile_update(
            db_session,
            session_id,
            CDSP_PROFILE_FULL,
        )
        assert result["rejected"] is False
        assert result["accepted_profile"] == CDSP_PROFILE_FULL
        assert result["flushed_count"] == 1

    async def test_downgrade_full_to_prioritized(self, manager, db_session):
        init = await manager.handle_session_init(
            db_session,
            "identity_abc",
            {"cdsp_version": 1, "sync_profile": CDSP_PROFILE_FULL},
        )
        session_id = init["session_id"]

        result = await manager.handle_profile_update(
            db_session,
            session_id,
            CDSP_PROFILE_PRIORITIZED,
        )
        assert result["rejected"] is False
        assert result["accepted_profile"] == CDSP_PROFILE_PRIORITIZED

    async def test_invalid_profile_rejected(self, manager, db_session):
        init = await manager.handle_session_init(
            db_session,
            "identity_abc",
            {"cdsp_version": 1, "sync_profile": CDSP_PROFILE_FULL},
        )
        result = await manager.handle_profile_update(
            db_session,
            init["session_id"],
            0xFF,
        )
        assert result["rejected"] is True


class TestSessionExpiry:
    async def test_expired_sessions_cleaned_up(self, manager, db_session):
        # Create session with expired last_activity
        repo = SessionRepo(db_session)
        sess = await repo.create_session(
            "old_session",
            "identity_old",
            CDSP_PROFILE_FULL,
        )
        sess.last_activity = time.time() - 7200  # 2 hours ago
        await db_session.flush()

        count = await manager.cleanup_expired_sessions(db_session)
        assert count >= 1

        # Session should be gone
        assert await repo.get_session("old_session") is None


class TestPreCDSPBackwardCompat:
    async def test_no_session_init_defaults_to_full(self, manager, db_session):
        """Pre-CDSP client that never sends Session Init gets FULL profile."""
        # Simulate: no session exists for this identity
        repo = SessionRepo(db_session)
        sess = await repo.get_active_session("legacy_client")
        assert sess is None

        # Handle as if the init timer fired and created a default session
        result = await manager.handle_session_init(
            db_session,
            "legacy_client",
            {"cdsp_version": 1, "sync_profile": CDSP_PROFILE_FULL},
        )
        assert result["rejected"] is False
        assert result["accepted_profile"] == CDSP_PROFILE_FULL

    def test_init_timer_fires(self, manager):
        """Init timer callback is invoked after timeout."""
        loop = asyncio.new_event_loop()
        try:
            callback_called = []

            def cb(identity_hash):
                callback_called.append(identity_hash)

            manager.start_init_timer("test_identity", cb, loop=loop)
            # Advance the event loop past the timeout
            loop.call_soon(loop.stop)
            loop.run_forever()
        finally:
            loop.close()
            asyncio.set_event_loop(None)
