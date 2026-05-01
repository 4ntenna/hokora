# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for CDSP sync profile enforcement on sync handlers."""

import time
from unittest.mock import MagicMock

import pytest_asyncio

from hokora.constants import (
    CDSP_PROFILE_FULL,
    CDSP_PROFILE_PRIORITIZED,
    CDSP_PROFILE_MINIMAL,
    CDSP_PROFILE_BATCHED,
    CDSP_PROFILE_LIMITS,
    NONCE_SIZE,
)
from hokora.config import NodeConfig
from hokora.db.models import Base
from hokora.db.queries import SessionRepo

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


def _make_sync_handler(db_session, cdsp_manager=None):
    """Create a SyncHandler with minimal mocks."""
    from hokora.protocol.sync import SyncHandler
    from hokora.core.channel import ChannelManager
    from hokora.core.sequencer import SequenceManager

    config = NodeConfig(db_encrypt=False)
    ch_mgr = MagicMock(spec=ChannelManager)
    channel = MagicMock()
    channel.access_mode = "public"
    channel.sealed = False
    channel.latest_seq = 10
    ch_mgr.get_channel.return_value = channel
    ch_mgr.list_channels.return_value = [channel]

    sequencer = MagicMock(spec=SequenceManager)
    sequencer.get_cached_seq.return_value = 10

    handler = SyncHandler(
        ch_mgr,
        sequencer,
        node_name="test",
        config=config,
        cdsp_manager=cdsp_manager,
    )
    return handler


async def _create_cdsp_session(db_session, identity_hash, profile):
    """Helper to insert a CDSP session into the DB."""
    repo = SessionRepo(db_session)
    return await repo.create_session(
        session_id=f"sess_{identity_hash}_{profile}",
        identity_hash=identity_hash,
        sync_profile=profile,
        expires_at=time.time() + 3600,
    )


class TestFullProfile:
    async def test_history_returns_up_to_100(self, db_session):
        """FULL profile: history limit should be capped at 100."""
        handler = _make_sync_handler(db_session)

        # No CDSP session => defaults to FULL
        profile = await handler._get_session_profile(db_session, "requester1")
        assert profile["max_sync_limit"] == 100
        assert profile["default_sync_limit"] == 50


class TestPrioritizedProfile:
    async def test_history_limit_20(self, db_session):
        """PRIORITIZED profile: history limit should be ≤20."""
        await _create_cdsp_session(db_session, "requester_p", CDSP_PROFILE_PRIORITIZED)
        handler = _make_sync_handler(db_session, cdsp_manager=MagicMock())

        profile = await handler._get_session_profile(db_session, "requester_p")
        assert profile["max_sync_limit"] == 20
        assert profile["default_sync_limit"] == 10

    async def test_history_direction_backward(self, db_session):
        """PRIORITIZED profile: default direction is backward (newest first)."""
        await _create_cdsp_session(db_session, "requester_p", CDSP_PROFILE_PRIORITIZED)
        handler = _make_sync_handler(db_session, cdsp_manager=MagicMock())

        profile = await handler._get_session_profile(db_session, "requester_p")
        assert profile.get("history_direction") == "backward"

    async def test_node_meta_omits_categories_roles(self, db_session):
        """PRIORITIZED profile: node_meta should not include categories/roles."""
        await _create_cdsp_session(db_session, "requester_p", CDSP_PROFILE_PRIORITIZED)
        handler = _make_sync_handler(db_session, cdsp_manager=MagicMock())

        profile = await handler._get_session_profile(db_session, "requester_p")
        assert profile["include_metadata"] is False


class TestMinimalProfile:
    async def test_search_returns_deferred(self, db_session):
        """MINIMAL profile: search should return deferred=True, no results."""
        await _create_cdsp_session(db_session, "requester_m", CDSP_PROFILE_MINIMAL)
        handler = _make_sync_handler(db_session, cdsp_manager=MagicMock())

        nonce = b"\x00" * NONCE_SIZE
        result = await handler._handle_search(
            db_session,
            nonce,
            {"channel_id": "ch1", "query": "test"},
            "ch1",
            requester_hash="requester_m",
        )
        assert result["deferred"] is True
        assert result["results"] == []

    async def test_fetch_media_returns_deferred(self, db_session):
        """MINIMAL profile: fetch_media should return media_deferred."""
        await _create_cdsp_session(db_session, "requester_m", CDSP_PROFILE_MINIMAL)
        handler = _make_sync_handler(db_session, cdsp_manager=MagicMock())

        nonce = b"\x00" * NONCE_SIZE
        result = await handler._handle_fetch_media(
            db_session,
            nonce,
            {"path": "test.jpg"},
            "ch1",
            requester_hash="requester_m",
        )
        assert result["deferred"] is True
        assert result["action"] == "media_deferred"


class TestBatchedProfile:
    async def test_history_returns_up_to_50(self, db_session):
        """BATCHED profile: history limit should be ≤50."""
        await _create_cdsp_session(db_session, "requester_b", CDSP_PROFILE_BATCHED)
        handler = _make_sync_handler(db_session, cdsp_manager=MagicMock())

        profile = await handler._get_session_profile(db_session, "requester_b")
        assert profile["max_sync_limit"] == 50
        assert profile["default_sync_limit"] == 25


class TestBackwardCompat:
    async def test_no_session_uses_full_limits(self, db_session):
        """No CDSP session → FULL limits (current behavior)."""
        handler = _make_sync_handler(db_session)

        profile = await handler._get_session_profile(db_session, "unknown_requester")
        assert profile["max_sync_limit"] == 100
        assert profile["media_fetch"] is True
        assert profile["live_push"] is True
        assert profile["include_metadata"] is True

    async def test_no_cdsp_manager_uses_full_limits(self, db_session):
        """No CDSP manager configured → FULL limits."""
        handler = _make_sync_handler(db_session, cdsp_manager=None)

        profile = await handler._get_session_profile(db_session, "any_requester")
        assert profile == CDSP_PROFILE_LIMITS[CDSP_PROFILE_FULL]
