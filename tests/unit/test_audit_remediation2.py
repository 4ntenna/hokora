# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for audit remediation round 2 — 13 confirmed issues."""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from hokora.config import NodeConfig
from hokora.constants import (
    MSG_DELETE,
    MSG_EDIT,
    MSG_REACTION,
    MAX_LOCK_ENTRIES,
    MAX_RATE_LIMIT_BUCKETS,
)
from hokora.core.message import MessageEnvelope, MessageProcessor
from hokora.core.sequencer import SequenceManager
from hokora.db.models import Channel
from hokora.db.queries import ChannelRepo
from hokora.exceptions import MessageError, RateLimitExceeded
from hokora.federation.key_rotation import KeyRotationManager
from hokora.security.permissions import PermissionResolver
from hokora.security.ratelimit import RateLimiter


# ===========================================================================
# CRITICAL-1: Cross-channel message edit/reaction/delete
# ===========================================================================


class TestCrossChannelBoundary:
    """Ensure edit/delete/reaction reject targets from a different channel."""

    async def _setup(self, session):
        """Create two channels and a message in channel A."""
        repo = ChannelRepo(session)
        ch_a = Channel(id="ch_a", name="Channel A", latest_seq=0)
        ch_b = Channel(id="ch_b", name="Channel B", latest_seq=0)
        await repo.create(ch_a)
        await repo.create(ch_b)

        sequencer = SequenceManager()
        processor = MessageProcessor(sequencer)

        # Ingest a message in channel A
        env = MessageEnvelope(
            channel_id="ch_a",
            sender_hash="sender1",
            timestamp=1700000000.0,
            body="original message",
        )
        msg = await processor.ingest(session, env)
        return processor, msg

    async def test_edit_rejects_cross_channel_target(self, session):
        processor, msg = await self._setup(session)
        edit_env = MessageEnvelope(
            channel_id="ch_b",  # different channel
            sender_hash="sender1",
            timestamp=1700000001.0,
            type=MSG_EDIT,
            body="edited",
            reply_to=msg.msg_hash,
        )
        with pytest.raises(MessageError, match="does not belong to this channel"):
            await processor.process_edit(session, edit_env)

    async def test_delete_rejects_cross_channel_target(self, session):
        processor, msg = await self._setup(session)
        del_env = MessageEnvelope(
            channel_id="ch_b",
            sender_hash="sender1",
            timestamp=1700000002.0,
            type=MSG_DELETE,
            reply_to=msg.msg_hash,
        )
        with pytest.raises(MessageError, match="does not belong to this channel"):
            await processor.process_delete(session, del_env)

    async def test_reaction_rejects_cross_channel_target(self, session):
        processor, msg = await self._setup(session)
        react_env = MessageEnvelope(
            channel_id="ch_b",
            sender_hash="sender1",
            timestamp=1700000003.0,
            type=MSG_REACTION,
            body="👍",
            reply_to=msg.msg_hash,
        )
        with pytest.raises(MessageError, match="does not belong to this channel"):
            await processor.process_reaction(session, react_env)


# ===========================================================================
# HIGH-1: Permission resolver cache invalidation
# ===========================================================================


class TestPermissionResolverNoCaching:
    """Ensure @everyone role is always fetched fresh."""

    async def test_everyone_role_reflects_runtime_changes(self, session):
        resolver = PermissionResolver(node_owner_hash="owner_hash")
        role_repo = MagicMock()

        # First call returns permissions=0
        mock_role_v1 = MagicMock()
        mock_role_v1.permissions = 0
        mock_role_v2 = MagicMock()
        mock_role_v2.permissions = 0xFF

        role_repo.get_by_name = AsyncMock(side_effect=[mock_role_v1, mock_role_v2])

        r1 = await resolver._get_everyone_role(role_repo)
        assert r1.permissions == 0

        # Second call should get updated permissions (no caching)
        r2 = await resolver._get_everyone_role(role_repo)
        assert r2.permissions == 0xFF


# ===========================================================================
# HIGH-2: Sequencer lock eviction batch size
# ===========================================================================


class TestSequencerLockEviction:
    """Verify lock eviction at capacity works correctly."""

    def test_lock_eviction_at_capacity(self):
        seq = SequenceManager()
        lock_dict = seq._locks

        # Fill to capacity
        for i in range(MAX_LOCK_ENTRIES):
            lock_dict[f"key_{i}"] = asyncio.Lock()

        # Getting a new key should still work (eviction clears space)
        new_lock = seq._get_lock("new_key", lock_dict)
        assert isinstance(new_lock, asyncio.Lock)
        assert "new_key" in lock_dict

    def test_lock_eviction_preserves_locked_entries(self):
        seq = SequenceManager()
        lock_dict = seq._locks

        # Create a locked entry at the beginning (first to be evicted)
        locked = asyncio.Lock()
        locked._locked = True  # simulate locked state
        lock_dict["locked_key"] = locked

        # Fill rest to capacity
        for i in range(MAX_LOCK_ENTRIES - 1):
            lock_dict[f"key_{i}"] = asyncio.Lock()

        # Trigger eviction
        seq._get_lock("trigger_key", lock_dict)

        # Locked entry should survive eviction
        assert "locked_key" in lock_dict


# ===========================================================================
# HIGH-3: Hash truncation removed
# ===========================================================================


class TestFullSha256Hash:
    """Verify compute_hash returns full 64-char SHA-256."""

    def test_compute_hash_returns_full_sha256(self):
        env = MessageEnvelope(
            channel_id="ch1",
            sender_hash="sender1",
            timestamp=1700000000.0,
            body="Hello",
        )
        h = env.compute_hash()
        assert len(h) == 64
        # Verify it's valid hex
        int(h, 16)


# ===========================================================================
# HIGH-4: Slowmode dict cap
# ===========================================================================


class TestSlowmodeDictCapped:
    """Verify _slowmode_last is capped at MAX_BUCKETS."""

    def test_slowmode_dict_capped(self):
        limiter = RateLimiter()
        # Fill slowmode dict to capacity with stale entries
        now = time.time()
        for i in range(MAX_RATE_LIMIT_BUCKETS):
            limiter._slowmode_last[f"id_{i}:ch_{i}"] = now - 700  # stale (>600s)

        # Next check should trigger cleanup and succeed
        limiter.check_slowmode("new_id", "new_ch", 5)
        assert len(limiter._slowmode_last) < MAX_RATE_LIMIT_BUCKETS + 1

    def test_slowmode_cap_raises_when_all_fresh(self):
        limiter = RateLimiter()
        now = time.time()
        for i in range(MAX_RATE_LIMIT_BUCKETS):
            limiter._slowmode_last[f"id_{i}:ch_{i}"] = now  # all fresh

        with pytest.raises(RateLimitExceeded, match="Too many tracked slowmode"):
            limiter.check_slowmode("new_id", "new_ch", 5)


# ===========================================================================
# MEDIUM-1: Config epoch duration validation
# ===========================================================================


class TestConfigEpochValidation:
    def test_invalid_epoch_duration_too_low(self, tmp_dir):
        with pytest.raises(ValueError, match="fs_epoch_duration"):
            NodeConfig(
                data_dir=tmp_dir,
                db_encrypt=False,
                fs_epoch_duration=100,  # below min of 300
                fs_min_epoch_duration=300,
                fs_max_epoch_duration=86400,
            )

    def test_invalid_epoch_duration_too_high(self, tmp_dir):
        with pytest.raises(ValueError, match="fs_epoch_duration"):
            NodeConfig(
                data_dir=tmp_dir,
                db_encrypt=False,
                fs_epoch_duration=100000,  # above max of 86400
                fs_min_epoch_duration=300,
                fs_max_epoch_duration=86400,
            )

    def test_invalid_min_gte_max(self, tmp_dir):
        with pytest.raises(ValueError, match="fs_min_epoch_duration must be less"):
            NodeConfig(
                data_dir=tmp_dir,
                db_encrypt=False,
                fs_epoch_duration=3600,
                fs_min_epoch_duration=86400,
                fs_max_epoch_duration=300,
            )

    def test_valid_epoch_duration_accepted(self, tmp_dir):
        config = NodeConfig(
            data_dir=tmp_dir,
            db_encrypt=False,
            fs_epoch_duration=3600,
            fs_min_epoch_duration=300,
            fs_max_epoch_duration=86400,
        )
        assert config.fs_epoch_duration == 3600


# ===========================================================================
# MEDIUM-2: Key rotation grace period cleanup
# ===========================================================================


class TestKeyRotationCleanup:
    def test_expired_rotation_cleaned_up(self):
        mgr = KeyRotationManager()
        mgr._pending_rotations["ch1"] = {
            "grace_end": time.time() - 1,  # already expired
        }
        assert mgr.is_in_grace_period("ch1") is False
        assert "ch1" not in mgr._pending_rotations

    def test_grace_period_true_when_active(self):
        mgr = KeyRotationManager()
        mgr._pending_rotations["ch2"] = {
            "grace_end": time.time() + 3600,  # still active
        }
        assert mgr.is_in_grace_period("ch2") is True
        assert "ch2" in mgr._pending_rotations


# ===========================================================================
# LOW-2: Reaction emoji length validation
# ===========================================================================


class TestEmojiLengthValidation:
    async def test_reaction_rejects_oversized_emoji(self, session):
        repo = ChannelRepo(session)
        ch = Channel(id="ch_emoji", name="emoji_test", latest_seq=0)
        await repo.create(ch)

        sequencer = SequenceManager()
        processor = MessageProcessor(sequencer)

        # Create a target message
        target_env = MessageEnvelope(
            channel_id="ch_emoji",
            sender_hash="sender1",
            timestamp=1700000000.0,
            body="target",
        )
        target = await processor.ingest(session, target_env)

        # Attempt reaction with oversized emoji
        react_env = MessageEnvelope(
            channel_id="ch_emoji",
            sender_hash="sender1",
            timestamp=1700000001.0,
            type=MSG_REACTION,
            body="x" * 33,
            reply_to=target.msg_hash,
        )
        with pytest.raises(MessageError, match="emoji too long"):
            await processor.process_reaction(session, react_env)

    async def test_reaction_accepts_valid_emoji(self, session):
        repo = ChannelRepo(session)
        ch = Channel(id="ch_emoji2", name="emoji_test2", latest_seq=0)
        await repo.create(ch)

        sequencer = SequenceManager()
        processor = MessageProcessor(sequencer)

        target_env = MessageEnvelope(
            channel_id="ch_emoji2",
            sender_hash="sender1",
            timestamp=1700000000.0,
            body="target",
        )
        target = await processor.ingest(session, target_env)

        react_env = MessageEnvelope(
            channel_id="ch_emoji2",
            sender_hash="sender1",
            timestamp=1700000001.0,
            type=MSG_REACTION,
            body="👍",
            reply_to=target.msg_hash,
        )
        result = await processor.process_reaction(session, react_env)
        assert "👍" in result.reactions
