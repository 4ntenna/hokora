# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for bug fixes (Bugs 1-12)."""

import time
import tempfile
from pathlib import Path
from unittest.mock import MagicMock


from hokora.constants import (
    MSG_PIN,
    MSG_EDIT,
    INVITE_FAILURE_BLOCK_THRESHOLD,
)
from hokora.core.message import MessageEnvelope, MessageProcessor
from hokora.core.sequencer import SequenceManager
from hokora.db.maintenance import MaintenanceManager
from hokora.db.models import Channel, Message
from hokora.db.queries import ChannelRepo, MessageRepo
from hokora.security.invites import InviteManager
from hokora.security.ratelimit import RateLimiter


# --- Bug 3: Backward pagination without before_seq ---


class TestBackwardPaginationNoBefore:
    async def test_backward_no_before_seq(self, session):
        """Backward direction without before_seq returns messages before since_seq."""
        ch_repo = ChannelRepo(session)
        await ch_repo.create(Channel(id="bpch1", name="bp_test", latest_seq=0))

        msg_repo = MessageRepo(session)
        for i in range(1, 11):
            await msg_repo.insert(
                Message(
                    msg_hash=f"bp{i:03d}",
                    channel_id="bpch1",
                    sender_hash="s1",
                    seq=i,
                    timestamp=time.time(),
                    type=1,
                    body=f"Message {i}",
                )
            )

        # Backward from since_seq=8, no before_seq -> should get messages < 8
        messages = await msg_repo.get_history(
            "bpch1",
            since_seq=8,
            direction="backward",
            limit=3,
        )
        assert len(messages) == 3
        # Should be messages with seq 5, 6, 7 (ascending after reverse)
        assert all(m.seq < 8 for m in messages)
        assert messages[-1].seq == 7


# --- Bug 2: Pin system message gets unique hash ---


class TestPinUniqueSystemHash:
    async def test_pin_creates_unique_system_message(self, session):
        """Pin system message hash differs from the pin request envelope hash."""
        ch_repo = ChannelRepo(session)
        await ch_repo.create(Channel(id="pinuch1", name="pin_unique", latest_seq=0))

        sequencer = SequenceManager()
        await sequencer.load_from_db(session, "pinuch1")
        processor = MessageProcessor(sequencer)

        # Create a message to pin
        msg_env = MessageEnvelope(
            channel_id="pinuch1",
            sender_hash="user1",
            timestamp=time.time(),
            body="Pin target",
        )
        msg = await processor.ingest(session, msg_env)

        # Pin it
        pin_env = MessageEnvelope(
            channel_id="pinuch1",
            sender_hash="user1",
            timestamp=time.time() + 1,
            type=MSG_PIN,
            reply_to=msg.msg_hash,
        )
        pin_envelope_hash = pin_env.compute_hash()
        sys_msg = await processor.ingest(session, pin_env)

        # System message hash should differ from the envelope hash
        assert sys_msg.msg_hash != pin_envelope_hash


# --- Bug 4: Invite failure only counts failures ---


class TestInviteFailureOnlyCountsFailures:
    async def test_successful_redemptions_dont_trigger_block(self, session):
        """Successful redemptions should not count toward the failure block."""
        mgr = InviteManager()

        # Create enough invites for successful redemptions
        for i in range(INVITE_FAILURE_BLOCK_THRESHOLD + 1):
            raw_token, _ = await mgr.create_invite(
                session,
                "creator",
                max_uses=1,
            )
            await mgr.redeem_invite(session, raw_token, "redeemer_hash")

        # User should NOT be blocked — all were successful
        # This should not raise
        raw_token, _ = await mgr.create_invite(session, "creator", max_uses=1)
        invite = await mgr.redeem_invite(session, raw_token, "redeemer_hash")
        assert invite.uses == 1


# --- Bug 5: Slowmode cleanup ---


class TestSlowmodeCleanup:
    def test_cleanup_removes_stale_slowmode(self):
        limiter = RateLimiter()
        # Manually set old slowmode entries
        limiter._slowmode_last["user1:ch1"] = time.time() - 7200
        limiter._slowmode_last["user2:ch2"] = time.time()

        limiter.cleanup_stale(max_age=3600)

        assert "user1:ch1" not in limiter._slowmode_last
        assert "user2:ch2" in limiter._slowmode_last


# --- Bug 6: Path traversal in secure delete ---


class TestSecureDeletePathTraversal:
    def test_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            media_dir = Path(tmpdir) / "media"
            media_dir.mkdir()

            engine = MagicMock()
            mgr = MaintenanceManager(engine, media_dir)

            # Attempt to delete a file outside media_dir
            traversal_path = str(media_dir / ".." / ".." / "etc" / "passwd")
            # Should not raise, just log warning and return
            mgr._secure_delete_file(traversal_path)

            # A file inside media_dir should be allowed
            safe_file = media_dir / "test.bin"
            safe_file.write_bytes(b"data")
            mgr._secure_delete_file(str(safe_file))
            assert not safe_file.exists()


# --- Bug 11: Edit messages don't appear in main timeline ---


class TestEditNoMainSeq:
    async def test_edit_no_main_seq(self, session):
        """Edit messages should have seq=None and not appear in main timeline."""
        ch_repo = ChannelRepo(session)
        await ch_repo.create(Channel(id="editseqch", name="edit_seq", latest_seq=0))

        sequencer = SequenceManager()
        await sequencer.load_from_db(session, "editseqch")
        processor = MessageProcessor(sequencer)

        # Create original message
        msg_env = MessageEnvelope(
            channel_id="editseqch",
            sender_hash="author1",
            timestamp=time.time(),
            body="Original",
        )
        msg = await processor.ingest(session, msg_env)
        assert msg.seq == 1

        # Edit it
        edit_env = MessageEnvelope(
            channel_id="editseqch",
            sender_hash="author1",
            timestamp=time.time() + 1,
            type=MSG_EDIT,
            body="Edited text",
            reply_to=msg.msg_hash,
        )
        edit_msg = await processor.ingest(session, edit_env)
        assert edit_msg.seq is None  # No main timeline seq

        # Next normal message should get seq=2, not 3
        msg2_env = MessageEnvelope(
            channel_id="editseqch",
            sender_hash="author1",
            timestamp=time.time() + 2,
            body="Next message",
        )
        msg2 = await processor.ingest(session, msg2_env)
        assert msg2.seq == 2

        # History should not include edit message
        msg_repo = MessageRepo(session)
        history = await msg_repo.get_history("editseqch", since_seq=0, limit=50)
        hashes = [m.msg_hash for m in history]
        assert edit_msg.msg_hash not in hashes
