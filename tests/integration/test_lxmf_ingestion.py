# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Integration test: LXMF message -> DB with signature check."""

import time
from unittest.mock import MagicMock

import LXMF

from hokora.core.message import MessageProcessor, MessageEnvelope
from hokora.core.sequencer import SequenceManager
from hokora.db.models import Channel
from hokora.db.queries import ChannelRepo, MessageRepo
from hokora.protocol.lxmf_bridge import LXMFBridge
from hokora.security.lxmf_inbound import reset_for_tests as reset_lxmf_inbound


class TestLXMFIngestion:
    async def test_valid_lxmf_to_db(self, session):
        """Test that a valid LXMF message flows through to the database."""
        # Setup channel
        ch_repo = ChannelRepo(session)
        await ch_repo.create(Channel(id="lxch1", name="lxmf_test", latest_seq=0))

        sequencer = SequenceManager()
        await sequencer.load_from_db(session, "lxch1")
        processor = MessageProcessor(sequencer)

        # Simulate LXMF message arrival
        envelope = MessageEnvelope(
            channel_id="lxch1",
            sender_hash="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
            timestamp=time.time(),
            type=1,
            body="Hello from LXMF!",
            lxmf_signature=b"\x00" * 64,
            display_name="TestUser",
        )

        msg = await processor.ingest(session, envelope)
        assert msg.seq == 1
        assert msg.body == "Hello from LXMF!"
        assert msg.lxmf_signature is not None

        # Verify in DB
        msg_repo = MessageRepo(session)
        retrieved = await msg_repo.get_by_hash(msg.msg_hash)
        assert retrieved is not None
        assert retrieved.display_name == "TestUser"

    async def test_signature_rejection(self, tmp_path):
        """Invalid signatures are rejected and no envelope is dispatched."""
        reset_lxmf_inbound()
        mock_msg = MagicMock()
        mock_msg.signature_validated = False
        mock_msg.unverified_reason = LXMF.LXMessage.SIGNATURE_INVALID
        mock_msg.source_hash = b"\x01" * 16

        callback = MagicMock()
        bridge = LXMFBridge(base_storagepath=str(tmp_path), ingest_callback=callback)

        bridge._on_lxmf_delivery(mock_msg)

        callback.assert_not_called()

    async def test_channel_lifecycle(self, session):
        """Test creating a channel and ingesting multiple messages."""
        ch_repo = ChannelRepo(session)
        await ch_repo.create(Channel(id="lxch2", name="lifecycle", latest_seq=0))

        sequencer = SequenceManager()
        await sequencer.load_from_db(session, "lxch2")
        processor = MessageProcessor(sequencer)

        # Ingest 3 messages
        for i in range(3):
            envelope = MessageEnvelope(
                channel_id="lxch2",
                sender_hash=f"sender_{i:032x}",
                timestamp=time.time() + i,
                body=f"Message {i}",
            )
            msg = await processor.ingest(session, envelope)
            assert msg.seq == i + 1

        # Verify history
        msg_repo = MessageRepo(session)
        history = await msg_repo.get_history("lxch2", since_seq=0, limit=10)
        assert len(history) == 3
        assert history[0].seq == 1
        assert history[2].seq == 3
