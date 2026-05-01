# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Integration test: full sync_history with nonce verification."""

import time


from hokora.constants import SYNC_HISTORY, SYNC_NODE_META
from hokora.core.sequencer import SequenceManager
from hokora.core.channel import ChannelManager
from hokora.core.message import MessageProcessor, MessageEnvelope
from hokora.db.models import Channel
from hokora.db.queries import ChannelRepo
from hokora.protocol.sync import SyncHandler
from hokora.protocol.wire import generate_nonce
from hokora.security.verification import VerificationService

from unittest.mock import MagicMock


class TestSyncProtocol:
    async def test_sync_history_full_flow(self, session, config):
        # Setup channel
        ch_repo = ChannelRepo(session)
        channel = Channel(id="synch1", name="sync_test", latest_seq=0)
        await ch_repo.create(channel)

        sequencer = SequenceManager()
        await sequencer.load_from_db(session, "synch1")

        # Ingest some messages
        processor = MessageProcessor(sequencer)
        for i in range(5):
            await processor.ingest(
                session,
                MessageEnvelope(
                    channel_id="synch1",
                    sender_hash=f"sender{i}",
                    timestamp=time.time() + i,
                    body=f"Message {i}",
                ),
            )

        # Create channel manager mock
        identity_mgr = MagicMock()
        ch_mgr = ChannelManager(config, identity_mgr)
        ch_mgr._channels["synch1"] = channel

        # Create sync handler
        handler = SyncHandler(ch_mgr, sequencer, node_name="TestNode")

        # Generate nonce and make request
        nonce = generate_nonce()
        result = await handler.handle(
            session,
            SYNC_HISTORY,
            nonce,
            payload={"channel_id": "synch1", "since_seq": 0, "limit": 10},
        )

        assert result["action"] == "history"
        assert len(result["messages"]) == 5
        assert result["latest_seq"] == 5
        assert "node_time" in result

        # Verify messages are ordered
        seqs = [m["seq"] for m in result["messages"]]
        assert seqs == [1, 2, 3, 4, 5]

    async def test_sync_node_meta(self, session, config):
        ch_repo = ChannelRepo(session)
        await ch_repo.create(Channel(id="mch1", name="meta_test", latest_seq=3))

        sequencer = SequenceManager()
        identity_mgr = MagicMock()
        ch_mgr = ChannelManager(config, identity_mgr)
        ch_mgr._channels["mch1"] = Channel(
            id="mch1",
            name="meta_test",
            description="A test",
            access_mode="public",
            latest_seq=3,
            identity_hash="abc",
        )

        handler = SyncHandler(ch_mgr, sequencer, node_name="TestNode")
        nonce = generate_nonce()

        result = await handler.handle(session, SYNC_NODE_META, nonce)
        assert result["action"] == "node_meta"
        assert result["node_name"] == "TestNode"
        assert len(result["channels"]) == 1
        assert result["channels"][0]["name"] == "meta_test"

    async def test_nonce_verification(self):
        """Verify nonce echo matches."""
        verifier = VerificationService()
        nonce = generate_nonce()
        assert verifier.verify_sync_nonce(nonce, nonce) is True
