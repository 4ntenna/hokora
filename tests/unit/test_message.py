# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Test message ingestion and dedup."""

import pytest

from hokora.core.message import MessageEnvelope, MessageProcessor
from hokora.core.sequencer import SequenceManager
from hokora.db.models import Channel, Thread
from hokora.db.queries import ChannelRepo
from hokora.exceptions import MessageError
from hokora.constants import MSG_TEXT, MSG_THREAD_REPLY


class TestMessageEnvelope:
    def test_compute_hash_deterministic(self):
        env = MessageEnvelope(
            channel_id="ch1",
            sender_hash="sender1",
            timestamp=1700000000.0,
            type=MSG_TEXT,
            body="Hello",
        )
        h1 = env.compute_hash()
        h2 = env.compute_hash()
        assert h1 == h2
        assert len(h1) == 64

    def test_different_messages_different_hashes(self):
        env1 = MessageEnvelope(
            channel_id="ch1",
            sender_hash="sender1",
            timestamp=1700000000.0,
            body="Hello",
        )
        env2 = MessageEnvelope(
            channel_id="ch1",
            sender_hash="sender1",
            timestamp=1700000001.0,
            body="Hello",
        )
        assert env1.compute_hash() != env2.compute_hash()

    def test_reply_to_included_in_hash(self):
        """reply_to field must affect hash to distinguish edits/deletes targeting different msgs."""
        env1 = MessageEnvelope(
            channel_id="ch1",
            sender_hash="sender1",
            timestamp=1700000000.0,
            body="edit text",
            reply_to="aaa",
        )
        env2 = MessageEnvelope(
            channel_id="ch1",
            sender_hash="sender1",
            timestamp=1700000000.0,
            body="edit text",
            reply_to="bbb",
        )
        assert env1.compute_hash() != env2.compute_hash()

    def test_reply_to_none_vs_set(self):
        """Hash differs between a message with no reply_to and one with reply_to."""
        env1 = MessageEnvelope(
            channel_id="ch1",
            sender_hash="sender1",
            timestamp=1700000000.0,
            body="Hello",
        )
        env2 = MessageEnvelope(
            channel_id="ch1",
            sender_hash="sender1",
            timestamp=1700000000.0,
            body="Hello",
            reply_to="target_hash",
        )
        assert env1.compute_hash() != env2.compute_hash()


class TestMessageProcessor:
    async def test_ingest_message(self, session):
        # Create channel
        repo = ChannelRepo(session)
        channel = Channel(id="testch", name="test", latest_seq=0)
        await repo.create(channel)

        sequencer = SequenceManager()
        await sequencer.load_from_db(session, "testch")

        processor = MessageProcessor(sequencer)
        envelope = MessageEnvelope(
            channel_id="testch",
            sender_hash="sender1",
            timestamp=1700000000.0,
            body="Test message",
        )

        msg = await processor.ingest(session, envelope)
        assert msg.seq == 1
        assert msg.body == "Test message"
        assert msg.channel_id == "testch"

    async def test_dedup(self, session):
        repo = ChannelRepo(session)
        channel = Channel(id="testch2", name="test2", latest_seq=0)
        await repo.create(channel)

        sequencer = SequenceManager()
        await sequencer.load_from_db(session, "testch2")

        processor = MessageProcessor(sequencer)
        envelope = MessageEnvelope(
            channel_id="testch2",
            sender_hash="sender1",
            timestamp=1700000000.0,
            body="Duplicate",
        )

        msg1 = await processor.ingest(session, envelope)
        msg2 = await processor.ingest(session, envelope)
        assert msg1.msg_hash == msg2.msg_hash
        assert msg1.seq == msg2.seq  # same message, same seq

    async def test_invalid_channel(self, session):
        sequencer = SequenceManager()
        processor = MessageProcessor(sequencer)
        envelope = MessageEnvelope(
            channel_id="nonexistent",
            sender_hash="sender1",
            timestamp=1700000000.0,
            body="Fail",
        )

        with pytest.raises(MessageError, match="not found"):
            await processor.ingest(session, envelope)

    async def test_body_too_large(self, session):
        repo = ChannelRepo(session)
        channel = Channel(id="testch3", name="test3", latest_seq=0)
        await repo.create(channel)

        sequencer = SequenceManager()
        await sequencer.load_from_db(session, "testch3")

        processor = MessageProcessor(sequencer)
        envelope = MessageEnvelope(
            channel_id="testch3",
            sender_hash="sender1",
            timestamp=1700000000.0,
            body="x" * 40000,
        )

        with pytest.raises(MessageError, match="maximum size"):
            await processor.ingest(session, envelope)

    async def test_ingest_sets_origin_node(self, session):
        """C1: origin_node should be set from node_identity_hash."""
        repo = ChannelRepo(session)
        channel = Channel(id="testch_origin", name="origin_test", latest_seq=0)
        await repo.create(channel)

        sequencer = SequenceManager()
        await sequencer.load_from_db(session, "testch_origin")

        node_hash = "abcdef1234567890" * 2
        processor = MessageProcessor(sequencer, node_identity_hash=node_hash)
        envelope = MessageEnvelope(
            channel_id="testch_origin",
            sender_hash="sender1",
            timestamp=1700000000.0,
            body="Test origin",
        )

        msg = await processor.ingest(session, envelope)
        assert msg.origin_node == node_hash

    async def test_ingest_origin_node_none_when_not_set(self, session):
        """C1 backward compat: no node_identity_hash → origin_node is None."""
        repo = ChannelRepo(session)
        channel = Channel(id="testch_no_origin", name="no_origin", latest_seq=0)
        await repo.create(channel)

        sequencer = SequenceManager()
        await sequencer.load_from_db(session, "testch_no_origin")

        processor = MessageProcessor(sequencer)
        envelope = MessageEnvelope(
            channel_id="testch_no_origin",
            sender_hash="sender1",
            timestamp=1700000000.0,
            body="No origin",
        )

        msg = await processor.ingest(session, envelope)
        assert msg.origin_node is None

    async def test_thread_replies_preserve_all_participants(self, session):
        """Multiple replies to the same thread must preserve all participants."""
        from sqlalchemy import select

        repo = ChannelRepo(session)
        channel = Channel(id="testch_conc", name="conc_test", latest_seq=0)
        await repo.create(channel)

        sequencer = SequenceManager()
        await sequencer.load_from_db(session, "testch_conc")

        processor = MessageProcessor(sequencer)

        # Create root message
        root_env = MessageEnvelope(
            channel_id="testch_conc",
            sender_hash="sender_root",
            timestamp=1700000000.0,
            body="Root",
        )
        root_msg = await processor.ingest(session, root_env)

        # Send replies from different senders
        for i, sender in enumerate(["sender_a", "sender_b", "sender_c"]):
            env = MessageEnvelope(
                channel_id="testch_conc",
                sender_hash=sender,
                timestamp=1700000000.0 + i + 1,
                body=f"Reply from {sender}",
                type=MSG_THREAD_REPLY,
                reply_to=root_msg.msg_hash,
            )
            await processor.ingest(session, env)

        result = await session.execute(
            select(Thread).where(Thread.root_msg_hash == root_msg.msg_hash)
        )
        thread = result.scalar_one()
        assert thread.reply_count == 3
        # All 3 senders must be in participant_hashes
        assert set(thread.participant_hashes) == {"sender_a", "sender_b", "sender_c"}
        # Verify the thread lock was created for this root hash
        assert root_msg.msg_hash in processor._thread_locks

    async def test_message_processor_has_thread_locks(self, session):
        """MessageProcessor must have _thread_locks dict."""
        sequencer = SequenceManager()
        processor = MessageProcessor(sequencer)
        assert isinstance(processor._thread_locks, dict)

    async def test_thread_reply_count_after_two_replies(self, session):
        """H6: Atomic reply_count increment — two replies should yield count=2."""
        from sqlalchemy import select

        repo = ChannelRepo(session)
        channel = Channel(id="testch_thread", name="thread_test", latest_seq=0)
        await repo.create(channel)

        sequencer = SequenceManager()
        await sequencer.load_from_db(session, "testch_thread")

        processor = MessageProcessor(sequencer)

        # Create root message
        root_env = MessageEnvelope(
            channel_id="testch_thread",
            sender_hash="sender1",
            timestamp=1700000000.0,
            body="Root",
        )
        root_msg = await processor.ingest(session, root_env)

        # First reply
        reply1 = MessageEnvelope(
            channel_id="testch_thread",
            sender_hash="sender2",
            timestamp=1700000001.0,
            body="Reply 1",
            type=MSG_THREAD_REPLY,
            reply_to=root_msg.msg_hash,
        )
        await processor.ingest(session, reply1)

        # Second reply
        reply2 = MessageEnvelope(
            channel_id="testch_thread",
            sender_hash="sender3",
            timestamp=1700000002.0,
            body="Reply 2",
            type=MSG_THREAD_REPLY,
            reply_to=root_msg.msg_hash,
        )
        await processor.ingest(session, reply2)

        # Verify count via fresh query
        result = await session.execute(
            select(Thread).where(Thread.root_msg_hash == root_msg.msg_hash)
        )
        thread = result.scalar_one()
        assert thread.reply_count == 2
