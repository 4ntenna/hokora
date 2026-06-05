# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""A message-mutation handler must reject a target message that belongs to a
different channel than the one being addressed."""

import pytest

from hokora.constants import MSG_DELETE, MSG_EDIT, MSG_PIN, MSG_REACTION
from hokora.core.message import MessageEnvelope, MessageProcessor
from hokora.core.sequencer import SequenceManager
from hokora.db.models import Channel
from hokora.db.queries import ChannelRepo
from hokora.exceptions import MessageError


class TestCrossChannelBoundary:
    """Ensure edit/delete/pin/reaction reject targets from a different channel."""

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

    async def test_pin_rejects_cross_channel_target(self, session):
        processor, msg = await self._setup(session)
        pin_env = MessageEnvelope(
            channel_id="ch_b",
            sender_hash="sender1",
            timestamp=1700000004.0,
            type=MSG_PIN,
            reply_to=msg.msg_hash,
        )
        with pytest.raises(MessageError, match="does not belong to this channel"):
            await processor.process_pin(session, pin_env)

    @pytest.mark.parametrize(
        "msg_type,body",
        [
            (MSG_EDIT, "edited"),
            (MSG_DELETE, ""),
            (MSG_PIN, ""),
            (MSG_REACTION, "👍"),
        ],
    )
    async def test_mutation_rejects_cross_channel_target_via_ingest(self, session, msg_type, body):
        """Drive every mutation type through ingest() so a handler that fetches a
        target without the shared channel check is caught."""
        processor, msg = await self._setup(session)
        env = MessageEnvelope(
            channel_id="ch_b",
            sender_hash="sender1",
            timestamp=1700000005.0,
            type=msg_type,
            body=body,
            reply_to=msg.msg_hash,
        )
        with pytest.raises(MessageError, match="does not belong to this channel"):
            await processor.ingest(session, env)
