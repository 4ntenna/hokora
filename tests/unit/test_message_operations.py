# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Message operation handler tests: edit, delete, pin, reaction, thread sequencing."""

import time
from unittest.mock import MagicMock

import pytest

from hokora.constants import (
    MSG_THREAD_REPLY,
    MSG_REACTION,
    MSG_DELETE,
    MSG_PIN,
    MSG_EDIT,
    PERM_SEND_MESSAGES,
    SYNC_HISTORY,
)
from hokora.core.channel import ChannelManager
from hokora.core.message import MessageEnvelope, MessageProcessor
from hokora.core.sequencer import SequenceManager
from hokora.db.models import Channel
from hokora.db.queries import (
    ChannelRepo,
    MessageRepo,
    IdentityRepo,
    RoleRepo,
)
from hokora.exceptions import PermissionDenied
from hokora.protocol.sync import SyncHandler
from hokora.protocol.wire import generate_nonce
from hokora.security.permissions import PermissionResolver
from hokora.security.roles import RoleManager


class TestOperationHandlers:
    async def _setup_with_message(self, session, channel_id="opch"):
        ch_repo = ChannelRepo(session)
        channel = Channel(id=channel_id, name="op_test", latest_seq=0)
        await ch_repo.create(channel)

        sequencer = SequenceManager()
        await sequencer.load_from_db(session, channel_id)
        processor = MessageProcessor(sequencer=sequencer)

        # Ingest a base message
        envelope = MessageEnvelope(
            channel_id=channel_id,
            sender_hash="author1",
            timestamp=time.time(),
            body="Original message",
        )
        msg = await processor.ingest(session, envelope)
        return processor, msg

    async def test_edit_wrong_sender(self, session):
        processor, msg = await self._setup_with_message(session, "editwch")

        edit_env = MessageEnvelope(
            channel_id="editwch",
            sender_hash="not_author",
            timestamp=time.time(),
            type=MSG_EDIT,
            body="Edited text",
            reply_to=msg.msg_hash,
        )

        with pytest.raises(PermissionDenied, match="author"):
            await processor.ingest(session, edit_env)

    async def test_edit_by_author(self, session):
        processor, msg = await self._setup_with_message(session, "editach")

        edit_env = MessageEnvelope(
            channel_id="editach",
            sender_hash="author1",
            timestamp=time.time(),
            type=MSG_EDIT,
            body="Edited text",
            reply_to=msg.msg_hash,
        )

        result = await processor.ingest(session, edit_env)
        assert result.body == "Edited text"

        # Verify edit chain updated
        msg_repo = MessageRepo(session)
        original = await msg_repo.get_by_hash(msg.msg_hash)
        assert len(original.edit_chain) == 1

    async def test_delete_requires_permission(self, session):
        """Delete of another's message without PERM_DELETE_OTHERS should be denied."""
        ch_repo = ChannelRepo(session)
        channel = Channel(id="delch", name="del_test", latest_seq=0)
        await ch_repo.create(channel)

        mgr = RoleManager()
        await mgr.ensure_builtin_roles(session)

        # Strip DELETE_OTHERS from everyone
        role_repo = RoleRepo(session)
        everyone = await role_repo.get_by_name("everyone")
        if everyone:
            everyone.permissions = PERM_SEND_MESSAGES  # only send
            await session.flush()

        ident_repo = IdentityRepo(session)
        await ident_repo.upsert("author_del")
        await ident_repo.upsert("other_del")

        sequencer = SequenceManager()
        await sequencer.load_from_db(session, "delch")
        resolver = PermissionResolver(node_owner_hash="node_owner_hash")
        processor = MessageProcessor(
            sequencer=sequencer,
            permission_resolver=resolver,
            identity_repo=ident_repo,
        )

        # Author posts a message
        msg_env = MessageEnvelope(
            channel_id="delch",
            sender_hash="author_del",
            timestamp=time.time(),
            body="Delete me",
        )
        msg = await processor.ingest(session, msg_env)

        # Other user tries to delete
        del_env = MessageEnvelope(
            channel_id="delch",
            sender_hash="other_del",
            timestamp=time.time(),
            type=MSG_DELETE,
            reply_to=msg.msg_hash,
        )

        with pytest.raises(PermissionDenied, match="DELETE_OTHERS"):
            await processor.ingest(session, del_env)

    async def test_pin_requires_permission(self, session):
        """Pin without PERM_PIN_MESSAGES should be denied."""
        ch_repo = ChannelRepo(session)
        channel = Channel(id="pinch", name="pin_test", latest_seq=0)
        await ch_repo.create(channel)

        mgr = RoleManager()
        await mgr.ensure_builtin_roles(session)

        role_repo = RoleRepo(session)
        everyone = await role_repo.get_by_name("everyone")
        if everyone:
            everyone.permissions = PERM_SEND_MESSAGES  # no pin perm
            await session.flush()

        ident_repo = IdentityRepo(session)
        await ident_repo.upsert("pin_user")

        sequencer = SequenceManager()
        await sequencer.load_from_db(session, "pinch")
        resolver = PermissionResolver(node_owner_hash="node_owner_hash")
        processor = MessageProcessor(
            sequencer=sequencer,
            permission_resolver=resolver,
            identity_repo=ident_repo,
        )

        # Create a message to pin
        msg_env = MessageEnvelope(
            channel_id="pinch",
            sender_hash="pin_user",
            timestamp=time.time(),
            body="Pin me",
        )
        msg = await processor.ingest(session, msg_env)

        # Try to pin
        pin_env = MessageEnvelope(
            channel_id="pinch",
            sender_hash="pin_user",
            timestamp=time.time() + 1,
            type=MSG_PIN,
            reply_to=msg.msg_hash,
        )

        with pytest.raises(PermissionDenied, match="PIN_MESSAGES"):
            await processor.ingest(session, pin_env)

    async def test_reaction_dedup(self, session):
        processor, msg = await self._setup_with_message(session, "reactch")

        # First reaction
        react_env = MessageEnvelope(
            channel_id="reactch",
            sender_hash="reactor1",
            timestamp=time.time(),
            type=MSG_REACTION,
            body="\U0001f44d",
            reply_to=msg.msg_hash,
        )
        await processor.ingest(session, react_env)

        # Duplicate reaction (same emoji, same identity)
        react_env2 = MessageEnvelope(
            channel_id="reactch",
            sender_hash="reactor1",
            timestamp=time.time() + 1,
            type=MSG_REACTION,
            body="\U0001f44d",
            reply_to=msg.msg_hash,
        )
        await processor.ingest(session, react_env2)

        # Should still be count=1
        msg_repo = MessageRepo(session)
        updated = await msg_repo.get_by_hash(msg.msg_hash)
        assert updated.reactions["\U0001f44d"]["count"] == 1


# ============================================================================
# Thread replies don't appear in main timeline
# ============================================================================


class TestThreadNoMainSeq:
    async def test_thread_no_main_seq(self, session, config):
        ch_repo = ChannelRepo(session)
        channel = Channel(id="thrch1", name="thread_test", latest_seq=0)
        await ch_repo.create(channel)

        sequencer = SequenceManager()
        await sequencer.load_from_db(session, "thrch1")
        processor = MessageProcessor(sequencer)

        # Post a normal message
        root_env = MessageEnvelope(
            channel_id="thrch1",
            sender_hash="user1",
            timestamp=time.time(),
            body="Root message",
        )
        root_msg = await processor.ingest(session, root_env)
        assert root_msg.seq == 1

        # Post a thread reply
        reply_env = MessageEnvelope(
            channel_id="thrch1",
            sender_hash="user2",
            timestamp=time.time() + 1,
            type=MSG_THREAD_REPLY,
            body="Thread reply",
            reply_to=root_msg.msg_hash,
        )
        reply_msg = await processor.ingest(session, reply_env)
        assert reply_msg.seq is None  # No main timeline seq
        assert reply_msg.thread_seq is not None
        assert reply_msg.thread_seq >= 1

        # Post another normal message
        normal_env = MessageEnvelope(
            channel_id="thrch1",
            sender_hash="user1",
            timestamp=time.time() + 2,
            body="Next message",
        )
        normal_msg = await processor.ingest(session, normal_env)
        assert normal_msg.seq == 2  # seq=2, not 3

        # Verify history excludes thread replies
        identity_mgr = MagicMock()
        ch_mgr = ChannelManager(config, identity_mgr)
        ch_mgr._channels["thrch1"] = channel

        handler = SyncHandler(ch_mgr, sequencer, node_name="TestNode")
        nonce = generate_nonce()
        result = await handler.handle(
            session,
            SYNC_HISTORY,
            nonce,
            payload={"channel_id": "thrch1", "since_seq": 0, "limit": 50},
        )

        # Thread replies should be filtered from main timeline
        types = [m["type"] for m in result["messages"]]
        assert MSG_THREAD_REPLY not in types
