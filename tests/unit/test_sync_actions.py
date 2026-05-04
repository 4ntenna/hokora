# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Sync handler action tests: subscribe_live, unsubscribe, fetch_media, member list,
pins, search, thread, has_more, node_meta, search query cap, challenge cleanup."""

import time
from unittest.mock import MagicMock, patch

import pytest
import pytest_asyncio

from hokora.constants import (
    SYNC_GET_PINS,
    SYNC_SEARCH,
    SYNC_THREAD,
    SYNC_SUBSCRIBE_LIVE,
    SYNC_UNSUBSCRIBE,
    SYNC_GET_MEMBER_LIST,
    SYNC_FETCH_MEDIA,
    SYNC_HISTORY,
    SYNC_NODE_META,
    MSG_THREAD_REPLY,
)
from hokora.core.channel import ChannelManager
from hokora.core.message import MessageEnvelope, MessageProcessor
from hokora.core.sequencer import SequenceManager
from hokora.db.models import (
    Channel,
    Category,
)
from hokora.db.queries import (
    ChannelRepo,
    MessageRepo,
    IdentityRepo,
    RoleRepo,
    CategoryRepo,
)
from hokora.exceptions import (
    SyncError,
    PermissionDenied,
)
from hokora.protocol.sync import SyncHandler
from hokora.protocol.wire import generate_nonce
from hokora.security.permissions import PermissionResolver
from hokora.security.roles import RoleManager


# ============================================================================
# Subscribe Live
# ============================================================================


class TestSubscribeLive:
    async def _make_handler(self, config, session, live_manager=None, media_transfer=None):
        ch_repo = ChannelRepo(session)
        channel = Channel(id="livech", name="live_test", latest_seq=0)
        await ch_repo.create(channel)

        sequencer = SequenceManager()
        identity_mgr = MagicMock()
        ch_mgr = ChannelManager(config, identity_mgr)
        ch_mgr._channels["livech"] = channel

        handler = SyncHandler(
            ch_mgr,
            sequencer,
            node_name="TestNode",
            live_manager=live_manager,
            media_transfer=media_transfer,
        )
        return handler

    async def test_subscribe_live_dispatches(self, session, config):
        live_mgr = MagicMock()
        handler = await self._make_handler(config, session, live_manager=live_mgr)
        link = MagicMock()
        nonce = generate_nonce()

        result = await handler.handle(
            session,
            SYNC_SUBSCRIBE_LIVE,
            nonce,
            payload={"channel_id": "livech"},
            link=link,
        )

        live_mgr.subscribe.assert_called_once_with(
            "livech",
            link,
            sync_profile=1,
            identity_hash=None,
            supports_sealed_at_rest=False,
        )
        assert result["action"] == "subscribed"

    async def test_subscribe_live_raises_without_manager(self, session, config):
        handler = await self._make_handler(config, session, live_manager=None)
        nonce = generate_nonce()

        with pytest.raises(SyncError, match="not available"):
            await handler.handle(
                session,
                SYNC_SUBSCRIBE_LIVE,
                nonce,
                payload={"channel_id": "livech"},
                link=MagicMock(),
            )

    async def test_subscribe_live_raises_without_link(self, session, config):
        live_mgr = MagicMock()
        handler = await self._make_handler(config, session, live_manager=live_mgr)
        nonce = generate_nonce()

        with pytest.raises(SyncError, match="No link"):
            await handler.handle(
                session,
                SYNC_SUBSCRIBE_LIVE,
                nonce,
                payload={"channel_id": "livech"},
                link=None,
            )


# ============================================================================
# Unsubscribe
# ============================================================================


class TestUnsubscribe:
    async def _make_handler(self, config, session, live_manager=None):
        ch_repo = ChannelRepo(session)
        channel = Channel(id="unsubch", name="unsub_test", latest_seq=0)
        await ch_repo.create(channel)

        sequencer = SequenceManager()
        identity_mgr = MagicMock()
        ch_mgr = ChannelManager(config, identity_mgr)
        ch_mgr._channels["unsubch"] = channel

        handler = SyncHandler(
            ch_mgr,
            sequencer,
            node_name="TestNode",
            live_manager=live_manager,
        )
        return handler

    async def test_unsubscribe_dispatches(self, session, config):
        live_mgr = MagicMock()
        handler = await self._make_handler(config, session, live_manager=live_mgr)
        link = MagicMock()
        nonce = generate_nonce()

        result = await handler.handle(
            session,
            SYNC_UNSUBSCRIBE,
            nonce,
            payload={"channel_id": "unsubch"},
            link=link,
        )

        live_mgr.unsubscribe.assert_called_once_with("unsubch", link)
        assert result["action"] == "unsubscribed"

    async def test_unsubscribe_raises_without_manager(self, session, config):
        handler = await self._make_handler(config, session, live_manager=None)
        nonce = generate_nonce()

        with pytest.raises(SyncError, match="not available"):
            await handler.handle(
                session,
                SYNC_UNSUBSCRIBE,
                nonce,
                payload={"channel_id": "unsubch"},
                link=MagicMock(),
            )

    async def test_unsubscribe_raises_without_link(self, session, config):
        live_mgr = MagicMock()
        handler = await self._make_handler(config, session, live_manager=live_mgr)
        nonce = generate_nonce()

        with pytest.raises(SyncError, match="No link"):
            await handler.handle(
                session,
                SYNC_UNSUBSCRIBE,
                nonce,
                payload={"channel_id": "unsubch"},
                link=None,
            )


# ============================================================================
# Fetch Media
# ============================================================================


class TestFetchMedia:
    async def _make_handler(self, config, session, media_transfer=None):
        ch_repo = ChannelRepo(session)
        channel = Channel(id="mediach", name="media_test", latest_seq=0)
        await ch_repo.create(channel)

        sequencer = SequenceManager()
        identity_mgr = MagicMock()
        ch_mgr = ChannelManager(config, identity_mgr)
        ch_mgr._channels["mediach"] = channel

        handler = SyncHandler(
            ch_mgr,
            sequencer,
            node_name="TestNode",
            media_transfer=media_transfer,
        )
        return handler

    async def test_fetch_media_dispatches(self, session, config):
        transfer = MagicMock()
        transfer.serve_media.return_value = True
        handler = await self._make_handler(config, session, media_transfer=transfer)
        link = MagicMock()
        nonce = generate_nonce()

        result = await handler.handle(
            session,
            SYNC_FETCH_MEDIA,
            nonce,
            payload={"path": "mediach/abc123.bin"},
            link=link,
        )

        transfer.serve_media.assert_called_once_with(link, "mediach/abc123.bin")
        assert result["action"] == "media_serving"

    async def test_fetch_media_raises_without_transfer(self, session, config):
        handler = await self._make_handler(config, session, media_transfer=None)
        nonce = generate_nonce()

        with pytest.raises(SyncError, match="not available"):
            await handler.handle(
                session,
                SYNC_FETCH_MEDIA,
                nonce,
                payload={"path": "mediach/abc.bin"},
                link=MagicMock(),
            )

    async def test_fetch_media_raises_without_link(self, session, config):
        transfer = MagicMock()
        handler = await self._make_handler(config, session, media_transfer=transfer)
        nonce = generate_nonce()

        with pytest.raises(SyncError, match="No link"):
            await handler.handle(
                session,
                SYNC_FETCH_MEDIA,
                nonce,
                payload={"path": "mediach/abc.bin"},
                link=None,
            )


# ============================================================================
# Member List Auth
# ============================================================================


class TestMemberListAuth:
    async def _setup(self, session, config, access_mode="public"):
        """Set up channel, identities, roles for member list auth tests."""
        ch_id = f"mlauth_{access_mode}_{id(session) % 10000}"
        ch_repo = ChannelRepo(session)
        channel = Channel(
            id=ch_id,
            name="ml_auth_test",
            latest_seq=0,
            access_mode=access_mode,
        )
        await ch_repo.create(channel)

        ident_repo = IdentityRepo(session)
        await ident_repo.upsert("requester_user", display_name="Requester")
        await ident_repo.upsert("member_user", display_name="Member")

        mgr = RoleManager()
        await mgr.ensure_builtin_roles(session)

        node_owner_hash = "node_owner_hash_ml"
        resolver = PermissionResolver(node_owner_hash=node_owner_hash)

        sequencer = SequenceManager()
        identity_mgr = MagicMock()
        ch_mgr = ChannelManager(config, identity_mgr)
        ch_mgr._channels[ch_id] = channel

        handler = SyncHandler(
            ch_mgr,
            sequencer,
            node_name="TestNode",
            permission_resolver=resolver,
        )
        return handler, ch_id, node_owner_hash

    async def test_private_channel_denied_for_non_member(self, session, config):
        handler, ch_id, _ = await self._setup(session, config, access_mode="private")
        nonce = generate_nonce()

        with pytest.raises(PermissionDenied, match="membership"):
            await handler.handle(
                session,
                SYNC_GET_MEMBER_LIST,
                nonce,
                payload={"channel_id": ch_id},
                requester_hash="requester_user",
            )

    async def test_public_channel_denied_without_manage_members(self, session, config):
        handler, ch_id, _ = await self._setup(session, config, access_mode="public")
        nonce = generate_nonce()

        with pytest.raises(PermissionDenied, match="MANAGE_MEMBERS"):
            await handler.handle(
                session,
                SYNC_GET_MEMBER_LIST,
                nonce,
                payload={"channel_id": ch_id},
                requester_hash="requester_user",
            )

    async def test_node_owner_always_allowed_public(self, session, config):
        """Node owner bypasses MANAGE_MEMBERS check on public channels via resolver."""
        handler, ch_id, node_owner = await self._setup(
            session,
            config,
            access_mode="public",
        )
        nonce = generate_nonce()

        # Node owner should pass the resolver check (Level 1: node owner)
        result = await handler.handle(
            session,
            SYNC_GET_MEMBER_LIST,
            nonce,
            payload={"channel_id": ch_id},
            requester_hash=node_owner,
        )
        assert result["action"] == "member_list"

    async def test_private_channel_allowed_for_member(self, session, config):
        """Member with a role on a private channel can access member list."""
        handler, ch_id, _ = await self._setup(
            session,
            config,
            access_mode="private",
        )

        # Give the requester a role on this channel
        role_repo = RoleRepo(session)
        everyone = await role_repo.get_by_name("everyone")
        ident_repo = IdentityRepo(session)
        await ident_repo.upsert("requester_user")
        await role_repo.assign_role(everyone.id, "requester_user", ch_id)

        nonce = generate_nonce()
        result = await handler.handle(
            session,
            SYNC_GET_MEMBER_LIST,
            nonce,
            payload={"channel_id": ch_id},
            requester_hash="requester_user",
        )
        assert result["action"] == "member_list"

    async def test_backward_compat_no_requester_hash(self, session, config):
        handler, ch_id, _ = await self._setup(session, config, access_mode="private")
        nonce = generate_nonce()

        # No requester_hash = no auth check (backward compat)
        result = await handler.handle(
            session,
            SYNC_GET_MEMBER_LIST,
            nonce,
            payload={"channel_id": ch_id},
        )
        assert result["action"] == "member_list"


# ============================================================================
# Sync Pins, Search, Thread
# ============================================================================


class TestSyncPinsSearchThread:
    async def _setup_channel(self, session, config, ch_id, sealed=False):
        ch_repo = ChannelRepo(session)
        channel = Channel(
            id=ch_id,
            name=f"{ch_id}_test",
            latest_seq=0,
            sealed=sealed,
        )
        await ch_repo.create(channel)

        sequencer = SequenceManager()
        await sequencer.load_from_db(session, ch_id)

        identity_mgr = MagicMock()
        ch_mgr = ChannelManager(config, identity_mgr)
        ch_mgr._channels[ch_id] = channel

        return ch_mgr, sequencer, channel

    async def test_get_pins_returns_pinned(self, session, config):
        ch_mgr, sequencer, channel = await self._setup_channel(
            session,
            config,
            "pinsch1",
        )
        processor = MessageProcessor(sequencer)

        # Insert a message and pin it
        env = MessageEnvelope(
            channel_id="pinsch1",
            sender_hash="user1",
            timestamp=time.time(),
            body="Pin me",
        )
        msg = await processor.ingest(session, env)

        msg_repo = MessageRepo(session)
        await msg_repo.set_pinned(msg.msg_hash, True)

        handler = SyncHandler(ch_mgr, sequencer, node_name="TestNode")
        nonce = generate_nonce()
        result = await handler.handle(
            session,
            SYNC_GET_PINS,
            nonce,
            payload={"channel_id": "pinsch1"},
        )

        assert result["action"] == "pins"
        assert len(result["messages"]) == 1
        assert result["messages"][0]["pinned"] is True

    async def test_search_fallback_no_fts(self, session, config):
        ch_mgr, sequencer, channel = await self._setup_channel(
            session,
            config,
            "searchch1",
        )
        processor = MessageProcessor(sequencer)

        env = MessageEnvelope(
            channel_id="searchch1",
            sender_hash="user1",
            timestamp=time.time(),
            body="findable keyword here",
        )
        await processor.ingest(session, env)

        # No FTS manager -> fallback to LIKE
        handler = SyncHandler(ch_mgr, sequencer, node_name="TestNode", fts_manager=None)
        nonce = generate_nonce()
        result = await handler.handle(
            session,
            SYNC_SEARCH,
            nonce,
            payload={"channel_id": "searchch1", "query": "findable"},
        )

        assert result["action"] == "search"
        assert len(result["results"]) >= 1

    async def test_search_rejects_sealed_channel(self, session, config):
        ch_mgr, sequencer, channel = await self._setup_channel(
            session,
            config,
            "sealsch1",
            sealed=True,
        )

        handler = SyncHandler(ch_mgr, sequencer, node_name="TestNode")
        nonce = generate_nonce()

        with pytest.raises(SyncError, match="sealed"):
            await handler.handle(
                session,
                SYNC_SEARCH,
                nonce,
                payload={"channel_id": "sealsch1", "query": "anything"},
            )

    async def test_thread_returns_messages(self, session, config):
        ch_mgr, sequencer, channel = await self._setup_channel(
            session,
            config,
            "threadch1",
        )
        processor = MessageProcessor(sequencer)

        # Root message
        root_env = MessageEnvelope(
            channel_id="threadch1",
            sender_hash="user1",
            timestamp=time.time(),
            body="Thread root",
        )
        root_msg = await processor.ingest(session, root_env)

        # Thread reply
        reply_env = MessageEnvelope(
            channel_id="threadch1",
            sender_hash="user2",
            timestamp=time.time() + 1,
            type=MSG_THREAD_REPLY,
            body="Thread reply",
            reply_to=root_msg.msg_hash,
        )
        await processor.ingest(session, reply_env)

        handler = SyncHandler(ch_mgr, sequencer, node_name="TestNode")
        nonce = generate_nonce()
        result = await handler.handle(
            session,
            SYNC_THREAD,
            nonce,
            payload={"root_hash": root_msg.msg_hash},
        )

        assert result["action"] == "thread"
        assert result["root_hash"] == root_msg.msg_hash
        assert len(result["messages"]) >= 2


# ============================================================================
# Sync Has More
# ============================================================================


class TestSyncHasMore:
    async def test_sync_has_more(self, session, config):
        ch_repo = ChannelRepo(session)
        channel = Channel(id="hmch1", name="hasmore_test", latest_seq=0)
        await ch_repo.create(channel)

        sequencer = SequenceManager()
        await sequencer.load_from_db(session, "hmch1")

        processor = MessageProcessor(sequencer)
        for i in range(10):
            await processor.ingest(
                session,
                MessageEnvelope(
                    channel_id="hmch1",
                    sender_hash=f"sender{i}",
                    timestamp=time.time() + i,
                    body=f"Message {i}",
                ),
            )

        identity_mgr = MagicMock()
        ch_mgr = ChannelManager(config, identity_mgr)
        ch_mgr._channels["hmch1"] = channel

        handler = SyncHandler(ch_mgr, sequencer, node_name="TestNode")
        nonce = generate_nonce()

        # Request with limit=5 (there are 10 messages)
        result = await handler.handle(
            session,
            SYNC_HISTORY,
            nonce,
            payload={"channel_id": "hmch1", "since_seq": 0, "limit": 5},
        )
        assert result["has_more"] is True

        # Request with limit=50 (only 10 messages)
        nonce2 = generate_nonce()
        result = await handler.handle(
            session,
            SYNC_HISTORY,
            nonce2,
            payload={"channel_id": "hmch1", "since_seq": 0, "limit": 50},
        )
        assert result["has_more"] is False
        assert result["gap_explanation"] is None


# ============================================================================
# Node Meta Complete
# ============================================================================


class TestNodeMetaComplete:
    async def test_node_meta_complete(self, session, config):
        # Create a category
        cat_repo = CategoryRepo(session)
        cat = Category(id="cat1", name="General", position=0, collapsed_default=True)
        await cat_repo.create(cat)

        # Create a channel
        ch_repo = ChannelRepo(session)
        channel = Channel(
            id="nmch1",
            name="meta_complete",
            latest_seq=0,
            category_id="cat1",
            identity_hash="abc123",
        )
        await ch_repo.create(channel)

        # Create roles
        mgr = RoleManager()
        await mgr.ensure_builtin_roles(session)

        sequencer = SequenceManager()
        identity_mgr = MagicMock()
        ch_mgr = ChannelManager(config, identity_mgr)
        ch_mgr._channels["nmch1"] = channel

        handler = SyncHandler(
            ch_mgr,
            sequencer,
            node_name="TestNode",
            node_identity="node_hash_123",
        )
        nonce = generate_nonce()

        result = await handler.handle(session, SYNC_NODE_META, nonce)

        # All required fields present
        assert result["node_identity"] == "node_hash_123"
        assert "categories" in result
        assert len(result["categories"]) >= 1
        assert result["categories"][0]["collapsed_default"] is True
        assert "roles" in result
        assert len(result["roles"]) >= 3  # 3 builtin roles
        assert "channels" in result
        ch = result["channels"][0]
        assert "member_count" in ch
        assert "last_activity" in ch


# ============================================================================
# Member List Action
# ============================================================================


class TestMemberListAction:
    async def test_member_list_action(self, session, config):
        ch_repo = ChannelRepo(session)
        channel = Channel(id="mlch1", name="member_test", latest_seq=0)
        await ch_repo.create(channel)

        # Create identity and role
        ident_repo = IdentityRepo(session)
        await ident_repo.upsert("member1", display_name="Alice")

        mgr = RoleManager()
        await mgr.ensure_builtin_roles(session)

        role_repo = RoleRepo(session)
        everyone_role = await role_repo.get_by_name("everyone")
        await role_repo.assign_role(everyone_role.id, "member1", "mlch1")

        sequencer = SequenceManager()
        identity_mgr = MagicMock()
        ch_mgr = ChannelManager(config, identity_mgr)
        ch_mgr._channels["mlch1"] = channel

        handler = SyncHandler(ch_mgr, sequencer, node_name="TestNode")
        nonce = generate_nonce()

        result = await handler.handle(
            session,
            SYNC_GET_MEMBER_LIST,
            nonce,
            payload={"channel_id": "mlch1"},
        )

        assert result["action"] == "member_list"
        assert len(result["members"]) >= 1
        member = result["members"][0]
        assert member["identity_hash"] == "member1"
        assert member["display_name"] == "Alice"
        assert len(member["roles"]) >= 1


# ============================================================================
# Search Query Cap
# ============================================================================


class TestSearchQueryCap:
    """4C: Search query length is capped."""

    @pytest_asyncio.fixture
    async def sync_handler(self, session_factory):
        from hokora.core.sequencer import SequenceManager

        cm = MagicMock()
        ch = MagicMock()
        ch.access_mode = "public"
        ch.sealed = False
        cm.get_channel.return_value = ch
        seq = SequenceManager()

        handler = SyncHandler(cm, seq, node_name="Test")
        return handler

    async def test_search_query_truncated(self, session, sync_handler):
        """A query longer than 500 chars should be truncated, not rejected."""
        long_query = "a" * 1000
        # This should not raise; query gets truncated internally
        # We mock the search to verify the truncated query
        with patch(
            "hokora.protocol.handlers.history._get_search_context",
            return_value={
                "context_before": [],
                "context_after": [],
            },
        ):
            from hokora.db.queries import MessageRepo

            with patch.object(MessageRepo, "search", return_value=[]) as mock_search:
                await sync_handler._handle_search(
                    session,
                    b"\x00" * 16,
                    {"channel_id": "ch1", "query": long_query},
                    "ch1",
                )
                # Verify search was called with truncated query
                called_query = mock_search.call_args[0][1]
                assert len(called_query) == 500

    async def test_search_short_query_unchanged(self, session, sync_handler):
        """Short queries should pass through unchanged."""
        with patch(
            "hokora.protocol.handlers.history._get_search_context",
            return_value={
                "context_before": [],
                "context_after": [],
            },
        ):
            from hokora.db.queries import MessageRepo

            with patch.object(MessageRepo, "search", return_value=[]) as mock_search:
                await sync_handler._handle_search(
                    session,
                    b"\x00" * 16,
                    {"channel_id": "ch1", "query": "hello"},
                    "ch1",
                )
                called_query = mock_search.call_args[0][1]
                assert called_query == "hello"


# ============================================================================
# Sync Handler Challenge Cleanup
# ============================================================================


class TestSyncHandlerChallengeCleanup:
    """3B2: SyncHandler.cleanup_stale_challenges prunes stale pending challenges."""

    def _make_handler(self):
        return SyncHandler(
            channel_manager=ChannelManager.__new__(ChannelManager),
            sequencer=SequenceManager.__new__(SequenceManager),
        )

    async def test_cleanup_removes_old_challenges(self):
        handler = self._make_handler()
        old_time = time.time() - 600
        handler._pending_counter_challenges["peer_a"] = (b"\x01" * 32, old_time)
        await handler.cleanup_stale_challenges(max_age=300)
        assert "peer_a" not in handler._pending_counter_challenges

    async def test_cleanup_keeps_recent_challenges(self):
        handler = self._make_handler()
        handler._pending_counter_challenges["peer_b"] = (b"\x02" * 32, time.time())
        await handler.cleanup_stale_challenges(max_age=300)
        assert "peer_b" in handler._pending_counter_challenges
