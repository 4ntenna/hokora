# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for RichMessageClient — Step C of the sync_engine refactor."""

from unittest.mock import MagicMock, patch

import pytest

from hokora.constants import (
    MSG_DELETE,
    MSG_EDIT,
    MSG_PIN,
    MSG_REACTION,
    MSG_THREAD_REPLY,
)
from hokora_tui.sync.rich_message_client import RichMessageClient
from hokora_tui.sync.state import SyncState


@pytest.fixture
def state():
    s = SyncState()
    s.display_name = "alice"
    return s


@pytest.fixture
def link_manager():
    lm = MagicMock()
    # Default: an active link is available
    active = MagicMock()
    lm.get_link.return_value = active
    lm.resolve_channel_identity.return_value = MagicMock()  # some identity
    return lm


@pytest.fixture
def dm_router():
    r = MagicMock()
    r.lxm_router = MagicMock()
    r.lxmf_source = MagicMock()
    return r


@pytest.fixture
def identity():
    return MagicMock()


@pytest.fixture
def client(link_manager, dm_router, state, identity):
    return RichMessageClient(link_manager, dm_router, state, identity)


class TestSendMessage:
    def test_no_link_returns_false(self, client, link_manager):
        link_manager.get_link.return_value = None
        assert client.send_message("ch1", {"body": "hi"}) is False

    def test_inactive_link_returns_false(self, client, link_manager):
        link_manager.get_link.return_value.status = "closed"
        with patch("hokora_tui.sync.rich_message_client.RNS") as rns:
            rns.Link.ACTIVE = "active"
            assert client.send_message("ch1", {"body": "hi"}) is False

    def test_no_lxm_router_returns_false(self, client, dm_router, link_manager):
        dm_router.lxm_router = None
        link_manager.get_link.return_value.status = "active"
        with patch("hokora_tui.sync.rich_message_client.RNS") as rns:
            rns.Link.ACTIVE = "active"
            assert client.send_message("ch1", {"body": "hi"}) is False

    def test_happy_path_calls_handle_outbound(self, client, dm_router, link_manager):
        link_manager.get_link.return_value.status = "active"
        with (
            patch("hokora_tui.sync.rich_message_client.RNS") as rns,
            patch("hokora_tui.sync.rich_message_client.LXMF") as lxmf,
        ):
            rns.Link.ACTIVE = "active"
            rns.Transport.has_path.return_value = True
            lxmf.LXMessage.return_value = MagicMock()
            assert client.send_message("ch1", {"body": "hello"}) is True
            dm_router.lxm_router.handle_outbound.assert_called_once()

    def test_no_dest_identity_returns_false(self, client, dm_router, link_manager):
        link_manager.get_link.return_value.status = "active"
        link_manager.resolve_channel_identity.return_value = None
        with patch("hokora_tui.sync.rich_message_client.RNS") as rns:
            rns.Link.ACTIVE = "active"
            assert client.send_message("ch1", {"body": "x"}) is False
            dm_router.lxm_router.handle_outbound.assert_not_called()


class TestTypedSends:
    def _patch_outbound(self):
        return (
            patch("hokora_tui.sync.rich_message_client.RNS"),
            patch("hokora_tui.sync.rich_message_client.LXMF"),
            patch("hokora_tui.sync.rich_message_client.time.sleep", return_value=None),
        )

    def test_send_reaction_uses_msg_reaction_type(self, client, link_manager, dm_router):
        link_manager.get_link.return_value.status = "active"
        with (
            patch("hokora_tui.sync.rich_message_client.RNS") as rns,
            patch("hokora_tui.sync.rich_message_client.LXMF") as lxmf,
            patch("hokora_tui.sync.rich_message_client.time.sleep", return_value=None),
            patch("hokora_tui.sync.rich_message_client.msgpack.packb") as packb,
        ):
            rns.Link.ACTIVE = "active"
            rns.Transport.has_path.return_value = True
            lxmf.LXMessage.return_value = MagicMock()
            packb.return_value = b"packed"
            client.send_reaction("ch1", "msg_hash_1", "👍")
            content_dict = packb.call_args.args[0]
            assert content_dict["type"] == MSG_REACTION
            assert content_dict["body"] == "👍"
            assert content_dict["reply_to"] == "msg_hash_1"
            assert content_dict["display_name"] == "alice"

    def test_send_edit(self, client, link_manager, dm_router):
        link_manager.get_link.return_value.status = "active"
        with (
            patch("hokora_tui.sync.rich_message_client.RNS") as rns,
            patch("hokora_tui.sync.rich_message_client.LXMF") as lxmf,
            patch("hokora_tui.sync.rich_message_client.time.sleep", return_value=None),
            patch("hokora_tui.sync.rich_message_client.msgpack.packb") as packb,
        ):
            rns.Link.ACTIVE = "active"
            rns.Transport.has_path.return_value = True
            lxmf.LXMessage.return_value = MagicMock()
            packb.return_value = b"packed"
            client.send_edit("ch1", "h1", "new body")
            assert packb.call_args.args[0]["type"] == MSG_EDIT
            assert packb.call_args.args[0]["body"] == "new body"

    def test_send_delete(self, client, link_manager, dm_router):
        link_manager.get_link.return_value.status = "active"
        with (
            patch("hokora_tui.sync.rich_message_client.RNS") as rns,
            patch("hokora_tui.sync.rich_message_client.LXMF") as lxmf,
            patch("hokora_tui.sync.rich_message_client.time.sleep", return_value=None),
            patch("hokora_tui.sync.rich_message_client.msgpack.packb") as packb,
        ):
            rns.Link.ACTIVE = "active"
            rns.Transport.has_path.return_value = True
            lxmf.LXMessage.return_value = MagicMock()
            packb.return_value = b"packed"
            client.send_delete("ch1", "h1")
            assert packb.call_args.args[0]["type"] == MSG_DELETE

    def test_send_pin(self, client, link_manager, dm_router):
        link_manager.get_link.return_value.status = "active"
        with (
            patch("hokora_tui.sync.rich_message_client.RNS") as rns,
            patch("hokora_tui.sync.rich_message_client.LXMF") as lxmf,
            patch("hokora_tui.sync.rich_message_client.time.sleep", return_value=None),
            patch("hokora_tui.sync.rich_message_client.msgpack.packb") as packb,
        ):
            rns.Link.ACTIVE = "active"
            rns.Transport.has_path.return_value = True
            lxmf.LXMessage.return_value = MagicMock()
            packb.return_value = b"packed"
            client.send_pin("ch1", "h1")
            assert packb.call_args.args[0]["type"] == MSG_PIN

    def test_send_thread_reply(self, client, link_manager, dm_router):
        link_manager.get_link.return_value.status = "active"
        with (
            patch("hokora_tui.sync.rich_message_client.RNS") as rns,
            patch("hokora_tui.sync.rich_message_client.LXMF") as lxmf,
            patch("hokora_tui.sync.rich_message_client.time.sleep", return_value=None),
            patch("hokora_tui.sync.rich_message_client.msgpack.packb") as packb,
        ):
            rns.Link.ACTIVE = "active"
            rns.Transport.has_path.return_value = True
            lxmf.LXMessage.return_value = MagicMock()
            packb.return_value = b"packed"
            client.send_thread_reply("ch1", "root_hash", "reply body")
            assert packb.call_args.args[0]["type"] == MSG_THREAD_REPLY
            assert packb.call_args.args[0]["reply_to"] == "root_hash"
            assert packb.call_args.args[0]["body"] == "reply body"
