# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for HistoryClient — Step C of the sync_engine refactor."""

import time
from unittest.mock import MagicMock, patch

import msgpack
import pytest

from hokora.security.verification import VerificationService
from hokora_tui.sync.history_client import HistoryClient
from hokora_tui.sync.state import SyncState


@pytest.fixture
def state():
    return SyncState()


@pytest.fixture
def link_manager():
    return MagicMock()


@pytest.fixture
def verifier():
    return VerificationService()


@pytest.fixture
def event_cb_ref():
    """A container for the currently-registered event callback."""
    return {"cb": None}


@pytest.fixture
def dispatcher_calls():
    return []


@pytest.fixture
def client(state, link_manager, verifier, event_cb_ref, dispatcher_calls):
    return HistoryClient(
        link_manager=link_manager,
        state=state,
        verifier=verifier,
        response_dispatcher=dispatcher_calls.append,
        event_callback_getter=lambda: event_cb_ref["cb"],
    )


class TestSyncRequests:
    def test_sync_history_noop_without_active_link(self, client, link_manager):
        link_manager.get_link.return_value = None
        client.sync_history("ch1")
        link_manager.get_link.assert_called_once_with("ch1")

    def test_sync_history_sends_packet(self, client, state, link_manager):
        active = MagicMock()
        with patch("hokora_tui.sync.history_client.RNS") as rns:
            rns.Link.ACTIVE = "active"
            active.status = "active"
            link_manager.get_link.return_value = active
            client.sync_history("ch1", since_seq=5, limit=20)
            rns.Packet.assert_called_once()
            assert len(state.pending_nonces) == 1

    def test_subscribe_live_sends_packet(self, client, state, link_manager):
        active = MagicMock()
        with patch("hokora_tui.sync.history_client.RNS") as rns:
            rns.Link.ACTIVE = "active"
            active.status = "active"
            link_manager.get_link.return_value = active
            client.subscribe_live("ch1")
            rns.Packet.assert_called_once()

    def test_unsubscribe_with_channel_id_sends_packet(self, client, state, link_manager):
        active = MagicMock()
        with patch("hokora_tui.sync.history_client.RNS") as rns:
            rns.Link.ACTIVE = "active"
            active.status = "active"
            link_manager.get_link.return_value = active
            client.unsubscribe("ch1")
            rns.Packet.assert_called_once()

    def test_unsubscribe_all_uses_any_active_link(self, client, link_manager):
        active = MagicMock()
        with patch("hokora_tui.sync.history_client.RNS") as rns:
            rns.Link.ACTIVE = "active"
            active.status = "active"
            link_manager.find_active_link.return_value = active
            client.unsubscribe()  # no channel_id
            link_manager.find_active_link.assert_called_once()
            rns.Packet.assert_called_once()

    def test_request_node_meta_sends_packet(self, client, link_manager):
        active = MagicMock()
        with patch("hokora_tui.sync.history_client.RNS") as rns:
            rns.Link.ACTIVE = "active"
            active.status = "active"
            link_manager.get_link.return_value = active
            client.request_node_meta("ch1")
            rns.Packet.assert_called_once()


class TestCursorAndWarnings:
    def test_cursor_get_set(self, client, state):
        assert client.get_cursor("ch1") == 0
        client.set_cursor("ch1", 42)
        assert state.cursors["ch1"] == 42
        assert client.get_cursor("ch1") == 42

    def test_cache_identity_key(self, client, state):
        client.cache_identity_key("a" * 32, b"pubkey")
        assert state.identity_keys["a" * 32] == b"pubkey"

    def test_get_seq_warnings_defaults_empty(self, client):
        assert client.get_seq_warnings("ch1") == []


class TestHandleHistory:
    def test_advances_cursor(self, client, state):
        client.set_cursor("ch1", 0)
        client.handle_history(
            {
                "channel_id": "ch1",
                "messages": [
                    {"seq": 2, "msg_hash": "h2"},
                    {"seq": 3, "msg_hash": "h3"},
                ],
            },
            message_callback=None,
        )
        assert state.cursors["ch1"] == 3

    def test_does_not_regress_cursor(self, client, state):
        client.set_cursor("ch1", 10)
        client.handle_history(
            {
                "channel_id": "ch1",
                "messages": [{"seq": 5, "msg_hash": "h5"}],
            },
            message_callback=None,
        )
        assert state.cursors["ch1"] == 10

    def test_records_seq_gap_warning(self, client, state):
        client.set_cursor("ch1", 1)
        client.handle_history(
            {
                "channel_id": "ch1",
                "messages": [
                    {"seq": 2, "msg_hash": "h2"},
                    {"seq": 20, "msg_hash": "h20"},  # big gap
                ],
            },
            message_callback=None,
        )
        warnings = state.seq_warnings.get("ch1", [])
        assert len(warnings) >= 1

    def test_key_change_marks_unverified(self, client, state):
        state.identity_keys["sender1"] = b"\x01" * 32
        messages = [
            {
                "seq": 1,
                "msg_hash": "h1",
                "sender_hash": "sender1",
                "sender_public_key": b"\x02" * 32,  # different!
                "lxmf_signed_part": b"signed",
                "lxmf_signature": b"sig",
            }
        ]
        client.handle_history(
            {"channel_id": "ch1", "messages": messages},
            message_callback=None,
        )
        assert messages[0]["verified"] is False

    def test_fires_message_callback(self, client):
        captured = []
        client.handle_history(
            {
                "channel_id": "ch1",
                "messages": [{"seq": 1, "msg_hash": "h1"}],
            },
            message_callback=lambda ch, msgs, seq: captured.append((ch, msgs, seq)),
        )
        assert len(captured) == 1
        ch, msgs, seq = captured[0]
        assert ch == "ch1"
        assert seq == 1


class TestHandleNodeMeta:
    def test_stores_channel_dest_hashes(self, client, state):
        with patch("hokora_tui.sync.history_client.RNS") as rns:
            rns.Transport.has_path.return_value = True
            client.handle_node_meta(
                {
                    "channels": [
                        {
                            "id": "ch1",
                            "destination_hash": "aa" * 16,
                            "lxmf_destination_hash": "bb" * 16,
                        }
                    ]
                },
                event_callback=None,
            )
            assert state.channel_dest_hashes["ch1"] == b"\xaa" * 16

    def test_requests_missing_lxmf_path(self, client):
        with patch("hokora_tui.sync.history_client.RNS") as rns:
            rns.Transport.has_path.return_value = False
            client.handle_node_meta(
                {
                    "channels": [
                        {
                            "id": "ch1",
                            "destination_hash": "aa" * 16,
                            "lxmf_destination_hash": "bb" * 16,
                        }
                    ]
                },
                event_callback=None,
            )
            rns.Transport.request_path.assert_called_with(b"\xbb" * 16)

    def test_fires_event_callback(self, client):
        received = []
        with patch("hokora_tui.sync.history_client.RNS"):
            client.handle_node_meta(
                {"channels": []},
                event_callback=lambda ev, data: received.append((ev, data)),
            )
        assert received == [("node_meta", {"channels": []})]


class TestOnPacket:
    def test_push_event_goes_to_event_callback(self, client, event_cb_ref, dispatcher_calls):
        received = []
        event_cb_ref["cb"] = lambda ev, data: received.append((ev, data))

        payload = msgpack.packb(
            {"event": "message_updated", "data": {"msg_hash": "h1"}},
            use_bin_type=True,
        )
        client._on_packet(payload, None)
        assert received == [("message_updated", {"msg_hash": "h1"})]
        assert dispatcher_calls == []  # push events don't go through dispatch

    def test_sync_response_dispatched(self, client, state, event_cb_ref, dispatcher_calls):
        nonce = b"\x01" * 16
        state.pending_nonces[nonce] = time.time()
        response = msgpack.packb(
            {
                "nonce": nonce,
                "data": {"action": "history", "channel_id": "ch1", "messages": []},
            },
            use_bin_type=True,
        )
        client._on_packet(response, None)
        assert nonce not in state.pending_nonces  # consumed
        assert len(dispatcher_calls) == 1
        assert dispatcher_calls[0]["action"] == "history"

    def test_unknown_nonce_discarded(self, client, state, dispatcher_calls):
        response = msgpack.packb(
            {
                "nonce": b"\xff" * 16,
                "data": {"action": "history"},
            },
            use_bin_type=True,
        )
        client._on_packet(response, None)
        assert dispatcher_calls == []

    def test_malformed_packet_does_not_raise(self, client, dispatcher_calls):
        client._on_packet(b"\xff\xff-not-msgpack", None)  # swallowed
        assert dispatcher_calls == []
