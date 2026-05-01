# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for QueryClient — Step C of the sync_engine refactor."""

from unittest.mock import MagicMock, patch

import pytest

from hokora_tui.sync.query_client import QueryClient
from hokora_tui.sync.state import SyncState


@pytest.fixture
def state():
    return SyncState()


@pytest.fixture
def link_manager():
    return MagicMock()


@pytest.fixture
def client(link_manager, state):
    return QueryClient(link_manager, state)


class TestSyncRequests:
    def test_search_noop_without_link(self, client, link_manager):
        link_manager.get_link.return_value = None
        client.search("ch1", "query")
        link_manager.get_link.assert_called_once_with("ch1")

    def test_search_sends_packet(self, client, state, link_manager):
        active = MagicMock()
        with patch("hokora_tui.sync.query_client.RNS") as rns:
            rns.Link.ACTIVE = "active"
            active.status = "active"
            link_manager.get_link.return_value = active
            client.search("ch1", "hello", limit=10)
            rns.Packet.assert_called_once()
            assert len(state.pending_nonces) == 1

    def test_get_thread_uses_any_active_link(self, client, link_manager):
        active = MagicMock()
        with patch("hokora_tui.sync.query_client.RNS") as rns:
            rns.Link.ACTIVE = "active"
            active.status = "active"
            link_manager.find_active_link.return_value = active
            client.get_thread("root_hash_xyz")
            link_manager.find_active_link.assert_called_once()
            rns.Packet.assert_called_once()

    def test_get_thread_noop_when_no_active_link(self, client, link_manager):
        link_manager.find_active_link.return_value = None
        client.get_thread("root")
        # No exception

    def test_get_pins_sends_packet(self, client, link_manager):
        active = MagicMock()
        with patch("hokora_tui.sync.query_client.RNS") as rns:
            rns.Link.ACTIVE = "active"
            active.status = "active"
            link_manager.get_link.return_value = active
            client.get_pins("ch1")
            rns.Packet.assert_called_once()

    def test_get_member_list_sends_packet(self, client, link_manager):
        active = MagicMock()
        with patch("hokora_tui.sync.query_client.RNS") as rns:
            rns.Link.ACTIVE = "active"
            active.status = "active"
            link_manager.get_link.return_value = active
            client.get_member_list("ch1", limit=30, offset=10)
            rns.Packet.assert_called_once()


class TestResponseHandlers:
    def test_handle_search_fires_both_callbacks(self, client):
        captured_search = []
        captured_event = []
        client.set_on_search(captured_search.append)
        client.handle_search(
            {"action": "search", "results": [1, 2, 3]},
            event_callback=lambda ev, data: captured_event.append((ev, data)),
        )
        assert len(captured_search) == 1
        assert captured_event[0][0] == "search_results"

    def test_handle_thread_fires_both_callbacks(self, client):
        captured_thread = []
        captured_event = []
        client.set_on_thread(captured_thread.append)
        client.handle_thread(
            {"messages": []},
            event_callback=lambda ev, data: captured_event.append(ev),
        )
        assert len(captured_thread) == 1
        assert captured_event == ["thread_messages"]

    def test_handle_pins_fires_both_callbacks(self, client):
        captured_pins = []
        captured_event = []
        client.set_on_pins(captured_pins.append)
        client.handle_pins(
            {"pinned": []},
            event_callback=lambda ev, data: captured_event.append(ev),
        )
        assert len(captured_pins) == 1
        assert captured_event == ["pinned_messages"]

    def test_handle_member_list_fires_both_callbacks(self, client):
        captured_ml = []
        captured_event = []
        client.set_on_member_list(captured_ml.append)
        client.handle_member_list(
            {"members": []},
            event_callback=lambda ev, data: captured_event.append(ev),
        )
        assert len(captured_ml) == 1
        assert captured_event == ["member_list"]

    def test_handler_without_callback_is_silent(self, client):
        # No set_on_search called — no callback registered
        client.handle_search({"x": 1}, event_callback=None)  # no raise

    def test_handler_without_event_callback_skips_event_but_fires_search(self, client):
        captured = []
        client.set_on_search(captured.append)
        client.handle_search({"y": 2}, event_callback=None)
        assert len(captured) == 1
