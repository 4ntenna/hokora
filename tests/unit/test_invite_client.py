# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for InviteClient — Step C of the sync_engine refactor."""

from unittest.mock import MagicMock, patch

import pytest

from hokora_tui.sync.invite_client import InviteClient
from hokora_tui.sync.state import SyncState


@pytest.fixture
def state():
    return SyncState()


@pytest.fixture
def link_manager():
    return MagicMock()


@pytest.fixture
def client(link_manager, state):
    return InviteClient(link_manager, state)


class TestSyncRequests:
    def test_create_invite_uses_any_active_link(self, client, link_manager):
        active = MagicMock()
        with patch("hokora_tui.sync.invite_client.RNS") as rns:
            link_manager.find_active_link.return_value = active
            client.create_invite("ch1", max_uses=5, expiry_hours=24)
            link_manager.find_active_link.assert_called_once()
            rns.Packet.assert_called_once()

    def test_create_invite_noop_without_active_link(self, client, link_manager):
        link_manager.find_active_link.return_value = None
        client.create_invite("ch1")
        # No exception

    def test_list_invites_with_channel(self, client, link_manager):
        active = MagicMock()
        with patch("hokora_tui.sync.invite_client.RNS") as rns:
            link_manager.find_active_link.return_value = active
            client.list_invites("ch1")
            rns.Packet.assert_called_once()

    def test_list_invites_without_channel(self, client, link_manager):
        active = MagicMock()
        with patch("hokora_tui.sync.invite_client.RNS") as rns:
            link_manager.find_active_link.return_value = active
            client.list_invites()
            rns.Packet.assert_called_once()

    def test_redeem_invite_uses_specific_channel_link(self, client, link_manager):
        active = MagicMock()
        with patch("hokora_tui.sync.invite_client.RNS") as rns:
            rns.Link.ACTIVE = "active"
            active.status = "active"
            link_manager.get_link.return_value = active
            client.redeem_invite("ch1", "token-abc")
            link_manager.get_link.assert_called_once_with("ch1")
            rns.Packet.assert_called_once()


class TestResponseHandlers:
    def test_invite_created_fires_both_callbacks(self, client):
        captured_result = []
        captured_event = []
        client.set_on_result(captured_result.append)
        client.handle_invite_created(
            {"token": "t1"},
            event_callback=lambda ev, data: captured_event.append((ev, data)),
        )
        assert len(captured_result) == 1
        assert captured_event[0][0] == "invite_created"

    def test_invite_list_fires_both_callbacks(self, client):
        captured_result = []
        captured_event = []
        client.set_on_result(captured_result.append)
        client.handle_invite_list(
            {"invites": []},
            event_callback=lambda ev, data: captured_event.append(ev),
        )
        assert len(captured_result) == 1
        assert captured_event == ["invite_list"]

    def test_invite_redeemed_fires_event_only(self, client):
        captured_result = []
        captured_event = []
        client.set_on_result(captured_result.append)
        client.handle_invite_redeemed(
            {"channel": "ch1"},
            event_callback=lambda ev, data: captured_event.append(ev),
        )
        # Redeems intentionally don't trigger the on_result callback —
        # they're routed only via event_callback.
        assert len(captured_result) == 0
        assert captured_event == ["invite_redeemed"]
