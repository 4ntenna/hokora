# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for ChannelLinkManager — Step A of the sync_engine refactor."""

from unittest.mock import MagicMock, patch

import pytest

from hokora_tui.sync.link_manager import (
    LINK_ESTABLISHMENT_TIMEOUT_PER_HOP,
    ChannelLinkManager,
)
from hokora_tui.sync.state import SyncState


@pytest.fixture
def reticulum():
    r = MagicMock()
    r.is_connected_to_shared_instance = True
    return r


@pytest.fixture
def state():
    return SyncState()


class TestConnectChannel:
    def test_uses_cached_identity_first(self, reticulum, state):
        cached = MagicMock()
        state.channel_identities["ch1"] = cached
        with patch("hokora_tui.sync.link_manager.RNS") as rns:
            rns.Destination.OUT = 1
            rns.Destination.SINGLE = 2
            rns.Link.ACCEPT_ALL = 99
            dest_mock = MagicMock()
            rns.Destination.return_value = dest_mock
            link_mock = MagicMock()
            link_mock.establishment_timeout = 6
            rns.Link.return_value = link_mock
            rns.Transport.has_path.return_value = True

            mgr = ChannelLinkManager(reticulum, None, state)
            mgr.connect_channel(b"\x01" * 16, "ch1")

            rns.Destination.assert_called_once()
            call_args = rns.Destination.call_args[0]
            assert call_args[0] is cached  # cached identity used
            # No pubkey fallback triggered
            assert rns.Identity.recall.call_count == 0
            # Link stored
            assert mgr.get_link("ch1") is link_mock

    def test_recalls_identity_when_not_cached(self, reticulum, state):
        recalled = MagicMock()
        with patch("hokora_tui.sync.link_manager.RNS") as rns:
            rns.Destination.OUT = 1
            rns.Destination.SINGLE = 2
            rns.Link.ACCEPT_ALL = 99
            rns.Identity.recall.return_value = recalled
            rns.Link.return_value = MagicMock(establishment_timeout=6)
            rns.Transport.has_path.return_value = True

            mgr = ChannelLinkManager(reticulum, None, state)
            mgr.connect_channel(b"\x02" * 16, "ch1")

            rns.Identity.recall.assert_called_once_with(b"\x02" * 16)

    def test_pubkey_seeded_fast_path_consumes_pending(self, reticulum, state):
        state.pending_pubkeys[(b"\x03" * 16).hex()] = b"\x99" * 32
        with patch("hokora_tui.sync.link_manager.RNS") as rns:
            rns.Destination.OUT = 1
            rns.Destination.SINGLE = 2
            rns.Link.ACCEPT_ALL = 99
            rns.Identity.recall.return_value = None  # force fallback
            ident = MagicMock()
            rns.Identity.return_value = ident
            rns.Link.return_value = MagicMock(establishment_timeout=6)
            rns.Transport.has_path.return_value = True

            mgr = ChannelLinkManager(reticulum, None, state)
            mgr.connect_channel(b"\x03" * 16, "ch1")

            ident.load_public_key.assert_called_once_with(b"\x99" * 32)
            # Pending pubkey consumed exactly once
            assert (b"\x03" * 16).hex() not in state.pending_pubkeys
            # Cached after successful seed
            assert state.channel_identities["ch1"] is ident

    def test_no_identity_defers_via_pending_connects(self, reticulum, state):
        """When no identity and no pubkey, requests path and defers."""
        with patch("hokora_tui.sync.link_manager.RNS") as rns:
            rns.Identity.recall.return_value = None

            mgr = ChannelLinkManager(reticulum, None, state)
            mgr.connect_channel(b"\x04" * 16, "ch1")

            rns.Transport.request_path.assert_called_once_with(b"\x04" * 16)
            assert state.pending_connects["ch1"] == b"\x04" * 16
            assert mgr.get_link("ch1") is None

    def test_extends_establishment_timeout_for_multihop(self, reticulum, state):
        cached = MagicMock()
        state.channel_identities["ch1"] = cached
        with patch("hokora_tui.sync.link_manager.RNS") as rns:
            rns.Destination.OUT = 1
            rns.Destination.SINGLE = 2
            rns.Link.ACCEPT_ALL = 99
            rns.Transport.hops_to.return_value = 3
            rns.Transport.has_path.return_value = True
            link_mock = MagicMock()
            link_mock.establishment_timeout = 6
            rns.Link.return_value = link_mock

            mgr = ChannelLinkManager(reticulum, None, state)
            mgr.connect_channel(b"\x05" * 16, "ch1")

            # 3 hops × 30s = 90s floor beats RNS baseline of 6
            assert link_mock.establishment_timeout == 3 * LINK_ESTABLISHMENT_TIMEOUT_PER_HOP

    def test_path_unknown_defers_when_standalone(self, reticulum, state):
        cached = MagicMock()
        state.channel_identities["ch1"] = cached
        reticulum.is_connected_to_shared_instance = False
        with patch("hokora_tui.sync.link_manager.RNS") as rns:
            rns.Transport.has_path.return_value = False
            mgr = ChannelLinkManager(reticulum, None, state)
            mgr.connect_channel(b"\x06" * 16, "ch1")
            assert state.pending_connects["ch1"] == b"\x06" * 16
            assert mgr.get_link("ch1") is None

    def test_path_unknown_proceeds_when_shared_instance(self, reticulum, state):
        cached = MagicMock()
        state.channel_identities["ch1"] = cached
        reticulum.is_connected_to_shared_instance = True
        with patch("hokora_tui.sync.link_manager.RNS") as rns:
            rns.Destination.OUT = 1
            rns.Destination.SINGLE = 2
            rns.Link.ACCEPT_ALL = 99
            rns.Transport.has_path.return_value = False
            link_mock = MagicMock(establishment_timeout=6)
            rns.Link.return_value = link_mock
            mgr = ChannelLinkManager(reticulum, None, state)
            mgr.connect_channel(b"\x07" * 16, "ch1")
            assert mgr.get_link("ch1") is link_mock
            assert "ch1" not in state.pending_connects


class TestRegisterChannel:
    def test_attaches_to_existing_active_link(self, reticulum, state):
        with patch("hokora_tui.sync.link_manager.RNS") as rns:
            active = MagicMock()
            active.status = rns.Link.ACTIVE = "active"
            mgr = ChannelLinkManager(reticulum, None, state)
            mgr._links["ch1"] = active
            mgr.register_channel("ch2")
            assert mgr.get_link("ch2") is active

    def test_noop_when_already_linked(self, reticulum, state):
        existing = MagicMock()
        mgr = ChannelLinkManager(reticulum, None, state)
        mgr._links["ch1"] = existing
        mgr.register_channel("ch1")
        assert mgr.get_link("ch1") is existing

    def test_stores_dest_hash_in_state(self, reticulum, state):
        with patch("hokora_tui.sync.link_manager.RNS") as rns:
            rns.Identity.recall.return_value = None
            mgr = ChannelLinkManager(reticulum, None, state)
            mgr.register_channel("ch1", destination_hash=b"\x08" * 16)
            assert state.channel_dest_hashes["ch1"] == b"\x08" * 16


class TestRetryPendingConnects:
    def test_resolves_when_identity_arrives(self, reticulum, state):
        with patch("hokora_tui.sync.link_manager.RNS") as rns:
            rns.Destination.OUT = 1
            rns.Destination.SINGLE = 2
            rns.Link.ACCEPT_ALL = 99
            rns.Transport.has_path.return_value = True
            rns.Link.return_value = MagicMock(establishment_timeout=6)
            recalled = MagicMock()
            rns.Identity.recall.return_value = recalled

            state.pending_connects["ch1"] = b"\x09" * 16
            mgr = ChannelLinkManager(reticulum, None, state)
            mgr.retry_pending_connects()
            # After connect succeeds, pending_connects is cleared
            assert "ch1" not in state.pending_connects
            assert mgr.get_link("ch1") is not None

    def test_leaves_unresolved_in_pending(self, reticulum, state):
        with patch("hokora_tui.sync.link_manager.RNS") as rns:
            rns.Identity.recall.return_value = None
            state.pending_connects["ch1"] = b"\x0a" * 16
            mgr = ChannelLinkManager(reticulum, None, state)
            mgr.retry_pending_connects()
            assert state.pending_connects["ch1"] == b"\x0a" * 16


class TestDisconnect:
    def test_disconnect_channel_tears_down_and_pops(self, reticulum, state):
        mgr = ChannelLinkManager(reticulum, None, state)
        link = MagicMock()
        mgr._links["ch1"] = link
        mgr.disconnect_channel("ch1")
        link.teardown.assert_called_once()
        assert mgr.get_link("ch1") is None

    def test_disconnect_all_dedupes_shared_link(self, reticulum, state):
        """Multiple channels on one link: teardown called once."""
        mgr = ChannelLinkManager(reticulum, None, state)
        shared = MagicMock()
        mgr._links["ch1"] = shared
        mgr._links["ch2"] = shared
        mgr.disconnect_all()
        assert shared.teardown.call_count == 1
        assert mgr.link_count() == 0

    def test_disconnect_all_clears_pending_connects(self, reticulum, state):
        mgr = ChannelLinkManager(reticulum, None, state)
        state.pending_connects["ch1"] = b"\x0b" * 16
        mgr.disconnect_all()
        assert state.pending_connects == {}


class TestAccessors:
    def test_is_connected_reflects_link_status(self, reticulum, state):
        with patch("hokora_tui.sync.link_manager.RNS") as rns:
            rns.Link.ACTIVE = "active"
            mgr = ChannelLinkManager(reticulum, None, state)
            link = MagicMock(status="active")
            mgr._links["ch1"] = link
            assert mgr.is_connected("ch1")
            link.status = "closed"
            assert not mgr.is_connected("ch1")

    def test_find_active_link_returns_first_active(self, reticulum, state):
        with patch("hokora_tui.sync.link_manager.RNS") as rns:
            rns.Link.ACTIVE = "active"
            mgr = ChannelLinkManager(reticulum, None, state)
            inactive = MagicMock(status="closed")
            active = MagicMock(status="active")
            mgr._links["a"] = inactive
            mgr._links["b"] = active
            # dict preserves insertion order; scan should find b
            assert mgr.find_active_link() is active

    def test_find_active_link_none_when_empty(self, reticulum, state):
        mgr = ChannelLinkManager(reticulum, None, state)
        assert mgr.find_active_link() is None

    def test_links_snapshot_is_live_reference(self, reticulum, state):
        """Backward-compat shim relies on this."""
        mgr = ChannelLinkManager(reticulum, None, state)
        snap = mgr.links_snapshot()
        link = MagicMock()
        mgr._links["ch1"] = link
        assert "ch1" in snap
        assert snap["ch1"] is link


class TestResolveChannelIdentity:
    def test_prefers_per_channel_recall(self, reticulum, state):
        state.channel_dest_hashes["ch1"] = b"\x01" * 16
        with patch("hokora_tui.sync.link_manager.RNS") as rns:
            recalled = MagicMock()
            rns.Identity.recall.return_value = recalled
            mgr = ChannelLinkManager(reticulum, None, state)
            result = mgr.resolve_channel_identity("ch1")
            assert result is recalled
            rns.Identity.recall.assert_called_with(b"\x01" * 16)

    def test_falls_back_to_any_recall(self, reticulum, state):
        """When ch1 doesn't recall but ch2 does, use ch2's identity."""
        state.channel_dest_hashes["ch1"] = b"\x01" * 16
        state.channel_dest_hashes["ch2"] = b"\x02" * 16
        with patch("hokora_tui.sync.link_manager.RNS") as rns:
            fallback = MagicMock()
            # First call (ch1) returns None; second (ch2) returns identity.
            rns.Identity.recall.side_effect = [None, None, fallback]
            mgr = ChannelLinkManager(reticulum, None, state)
            result = mgr.resolve_channel_identity("ch1")
            assert result is fallback

    def test_uses_cached_identity_when_no_recall(self, reticulum, state):
        cached = MagicMock()
        state.channel_identities["ch1"] = cached
        with patch("hokora_tui.sync.link_manager.RNS") as rns:
            rns.Identity.recall.return_value = None
            mgr = ChannelLinkManager(reticulum, None, state)
            result = mgr.resolve_channel_identity("ch1")
            assert result is cached

    def test_falls_back_to_link_destination(self, reticulum, state):
        link = MagicMock()
        link.destination.identity = "link-identity"
        with patch("hokora_tui.sync.link_manager.RNS") as rns:
            rns.Identity.recall.return_value = None
            mgr = ChannelLinkManager(reticulum, None, state)
            result = mgr.resolve_channel_identity("unknown", link=link)
            assert result == "link-identity"

    def test_returns_none_when_all_fail(self, reticulum, state):
        with patch("hokora_tui.sync.link_manager.RNS") as rns:
            rns.Identity.recall.return_value = None
            mgr = ChannelLinkManager(reticulum, None, state)
            assert mgr.resolve_channel_identity("unknown") is None


class TestCallbacks:
    def test_on_established_fires_with_channel_and_link(self, reticulum, state):
        mgr = ChannelLinkManager(reticulum, None, state)
        received = []
        mgr.set_on_established(lambda ch, lnk: received.append((ch, lnk)))
        link = MagicMock()
        link.keepalive = 5
        mgr._handle_established(link, "ch1")
        assert received == [("ch1", link)]

    def test_on_established_overrides_keepalive(self, reticulum, state):
        """Low-RTT link with 5s keepalive gets bumped to 120s."""
        mgr = ChannelLinkManager(reticulum, None, state)
        link = MagicMock()
        link.keepalive = 5
        mgr._handle_established(link, "ch1")
        assert link.keepalive == 120

    def test_on_established_preserves_higher_keepalive(self, reticulum, state):
        mgr = ChannelLinkManager(reticulum, None, state)
        link = MagicMock()
        link.keepalive = 300
        mgr._handle_established(link, "ch1")
        assert link.keepalive == 300

    def test_on_closed_pops_link_and_fires_callback(self, reticulum, state):
        mgr = ChannelLinkManager(reticulum, None, state)
        received = []
        mgr.set_on_closed(lambda ch, lnk: received.append((ch, lnk)))
        link = MagicMock()
        mgr._links["ch1"] = link
        mgr._handle_closed(link, "ch1")
        assert mgr.get_link("ch1") is None
        assert received == [("ch1", link)]

    def test_callback_exception_does_not_propagate(self, reticulum, state):
        mgr = ChannelLinkManager(reticulum, None, state)

        def raising(*args):
            raise RuntimeError("boom")

        mgr.set_on_established(raising)
        mgr.set_on_closed(raising)
        # Should not raise — callbacks fire on RNS threads; we log and swallow.
        link = MagicMock(keepalive=200)
        mgr._handle_established(link, "ch1")
        mgr._handle_closed(link, "ch1")
