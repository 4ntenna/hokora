# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for the Discovery info panel widget builders.

Locks the panel's contract: every required field renders, missing
optional fields degrade gracefully, full hashes pass through without
truncation, and the B-lite TOFU verify-state is surfaced from the
``SyncEngine.identity_keys`` cache.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import urwid

from hokora_tui.widgets.info_panel import (
    _format_hops,
    _format_last_seen,
    _format_node_type,
    _format_verify_state,
    _resolve_interface,
    build_node_info_panel,
    build_peer_info_panel,
)


def _walk_text(widget) -> list[str]:
    """Collect every Text segment string in a widget tree, depth-first.

    Used by tests to assert that a label/value appears somewhere in the
    rendered Pile/Columns hierarchy without depending on the exact
    layout shape.
    """
    out: list[str] = []
    if isinstance(widget, urwid.Text):
        out.append(widget.text)
        return out
    # Containers expose ``contents`` (Pile/Columns: list of (widget, options))
    # or wrap a single child via ``original_widget`` (WidgetPlaceholder /
    # AttrMap / LineBox / Filler).
    contents = getattr(widget, "contents", None)
    if contents is not None:
        for item in contents:
            child = item[0] if isinstance(item, tuple) else item
            out.extend(_walk_text(child))
        return out
    inner = getattr(widget, "original_widget", None)
    if isinstance(inner, urwid.Widget):
        out.extend(_walk_text(inner))
    return out


# ─────────────────────────────────────────────────────────────────────
# Node info panel
# ─────────────────────────────────────────────────────────────────────


class TestBuildNodeInfoPanel:
    def _full_node(self) -> dict:
        return {
            "hash": "Test-Node",
            "node_name": "Test-Node",
            "node_identity_hash": "00000000000000000000000000000000",
            "primary_dest": "11111111111111111111111111111111",
            "channel_count": 4,
            "last_seen": 1700000000.0,
            "channels": ["Announcements", "General", "Feedback", "Sealed"],
            "channel_dests": {
                "2222222222222222": "4444444444444444",
                "3333333333333333": "5555555555555555",
            },
            "bookmarked": True,
            "hops": 0,
        }

    def test_renders_full_node(self):
        with patch(
            "hokora_tui.widgets.info_panel._resolve_interface", return_value="TCPClientInterface"
        ):
            w = build_node_info_panel(self._full_node())
        assert isinstance(w, urwid.Widget)
        text = " ".join(_walk_text(w))
        assert "Node Info" in text
        assert "Test-Node" in text
        assert "00000000000000000000000000000000" in text  # full identity hash, not truncated
        assert "4444444444444444" in text  # destination hash
        assert "direct (0 hops)" in text
        assert "Announcements" in text
        assert "Feedback" in text
        assert "★ saved" in text
        assert "Esc to close" in text
        # Type defaults to community-only when role hint absent.
        assert "Community Node" in text

    def test_renders_node_with_propagation_role(self):
        nd = self._full_node()
        nd["propagation_enabled"] = True
        with patch("hokora_tui.widgets.info_panel._resolve_interface", return_value="x"):
            w = build_node_info_panel(nd)
        text = " ".join(_walk_text(w))
        assert "Community Node · Propagation Node" in text

    def test_missing_identity_hash_renders_fallback(self):
        nd = self._full_node()
        del nd["node_identity_hash"]
        with patch("hokora_tui.widgets.info_panel._resolve_interface", return_value="(unknown)"):
            w = build_node_info_panel(nd)
        text = " ".join(_walk_text(w))
        assert "(not announced)" in text
        # Old wording included " — older daemon" — keep that out so the
        # message stays neutral and doesn't blame the announcing party.
        assert "older daemon" not in text

    def test_minimal_node_does_not_crash(self):
        """Only the truly required fields — name + hash. Everything else None/missing."""
        minimal = {"hash": "node-key", "node_name": "TestNode"}
        with patch("hokora_tui.widgets.info_panel._resolve_interface", return_value="(unknown)"):
            w = build_node_info_panel(minimal)
        assert isinstance(w, urwid.Widget)
        text = " ".join(_walk_text(w))
        assert "TestNode" in text

    def test_unbookmarked_node(self):
        nd = self._full_node()
        nd["bookmarked"] = False
        with patch("hokora_tui.widgets.info_panel._resolve_interface", return_value="x"):
            w = build_node_info_panel(nd)
        text = " ".join(_walk_text(w))
        assert "not bookmarked" in text

    def test_truncates_channel_dest_list_at_10(self):
        nd = self._full_node()
        nd["channel_dests"] = {f"id{i:02d}": f"dest{i:02d}" for i in range(15)}
        with patch("hokora_tui.widgets.info_panel._resolve_interface", return_value="x"):
            w = build_node_info_panel(nd)
        text = " ".join(_walk_text(w))
        assert "+5 more" in text


# ─────────────────────────────────────────────────────────────────────
# Peer info panel
# ─────────────────────────────────────────────────────────────────────


class TestBuildPeerInfoPanel:
    def _full_peer(self) -> dict:
        return {
            "hash": "66666666666666666666666666666666",
            "display_name": "alice",
            "status_text": "Online",
            "last_seen": 1700000000.0,
            "bookmarked": False,
            "hops": 1,
        }

    def test_renders_full_peer(self):
        engine = SimpleNamespace(identity_keys={})
        with patch("hokora_tui.widgets.info_panel._resolve_interface", return_value="TCPClient"):
            w = build_peer_info_panel(self._full_peer(), sync_engine=engine)
        text = " ".join(_walk_text(w))
        assert "Peer Info" in text
        assert "alice" in text
        assert "Online" in text
        assert "66666666666666666666666666666666" in text  # full hash
        assert "1 hop" in text

    def test_verified_state_when_pubkey_cached(self):
        peer = self._full_peer()
        engine = SimpleNamespace(identity_keys={peer["hash"]: b"x" * 32})
        with patch("hokora_tui.widgets.info_panel._resolve_interface", return_value="x"):
            w = build_peer_info_panel(peer, sync_engine=engine)
        text = " ".join(_walk_text(w))
        assert "verified" in text

    def test_no_key_cached_state(self):
        engine = SimpleNamespace(identity_keys={})
        with patch("hokora_tui.widgets.info_panel._resolve_interface", return_value="x"):
            w = build_peer_info_panel(self._full_peer(), sync_engine=engine)
        text = " ".join(_walk_text(w))
        assert "no key cached" in text

    def test_no_sync_engine_does_not_crash(self):
        with patch("hokora_tui.widgets.info_panel._resolve_interface", return_value="x"):
            w = build_peer_info_panel(self._full_peer(), sync_engine=None)
        text = " ".join(_walk_text(w))
        assert "no key cached" in text

    def test_minimal_peer_does_not_crash(self):
        with patch("hokora_tui.widgets.info_panel._resolve_interface", return_value="(unknown)"):
            w = build_peer_info_panel({"hash": "h" * 32, "display_name": "anon"})
        assert isinstance(w, urwid.Widget)


# ─────────────────────────────────────────────────────────────────────
# Internal formatting helpers
# ─────────────────────────────────────────────────────────────────────


class TestFormatNodeType:
    """Role-composition for the info panel Type field."""

    def test_pre_upgrade_daemon_renders_community_only(self):
        # propagation_enabled key absent — older daemon, no role hint.
        assert _format_node_type({}) == "Community Node"

    def test_propagation_disabled_renders_community_only(self):
        assert _format_node_type({"propagation_enabled": False}) == "Community Node"

    def test_propagation_enabled_appends_propagation(self):
        assert (
            _format_node_type({"propagation_enabled": True}) == "Community Node · Propagation Node"
        )

    def test_propagation_none_renders_community_only(self):
        # Explicit None (unknown) treated same as absent.
        assert _format_node_type({"propagation_enabled": None}) == "Community Node"


class TestFormatHops:
    def test_none_renders_unknown(self):
        assert "unknown" in _format_hops(None)

    def test_zero_is_direct(self):
        assert "direct" in _format_hops(0)
        assert "0 hops" in _format_hops(0)

    def test_singular(self):
        assert _format_hops(1) == "1 hop"

    def test_plural(self):
        assert _format_hops(5) == "5 hops"


class TestFormatLastSeen:
    def test_none_renders_never(self):
        assert _format_last_seen(None) == "(never)"

    def test_zero_renders_never(self):
        assert _format_last_seen(0) == "(never)"

    def test_invalid_renders_unknown(self):
        assert "unknown" in _format_last_seen("not-a-number")

    def test_recent_includes_relative_and_absolute(self):
        import time as _time

        s = _format_last_seen(_time.time() - 30)
        assert "ago" in s
        assert "T" in s and "Z" in s  # ISO 8601 UTC marker


class TestFormatVerifyState:
    def test_no_engine_returns_no_key_cached(self):
        assert "no key cached" in _format_verify_state("h" * 32, None)

    def test_no_peer_hash_returns_no_key_cached(self):
        engine = SimpleNamespace(identity_keys={"h" * 32: b"x" * 32})
        assert "no key cached" in _format_verify_state(None, engine)

    def test_cached_returns_verified(self):
        engine = SimpleNamespace(identity_keys={"h" * 32: b"x" * 32})
        assert "verified" in _format_verify_state("h" * 32, engine)

    def test_engine_without_identity_keys_attr(self):
        # Defensive: engine reference present but no attribute → graceful.
        engine = SimpleNamespace()  # no identity_keys
        assert "no key cached" in _format_verify_state("h" * 32, engine)


class TestResolveInterface:
    def test_no_dest_returns_unknown(self):
        assert _resolve_interface(None) == "(unknown)"
        assert _resolve_interface("") == "(unknown)"

    def test_invalid_hex_returns_unknown(self):
        assert _resolve_interface("not-hex") == "(unknown)"

    def test_rns_unavailable_returns_unknown(self):
        with patch.dict("sys.modules", {"RNS": None}):
            assert _resolve_interface("aabb") == "(unknown)"

    def test_rns_no_path_returns_no_path(self):
        fake_rns = MagicMock()
        fake_rns.Transport.next_hop_interface.return_value = None
        with patch.dict("sys.modules", {"RNS": fake_rns}):
            result = _resolve_interface("aabbccdd")
        assert result == "(no path)"

    def test_rns_returns_interface_name(self):
        fake_iface = MagicMock()
        fake_iface.name = "TCPClientInterface[seed.example.org:4242]"
        fake_rns = MagicMock()
        fake_rns.Transport.next_hop_interface.return_value = fake_iface
        with patch.dict("sys.modules", {"RNS": fake_rns}):
            result = _resolve_interface("aabbccdd")
        assert "TCPClientInterface" in result

    def test_rns_exception_falls_through(self):
        fake_rns = MagicMock()
        fake_rns.Transport.next_hop_interface.side_effect = RuntimeError("boom")
        with patch.dict("sys.modules", {"RNS": fake_rns}):
            assert _resolve_interface("aabbccdd") == "(unknown)"


# ─────────────────────────────────────────────────────────────────────
# Subview wiring — Modal.show is called with the right widget
# ─────────────────────────────────────────────────────────────────────


class TestSubviewModalWiring:
    def test_nodes_subview_show_info_calls_modal(self):
        from hokora_tui.views.discovery.nodes_subview import NodesSubView
        from hokora_tui.widgets.node_item import NodeItem

        app = MagicMock()
        sub = NodesSubView(app, on_node_selected=lambda d: None)
        # Mock a focused NodeItem so show_info_focused has something to use.
        node = {"hash": "x", "node_name": "TestNode", "hops": 0}
        item = NodeItem(node, lambda d: None)
        sub.walker.append(item)
        sub.walker.set_focus(0)

        with patch("hokora_tui.views.discovery.nodes_subview.Modal.show") as mock_show:
            sub.show_info_focused()
        mock_show.assert_called_once()
        # First positional arg is the app; title should mention the node name.
        args, kwargs = mock_show.call_args
        assert "TestNode" in args[1]

    def test_peers_subview_show_info_calls_modal(self):
        from hokora_tui.views.discovery.peers_subview import PeersSubView
        from hokora_tui.widgets.peer_item import PeerItem

        app = MagicMock()
        sub = PeersSubView(app, on_peer_selected=lambda d: None)
        peer = {"hash": "h" * 32, "display_name": "bob", "hops": 1}
        item = PeerItem(peer, lambda d: None)
        sub.walker.append(item)
        sub.walker.set_focus(0)

        with patch("hokora_tui.views.discovery.peers_subview.Modal.show") as mock_show:
            sub.show_info_focused()
        mock_show.assert_called_once()
        args, kwargs = mock_show.call_args
        assert "bob" in args[1]

    def test_subview_show_info_no_focus_is_noop(self):
        from hokora_tui.views.discovery.nodes_subview import NodesSubView

        app = MagicMock()
        sub = NodesSubView(app, on_node_selected=lambda d: None)
        # Walker is empty → get_focus returns (None, None).
        with patch("hokora_tui.views.discovery.nodes_subview.Modal.show") as mock_show:
            sub.show_info_focused()
        mock_show.assert_not_called()
