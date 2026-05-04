# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Hop-count capture in the TUI Announcer.

Validates that ``Announcer._on_announce`` queries
``RNS.Transport.hops_to(destination_hash)`` for every inbound channel
and profile announce, that the PATHFINDER_M sentinel is mapped to None,
and that exceptions raised inside RNS degrade to None rather than
killing the announce listener.

The widget-side rendering helpers (``widgets/node_item._format_hops``
and ``widgets/peer_item._format_hops``) are also exercised here to keep
the round-trip in one file.
"""

from __future__ import annotations

import sys
import time
from unittest.mock import MagicMock, patch

import msgpack
import pytest

from hokora_tui.announcer import Announcer
from hokora_tui.widgets.node_item import _format_hops as _format_hops_node
from hokora_tui.widgets.peer_item import _format_hops as _format_hops_peer


# ── Test fixtures ───────────────────────────────────────────────────


def _make_app():
    """Construct a minimal HokoraTUI stand-in for Announcer."""
    app = MagicMock()
    app.state.discovered_nodes = {}
    app.state.discovered_peers = {}
    app.state.auto_announce = False
    app.state.identity = None
    app.state.emit = MagicMock()
    app._schedule_redraw = MagicMock()
    app.db = None
    app.sync_engine = None
    return app


def _channel_announce_blob(node_name="NodeA", channel="general", channel_id="abc12345"):
    return msgpack.packb(
        {
            "type": "channel",
            "node": node_name,
            "name": channel,
            "channel_id": channel_id,
            "node_identity_hash": "0123456789abcdef0123456789abcdef",
            "time": time.time(),
        }
    )


def _profile_announce_blob(display_name="alice", status="Online"):
    return msgpack.packb(
        {
            "type": "profile",
            "display_name": display_name,
            "status_text": status,
            "time": time.time(),
        }
    )


def _make_identity(hex_hash: str = "f" * 32):
    ident = MagicMock()
    ident.hexhash = hex_hash
    return ident


def _patch_rns(hops_value=0, hexrep_value="deadbeef", hops_side_effect=None):
    """Install a fake RNS module the announcer's `import RNS` will pick up.

    Returns the patched module so callers can configure further or assert
    on its mock attributes.
    """
    fake = MagicMock()
    fake.hexrep.return_value = hexrep_value
    fake.Transport.PATHFINDER_M = 128
    if hops_side_effect is not None:
        fake.Transport.hops_to.side_effect = hops_side_effect
    else:
        fake.Transport.hops_to.return_value = hops_value
    return patch.dict(sys.modules, {"RNS": fake})


# ── Channel announce ─────────────────────────────────────────────────


class TestChannelAnnounceHops:
    def test_direct_neighbor_records_hops_zero(self):
        app = _make_app()
        ann = Announcer(app)
        with _patch_rns(hops_value=0):
            ann._on_announce(b"\xde\xad\xbe\xef", _make_identity(), _channel_announce_blob())

        node = next(iter(app.state.discovered_nodes.values()))
        assert node["hops"] == 0

    def test_routed_path_records_real_hop_count(self):
        app = _make_app()
        ann = Announcer(app)
        with _patch_rns(hops_value=3):
            ann._on_announce(b"\xde\xad\xbe\xef", _make_identity(), _channel_announce_blob())

        node = next(iter(app.state.discovered_nodes.values()))
        assert node["hops"] == 3

    def test_pathfinder_m_sentinel_maps_to_none(self):
        app = _make_app()
        ann = Announcer(app)
        with _patch_rns(hops_value=128):
            ann._on_announce(b"\xde\xad\xbe\xef", _make_identity(), _channel_announce_blob())

        node = next(iter(app.state.discovered_nodes.values()))
        assert node["hops"] is None

    def test_above_pathfinder_m_also_maps_to_none(self):
        app = _make_app()
        ann = Announcer(app)
        with _patch_rns(hops_value=250):
            ann._on_announce(b"\xde\xad\xbe\xef", _make_identity(), _channel_announce_blob())

        node = next(iter(app.state.discovered_nodes.values()))
        assert node["hops"] is None

    def test_hops_to_exception_degrades_to_none_does_not_break_ingest(self):
        app = _make_app()
        ann = Announcer(app)
        with _patch_rns(hops_side_effect=RuntimeError("path table locked")):
            ann._on_announce(b"\xde\xad\xbe\xef", _make_identity(), _channel_announce_blob())

        assert len(app.state.discovered_nodes) == 1
        node = next(iter(app.state.discovered_nodes.values()))
        assert node["hops"] is None
        # Other fields populated normally — the failure was contained.
        assert node["node_name"] == "NodeA"
        assert "general" in node["channels"]


# ── Profile announce ─────────────────────────────────────────────────


class TestProfileAnnounceHops:
    def test_profile_announce_records_hops(self):
        app = _make_app()
        ann = Announcer(app)
        with _patch_rns(hops_value=2, hexrep_value="cafebabe"):
            ann._on_announce(
                b"\xca\xfe\xba\xbe", _make_identity("a" * 32), _profile_announce_blob()
            )

        peer = next(iter(app.state.discovered_peers.values()))
        assert peer["hops"] == 2
        assert peer["display_name"] == "alice"

    def test_profile_announce_unknown_path_records_none(self):
        app = _make_app()
        ann = Announcer(app)
        with _patch_rns(hops_value=128, hexrep_value="cafebabe"):
            ann._on_announce(
                b"\xca\xfe\xba\xbe", _make_identity("b" * 32), _profile_announce_blob()
            )

        peer = next(iter(app.state.discovered_peers.values()))
        assert peer["hops"] is None


# ── Widget rendering helpers ─────────────────────────────────────────


@pytest.mark.parametrize(
    "fmt",
    [_format_hops_node, _format_hops_peer],
    ids=["node_item", "peer_item"],
)
class TestFormatHops:
    def test_none_renders_as_question_mark(self, fmt):
        label, style = fmt(None)
        assert label == "?h"
        assert style == "node_stale"

    def test_zero_renders_as_direct(self, fmt):
        label, style = fmt(0)
        assert label == "direct"
        assert style == "node_recent"

    def test_one_renders_as_one_hop(self, fmt):
        label, style = fmt(1)
        assert label == "1h"
        assert style == "default"

    def test_high_count_renders_with_count(self, fmt):
        label, style = fmt(7)
        assert label == "7h"
        assert style == "default"
