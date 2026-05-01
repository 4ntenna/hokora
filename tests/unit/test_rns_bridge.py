# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for ``ReticulumBridge``.

Pin the CDSP spec contract (interface-type information must NOT leak
through this abstraction) plus the MDU-based Packet→Resource auto-
promotion that lets every send-site stay transport-agnostic.

``ReticulumBridge`` does ``import RNS`` inside each method (lazy), so
tests patch ``sys.modules["RNS"]`` for the duration of the call.
"""

from contextlib import contextmanager
from unittest.mock import MagicMock, patch


@contextmanager
def _patched_rns(mdu: int = 500):
    """Replace the ``RNS`` module in ``sys.modules`` with a MagicMock
    that exposes ``Link.MDU``, ``Packet``, ``Resource``, ``Destination``,
    and ``Transport``. The MDU is configurable per test."""
    rns_mod = MagicMock()
    rns_mod.Link.MDU = mdu
    rns_mod.Destination.IN = 1
    rns_mod.Destination.SINGLE = 2
    with patch.dict("sys.modules", {"RNS": rns_mod}):
        yield rns_mod


def _make_bridge():
    """Construct a ReticulumBridge with mock RNS / router / identity."""
    from hokora.protocol.rns_bridge import ReticulumBridge

    return ReticulumBridge(MagicMock(), MagicMock(), MagicMock())


def test_get_identity_returns_constructor_arg():
    from hokora.protocol.rns_bridge import ReticulumBridge

    identity = MagicMock()
    bridge = ReticulumBridge(MagicMock(), MagicMock(), identity)
    assert bridge.get_identity() is identity


def test_send_packet_uses_rns_packet_when_under_mdu():
    bridge = _make_bridge()
    link = MagicMock()
    payload = b"x" * 100
    with _patched_rns(mdu=500) as rns_mod:
        bridge.send_packet(link, payload)
        rns_mod.Packet.assert_called_once_with(link, payload)
        rns_mod.Packet.return_value.send.assert_called_once()
        rns_mod.Resource.assert_not_called()


def test_send_packet_promotes_to_resource_above_mdu():
    """Single chokepoint: every send above MDU goes through Resource —
    no transport-aware send-site needs to reason about MDU itself."""
    bridge = _make_bridge()
    link = MagicMock()
    payload = b"y" * 1000
    with _patched_rns(mdu=500) as rns_mod:
        bridge.send_packet(link, payload)
        rns_mod.Resource.assert_called_once_with(payload, link)
        rns_mod.Packet.assert_not_called()


def test_send_packet_at_exactly_mdu_uses_packet():
    """Boundary: data exactly == MDU is still a Packet (not Resource)."""
    bridge = _make_bridge()
    link = MagicMock()
    with _patched_rns(mdu=500) as rns_mod:
        bridge.send_packet(link, b"z" * 500)
        rns_mod.Packet.assert_called_once()
        rns_mod.Resource.assert_not_called()


def test_send_resource_unconditional():
    """``send_resource`` skips the MDU check — used when the caller
    already knows the payload won't fit a Packet."""
    bridge = _make_bridge()
    link = MagicMock()
    payload = b"any size"
    with _patched_rns() as rns_mod:
        bridge.send_resource(link, payload)
        rns_mod.Resource.assert_called_once_with(payload, link)
        rns_mod.Packet.assert_not_called()


def test_get_destination_constructs_in_single():
    """``get_destination`` always builds an IN/SINGLE destination — the
    bridge never produces OUT or GROUP ones (those are constructed by
    callers that own outbound routing themselves)."""
    bridge = _make_bridge()
    ident = MagicMock()
    with _patched_rns() as rns_mod:
        bridge.get_destination(ident, "lxmf", "delivery")
        rns_mod.Destination.assert_called_once_with(ident, 1, 2, "lxmf", "delivery")


def test_request_path_delegates_to_transport():
    bridge = _make_bridge()
    target = b"\xaa" * 16
    with _patched_rns() as rns_mod:
        bridge.request_path(target)
        rns_mod.Transport.request_path.assert_called_once_with(target)


def test_no_interface_inspection_methods():
    """CDSP spec invariant: the bridge MUST NOT expose interface-type
    accessors. A regression that adds ``get_interface_type``,
    ``get_link_transport``, etc. would let app-layer code reason about
    LoRa-vs-TCP and break the transport-agnostic contract."""
    from hokora.protocol.rns_bridge import ReticulumBridge

    forbidden = (
        "get_interface_type",
        "get_link_transport",
        "get_bitrate",
        "get_attached_interface",
    )
    for name in forbidden:
        assert not hasattr(ReticulumBridge, name), (
            f"ReticulumBridge.{name} would leak interface-type info — see CDSP spec §4.1.3"
        )
