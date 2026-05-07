# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for the inbound resource size chokepoint.

These tests use a real ``RNS.ResourceAdvertisement`` (not ``MagicMock``) so
attribute drift between the filter and the RNS API surface fails loudly.
"""

import logging

import RNS
from RNS.vendor import umsgpack

from hokora.protocol.rns_bridge import make_resource_filter


def _build_advertisement(total_size: int, transfer_size: int = None) -> RNS.ResourceAdvertisement:
    """Pack and unpack a real ResourceAdvertisement with the given data size."""
    if transfer_size is None:
        transfer_size = total_size
    adv_dict = {
        "t": transfer_size,
        "d": total_size,
        "n": 1,
        "h": b"\x00" * 32,
        "r": b"\x00" * 32,
        "o": b"\x00" * 32,
        "m": b"\x00" * 32,
        "f": 0x00,
        "i": 1,
        "l": 1,
        "q": None,
    }
    return RNS.ResourceAdvertisement.unpack(umsgpack.packb(adv_dict))


class TestSizeBoundary:
    def test_under_cap_accepts(self):
        f = make_resource_filter(max_data_size=5 * 1024 * 1024, label="test")
        assert f(_build_advertisement(1024 * 1024)) is True

    def test_at_cap_accepts(self):
        cap = 5 * 1024 * 1024
        f = make_resource_filter(max_data_size=cap, label="test")
        assert f(_build_advertisement(cap)) is True

    def test_over_cap_rejects(self):
        f = make_resource_filter(max_data_size=5 * 1024 * 1024, label="test")
        assert f(_build_advertisement(10 * 1024 * 1024)) is False

    def test_zero_size_accepts(self):
        # An empty resource is degenerate but legitimate.
        f = make_resource_filter(max_data_size=5 * 1024 * 1024, label="test")
        assert f(_build_advertisement(0)) is True


class TestMalformedSize:
    def test_negative_size_rejects(self):
        f = make_resource_filter(max_data_size=5 * 1024 * 1024, label="test")
        adv = _build_advertisement(0)
        adv.d = -1
        assert f(adv) is False


class TestRejectionHook:
    def test_on_reject_fires_with_oversize(self):
        reasons = []
        f = make_resource_filter(
            max_data_size=1024,
            label="test",
            on_reject=reasons.append,
        )
        f(_build_advertisement(2048))
        assert reasons == ["oversize"]

    def test_on_reject_fires_with_malformed(self):
        reasons = []
        f = make_resource_filter(
            max_data_size=1024,
            label="test",
            on_reject=reasons.append,
        )
        adv = _build_advertisement(0)
        adv.d = -1
        f(adv)
        assert reasons == ["malformed"]

    def test_on_reject_does_not_fire_on_accept(self):
        reasons = []
        f = make_resource_filter(
            max_data_size=1024 * 1024,
            label="test",
            on_reject=reasons.append,
        )
        f(_build_advertisement(512))
        assert reasons == []


class TestLogging:
    def test_oversize_logs_warning(self, caplog):
        f = make_resource_filter(max_data_size=1024, label="daemon-link")
        with caplog.at_level(logging.WARNING, logger="hokora.protocol.rns_bridge"):
            f(_build_advertisement(2048))
        assert "daemon-link" in caplog.text
        assert "2048" in caplog.text


class TestApiContract:
    """Pin the assumption that callers must use ``get_data_size()``.

    If RNS ever renames the accessor, this test fails before production does.
    """

    def test_advertisement_exposes_get_data_size(self):
        adv = _build_advertisement(12345)
        assert adv.get_data_size() == 12345

    def test_advertisement_has_no_data_size_attribute(self):
        # ``data_size`` would AttributeError silently inside RNS callback
        # dispatch; only ``get_data_size()`` / ``.d`` are safe to read.
        adv = _build_advertisement(12345)
        try:
            _ = adv.data_size
        except AttributeError:
            return
        raise AssertionError("ResourceAdvertisement gained a data_size attribute")
