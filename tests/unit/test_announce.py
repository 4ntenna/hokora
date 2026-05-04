# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for AnnounceHandler: channel announce parsing, profile building."""

import msgpack

from hokora.core.announce import AnnounceHandler


class TestParseChannelAnnounce:
    def test_parse_channel_announce_valid(self):
        data = msgpack.packb(
            {
                "type": "channel",
                "name": "general",
                "description": "A test channel",
                "node": "TestNode",
                "time": 1700000000.0,
            }
        )
        result = AnnounceHandler.parse_channel_announce(data)
        assert result is not None
        assert result["type"] == "channel"
        assert result["name"] == "general"

    def test_parse_channel_announce_malformed_returns_none(self):
        result = AnnounceHandler.parse_channel_announce(b"\xff\xfe\x00invalid")
        assert result is None

    def test_parse_channel_announce_wrong_type_returns_none(self):
        data = msgpack.packb(
            {
                "type": "profile",
                "display_name": "Alice",
            }
        )
        result = AnnounceHandler.parse_channel_announce(data)
        assert result is None


class TestParseAnnounceDispatch:
    """Unified ``parse_announce()`` dispatch by announce type."""

    def test_parse_announce_channel(self):
        data = msgpack.packb({"type": "channel", "name": "gen"})
        result = AnnounceHandler.parse_announce(data)
        assert result is not None
        assert result["type"] == "channel"
        assert result["name"] == "gen"

    def test_parse_announce_profile(self):
        data = msgpack.packb({"type": "profile", "display_name": "Ada"})
        result = AnnounceHandler.parse_announce(data)
        assert result is not None
        assert result["type"] == "profile"

    def test_parse_announce_key_rotation_envelope(self):
        payload = msgpack.packb(
            {
                "type": "key_rotation",
                "channel_id": "ch01",
                "old_hash": "a" * 64,
                "new_hash": "b" * 64,
            }
        )
        envelope = msgpack.packb(
            {
                "payload": payload,
                "old_signature": b"\x01" * 64,
                "new_signature": b"\x02" * 64,
            }
        )
        result = AnnounceHandler.parse_announce(envelope)
        assert result is not None
        assert result["type"] == "key_rotation"
        assert result["payload"]["channel_id"] == "ch01"
        # Full envelope preserved for downstream signature verification.
        assert "envelope" in result

    def test_parse_announce_unknown_type_returns_none(self):
        data = msgpack.packb({"type": "something_weird", "x": 1})
        assert AnnounceHandler.parse_announce(data) is None

    def test_parse_announce_malformed_returns_none(self):
        assert AnnounceHandler.parse_announce(b"\xff\xfe\x00") is None

    def test_parse_announce_non_dict_returns_none(self):
        data = msgpack.packb(["not", "a", "dict"])
        assert AnnounceHandler.parse_announce(data) is None


class TestParseKeyRotationAnnounce:
    """Delegating wrapper around ``KeyRotationManager.verify_rotation``."""

    def test_parse_key_rotation_delegates_to_verifier(self):
        from unittest.mock import patch

        sentinel = {"channel_id": "ch01"}
        with patch(
            "hokora.federation.key_rotation.KeyRotationManager.verify_rotation",
            return_value=sentinel,
        ):
            result = AnnounceHandler.parse_key_rotation_announce(b"any-bytes")
        assert result is sentinel

    def test_parse_key_rotation_returns_none_on_failed_verify(self):
        from unittest.mock import patch

        with patch(
            "hokora.federation.key_rotation.KeyRotationManager.verify_rotation",
            return_value=None,
        ):
            assert AnnounceHandler.parse_key_rotation_announce(b"bad") is None
