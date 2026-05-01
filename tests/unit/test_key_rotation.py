# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for federation/key_rotation.py."""

import time
from unittest.mock import MagicMock, patch

import msgpack

from hokora.federation.key_rotation import KeyRotationManager, KEY_ROTATION_GRACE_PERIOD


class TestKeyRotationManager:
    def test_initiate_rotation(self):
        mgr = KeyRotationManager()

        old_identity = MagicMock()
        old_identity.hexhash = "a" * 32
        old_identity.sign = MagicMock(return_value=b"\x01" * 64)

        new_identity = MagicMock()
        new_identity.hexhash = "b" * 32
        new_identity.sign = MagicMock(return_value=b"\x02" * 64)

        old_dest = MagicMock()

        result = mgr.initiate_rotation("ch1", old_identity, new_identity, old_dest)

        # Both identities should have signed
        old_identity.sign.assert_called_once()
        new_identity.sign.assert_called_once()
        # Destination should have announced
        old_dest.announce.assert_called_once()

        # Result should be valid msgpack
        data = msgpack.unpackb(result, raw=False)
        assert "payload" in data
        assert "old_signature" in data
        assert "new_signature" in data

        payload = msgpack.unpackb(data["payload"], raw=False)
        assert payload["type"] == "key_rotation"
        assert payload["channel_id"] == "ch1"
        assert payload["old_hash"] == "a" * 32
        assert payload["new_hash"] == "b" * 32

    @patch("hokora.federation.key_rotation.RNS")
    def test_verify_rotation_valid(self, mock_rns):
        old_identity = MagicMock()
        old_identity.validate = MagicMock(return_value=True)
        new_identity = MagicMock()
        new_identity.validate = MagicMock(return_value=True)

        mock_rns.Identity.recall = MagicMock(side_effect=[old_identity, new_identity])

        payload = msgpack.packb(
            {
                "type": "key_rotation",
                "channel_id": "ch1",
                "old_hash": "a" * 32,
                "new_hash": "b" * 32,
                "timestamp": time.time(),
                "grace_period": KEY_ROTATION_GRACE_PERIOD,
            },
            use_bin_type=True,
        )

        announce_data = msgpack.packb(
            {
                "payload": payload,
                "old_signature": b"\x01" * 64,
                "new_signature": b"\x02" * 64,
            },
            use_bin_type=True,
        )

        result = KeyRotationManager.verify_rotation(announce_data)
        assert result is not None
        assert result["channel_id"] == "ch1"

    @patch("hokora.federation.key_rotation.RNS")
    def test_verify_rotation_invalid_old_sig(self, mock_rns):
        old_identity = MagicMock()
        old_identity.validate = MagicMock(return_value=False)  # Invalid
        new_identity = MagicMock()
        new_identity.validate = MagicMock(return_value=True)

        mock_rns.Identity.recall = MagicMock(side_effect=[old_identity, new_identity])

        payload = msgpack.packb(
            {
                "type": "key_rotation",
                "channel_id": "ch1",
                "old_hash": "a" * 32,
                "new_hash": "b" * 32,
                "timestamp": time.time(),
                "grace_period": KEY_ROTATION_GRACE_PERIOD,
            },
            use_bin_type=True,
        )

        announce_data = msgpack.packb(
            {
                "payload": payload,
                "old_signature": b"\x01" * 64,
                "new_signature": b"\x02" * 64,
            },
            use_bin_type=True,
        )

        result = KeyRotationManager.verify_rotation(announce_data)
        assert result is None

    @patch("hokora.federation.key_rotation.RNS")
    def test_verify_rotation_invalid_new_sig(self, mock_rns):
        old_identity = MagicMock()
        old_identity.validate = MagicMock(return_value=True)
        new_identity = MagicMock()
        new_identity.validate = MagicMock(return_value=False)  # Invalid

        mock_rns.Identity.recall = MagicMock(side_effect=[old_identity, new_identity])

        payload = msgpack.packb(
            {
                "type": "key_rotation",
                "channel_id": "ch1",
                "old_hash": "a" * 32,
                "new_hash": "b" * 32,
                "timestamp": time.time(),
                "grace_period": KEY_ROTATION_GRACE_PERIOD,
            },
            use_bin_type=True,
        )

        announce_data = msgpack.packb(
            {
                "payload": payload,
                "old_signature": b"\x01" * 64,
                "new_signature": b"\x02" * 64,
            },
            use_bin_type=True,
        )

        result = KeyRotationManager.verify_rotation(announce_data)
        assert result is None

    @patch("hokora.federation.key_rotation.RNS")
    def test_verify_rotation_unknown_identity(self, mock_rns):
        mock_rns.Identity.recall = MagicMock(return_value=None)

        payload = msgpack.packb(
            {
                "type": "key_rotation",
                "channel_id": "ch1",
                "old_hash": "a" * 32,
                "new_hash": "b" * 32,
                "timestamp": time.time(),
                "grace_period": KEY_ROTATION_GRACE_PERIOD,
            },
            use_bin_type=True,
        )

        announce_data = msgpack.packb(
            {
                "payload": payload,
                "old_signature": b"\x01" * 64,
                "new_signature": b"\x02" * 64,
            },
            use_bin_type=True,
        )

        result = KeyRotationManager.verify_rotation(announce_data)
        assert result is None

    def test_verify_rotation_malformed(self):
        result = KeyRotationManager.verify_rotation(b"not msgpack")
        assert result is None

    def test_is_in_grace_period_active(self):
        mgr = KeyRotationManager()
        mgr._pending_rotations["ch1"] = {
            "old_identity": MagicMock(),
            "new_identity": MagicMock(),
            "timestamp": time.time(),
            "grace_end": time.time() + 3600,
        }
        assert mgr.is_in_grace_period("ch1") is True

    def test_is_in_grace_period_expired(self):
        mgr = KeyRotationManager()
        mgr._pending_rotations["ch1"] = {
            "old_identity": MagicMock(),
            "new_identity": MagicMock(),
            "timestamp": time.time() - 200000,
            "grace_end": time.time() - 100,
        }
        assert mgr.is_in_grace_period("ch1") is False

    def test_is_in_grace_period_unknown(self):
        mgr = KeyRotationManager()
        assert mgr.is_in_grace_period("unknown") is False
