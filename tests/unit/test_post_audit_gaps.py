# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for post-audit gap implementations (items 1-6)."""

import struct
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from hokora.constants import (
    SYNC_HISTORY,
)
from hokora.db.models import Channel, Message
from hokora.db.queries import ChannelRepo, MessageRepo
from hokora.db.maintenance import MaintenanceManager
from hokora.exceptions import SyncError
from hokora.protocol.wire import (
    encode_sync_request,
    decode_sync_request,
    encode_sync_response,
    decode_sync_response,
    generate_nonce,
    _add_length_header,
    _strip_length_header,
)
from hokora.security.sealed import SealedChannelManager


# --- Item 1: Client-side signature verification ---


class TestClientSideSignatureVerification:
    def test_sync_engine_verifies_valid_signature(self):
        """SyncEngine marks messages as verified when signature is valid."""
        with patch("hokora_tui.sync_engine.RNS"):
            from hokora_tui.sync_engine import SyncEngine

            engine = SyncEngine(MagicMock())

            # Generate a real Ed25519 key pair
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

            private_key = Ed25519PrivateKey.generate()
            public_key = private_key.public_key()

            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

            pub_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

            # Signature now verifies lxmf_signed_part (not body)
            signed_part = b"\x01" * 64
            sig = private_key.sign(signed_part)

            messages = [
                {
                    "msg_hash": "h1",
                    "channel_id": "ch1",
                    "sender_hash": "sender1",
                    "seq": 1,
                    "timestamp": time.time(),
                    "type": 1,
                    "body": "Hello mesh",
                    "lxmf_signature": sig,
                    "lxmf_signed_part": signed_part,
                    "sender_public_key": pub_bytes,
                }
            ]

            # Simulate _handle_response
            callback_data = {}
            engine.set_message_callback(
                lambda cid, msgs, seq=0: callback_data.update({"msgs": msgs})
            )
            engine._handle_response(
                {"action": "history", "channel_id": "ch1", "messages": messages}
            )

            assert callback_data["msgs"][0]["verified"] is True

    def test_sync_engine_flags_invalid_signature(self):
        with patch("hokora_tui.sync_engine.RNS"):
            from hokora_tui.sync_engine import SyncEngine

            engine = SyncEngine(MagicMock())

            # Generate real key but sign with different key
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

            real_key = Ed25519PrivateKey.generate()
            fake_key = Ed25519PrivateKey.generate()
            pub_bytes = real_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

            signed_part = b"\x01" * 64
            bad_sig = fake_key.sign(signed_part)  # Wrong key

            messages = [
                {
                    "msg_hash": "h2",
                    "channel_id": "ch1",
                    "sender_hash": "sender2",
                    "seq": 1,
                    "timestamp": time.time(),
                    "type": 1,
                    "body": "Hello mesh",
                    "lxmf_signature": bad_sig,
                    "lxmf_signed_part": signed_part,
                    "sender_public_key": pub_bytes,
                }
            ]

            callback_data = {}
            engine.set_message_callback(
                lambda cid, msgs, seq=0: callback_data.update({"msgs": msgs})
            )
            engine._handle_response(
                {"action": "history", "channel_id": "ch1", "messages": messages}
            )

            assert callback_data["msgs"][0]["verified"] is False

    def test_sync_engine_no_public_key(self):
        with patch("hokora_tui.sync_engine.RNS"):
            from hokora_tui.sync_engine import SyncEngine

            engine = SyncEngine(MagicMock())

            messages = [
                {
                    "msg_hash": "h3",
                    "channel_id": "ch1",
                    "sender_hash": "unknown_sender",
                    "seq": 1,
                    "timestamp": time.time(),
                    "type": 1,
                    "body": "test",
                    "lxmf_signature": b"\x00" * 64,
                }
            ]

            callback_data = {}
            engine.set_message_callback(
                lambda cid, msgs, seq=0: callback_data.update({"msgs": msgs})
            )
            engine._handle_response(
                {"action": "history", "channel_id": "ch1", "messages": messages}
            )

            assert callback_data["msgs"][0]["verified"] is False


# --- Item 2: Client-side sequence integrity checking ---


class TestClientSideSequenceIntegrity:
    def test_sequence_gap_warning_generated(self):
        with patch("hokora_tui.sync_engine.RNS"):
            from hokora_tui.sync_engine import SyncEngine

            engine = SyncEngine(MagicMock())
            engine.set_cursor("ch1", 10)

            # Gap of 20 (10 -> 30) should trigger warning
            messages = [
                {
                    "msg_hash": "hg1",
                    "channel_id": "ch1",
                    "sender_hash": "s1",
                    "seq": 30,
                    "timestamp": time.time(),
                    "type": 1,
                    "body": "After gap",
                }
            ]

            engine.set_message_callback(lambda cid, msgs, seq=0: None)
            engine._handle_response(
                {"action": "history", "channel_id": "ch1", "messages": messages}
            )

            warnings = engine.get_seq_warnings("ch1")
            assert len(warnings) == 1
            assert "gap" in warnings[0].lower()

    def test_no_warning_for_small_gap(self):
        with patch("hokora_tui.sync_engine.RNS"):
            from hokora_tui.sync_engine import SyncEngine

            engine = SyncEngine(MagicMock())
            engine.set_cursor("ch1", 10)

            messages = [
                {
                    "msg_hash": "hg2",
                    "channel_id": "ch1",
                    "sender_hash": "s1",
                    "seq": 11,
                    "timestamp": time.time(),
                    "type": 1,
                    "body": "Next message",
                }
            ]

            engine.set_message_callback(lambda cid, msgs, seq=0: None)
            engine._handle_response(
                {"action": "history", "channel_id": "ch1", "messages": messages}
            )

            warnings = engine.get_seq_warnings("ch1")
            assert len(warnings) == 0


# --- Item 3: Metadata scrubbing ---


class TestMetadataScrubbing:
    async def test_scrub_old_messages(self, session, engine):
        ch_repo = ChannelRepo(session)
        await ch_repo.create(Channel(id="scrub1", name="scrub_test", latest_seq=0))

        msg_repo = MessageRepo(session)
        old_ts = time.time() - (40 * 86400)  # 40 days ago
        await msg_repo.insert(
            Message(
                msg_hash="scrub001",
                channel_id="scrub1",
                sender_hash="s1",
                seq=1,
                timestamp=old_ts,
                type=1,
                body="Old message",
            )
        )
        recent_ts = time.time() - 86400  # 1 day ago
        await msg_repo.insert(
            Message(
                msg_hash="scrub002",
                channel_id="scrub1",
                sender_hash="s2",
                seq=2,
                timestamp=recent_ts,
                type=1,
                body="Recent message",
            )
        )
        await session.flush()

        mm = MaintenanceManager(engine, Path("/tmp"))
        count = await mm.scrub_metadata(session, days=30)
        assert count == 1

        # Old message sender nulled
        old_msg = await msg_repo.get_by_hash("scrub001")
        assert old_msg.sender_hash is None

        # Recent message untouched
        recent_msg = await msg_repo.get_by_hash("scrub002")
        assert recent_msg.sender_hash == "s2"

    async def test_scrub_disabled(self, session, engine):
        mm = MaintenanceManager(engine, Path("/tmp"))
        count = await mm.scrub_metadata(session, days=0)
        assert count == 0


# --- Item 4: Sealed channel key distribution ---


class TestSealedKeyDistribution:
    def test_distribute_key_calls_lxmf(self):
        import sys

        mock_rns = MagicMock()
        mock_lxmf = MagicMock()

        mock_identity = MagicMock()
        mock_identity.encrypt = MagicMock(return_value=b"\xee" * 32)
        mock_rns.Identity.recall = MagicMock(return_value=mock_identity)
        mock_rns.Destination = MagicMock()
        mock_lxmf.LXMessage = MagicMock()
        mock_lxmf.LXMessage.DIRECT = 1

        # Patch at sys.modules level for local imports
        with patch.dict(sys.modules, {"RNS": mock_rns, "LXMF": mock_lxmf}):
            mgr = SealedChannelManager()
            mgr.generate_key("ch1")

            mock_router = MagicMock()
            mock_router.get_delivery_destination.return_value = MagicMock()

            results = mgr.distribute_key(
                "ch1",
                ["aa" * 16, "bb" * 16],
                mock_router,
                MagicMock(),
            )

        assert len(results) == 2
        assert all(r["success"] for r in results)
        assert mock_router.handle_outbound.call_count == 2

    def test_distribute_key_unknown_identity(self):
        import sys

        mock_rns = MagicMock()
        mock_lxmf = MagicMock()
        mock_rns.Identity.recall = MagicMock(return_value=None)

        with patch.dict(sys.modules, {"RNS": mock_rns, "LXMF": mock_lxmf}):
            mgr = SealedChannelManager()
            mgr.generate_key("ch1")

            mock_router = MagicMock()
            results = mgr.distribute_key(
                "ch1",
                ["unknown_hash"],
                mock_router,
                MagicMock(),
            )

        assert len(results) == 1
        assert results[0]["success"] is False


# --- Item 5: Sealed channel member removal key rotation ---


class TestSealedKeyRotationOnRemoval:
    def test_rotate_and_distribute(self):
        import sys

        mock_rns = MagicMock()
        mock_lxmf = MagicMock()

        mock_rns.Identity.recall = MagicMock(
            return_value=MagicMock(encrypt=MagicMock(return_value=b"\x00" * 32))
        )
        mock_rns.Destination = MagicMock()
        mock_lxmf.LXMessage = MagicMock()
        mock_lxmf.LXMessage.DIRECT = 1

        with patch.dict(sys.modules, {"RNS": mock_rns, "LXMF": mock_lxmf}):
            mgr = SealedChannelManager()
            mgr.generate_key("ch1")
            original_epoch = mgr.get_epoch("ch1")

            mock_router = MagicMock()
            mock_router.get_delivery_destination.return_value = MagicMock()

            key, epoch, results = mgr.rotate_and_distribute(
                "ch1",
                ["remaining_member"],
                mock_router,
                MagicMock(),
            )

        assert epoch == original_epoch + 1
        assert len(results) == 1


# --- Item 6: Wire protocol 2-byte length header ---


class TestWireLengthHeader:
    def test_encode_decode_request_with_header(self):
        nonce = generate_nonce()
        payload = {"channel_id": "test123", "since_seq": 42}
        encoded = encode_sync_request(SYNC_HISTORY, nonce, payload)

        # Verify 2-byte header is present
        header_len = struct.unpack("!H", encoded[:2])[0]
        assert header_len == len(encoded) - 2

        decoded = decode_sync_request(encoded)
        assert decoded["action"] == SYNC_HISTORY
        assert decoded["nonce"] == nonce
        assert decoded["payload"]["channel_id"] == "test123"

    def test_encode_decode_response_with_header(self):
        nonce = generate_nonce()
        data = {"action": "history", "messages": []}
        encoded = encode_sync_response(nonce, data, node_time=1700000000.0)

        header_len = struct.unpack("!H", encoded[:2])[0]
        assert header_len == len(encoded) - 2

        decoded = decode_sync_response(encoded)
        assert decoded["nonce"] == nonce
        assert decoded["node_time"] == 1700000000.0

    def test_strip_header_too_short(self):
        with pytest.raises(SyncError, match="too short"):
            _strip_length_header(b"\x00")

    def test_strip_header_length_mismatch(self):
        # Header says 100 bytes but payload is only 5
        data = struct.pack("!H", 100) + b"\x00" * 5
        with pytest.raises(SyncError, match="mismatch"):
            _strip_length_header(data)

    def test_add_header_roundtrip(self):
        original = b"hello world"
        framed = _add_length_header(original)
        assert _strip_length_header(framed) == original
