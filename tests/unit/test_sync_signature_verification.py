# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for mandatory signature verification on sync reads."""

import logging
import time
from unittest.mock import MagicMock

import msgpack

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hokora.core.message import MessageEnvelope
from hokora.db.models import Message, Channel
from hokora.db.queries import IdentityRepo, MessageRepo
from hokora.protocol.wire import encode_message_for_sync
from hokora.security.verification import VerificationService
from hokora.constants import MSG_TEXT


# ---------- helpers ----------


def _make_ed25519_keypair():
    """Return (private_key, public_key_bytes_32)."""
    priv = Ed25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes_raw()
    return priv, pub_bytes


def _make_lxmf_signed_part(dest_hash, src_hash, payload, msg_hash):
    """Reconstruct the byte sequence LXMF signs."""
    packed = msgpack.packb(payload)
    return dest_hash + src_hash + packed + msg_hash


# ---------- Unit tests ----------


class TestLxmfSignedPartExtraction:
    """Step 1-2: LXMF bridge extracts sender_public_key and lxmf_signed_part."""

    def test_envelope_has_new_fields(self):
        env = MessageEnvelope(
            channel_id="ch1",
            sender_hash="aabb",
            timestamp=time.time(),
            lxmf_signed_part=b"\x01" * 16,
            sender_public_key=b"\x02" * 32,
        )
        assert env.lxmf_signed_part == b"\x01" * 16
        assert env.sender_public_key == b"\x02" * 32

    def test_envelope_defaults_none(self):
        env = MessageEnvelope(
            channel_id="ch1",
            sender_hash="aabb",
            timestamp=time.time(),
        )
        assert env.lxmf_signed_part is None
        assert env.sender_public_key is None

    def test_lxmf_bridge_extracts_signed_part(self):
        """Verify the bridge correctly reconstructs lxmf_signed_part."""
        from hokora.protocol.lxmf_bridge import LXMFBridge

        bridge = LXMFBridge(base_storagepath="/tmp/test_lxmf")
        bridge.ingest_callback = MagicMock()

        # Register a fake channel
        mock_dest = MagicMock()
        mock_dest.hash = b"\x01" * 16
        bridge._registered_destinations["ch1"] = {
            "identity": MagicMock(),
            "destination": mock_dest,
        }

        # Build a mock LXMF message with known attributes
        msg = MagicMock()
        msg.signature_validated = True
        msg.source_hash = b"\x03" * 16
        msg.destination_hash = b"\x01" * 16
        msg.source = MagicMock()
        msg.source.identity = MagicMock()
        # ``lxmf_bridge`` reads sig_pub_bytes (32-byte Ed25519 key)
        # rather than get_public_key() (64-byte blob). Mock both so the
        # bridge's fallback path also works if sig_pub_bytes is ever
        # missing on a future RNS version.
        msg.source.identity.sig_pub_bytes = b"\xaa" * 32
        msg.source.identity.get_public_key.return_value = (b"\x00" * 32) + (b"\xaa" * 32)
        # ``lxmf_signed_part`` reconstruction sources ``packed_payload``
        # from ``message.packed[96:]`` rather than repacking the
        # (possibly-stamp-mutated) payload list.
        # Build a fake wire blob that matches LXMessage layout:
        #   dest_hash (16) + source_hash (16) + signature (64) + packed_payload
        payload_bytes = msgpack.packb([time.time(), b"t", b"test content", None])
        import RNS

        hashed_part = msg.destination_hash + msg.source_hash + payload_bytes
        msg.hash = RNS.Identity.full_hash(hashed_part)
        msg.packed = msg.destination_hash + msg.source_hash + (b"\x00" * 64) + payload_bytes
        msg.payload = [None, b"t", b"test content", None]  # unpacked form
        msg.signature = b"\x00" * 64
        msg.timestamp = time.time()
        msg.content = msgpack.packb({"type": MSG_TEXT, "body": "hello"})

        bridge._on_lxmf_delivery(msg)

        # Verify envelope was passed to callback
        assert bridge.ingest_callback.called
        envelope = bridge.ingest_callback.call_args[0][0]
        assert isinstance(envelope, MessageEnvelope)
        assert envelope.sender_public_key == b"\xaa" * 32
        assert envelope.lxmf_signed_part is not None

        # Signed part = hashed_part + message.hash (exactly what LXMF signs).
        assert envelope.lxmf_signed_part == hashed_part + msg.hash


class TestSyncResponseIncludesKeys:
    """Step 4: encode_message_for_sync includes new fields."""

    def test_encode_includes_lxmf_signed_part(self):
        msg = MagicMock(spec=Message)
        msg.msg_hash = "abc123"
        msg.channel_id = "ch1"
        msg.sender_hash = "sender1"
        msg.seq = 1
        msg.thread_seq = None
        msg.timestamp = time.time()
        msg.type = MSG_TEXT
        msg.body = "hello"
        msg.media_path = None
        msg.media_meta = None
        msg.reply_to = None
        msg.deleted = False
        msg.pinned = False
        msg.pinned_at = None
        msg.edit_chain = []
        msg.reactions = {}
        msg.lxmf_signature = b"\x00" * 64
        msg.lxmf_signed_part = b"\x01" * 48
        msg.display_name = "Alice"
        msg.mentions = []

        encoded = encode_message_for_sync(msg)

        assert "lxmf_signed_part" in encoded
        assert encoded["lxmf_signed_part"] == b"\x01" * 48
        assert "sender_public_key" in encoded
        assert encoded["sender_public_key"] is None  # Populated by sync handler


class TestClientVerificationWithCorrectBytes:
    """Step 5: Client verifies using LXMF signed bytes."""

    def test_verified_true_with_valid_signature(self):
        """Full round-trip: sign, encode, verify on client."""
        priv, pub_bytes = _make_ed25519_keypair()

        dest_hash = b"\x01" * 16
        src_hash = b"\x03" * 16
        payload = [time.time(), "test message"]
        msg_hash = b"\xff" * 16

        signed_part = _make_lxmf_signed_part(dest_hash, src_hash, payload, msg_hash)
        signature = priv.sign(signed_part)

        # Simulate sync response message dict
        msg = {
            "msg_hash": "abc123",
            "sender_hash": "sender1",
            "body": "test message",
            "lxmf_signature": signature,
            "lxmf_signed_part": signed_part,
            "sender_public_key": pub_bytes,
            "seq": 1,
        }

        # Run client verification logic inline
        sig = msg.get("lxmf_signature")
        pub_key = msg.get("sender_public_key")
        sp = msg.get("lxmf_signed_part")

        verified = VerificationService.verify_ed25519_signature(pub_key, sp, sig)
        assert verified is True

    def test_verified_false_with_tampered_signed_part(self):
        """Tampered signed_part should fail verification."""
        priv, pub_bytes = _make_ed25519_keypair()

        signed_part = b"\x01" * 64
        signature = priv.sign(signed_part)

        # Tamper with signed_part
        tampered = b"\x02" * 64

        verified = VerificationService.verify_ed25519_signature(
            pub_bytes,
            tampered,
            signature,
        )
        assert verified is False

    def test_verified_false_missing_pubkey(self):
        """No public key -> verified=False."""
        msg = {
            "lxmf_signature": b"\x00" * 64,
            "lxmf_signed_part": b"\x01" * 48,
            "sender_public_key": None,
            "sender_hash": "sender1",
        }
        sig = msg["lxmf_signature"]
        pub_key = msg["sender_public_key"]
        signed_part = msg["lxmf_signed_part"]

        # Client logic: if any of sig/pub_key/signed_part is falsy -> verified=False
        if sig and pub_key and signed_part:
            verified = True
        else:
            verified = False
        assert verified is False

    def test_verified_false_missing_signed_part(self):
        """No signed_part -> verified=False."""
        msg = {
            "lxmf_signature": b"\x00" * 64,
            "lxmf_signed_part": None,
            "sender_public_key": b"\x02" * 32,
            "sender_hash": "sender1",
        }
        if msg["lxmf_signature"] and msg["sender_public_key"] and msg["lxmf_signed_part"]:
            verified = True
        else:
            verified = False
        assert verified is False


class TestClientKeyConsistencyCheck:
    """Step 5: Client detects public key changes (potential MITM)."""

    def test_key_change_logs_warning(self, caplog):
        """Different pubkey for same sender should warn and set verified=False."""
        from hokora_tui.sync_engine import SyncEngine

        engine = SyncEngine(reticulum=MagicMock(), identity=None)

        priv1, pub1 = _make_ed25519_keypair()
        priv2, pub2 = _make_ed25519_keypair()

        # Cache first key
        engine.cache_identity_key("sender1", pub1)

        # Build message with second (different) key
        signed_part = b"\x01" * 64
        signature = priv2.sign(signed_part)

        messages = [
            {
                "msg_hash": "msg1",
                "sender_hash": "sender1",
                "body": "test",
                "lxmf_signature": signature,
                "lxmf_signed_part": signed_part,
                "sender_public_key": pub2,
                "seq": 1,
            }
        ]

        data = {
            "action": "history",
            "channel_id": "ch1",
            "messages": messages,
        }

        with caplog.at_level(logging.WARNING, logger="hokora_tui.sync_engine"):
            engine._handle_response(data)

        assert any("PUBLIC KEY CHANGED" in r.message for r in caplog.records)
        assert messages[0]["verified"] is False

    def test_consistent_key_no_warning(self, caplog):
        """Same pubkey for same sender should not warn."""
        from hokora_tui.sync_engine import SyncEngine

        engine = SyncEngine(reticulum=MagicMock(), identity=None)

        priv, pub = _make_ed25519_keypair()
        engine.cache_identity_key("sender1", pub)

        signed_part = b"\x01" * 64
        signature = priv.sign(signed_part)

        messages = [
            {
                "msg_hash": "msg2",
                "sender_hash": "sender1",
                "body": "test",
                "lxmf_signature": signature,
                "lxmf_signed_part": signed_part,
                "sender_public_key": pub,
                "seq": 2,
            }
        ]

        data = {
            "action": "history",
            "channel_id": "ch1",
            "messages": messages,
        }

        with caplog.at_level(logging.WARNING, logger="hokora_tui.sync_engine"):
            engine._handle_response(data)

        assert not any("PUBLIC KEY CHANGED" in r.message for r in caplog.records)
        assert messages[0]["verified"] is True


class TestIdentityRepoGetBatch:
    """Step 4: Batch lookup for sender public keys."""

    async def test_get_batch_returns_matching(self, session):
        repo = IdentityRepo(session)
        await repo.upsert("hash_a", public_key=b"\x01" * 32, display_name="Alice")
        await repo.upsert("hash_b", public_key=b"\x02" * 32, display_name="Bob")
        await repo.upsert("hash_c", display_name="Carol")  # no public key

        results = await repo.get_batch({"hash_a", "hash_b", "hash_c"})
        result_map = {r.hash: r for r in results}

        assert len(results) == 3
        assert result_map["hash_a"].public_key == b"\x01" * 32
        assert result_map["hash_b"].public_key == b"\x02" * 32
        assert result_map["hash_c"].public_key is None

    async def test_get_batch_empty_set(self, session):
        repo = IdentityRepo(session)
        results = await repo.get_batch(set())
        assert results == []

    async def test_get_batch_no_matches(self, session):
        repo = IdentityRepo(session)
        results = await repo.get_batch({"nonexistent"})
        assert results == []


class TestMessageModelHasSignedPart:
    """Step 3: Message ORM model stores lxmf_signed_part."""

    async def test_message_stores_lxmf_signed_part(self, session):
        # Create required channel first
        channel = Channel(id="ch1", name="test")
        session.add(channel)
        await session.flush()

        msg = Message(
            msg_hash="testhash1",
            channel_id="ch1",
            sender_hash="sender1",
            seq=1,
            timestamp=time.time(),
            type=MSG_TEXT,
            body="hello",
            lxmf_signature=b"\x00" * 64,
            lxmf_signed_part=b"\x01" * 48,
        )
        session.add(msg)
        await session.flush()

        repo = MessageRepo(session)
        fetched = await repo.get_by_hash("testhash1")
        assert fetched is not None
        assert fetched.lxmf_signed_part == b"\x01" * 48

    async def test_message_null_lxmf_signed_part(self, session):
        channel = Channel(id="ch2", name="test2")
        session.add(channel)
        await session.flush()

        msg = Message(
            msg_hash="testhash2",
            channel_id="ch2",
            sender_hash="sender2",
            seq=1,
            timestamp=time.time(),
            type=MSG_TEXT,
            body="old message",
        )
        session.add(msg)
        await session.flush()

        repo = MessageRepo(session)
        fetched = await repo.get_by_hash("testhash2")
        assert fetched is not None
        assert fetched.lxmf_signed_part is None
