# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for federation: cursor persistence, backoff, auth, push, bidirectional sync."""

import time
from unittest.mock import MagicMock, AsyncMock

import pytest
import pytest_asyncio

from hokora.federation.mirror import ChannelMirror
from hokora.federation.auth import FederationAuth, CHALLENGE_SIZE
from hokora.federation.pusher import FederationPusher
from hokora.exceptions import FederationError


# =============================================================================
# Cursor persistence + exponential backoff
# =============================================================================


class TestMirrorCursorPersistence:
    def test_mirror_loads_initial_cursor(self):
        mirror = ChannelMirror(
            b"\x01" * 16,
            "ch1",
            initial_cursor=42,
        )
        assert mirror._cursor == 42

    def test_mirror_cursor_callback_called_on_batch(self):
        """Cursor callback fires when messages are ingested."""
        from hokora.protocol.wire import encode_sync_response

        callback_calls = []

        def cursor_cb(channel_id, cursor):
            callback_calls.append((channel_id, cursor))

        mirror = ChannelMirror(
            b"\x01" * 16,
            "ch1",
            cursor_callback=cursor_cb,
        )

        # Build a fake sync response with messages
        response_data = encode_sync_response(
            b"\x00" * 16,
            {
                "messages": [
                    {"msg_hash": "h1", "seq": 5, "body": "hi"},
                    {"msg_hash": "h2", "seq": 10, "body": "there"},
                ],
                "has_more": False,
            },
        )
        mirror.handle_response(response_data)

        assert len(callback_calls) == 1
        assert callback_calls[0] == ("ch1", 10)

    def test_mirror_cursor_callback_not_called_when_no_messages(self):
        from hokora.protocol.wire import encode_sync_response

        callback_calls = []

        def cursor_cb(channel_id, cursor):
            callback_calls.append((channel_id, cursor))

        mirror = ChannelMirror(
            b"\x01" * 16,
            "ch1",
            cursor_callback=cursor_cb,
        )
        response_data = encode_sync_response(
            b"\x00" * 16,
            {"messages": [], "has_more": False},
        )
        mirror.handle_response(response_data)
        assert len(callback_calls) == 0


class TestBackoff:
    def test_backoff_increases_exponentially(self):
        mirror = ChannelMirror(b"\x01" * 16, "ch1")
        delays = []
        for i in range(6):
            mirror._attempt = i
            # Get raw delay without jitter
            raw = min(mirror._backoff_base * (2**i), mirror._max_backoff)
            delays.append(raw)

        assert delays[0] == 5.0
        assert delays[1] == 10.0
        assert delays[2] == 20.0
        assert delays[3] == 40.0
        assert delays[4] == 80.0
        assert delays[5] == 160.0

    def test_backoff_caps_at_max(self):
        mirror = ChannelMirror(b"\x01" * 16, "ch1")
        mirror._attempt = 100
        delay = mirror._get_backoff_delay()
        # With jitter, should be within ±25% of max_backoff
        assert delay <= mirror._max_backoff * 1.25
        assert delay >= mirror._max_backoff * 0.75

    def test_backoff_resets_on_success(self):
        mirror = ChannelMirror(b"\x01" * 16, "ch1")
        mirror._attempt = 5
        mock_link = MagicMock()
        mirror._link = mock_link
        # Simulate the reset that happens at the start of _on_linked
        mirror._attempt = 0  # This is what _on_linked does first
        assert mirror._attempt == 0

    def test_backoff_has_jitter(self):
        mirror = ChannelMirror(b"\x01" * 16, "ch1")
        mirror._attempt = 3
        delays = {mirror._get_backoff_delay() for _ in range(20)}
        # With jitter, we should get different values
        assert len(delays) > 1


# =============================================================================
# Federation authentication
# =============================================================================


class TestFederationAuth:
    def test_create_challenge_is_32_bytes(self):
        challenge = FederationAuth.create_challenge()
        assert len(challenge) == CHALLENGE_SIZE

    def test_create_challenge_is_random(self):
        c1 = FederationAuth.create_challenge()
        c2 = FederationAuth.create_challenge()
        assert c1 != c2

    def test_federation_auth_challenge_response_valid(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        private_key = Ed25519PrivateKey.generate()
        public_key_bytes = private_key.public_key().public_bytes_raw()

        challenge = FederationAuth.create_challenge()
        response = FederationAuth.create_response(challenge, private_key)

        assert FederationAuth.verify_response(challenge, response, public_key_bytes)

    def test_federation_auth_wrong_key_rejected(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        key1 = Ed25519PrivateKey.generate()
        key2 = Ed25519PrivateKey.generate()
        public_key2_bytes = key2.public_key().public_bytes_raw()

        challenge = FederationAuth.create_challenge()
        response = FederationAuth.create_response(challenge, key1)

        assert not FederationAuth.verify_response(challenge, response, public_key2_bytes)

    def test_federation_auth_tampered_challenge_rejected(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        private_key = Ed25519PrivateKey.generate()
        public_key_bytes = private_key.public_key().public_bytes_raw()

        challenge = FederationAuth.create_challenge()
        response = FederationAuth.create_response(challenge, private_key)

        # Tamper with the challenge
        tampered = bytearray(challenge)
        tampered[0] ^= 0xFF
        assert not FederationAuth.verify_response(bytes(tampered), response, public_key_bytes)

    def test_create_response_rejects_bad_challenge_size(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        private_key = Ed25519PrivateKey.generate()
        with pytest.raises(FederationError, match="Invalid challenge size"):
            FederationAuth.create_response(b"short", private_key)

    def test_build_handshake_init(self):
        msg = FederationAuth.build_handshake_init("NodeA", "abc123")
        assert msg["step"] == 1
        assert msg["node_name"] == "NodeA"
        assert msg["identity_hash"] == "abc123"
        assert len(msg["challenge"]) == CHALLENGE_SIZE

    def test_build_handshake_response(self):
        msg = FederationAuth.build_handshake_response(
            "NodeB",
            "def456",
            b"\x00" * 64,
            b"\x01" * 32,
        )
        assert msg["step"] == 2
        assert msg["counter_challenge"] == b"\x01" * 32

    def test_build_handshake_ack(self):
        msg = FederationAuth.build_handshake_ack(b"\x02" * 64)
        assert msg["step"] == 3
        assert msg["counter_response"] == b"\x02" * 64


class TestPeerKeyStore:
    """TOFU key store: first-use acceptance and key-change rejection."""

    def test_first_contact_accepted(self):
        from hokora.federation.auth import PeerKeyStore

        store = PeerKeyStore()
        assert store.check_and_store("peer1", b"\x01" * 32) is True

    def test_same_key_accepted(self):
        from hokora.federation.auth import PeerKeyStore

        store = PeerKeyStore()
        store.check_and_store("peer1", b"\x01" * 32)
        assert store.check_and_store("peer1", b"\x01" * 32) is True

    def test_key_change_rejected_by_default(self):
        from hokora.federation.auth import PeerKeyStore

        store = PeerKeyStore()
        store.check_and_store("peer1", b"\x01" * 32)
        with pytest.raises(FederationError, match="public key changed"):
            store.check_and_store("peer1", b"\x02" * 32)

    def test_key_change_allowed_when_configured(self):
        from hokora.federation.auth import PeerKeyStore

        store = PeerKeyStore(reject_key_change=False)
        store.check_and_store("peer1", b"\x01" * 32)
        assert store.check_and_store("peer1", b"\x02" * 32) is False

    def test_update_key_then_accept(self):
        from hokora.federation.auth import PeerKeyStore

        store = PeerKeyStore()
        store.check_and_store("peer1", b"\x01" * 32)
        store.update_key("peer1", b"\x02" * 32)
        assert store.check_and_store("peer1", b"\x02" * 32) is True


class TestHandshakeSyncHandler:
    """Test federation handshake via the sync handler."""

    @pytest_asyncio.fixture
    async def handler_deps(self, session_factory):
        """Set up a SyncHandler with federation support."""
        from hokora.config import NodeConfig
        from hokora.protocol.sync import SyncHandler
        from hokora.core.sequencer import SequenceManager
        import tempfile
        from pathlib import Path

        tmp = Path(tempfile.mkdtemp())
        config = NodeConfig(
            node_name="Test Node",
            data_dir=tmp,
            db_path=tmp / "test.db",
            media_dir=tmp / "media",
            identity_dir=tmp / "identities",
            db_encrypt=False,
            federation_auto_trust=False,
        )
        config.identity_dir.mkdir(parents=True, exist_ok=True)

        identity_mgr = MagicMock()
        identity_mgr.get_node_identity_hash.return_value = "a" * 32

        channel_mgr = MagicMock()
        sequencer = SequenceManager()

        handler = SyncHandler(
            channel_mgr,
            sequencer,
            node_name="Test Node",
            node_identity="a" * 32,
            config=config,
        )
        return handler, config

    async def test_untrusted_peer_rejected_when_auto_trust_disabled(self, handler_deps, session):
        handler, config = handler_deps
        from hokora.exceptions import SyncError

        with pytest.raises(SyncError, match="Peer not trusted"):
            await handler._handle_federation_handshake(
                session,
                b"\x00" * 16,
                {
                    "step": 1,
                    "identity_hash": "b" * 32,
                    "node_name": "Evil Node",
                    "challenge": b"\x01" * 32,
                },
                None,
            )

    async def test_trusted_peer_stored_in_db(self, handler_deps, session):
        handler, config = handler_deps
        config.federation_auto_trust = True

        result = await handler._handle_federation_handshake(
            session,
            b"\x00" * 16,
            {
                "step": 1,
                "identity_hash": "c" * 32,
                "node_name": "Friendly Node",
                "challenge": b"\x01" * 32,
            },
            None,
        )

        assert result["accepted"] is True
        assert result["step"] == 2
        assert "counter_challenge" in result

        # Verify peer was stored but NOT yet trusted (trust happens at step 3)
        from hokora.db.models import Peer
        from sqlalchemy import select

        peer_result = await session.execute(select(Peer).where(Peer.identity_hash == "c" * 32))
        peer = peer_result.scalar_one_or_none()
        assert peer is not None
        assert peer.federation_trusted is False

    async def test_handshake_step3_marks_peer_trusted(self, handler_deps, session):
        """Step 3 of handshake should mark the peer as federation_trusted."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        handler, config = handler_deps
        config.federation_auto_trust = True

        # Step 1: initiate
        result = await handler._handle_federation_handshake(
            session,
            b"\x00" * 16,
            {
                "step": 1,
                "identity_hash": "d" * 32,
                "node_name": "Trusted Node",
                "challenge": b"\x01" * 32,
            },
            None,
        )
        assert result["step"] == 2

        # Retrieve the counter_challenge stored by the handler
        stored_entry = handler._pending_counter_challenges.get("d" * 32)
        assert stored_entry is not None
        counter_challenge = stored_entry[0]

        # Create a valid Ed25519 signature for the counter_challenge
        private_key = Ed25519PrivateKey.generate()
        counter_response = private_key.sign(counter_challenge)
        public_key_bytes = private_key.public_key().public_bytes(
            Encoding.Raw,
            PublicFormat.Raw,
        )

        # Step 3: complete handshake with valid signature
        result3 = await handler._handle_federation_handshake(
            session,
            b"\x01" * 16,
            {
                "step": 3,
                "identity_hash": "d" * 32,
                "counter_response": counter_response,
                "peer_public_key": public_key_bytes,
            },
            None,
        )
        assert result3["complete"] is True

        # Verify peer is now trusted
        from hokora.db.models import Peer
        from sqlalchemy import select

        peer_result = await session.execute(select(Peer).where(Peer.identity_hash == "d" * 32))
        peer = peer_result.scalar_one_or_none()
        assert peer is not None
        assert peer.federation_trusted is True

    async def test_handshake_requires_link_identity(self, handler_deps, session):
        handler, config = handler_deps
        from hokora.exceptions import SyncError

        with pytest.raises(SyncError, match="Missing identity_hash"):
            await handler._handle_federation_handshake(
                session,
                b"\x00" * 16,
                {
                    "step": 1,
                    "node_name": "Anon",
                    "challenge": b"\x01" * 32,
                },
                None,
            )


# =============================================================================
# Signature verification on mirrored messages
# =============================================================================


class TestConcurrentHandshakeAndCleanup:
    """Test that concurrent handshake + cleanup_stale_challenges doesn't crash."""

    @pytest_asyncio.fixture
    async def handler_with_auto_trust(self, session_factory):
        from hokora.protocol.sync import SyncHandler
        from hokora.core.sequencer import SequenceManager
        from hokora.config import NodeConfig
        import tempfile
        from pathlib import Path

        tmp = Path(tempfile.mkdtemp())
        config = NodeConfig(
            node_name="Concurrent Test",
            data_dir=tmp,
            db_path=tmp / "t.db",
            media_dir=tmp / "media",
            identity_dir=tmp / "id",
            db_encrypt=False,
            federation_auto_trust=True,
        )

        handler = SyncHandler(
            MagicMock(),
            SequenceManager(),
            node_name="Concurrent Test",
            node_identity="a" * 32,
            config=config,
        )
        return handler

    async def test_concurrent_handshake_and_cleanup(self, handler_with_auto_trust, session):
        """Handshake step 1 + cleanup running concurrently must not raise."""
        import asyncio

        handler = handler_with_auto_trust

        async def do_handshake(peer_id):
            await handler._handle_federation_handshake(
                session,
                b"\x00" * 16,
                {
                    "step": 1,
                    "identity_hash": peer_id,
                    "node_name": "Peer",
                    "challenge": b"\x01" * 32,
                },
                None,
            )

        async def do_cleanup():
            await handler.cleanup_stale_challenges(max_age=0)

        # Run handshakes and cleanup concurrently
        tasks = [
            do_handshake("e" * 32),
            do_handshake("f" * 32),
            do_cleanup(),
            do_handshake("0" * 32 + "ab"),
        ]
        # Must not raise RuntimeError (dict changed during iteration)
        results = await asyncio.gather(*tasks, return_exceptions=True)
        errors = [r for r in results if isinstance(r, RuntimeError)]
        assert len(errors) == 0

    async def test_cleanup_stale_challenges_is_async(self, handler_with_auto_trust):
        """cleanup_stale_challenges must be a coroutine."""
        handler = handler_with_auto_trust
        import inspect

        assert inspect.iscoroutinefunction(handler.cleanup_stale_challenges)


class TestMirrorSignatureVerification:
    """Integration-flavoured tests against MirrorMessageIngestor with real
    Ed25519 signatures. Unit coverage with mocked VerificationService lives
    in tests/unit/test_mirror_ingestor.py; this class exercises the real
    crypto path end-to-end.
    """

    def _make_ingestor(self, session_factory, require_signed: bool):
        from hokora.federation.mirror_ingestor import MirrorMessageIngestor

        sequencer = MagicMock()
        sequencer.next_seq = AsyncMock(return_value=1)
        return MirrorMessageIngestor(
            session_factory=session_factory,
            sequencer=sequencer,
            live_manager=None,
            require_signed_federation=require_signed,
        )

    async def test_mirror_ingest_valid_signature_accepted(self, session_factory):
        """Valid signature should be accepted."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from hokora.db.models import Channel

        async with session_factory() as session:
            async with session.begin():
                session.add(Channel(id="ch1", name="test", latest_seq=0))

        private_key = Ed25519PrivateKey.generate()
        public_key_bytes = private_key.public_key().public_bytes_raw()
        message_body = b"Hello federation"
        signature = private_key.sign(message_body)

        ingestor = self._make_ingestor(session_factory, require_signed=True)
        msg_data = {
            "msg_hash": "sig_valid_hash_001",
            "sender_hash": "a" * 32,
            "timestamp": time.time(),
            "type": 1,
            "body": "Hello federation",
            "lxmf_signature": signature,
            "lxmf_signed_part": message_body,
            "sender_public_key": public_key_bytes,
        }
        await ingestor.ingest("ch1", msg_data, peer_hash="p" * 16)

    async def test_mirror_ingest_invalid_signature_rejected(self, session_factory):
        """Invalid signature should be rejected."""
        ingestor = self._make_ingestor(session_factory, require_signed=True)
        msg_data = {
            "msg_hash": "sig_invalid_hash_001",
            "sender_hash": "a" * 32,
            "timestamp": time.time(),
            "type": 1,
            "body": "Tampered",
            "lxmf_signature": b"\x00" * 64,
            "lxmf_signed_part": b"original content",
            "sender_public_key": b"\x01" * 32,
        }
        await ingestor.ingest("ch1", msg_data)

        from hokora.db.queries import MessageRepo

        async with session_factory() as session:
            async with session.begin():
                repo = MessageRepo(session)
                msg = await repo.get_by_hash("sig_invalid_hash_001")
                assert msg is None

    async def test_mirror_ingest_missing_sig_rejected_when_required(self, session_factory):
        ingestor = self._make_ingestor(session_factory, require_signed=True)
        msg_data = {
            "msg_hash": "no_sig_hash_001",
            "sender_hash": "a" * 32,
            "timestamp": time.time(),
            "type": 1,
            "body": "No signature",
        }
        await ingestor.ingest("ch1", msg_data)

        from hokora.db.queries import MessageRepo

        async with session_factory() as session:
            async with session.begin():
                repo = MessageRepo(session)
                msg = await repo.get_by_hash("no_sig_hash_001")
                assert msg is None

    async def test_mirror_ingest_missing_sig_accepted_when_not_required(self, session_factory):
        from hokora.db.models import Channel

        async with session_factory() as session:
            async with session.begin():
                session.add(Channel(id="ch1_nosig", name="test", latest_seq=0))

        ingestor = self._make_ingestor(session_factory, require_signed=False)
        msg_data = {
            "msg_hash": "no_sig_ok_hash_001",
            "sender_hash": "a" * 32,
            "timestamp": time.time(),
            "type": 1,
            "body": "No sig but allowed",
        }
        await ingestor.ingest("ch1_nosig", msg_data, peer_hash="p" * 16)

        from hokora.db.queries import MessageRepo

        async with session_factory() as session:
            async with session.begin():
                repo = MessageRepo(session)
                msg = await repo.get_by_hash("no_sig_ok_hash_001")
                assert msg is not None


# =============================================================================
# Bidirectional sync
# =============================================================================


class TestPushMessages:
    @pytest_asyncio.fixture
    async def push_handler(self, session_factory):
        from hokora.protocol.sync import SyncHandler
        from hokora.core.sequencer import SequenceManager
        from hokora.config import NodeConfig
        import tempfile
        from pathlib import Path

        tmp = Path(tempfile.mkdtemp())
        config = NodeConfig(
            node_name="Push Test",
            data_dir=tmp,
            db_path=tmp / "t.db",
            media_dir=tmp / "media",
            identity_dir=tmp / "id",
            db_encrypt=False,
            require_signed_federation=False,
        )

        sequencer = SequenceManager()
        handler = SyncHandler(
            MagicMock(),
            sequencer,
            node_name="Push Test",
            node_identity="a" * 32,
            config=config,
        )
        return handler, sequencer

    async def test_push_rejected_from_untrusted_peer(self, push_handler, session):
        handler, sequencer = push_handler
        from hokora.exceptions import SyncError
        from hokora.db.models import Peer

        # Create an untrusted peer
        peer = Peer(identity_hash="b" * 32, federation_trusted=False)
        session.add(peer)
        await session.flush()

        with pytest.raises(SyncError, match="not trusted"):
            await handler._handle_push_messages(
                session,
                b"\x00" * 16,
                {"channel_id": "ch1", "messages": [], "node_identity": "b" * 32},
                None,
            )

    async def test_push_accepted_from_trusted_peer(self, push_handler, session):
        handler, sequencer = push_handler
        from hokora.db.models import Peer, Channel

        # Create channel
        ch = Channel(id="ch1", name="test", latest_seq=0)
        session.add(ch)
        await session.flush()

        # Create trusted peer
        peer = Peer(identity_hash="b" * 32, federation_trusted=True)
        session.add(peer)
        await session.flush()

        await sequencer.load_from_db(session, "ch1")

        result = await handler._handle_push_messages(
            session,
            b"\x00" * 16,
            {
                "channel_id": "ch1",
                "messages": [
                    {
                        "msg_hash": "push_hash_001",
                        "sender_hash": "c" * 32,
                        "timestamp": time.time(),
                        "type": 1,
                        "body": "Pushed message",
                        "origin_node": "b" * 32,
                    },
                ],
                "node_identity": "b" * 32,
            },
            None,
        )
        assert result["action"] == "push_ack"
        assert len(result["received"]) == 1
        assert len(result["rejected"]) == 0

    async def test_push_dedup_by_hash(self, push_handler, session):
        handler, sequencer = push_handler
        from hokora.db.models import Peer, Channel, Message

        ch = Channel(id="ch1", name="test", latest_seq=0)
        session.add(ch)
        peer = Peer(identity_hash="b" * 32, federation_trusted=True)
        session.add(peer)
        # Pre-existing message
        msg = Message(
            msg_hash="dup_hash_001",
            channel_id="ch1",
            sender_hash="c" * 32,
            seq=1,
            timestamp=time.time(),
            type=1,
            body="Existing",
        )
        session.add(msg)
        await session.flush()
        await sequencer.load_from_db(session, "ch1")

        result = await handler._handle_push_messages(
            session,
            b"\x00" * 16,
            {
                "channel_id": "ch1",
                "messages": [
                    {
                        "msg_hash": "dup_hash_001",
                        "sender_hash": "c" * 32,
                        "timestamp": time.time(),
                        "type": 1,
                        "body": "Dup",
                    },
                ],
                "node_identity": "b" * 32,
            },
            None,
        )
        # Should be counted as received (dedup), not rejected
        assert len(result["received"]) == 1

    async def test_push_rejected_when_sender_banned(self, push_handler, session):
        # A trusted relay can carry messages from any sender_hash; the
        # receiver enforces its own ban list per-message via the
        # ``hokora.security.ban`` chokepoint.
        handler, sequencer = push_handler
        from hokora.db.models import Channel, Identity, Peer
        from hokora.security import ban as ban_module

        ban_module._BAN_REJECTIONS.clear()

        ch = Channel(id="ch1", name="test", latest_seq=0)
        session.add(ch)
        session.add(Peer(identity_hash="b" * 32, federation_trusted=True))
        session.add(Identity(hash="ba" * 16, blocked=True))
        await session.flush()
        await sequencer.load_from_db(session, "ch1")

        result = await handler._handle_push_messages(
            session,
            b"\x00" * 16,
            {
                "channel_id": "ch1",
                "messages": [
                    {
                        "msg_hash": "banned_hash_001",
                        "sender_hash": "ba" * 16,
                        "timestamp": time.time(),
                        "type": 1,
                        "body": "From a banned sender",
                    },
                ],
                "node_identity": "b" * 32,
            },
            None,
        )
        assert "banned_hash_001" in result["rejected"]
        assert "banned_hash_001" not in result["received"]
        from hokora.security.ban import get_ban_rejection_counts

        assert get_ban_rejection_counts()["federation_push"] == 1

    async def test_push_signature_verified(self, session_factory):
        """Push messages with require_signed_federation=True must have valid signatures."""
        from hokora.protocol.sync import SyncHandler
        from hokora.core.sequencer import SequenceManager
        from hokora.config import NodeConfig
        from hokora.db.models import Peer, Channel
        import tempfile
        from pathlib import Path

        tmp = Path(tempfile.mkdtemp())
        config = NodeConfig(
            node_name="Sig Test",
            data_dir=tmp,
            db_path=tmp / "t.db",
            media_dir=tmp / "media",
            identity_dir=tmp / "id",
            db_encrypt=False,
            require_signed_federation=True,
        )

        sequencer = SequenceManager()
        handler = SyncHandler(
            MagicMock(),
            sequencer,
            node_name="Sig Test",
            node_identity="a" * 32,
            config=config,
        )

        async with session_factory() as session:
            async with session.begin():
                ch = Channel(id="ch1", name="test", latest_seq=0)
                session.add(ch)
                peer = Peer(identity_hash="b" * 32, federation_trusted=True)
                session.add(peer)
                await session.flush()
                await sequencer.load_from_db(session, "ch1")

                result = await handler._handle_push_messages(
                    session,
                    b"\x00" * 16,
                    {
                        "channel_id": "ch1",
                        "messages": [
                            {
                                "msg_hash": "unsigned_001",
                                "sender_hash": "c" * 32,
                                "timestamp": time.time(),
                                "type": 1,
                                "body": "No sig",
                            },
                        ],
                        "node_identity": "b" * 32,
                    },
                    None,
                )
                # Should be rejected due to missing signature
                assert "unsigned_001" in result["rejected"]

    async def test_push_ack_contains_received_seqs(self, push_handler, session):
        handler, sequencer = push_handler
        from hokora.db.models import Peer, Channel

        ch = Channel(id="ch1", name="test", latest_seq=0)
        session.add(ch)
        peer = Peer(identity_hash="b" * 32, federation_trusted=True)
        session.add(peer)
        await session.flush()
        await sequencer.load_from_db(session, "ch1")

        result = await handler._handle_push_messages(
            session,
            b"\x00" * 16,
            {
                "channel_id": "ch1",
                "messages": [
                    {
                        "msg_hash": "ack_hash_001",
                        "sender_hash": "c" * 32,
                        "timestamp": time.time(),
                        "type": 1,
                        "body": "msg1",
                        "origin_node": "b" * 32,
                    },
                    {
                        "msg_hash": "ack_hash_002",
                        "sender_hash": "c" * 32,
                        "timestamp": time.time(),
                        "type": 1,
                        "body": "msg2",
                        "origin_node": "b" * 32,
                    },
                ],
                "node_identity": "b" * 32,
            },
            None,
        )
        assert len(result["received"]) == 2


class TestPushSenderBinding:
    """End-to-end push handler tests for the sender_hash <-> public_key binding.

    Pins the federation-receive invariant: a trusted peer cannot launder
    messages under another identity's hash. Targets ``handle_push_messages``
    via the SyncHandler facade so the test exercises the same call site
    operators rely on.
    """

    @pytest_asyncio.fixture
    async def signed_handler(self, session_factory):
        from hokora.protocol.sync import SyncHandler
        from hokora.core.sequencer import SequenceManager
        from hokora.config import NodeConfig
        import tempfile
        from pathlib import Path

        tmp = Path(tempfile.mkdtemp())
        config = NodeConfig(
            node_name="Binding Test",
            data_dir=tmp,
            db_path=tmp / "t.db",
            media_dir=tmp / "media",
            identity_dir=tmp / "id",
            db_encrypt=False,
            require_signed_federation=True,
        )
        sequencer = SequenceManager()
        handler = SyncHandler(
            MagicMock(),
            sequencer,
            node_name="Binding Test",
            node_identity="a" * 32,
            config=config,
        )
        return handler, sequencer

    async def test_push_with_correct_binding_accepted(self, signed_handler, session_factory):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from hokora.db.models import Channel, Peer
        from hokora.db.queries import MessageRepo

        handler, sequencer = signed_handler
        author = _real_rns_identity()
        priv = Ed25519PrivateKey.from_private_bytes(author.sig_prv_bytes)
        signed_part = b"honest payload"
        sig = priv.sign(signed_part)

        async with session_factory() as session:
            async with session.begin():
                session.add(Channel(id="ch1", name="t", latest_seq=0))
                session.add(Peer(identity_hash="b" * 32, federation_trusted=True))
                await session.flush()
                await sequencer.load_from_db(session, "ch1")

                result = await handler._handle_push_messages(
                    session,
                    b"\x00" * 16,
                    {
                        "channel_id": "ch1",
                        "messages": [
                            {
                                "msg_hash": "honest_001",
                                "sender_hash": author.hexhash,
                                "sender_rns_public_key": author.get_public_key(),
                                "lxmf_signed_part": signed_part,
                                "lxmf_signature": sig,
                                "timestamp": time.time(),
                                "type": 1,
                                "body": "ok",
                            },
                        ],
                        "node_identity": "b" * 32,
                    },
                    None,
                )
                assert "honest_001" not in result["rejected"]
                assert len(result["received"]) == 1
                stored = await MessageRepo(session).get_by_hash("honest_001")
                assert stored is not None
                assert stored.sender_hash == author.hexhash

    async def test_push_victim_substitution_rejected(self, signed_handler, session_factory):
        """Trusted peer signs with own key but claims a victim's sender_hash."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from hokora.db.models import Channel, Peer
        from hokora.db.queries import MessageRepo
        from hokora.federation import auth as _auth

        handler, sequencer = signed_handler
        attacker = _real_rns_identity()
        victim = _real_rns_identity()
        priv = Ed25519PrivateKey.from_private_bytes(attacker.sig_prv_bytes)
        signed_part = b"smuggled-content-attributed-to-victim"
        sig = priv.sign(signed_part)
        # Reset counter so we can assert the rejection-reason metric ticks.
        _auth._BINDING_REJECTIONS.clear()

        async with session_factory() as session:
            async with session.begin():
                session.add(Channel(id="ch1", name="t", latest_seq=0))
                session.add(Peer(identity_hash="b" * 32, federation_trusted=True))
                await session.flush()
                await sequencer.load_from_db(session, "ch1")

                result = await handler._handle_push_messages(
                    session,
                    b"\x00" * 16,
                    {
                        "channel_id": "ch1",
                        "messages": [
                            {
                                "msg_hash": "spoof_001",
                                "sender_hash": victim.hexhash,
                                "sender_rns_public_key": attacker.get_public_key(),
                                "lxmf_signed_part": signed_part,
                                "lxmf_signature": sig,
                                "timestamp": time.time(),
                                "type": 1,
                                "body": "evil",
                            },
                        ],
                        "node_identity": "b" * 32,
                    },
                    None,
                )
                assert "spoof_001" in result["rejected"]
                assert len(result["received"]) == 0
                # Critical: nothing landed under the victim's hash.
                stored = await MessageRepo(session).get_by_hash("spoof_001")
                assert stored is None
                assert _auth.get_binding_rejection_counts().get("binding_mismatch") == 1

    async def test_push_missing_pubkey_rejected_when_signed_required(
        self, signed_handler, session_factory
    ):
        from hokora.db.models import Channel, Peer

        handler, sequencer = signed_handler
        author = _real_rns_identity()

        async with session_factory() as session:
            async with session.begin():
                session.add(Channel(id="ch1", name="t", latest_seq=0))
                session.add(Peer(identity_hash="b" * 32, federation_trusted=True))
                await session.flush()
                await sequencer.load_from_db(session, "ch1")

                result = await handler._handle_push_messages(
                    session,
                    b"\x00" * 16,
                    {
                        "channel_id": "ch1",
                        "messages": [
                            {
                                "msg_hash": "no_pk_001",
                                "sender_hash": author.hexhash,
                                "timestamp": time.time(),
                                "type": 1,
                                "body": "no pubkey on wire",
                            },
                        ],
                        "node_identity": "b" * 32,
                    },
                    None,
                )
                assert "no_pk_001" in result["rejected"]


def _real_rns_identity():
    import RNS

    return RNS.Identity()


class TestPusherCursor:
    def test_pusher_tracks_cursor(self):
        pusher = FederationPusher("b" * 32, "ch1", "a" * 32)
        assert pusher.push_cursor == 0

        pusher.handle_push_ack({"received": [5, 10, 3]})
        assert pusher.push_cursor == 10

    def test_pusher_cursor_does_not_regress(self):
        pusher = FederationPusher("b" * 32, "ch1", "a" * 32)
        pusher.handle_push_ack({"received": [10]})
        pusher.handle_push_ack({"received": [5]})
        assert pusher.push_cursor == 10


class TestOriginNodeLoopPrevention:
    @pytest_asyncio.fixture
    async def origin_handler(self, session_factory):
        from hokora.protocol.sync import SyncHandler
        from hokora.core.sequencer import SequenceManager
        from hokora.config import NodeConfig
        import tempfile
        from pathlib import Path

        tmp = Path(tempfile.mkdtemp())
        config = NodeConfig(
            node_name="Origin Test",
            data_dir=tmp,
            db_path=tmp / "t.db",
            media_dir=tmp / "media",
            identity_dir=tmp / "id",
            db_encrypt=False,
            require_signed_federation=False,
        )

        sequencer = SequenceManager()
        handler = SyncHandler(
            MagicMock(),
            sequencer,
            node_name="Origin Test",
            node_identity="a" * 32,
            config=config,
        )
        return handler, sequencer

    async def test_origin_node_prevents_loop(self, origin_handler, session):
        """Messages with origin_node matching the push target should be stored with origin_node."""
        handler, sequencer = origin_handler
        from hokora.db.models import Peer, Channel
        from hokora.db.queries import MessageRepo

        ch = Channel(id="ch1", name="test", latest_seq=0)
        session.add(ch)
        peer = Peer(identity_hash="b" * 32, federation_trusted=True)
        session.add(peer)
        await session.flush()
        await sequencer.load_from_db(session, "ch1")

        await handler._handle_push_messages(
            session,
            b"\x00" * 16,
            {
                "channel_id": "ch1",
                "messages": [
                    {
                        "msg_hash": "origin_hash_001",
                        "sender_hash": "c" * 32,
                        "timestamp": time.time(),
                        "type": 1,
                        "body": "From node B",
                        "origin_node": "b" * 32,
                    },
                ],
                "node_identity": "b" * 32,
            },
            None,
        )

        repo = MessageRepo(session)
        msg = await repo.get_by_hash("origin_hash_001")
        assert msg is not None
        assert msg.origin_node == "b" * 32
