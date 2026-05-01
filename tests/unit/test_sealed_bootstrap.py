# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for ``SealedKeyBootstrap``."""

import time
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio

from hokora.core.sealed_bootstrap import SealedKeyBootstrap
from hokora.db.models import Channel, Message, SealedKey
from hokora.security.sealed import SealedChannelManager


@pytest.fixture
def node_identity():
    """Mock node identity with decrypt() that round-trips encrypt()."""
    node = MagicMock()
    # decrypt returns a deterministic 32-byte group key for any blob
    node.decrypt = MagicMock(return_value=b"\x11" * 32)
    return node


@pytest.fixture
def identity_manager(node_identity):
    im = MagicMock()
    im.get_node_identity = MagicMock(return_value=node_identity)
    im.get_node_identity_hash = MagicMock(return_value="a" * 64)
    return im


@pytest.fixture
def sealed_manager():
    return SealedChannelManager()


@pytest_asyncio.fixture
async def _channels(session_factory):
    """Seed 2 sealed + 1 unsealed channel in their own transaction."""
    c1_id = "c" * 64
    c2_id = "d" + "c" * 63
    c3_id = "e" * 64
    async with session_factory() as s:
        async with s.begin():
            s.add(Channel(id=c1_id, name="sealed-1", sealed=True))
            s.add(Channel(id=c2_id, name="sealed-2", sealed=True))
            s.add(Channel(id=c3_id, name="public", sealed=False))

    # Return simple handles (id + name) — bootstrap only cares about ids.
    class _Ref:
        def __init__(self, id, name):
            self.id = id
            self.name = name

    return _Ref(c1_id, "sealed-1"), _Ref(c2_id, "sealed-2"), _Ref(c3_id, "public")


class TestLoadExistingKeys:
    async def test_returns_zero_when_no_sealed_channels(
        self, session_factory, sealed_manager, identity_manager
    ):
        bootstrap = SealedKeyBootstrap(session_factory, sealed_manager, identity_manager)
        assert await bootstrap.load_existing_keys() == 0

    async def test_decrypts_and_stores_in_manager(
        self, session_factory, sealed_manager, identity_manager, _channels
    ):
        c1, _c2, _c3 = _channels
        # Persist a sealed key for c1
        async with session_factory() as s:
            async with s.begin():
                s.add(
                    SealedKey(
                        channel_id=c1.id,
                        epoch=1,
                        encrypted_key_blob=b"\x42" * 32,
                        identity_hash="a" * 64,
                    )
                )

        bootstrap = SealedKeyBootstrap(session_factory, sealed_manager, identity_manager)
        loaded = await bootstrap.load_existing_keys()
        assert loaded == 1
        assert sealed_manager.get_key(c1.id) == b"\x11" * 32

    async def test_tolerates_decryption_failures(
        self, session_factory, sealed_manager, identity_manager, _channels
    ):
        c1, _c2, _c3 = _channels
        async with session_factory() as s:
            async with s.begin():
                s.add(
                    SealedKey(
                        channel_id=c1.id,
                        epoch=1,
                        encrypted_key_blob=b"\x42" * 32,
                        identity_hash="a" * 64,
                    )
                )

        identity_manager.get_node_identity().decrypt.side_effect = RuntimeError("bad blob")

        bootstrap = SealedKeyBootstrap(session_factory, sealed_manager, identity_manager)
        loaded = await bootstrap.load_existing_keys()
        assert loaded == 0
        assert sealed_manager.get_key(c1.id) is None


class TestBootstrapMissingKeys:
    async def test_generates_key_for_sealed_channel_without_key(
        self, session_factory, sealed_manager, identity_manager, _channels
    ):
        c1, c2, _c3 = _channels
        bootstrap = SealedKeyBootstrap(session_factory, sealed_manager, identity_manager)
        bootstrapped = await bootstrap.bootstrap_missing_keys()
        assert set(bootstrapped) == {c1.id, c2.id}
        assert sealed_manager.get_key(c1.id) is not None
        assert sealed_manager.get_key(c2.id) is not None

    async def test_is_idempotent(
        self, session_factory, sealed_manager, identity_manager, _channels
    ):
        bootstrap = SealedKeyBootstrap(session_factory, sealed_manager, identity_manager)
        first = await bootstrap.bootstrap_missing_keys()
        assert len(first) == 2
        second = await bootstrap.bootstrap_missing_keys()
        assert second == []

    async def test_skips_unsealed_channels(
        self, session_factory, sealed_manager, identity_manager, _channels
    ):
        _c1, _c2, c3 = _channels
        bootstrap = SealedKeyBootstrap(session_factory, sealed_manager, identity_manager)
        bootstrapped = await bootstrap.bootstrap_missing_keys()
        assert c3.id not in bootstrapped
        assert sealed_manager.get_key(c3.id) is None

    async def test_returns_empty_when_node_identity_missing(
        self, session_factory, sealed_manager, identity_manager, _channels
    ):
        identity_manager.get_node_identity.return_value = None
        bootstrap = SealedKeyBootstrap(session_factory, sealed_manager, identity_manager)
        assert await bootstrap.bootstrap_missing_keys() == []


class TestPurgePlaintextFromSealedChannels:
    async def test_removes_rows_with_null_encrypted_body(
        self, session_factory, sealed_manager, identity_manager, _channels
    ):
        c1, _c2, c3 = _channels
        async with session_factory() as s:
            async with s.begin():
                # Plaintext msg in sealed channel (violates invariant)
                s.add(
                    Message(
                        msg_hash="m1" + "0" * 62,
                        channel_id=c1.id,
                        sender_hash="b" * 64,
                        seq=1,
                        timestamp=time.time(),
                        type=1,
                        body="plaintext",
                        encrypted_body=None,
                    )
                )
                # Properly encrypted msg in sealed channel (keep)
                s.add(
                    Message(
                        msg_hash="m2" + "0" * 62,
                        channel_id=c1.id,
                        sender_hash="b" * 64,
                        seq=2,
                        timestamp=time.time(),
                        type=1,
                        body=None,
                        encrypted_body=b"\x01" * 64,
                    )
                )
                # Plaintext msg in unsealed channel (keep — invariant doesn't apply)
                s.add(
                    Message(
                        msg_hash="m3" + "0" * 62,
                        channel_id=c3.id,
                        sender_hash="b" * 64,
                        seq=1,
                        timestamp=time.time(),
                        type=1,
                        body="public fine",
                        encrypted_body=None,
                    )
                )

        bootstrap = SealedKeyBootstrap(session_factory, sealed_manager, identity_manager)
        purged = await bootstrap.purge_plaintext_from_sealed_channels()
        assert purged == 1

    async def test_noop_on_clean_deploy(self, session_factory, sealed_manager, identity_manager):
        bootstrap = SealedKeyBootstrap(session_factory, sealed_manager, identity_manager)
        assert await bootstrap.purge_plaintext_from_sealed_channels() == 0

    async def test_nullifies_cohabiting_plaintext_and_prunes_fts(
        self,
        session_factory,
        sealed_manager,
        identity_manager,
        _channels,
        fts_manager,  # noqa: F841 — initialises FTS5 + triggers for this DB
    ):
        """Legacy rows where both body and encrypted_body exist must get
        body=NULL and their FTS plaintext snippet removed."""
        from sqlalchemy import text as _text

        c1, _c2, c3 = _channels
        async with session_factory() as s:
            async with s.begin():
                # Legacy co-populated sealed row — body plaintext from
                # a write path that bypassed the sealed helper.
                s.add(
                    Message(
                        msg_hash="leak" + "0" * 60,
                        channel_id=c1.id,
                        sender_hash="b" * 64,
                        seq=1,
                        timestamp=time.time(),
                        type=1,
                        body="uniqueword leakedplaintext",
                        encrypted_body=b"\xaa" * 64,
                        encryption_nonce=b"\xbb" * 12,
                        encryption_epoch=1,
                    )
                )
                # Clean sealed row (only ciphertext) — must survive.
                s.add(
                    Message(
                        msg_hash="clean" + "0" * 59,
                        channel_id=c1.id,
                        sender_hash="b" * 64,
                        seq=2,
                        timestamp=time.time(),
                        type=1,
                        body=None,
                        encrypted_body=b"\xcc" * 64,
                        encryption_nonce=b"\xdd" * 12,
                        encryption_epoch=1,
                    )
                )
                # Public channel row — plaintext allowed, must not be touched.
                s.add(
                    Message(
                        msg_hash="public" + "0" * 58,
                        channel_id=c3.id,
                        sender_hash="b" * 64,
                        seq=1,
                        timestamp=time.time(),
                        type=1,
                        body="uniqueword public ok",
                        encrypted_body=None,
                    )
                )

        # The hardened messages_ai trigger refuses to index rows where
        # encrypted_body is set, so the ORM insert above does NOT
        # populate FTS. To test the purge function's FTS-prune path
        # (which remains load-bearing for upgrading legacy databases
        # where the unguarded trigger DID index such rows), force the
        # legacy FTS entry in directly.
        async with session_factory() as s:
            async with s.begin():
                leaked_rowid = (
                    await s.execute(
                        _text("SELECT rowid FROM messages WHERE msg_hash = :h"),
                        {"h": "leak" + "0" * 60},
                    )
                ).scalar()
                await s.execute(
                    _text(
                        "INSERT INTO messages_fts(rowid, msg_hash, channel_id, body) "
                        "VALUES (:rid, :h, :cid, :body)"
                    ),
                    {
                        "rid": leaked_rowid,
                        "h": "leak" + "0" * 60,
                        "cid": c1.id,
                        "body": "uniqueword leakedplaintext",
                    },
                )

        # Sanity: FTS has indexed the (manually-seeded) legacy leak before purge.
        async with session_factory() as s:
            pre = (
                await s.execute(
                    _text(
                        "SELECT COUNT(*) FROM messages_fts "
                        "WHERE messages_fts MATCH 'uniqueword' "
                        "AND channel_id = :cid"
                    ),
                    {"cid": c1.id},
                )
            ).scalar()
        assert pre == 1, "pre-condition: leaked plaintext is in FTS index"

        bootstrap = SealedKeyBootstrap(session_factory, sealed_manager, identity_manager)
        affected = await bootstrap.purge_plaintext_from_sealed_channels()
        assert affected == 1, "exactly one co-populated sealed row was nullified"

        async with session_factory() as s:
            # The co-populated row survives but body is now NULL.
            row = (
                await s.execute(
                    _text("SELECT body, encrypted_body FROM messages WHERE msg_hash = :h"),
                    {"h": "leak" + "0" * 60},
                )
            ).fetchone()
            assert row is not None
            body, enc_body = row
            assert body is None, "plaintext body nullified"
            assert enc_body is not None, "ciphertext preserved"

            # FTS index no longer matches the leaked plaintext for the
            # sealed channel.
            post = (
                await s.execute(
                    _text(
                        "SELECT COUNT(*) FROM messages_fts "
                        "WHERE messages_fts MATCH 'uniqueword' "
                        "AND channel_id = :cid"
                    ),
                    {"cid": c1.id},
                )
            ).scalar()
            assert post == 0, "FTS row pruned for sealed-channel plaintext"

            # Public channel FTS entry untouched.
            pub = (
                await s.execute(
                    _text(
                        "SELECT COUNT(*) FROM messages_fts "
                        "WHERE messages_fts MATCH 'uniqueword' "
                        "AND channel_id = :cid"
                    ),
                    {"cid": c3.id},
                )
            ).scalar()
            assert pub == 1, "public channel FTS unaffected"


class TestRunAll:
    async def test_invokes_three_phases_in_order(
        self, session_factory, sealed_manager, identity_manager
    ):
        bootstrap = SealedKeyBootstrap(session_factory, sealed_manager, identity_manager)
        bootstrap.load_existing_keys = AsyncMock(return_value=0)
        bootstrap.bootstrap_missing_keys = AsyncMock(return_value=[])
        bootstrap.purge_plaintext_from_sealed_channels = AsyncMock(return_value=0)

        await bootstrap.run_all()

        bootstrap.load_existing_keys.assert_awaited_once()
        bootstrap.bootstrap_missing_keys.assert_awaited_once()
        bootstrap.purge_plaintext_from_sealed_channels.assert_awaited_once()
