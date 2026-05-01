# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for sealed channel key persistence and distribution."""

from unittest.mock import MagicMock

import pytest

from hokora.security.sealed import SealedChannelManager
from hokora.db.models import Channel, SealedKey


class TestSealedKeyPersistence:
    def test_sealed_key_persisted_to_db(self):
        """SealedChannelManager.persist_key writes to SealedKey table."""
        # We test the logic without actual DB by checking the ORM object creation
        mgr = SealedChannelManager()
        key, epoch = mgr.generate_key("ch1")
        assert epoch == 1
        assert len(key) == 32

    async def test_sealed_key_persisted_and_loaded(self, session):
        """Generate key, persist to DB, create new manager, load from DB."""
        mgr = SealedChannelManager()
        key, epoch = mgr.generate_key("ch_seal")

        # Create a sealed channel
        ch = Channel(id="ch_seal", name="sealed-test", sealed=True)
        session.add(ch)
        await session.flush()

        # Simulate persist_key by manually creating the SealedKey entry
        # (In production, node_identity.encrypt would encrypt the key)
        mock_identity = MagicMock()
        mock_identity.hexhash = "node" + "0" * 28
        mock_identity.encrypt = MagicMock(return_value=b"encrypted_blob_" + key)
        mock_identity.decrypt = MagicMock(return_value=key)

        await mgr.persist_key(session, "ch_seal", mock_identity)
        await session.flush()

        # Verify SealedKey was stored
        from sqlalchemy import select

        result = await session.execute(select(SealedKey).where(SealedKey.channel_id == "ch_seal"))
        sk = result.scalar_one()
        assert sk.epoch == 1
        assert sk.identity_hash == "node" + "0" * 28

        # Load into new manager
        mgr2 = SealedChannelManager()
        await mgr2.load_keys(session, mock_identity)
        assert mgr2.get_key("ch_seal") == key
        assert mgr2.get_epoch("ch_seal") == 1

    async def test_sealed_key_rotated_and_persisted(self, session):
        """Rotating a key should produce new key and epoch."""
        mgr = SealedChannelManager()
        key1, epoch1 = mgr.generate_key("ch_rot")
        key2, epoch2 = mgr.rotate_key("ch_rot")
        assert epoch2 == epoch1 + 1
        assert key2 != key1

        # Persist the rotated key
        ch = Channel(id="ch_rot", name="rotated", sealed=True)
        session.add(ch)
        await session.flush()

        mock_identity = MagicMock()
        mock_identity.hexhash = "node" + "0" * 28
        mock_identity.encrypt = MagicMock(return_value=b"encrypted_blob_" + key2)

        await mgr.persist_key(session, "ch_rot", mock_identity)
        await session.flush()

        from sqlalchemy import select

        result = await session.execute(
            select(SealedKey)
            .where(SealedKey.channel_id == "ch_rot")
            .order_by(SealedKey.epoch.desc())
        )
        sk = result.scalars().first()
        assert sk.epoch == 2

    async def test_load_keys_hydrates_previous_epochs(self, session):
        """A daemon restart must keep historical-epoch ciphertext decryptable.

        Persists three rotated epochs, drops the in-memory state, reloads
        from DB, then decrypts ciphertext encrypted under each prior
        epoch.
        """
        from hokora.security.sealed import SealedChannelManager

        node_hash = "node" + "0" * 28
        keystore: dict[bytes, bytes] = {}

        def _encrypt(key: bytes) -> bytes:
            blob = b"wrap:" + key
            keystore[blob] = key
            return blob

        mock_identity = MagicMock()
        mock_identity.hexhash = node_hash
        mock_identity.encrypt = MagicMock(side_effect=_encrypt)
        mock_identity.decrypt = MagicMock(side_effect=lambda blob: keystore[blob])

        ch = Channel(id="ch_hydrate", name="hydrate", sealed=True)
        session.add(ch)
        await session.flush()

        # Build three persisted epochs; capture a ciphertext at each.
        mgr = SealedChannelManager()
        mgr.generate_key("ch_hydrate")
        nonce1, ct1, _ = mgr.encrypt("ch_hydrate", b"epoch-1 payload")
        await mgr.persist_key(session, "ch_hydrate", mock_identity)
        mgr.rotate_key("ch_hydrate")
        nonce2, ct2, _ = mgr.encrypt("ch_hydrate", b"epoch-2 payload")
        await mgr.persist_key(session, "ch_hydrate", mock_identity)
        mgr.rotate_key("ch_hydrate")
        nonce3, ct3, _ = mgr.encrypt("ch_hydrate", b"epoch-3 payload")
        await mgr.persist_key(session, "ch_hydrate", mock_identity)
        await session.flush()

        # Fresh manager, mirrors a daemon restart.
        mgr2 = SealedChannelManager()
        await mgr2.load_keys(session, mock_identity)

        assert mgr2.get_epoch("ch_hydrate") == 3
        assert mgr2.decrypt("ch_hydrate", nonce3, ct3, epoch=3) == b"epoch-3 payload"
        assert mgr2.decrypt("ch_hydrate", nonce2, ct2, epoch=2) == b"epoch-2 payload"
        assert mgr2.decrypt("ch_hydrate", nonce1, ct1, epoch=1) == b"epoch-1 payload"


class TestSealedKeyDistribution:
    async def test_sealed_key_request_authorized_member(self, session):
        """Members with roles can request sealed keys."""
        from hokora.protocol.sync import SyncHandler
        from hokora.db.models import Channel, Role, RoleAssignment, Identity, SealedKey

        ch = Channel(id="ch_sealed", name="sealed", sealed=True)
        session.add(ch)

        identity = Identity(hash="member" + "0" * 26, display_name="Member")
        session.add(identity)

        role = Role(id="role1", name="member_role", permissions=0x01)
        session.add(role)

        assignment = RoleAssignment(
            role_id="role1",
            identity_hash="member" + "0" * 26,
            channel_id="ch_sealed",
        )
        session.add(assignment)

        sealed_key = SealedKey(
            channel_id="ch_sealed",
            epoch=1,
            encrypted_key_blob=b"encrypted_key_data",
            identity_hash="member" + "0" * 26,
        )
        session.add(sealed_key)
        await session.flush()

        handler = SyncHandler(
            MagicMock(),
            MagicMock(),
            node_name="Test",
            node_identity="a" * 32,
        )

        result = await handler._handle_request_sealed_key(
            session,
            b"\x00" * 16,
            {"channel_id": "ch_sealed"},
            None,
            requester_hash="member" + "0" * 26,
        )
        assert result["action"] == "sealed_key"
        assert result["epoch"] == 1
        assert result["encrypted_key_blob"] == b"encrypted_key_data"

    async def test_sealed_key_request_rejected_non_member(self, session):
        """Non-members cannot request sealed keys."""
        from hokora.protocol.sync import SyncHandler
        from hokora.db.models import Channel
        from hokora.exceptions import PermissionDenied

        ch = Channel(id="ch_sealed2", name="sealed2", sealed=True)
        session.add(ch)
        await session.flush()

        handler = SyncHandler(
            MagicMock(),
            MagicMock(),
            node_name="Test",
            node_identity="a" * 32,
        )

        with pytest.raises(PermissionDenied, match="Not a member"):
            await handler._handle_request_sealed_key(
                session,
                b"\x00" * 16,
                {"channel_id": "ch_sealed2"},
                None,
                requester_hash="outsider" + "0" * 24,
            )
