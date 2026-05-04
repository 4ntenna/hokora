# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for the role-scope semantics + sealed-channel invariant fixes.

Covers:
    - ``get_identity_roles(strict_channel_scope=True)`` excludes node-scoped rows.
    - Sealed channels refuse plaintext writes when no key is provisioned.
    - Sealed channels store ciphertext (body=None) once a key exists.
"""

import pytest
from unittest.mock import MagicMock

from hokora.constants import ACCESS_PRIVATE, MSG_TEXT, PERM_NODE_OWNER
from hokora.db.models import Channel, Identity, Role, RoleAssignment
from hokora.db.queries import RoleRepo
from hokora.exceptions import PermissionDenied


NODE_MEMBER = "a" * 32
CHAN_MEMBER = "b" * 32
NODE_OWNER = "c" * 32


# ---------------------------------------------------------------------------
# get_identity_roles — scope semantics
# ---------------------------------------------------------------------------


class TestGetIdentityRolesScope:
    async def test_strict_channel_scope_excludes_node_scoped(self, session):
        ch_id = "chan0000abc12345"
        role_id = "role_member_0001"
        session.add(Role(id=role_id, name="member", permissions=0x80EF))
        session.add(Channel(id=ch_id, name="test", access_mode=ACCESS_PRIVATE))
        session.add(Identity(hash=NODE_MEMBER))
        # NODE-scoped assignment (channel_id IS NULL)
        session.add(RoleAssignment(role_id=role_id, identity_hash=NODE_MEMBER, channel_id=None))
        await session.flush()

        repo = RoleRepo(session)
        lenient = await repo.get_identity_roles(NODE_MEMBER, ch_id)
        strict = await repo.get_identity_roles(NODE_MEMBER, ch_id, strict_channel_scope=True)

        assert len(lenient) == 1, "lenient query must return the node-scoped role"
        assert strict == [], "strict query must exclude node-scoped rows"

    async def test_strict_channel_scope_returns_channel_scoped(self, session):
        ch_id = "chan0000def67890"
        role_id = "role_member_0002"
        session.add(Role(id=role_id, name="member", permissions=0x80EF))
        session.add(Channel(id=ch_id, name="test2", access_mode=ACCESS_PRIVATE))
        session.add(Identity(hash=CHAN_MEMBER))
        # CHANNEL-scoped assignment
        session.add(RoleAssignment(role_id=role_id, identity_hash=CHAN_MEMBER, channel_id=ch_id))
        await session.flush()

        repo = RoleRepo(session)
        strict = await repo.get_identity_roles(CHAN_MEMBER, ch_id, strict_channel_scope=True)
        assert len(strict) == 1, "channel-scoped role must pass strict check"
        assert strict[0].id == role_id

    async def test_default_still_lenient_for_permission_calc(self, session):
        """Backwards-compat: get_effective_permissions relies on lenient behavior
        so node_owner's node-wide permissions still flow through."""
        ch_id = "chan0000111f4242"
        role_id = "role_nodeowner_01"
        session.add(Role(id=role_id, name="node_owner", permissions=PERM_NODE_OWNER))
        session.add(Channel(id=ch_id, name="test3", access_mode=ACCESS_PRIVATE))
        session.add(Identity(hash=NODE_OWNER))
        session.add(RoleAssignment(role_id=role_id, identity_hash=NODE_OWNER, channel_id=None))
        await session.flush()

        repo = RoleRepo(session)
        # Default (strict_channel_scope=False): node-owner still visible for channel-scoped query
        lenient = await repo.get_identity_roles(NODE_OWNER, ch_id)
        assert len(lenient) == 1


# ---------------------------------------------------------------------------
# Sealed-channel invariant
# ---------------------------------------------------------------------------


class TestSealedInvariant:
    """MessageProcessor.ingest must refuse plaintext writes to sealed channels
    without an available encryption key, and must always store ciphertext
    (body=None) when a key is available.
    """

    async def test_sealed_write_without_key_raises(self, session):
        """A sealed channel with no SealedKey rejects writes with PermissionDenied."""
        from hokora.core.message import MessageProcessor, MessageEnvelope

        # Build a sealed channel in the DB so _check_permissions finds it
        ch_id = "sealed_no_key__0"
        session.add(Channel(id=ch_id, name="seal", access_mode=ACCESS_PRIVATE, sealed=True))
        role_id = "role_member_nokey"
        session.add(Role(id=role_id, name="member", permissions=0x80EF))
        session.add(Identity(hash=CHAN_MEMBER))
        # CHANNEL-scoped role so membership gate passes
        session.add(RoleAssignment(role_id=role_id, identity_hash=CHAN_MEMBER, channel_id=ch_id))
        await session.flush()

        # Sealed manager with NO key for this channel
        sealed_mgr = MagicMock()
        sealed_mgr.get_key.return_value = None

        mp = MessageProcessor(
            sequencer=_sequencer_mock(),
            permission_resolver=_permission_resolver_mock(),
            sealed_manager=sealed_mgr,
            node_identity_hash=NODE_OWNER,
        )

        env = MessageEnvelope(
            channel_id=ch_id,
            sender_hash=CHAN_MEMBER,
            type=MSG_TEXT,
            body="hello",
            timestamp=1000.0,
        )

        with pytest.raises(PermissionDenied, match="no encryption key"):
            await mp.ingest(session, env)

    async def test_sealed_write_with_key_stores_ciphertext(self, session):
        """Sealed write with available key stores ciphertext and body=None."""
        from hokora.core.message import MessageProcessor, MessageEnvelope

        ch_id = "sealed_with_key_0"
        session.add(Channel(id=ch_id, name="seal2", access_mode=ACCESS_PRIVATE, sealed=True))
        role_id = "role_member_key_0"
        session.add(Role(id=role_id, name="member", permissions=0x80EF))
        session.add(Identity(hash=CHAN_MEMBER))
        session.add(RoleAssignment(role_id=role_id, identity_hash=CHAN_MEMBER, channel_id=ch_id))
        await session.flush()

        # Sealed manager WITH a key — encrypt returns deterministic blobs.
        sealed_mgr = MagicMock()
        sealed_mgr.get_key.return_value = {"key": b"k" * 32, "epoch": 1}
        sealed_mgr.encrypt.return_value = (
            b"nonce_24_bytes__________",  # 24-byte nonce
            b"ciphertext_opaque",  # ciphertext
            1,  # epoch
        )

        mp = MessageProcessor(
            sequencer=_sequencer_mock(),
            permission_resolver=_permission_resolver_mock(),
            sealed_manager=sealed_mgr,
            node_identity_hash=NODE_OWNER,
        )

        env = MessageEnvelope(
            channel_id=ch_id,
            sender_hash=CHAN_MEMBER,
            type=MSG_TEXT,
            body="secret payload",
            timestamp=2000.0,
        )

        stored = await mp.ingest(session, env)

        assert stored is not None
        assert stored.body is None, "sealed rows must not carry plaintext body"
        assert stored.encrypted_body == b"ciphertext_opaque"
        assert stored.encryption_nonce == b"nonce_24_bytes__________"
        assert stored.encryption_epoch == 1

    async def test_unsealed_channel_still_stores_plaintext(self, session):
        """Non-sealed channels remain plaintext; invariant is scoped to sealed=True."""
        from hokora.core.message import MessageProcessor, MessageEnvelope

        ch_id = "public_channel_0_"
        from hokora.constants import ACCESS_PUBLIC

        session.add(Channel(id=ch_id, name="pub", access_mode=ACCESS_PUBLIC, sealed=False))
        session.add(Identity(hash=NODE_OWNER))
        await session.flush()

        # Sealed manager irrelevant for unsealed channels
        sealed_mgr = MagicMock()
        sealed_mgr.get_key.return_value = None

        mp = MessageProcessor(
            sequencer=_sequencer_mock(),
            permission_resolver=_permission_resolver_mock(),
            sealed_manager=sealed_mgr,
            node_identity_hash=NODE_OWNER,
        )

        env = MessageEnvelope(
            channel_id=ch_id,
            sender_hash=NODE_OWNER,
            type=MSG_TEXT,
            body="public note",
            timestamp=3000.0,
        )
        stored = await mp.ingest(session, env)
        assert stored.body == "public note"
        assert stored.encrypted_body is None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _channel_manager_for(ch_id, sealed=True, access=ACCESS_PRIVATE):
    cm = MagicMock()
    ch = MagicMock()
    ch.id = ch_id
    ch.name = ch_id
    ch.access_mode = access
    ch.sealed = sealed
    ch.slowmode = 0
    cm.get_channel.return_value = ch
    return cm


def _sequencer_mock():
    seq = MagicMock()

    async def next_seq(session, channel_id):
        return 1

    async def next_thread_seq(session, root, ch):
        return 1

    seq.next_seq = next_seq
    seq.next_thread_seq = next_thread_seq
    return seq


def _permission_resolver_mock():
    from hokora.constants import PERM_SEND_MESSAGES, PERM_READ_HISTORY

    pr = MagicMock()
    pr.node_owner_hash = NODE_OWNER

    async def get_effective_permissions(session, sender, channel):
        return PERM_SEND_MESSAGES | PERM_READ_HISTORY | 0x80EF

    pr.get_effective_permissions = get_effective_permissions
    return pr
