# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Sealed-invariant coverage tests.

These tests lock in the rule that **every** Message-write path respects
``channel.sealed``. Edits, pin system messages, federation pushes, and
mirror ingests all route through ``security.sealed_invariant``; if any
path regresses, one of the tests below fails.

Each test asserts the at-rest shape of the stored row: ``body`` must be
``None`` for sealed channels, ``encrypted_body`` must be populated. The
``TestSealedInvariantChokepointIntegrity`` class proves the helpers are
load-bearing — a future refactor that re-implements sealing inline
breaks those tests immediately.
"""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from sqlalchemy import select, text

from hokora.constants import MSG_EDIT, MSG_PIN, MSG_TEXT
from hokora.core.message import MessageEnvelope, MessageProcessor
from hokora.db.models import Channel, Message
from hokora.federation.mirror_ingestor import MirrorMessageIngestor
from hokora.security.sealed import SealedChannelManager


SEALED_CHANNEL_ID = "sea1" + "0" * 60
PUBLIC_CHANNEL_ID = "pub1" + "0" * 60
# Sender == node_identity_hash so the sealed-membership gate (which
# requires either node-owner bypass or an explicit channel-scoped role)
# succeeds without needing to seed a role_assignments row in every test.
# We're exercising the crypto/storage side of the invariant here, not
# the membership gate.
NODE_HASH = "a" * 64
SENDER_HASH = NODE_HASH


@pytest_asyncio.fixture
async def _channels(session_factory):
    async with session_factory() as s:
        async with s.begin():
            s.add(Channel(id=SEALED_CHANNEL_ID, name="sealed", sealed=True))
            s.add(Channel(id=PUBLIC_CHANNEL_ID, name="public", sealed=False))


@pytest.fixture
def _sealed_manager():
    mgr = SealedChannelManager()
    mgr.generate_key(SEALED_CHANNEL_ID)
    return mgr


def _permissive_resolver():
    """Returns PERM_ALL so permission checks never block these tests."""
    resolver = MagicMock()
    resolver.get_effective_permissions = AsyncMock(return_value=0xFFFF)
    return resolver


def _sequencer(start: int = 1):
    seq = MagicMock()
    state = {"n": start}

    async def _next(_session, _channel_id):
        n = state["n"]
        state["n"] += 1
        return n

    async def _next_thread(_session, _parent_hash, _channel_id):
        return 1

    seq.next_seq = AsyncMock(side_effect=_next)
    seq.next_thread_seq = AsyncMock(side_effect=_next_thread)
    return seq


def _make_processor(sealed_manager, resolver=None):
    return MessageProcessor(
        sequencer=_sequencer(),
        permission_resolver=resolver or _permissive_resolver(),
        rate_limiter=None,
        identity_repo=None,
        node_identity_hash=NODE_HASH,
        sealed_manager=sealed_manager,
    )


async def _fetch(session_factory, msg_hash):
    async with session_factory() as s:
        row = (await s.execute(select(Message).where(Message.msg_hash == msg_hash))).scalar_one()
        return row


# ── Send path (regression — already covered by other tests, locked in again)


class TestIngestPathSealed:
    async def test_sealed_send_stores_ciphertext_only(
        self, session_factory, _channels, _sealed_manager
    ):
        """MessageProcessor.ingest — the primary path, reconfirmed."""
        proc = _make_processor(_sealed_manager)
        env = MessageEnvelope(
            channel_id=SEALED_CHANNEL_ID,
            sender_hash=SENDER_HASH,
            timestamp=time.time(),
            type=MSG_TEXT,
            body="top secret message",
        )
        async with session_factory() as s:
            async with s.begin():
                msg = await proc.ingest(s, env)

        stored = await _fetch(session_factory, msg.msg_hash)
        assert stored.body is None
        assert stored.encrypted_body is not None
        assert stored.encryption_nonce is not None
        assert stored.encryption_epoch == 1


# ── Edit path (sealed body must remain encrypted at rest)


class TestEditPathSealed:
    async def test_sealed_edit_does_not_leak_plaintext_to_original_or_edit_row(
        self, session_factory, _channels, _sealed_manager
    ):
        """An edit to a sealed message must:
        - store the edit row with body=None, encrypted_body populated
        - overwrite the original's body to None (not the plaintext edit text)
        - overwrite the original's encrypted_body with fresh ciphertext
        """
        proc = _make_processor(_sealed_manager)

        # Seed the original sealed message via the ingest path
        original_env = MessageEnvelope(
            channel_id=SEALED_CHANNEL_ID,
            sender_hash=SENDER_HASH,
            timestamp=time.time(),
            type=MSG_TEXT,
            body="original plaintext",
        )
        async with session_factory() as s:
            async with s.begin():
                original = await proc.ingest(s, original_env)
        original_hash = original.msg_hash

        # Edit with plaintext body — without the chokepoint this would
        # leak plaintext onto both the edit row and the original's body
        # column.
        edit_env = MessageEnvelope(
            channel_id=SEALED_CHANNEL_ID,
            sender_hash=SENDER_HASH,
            timestamp=time.time() + 1,
            type=MSG_EDIT,
            body="edited plaintext ONEFISH",
            reply_to=original_hash,
        )
        async with session_factory() as s:
            async with s.begin():
                edit_msg = await proc.process_edit(s, edit_env)

        # Edit row: no plaintext body at rest
        edit_stored = await _fetch(session_factory, edit_msg.msg_hash)
        assert edit_stored.body is None, (
            "edit row must not persist plaintext body for a sealed channel"
        )
        assert edit_stored.encrypted_body is not None

        # Original: body cleared; encrypted_body updated to the NEW edit ciphertext
        orig_stored = await _fetch(session_factory, original_hash)
        assert orig_stored.body is None, (
            "original's body must be cleared to None, not set to plaintext"
        )
        assert orig_stored.encrypted_body is not None
        assert orig_stored.encrypted_body != original.encrypted_body, (
            "original's encrypted_body must be replaced with the edit ciphertext"
        )

    async def test_public_edit_still_writes_plaintext(
        self, session_factory, _channels, _sealed_manager
    ):
        """Sanity — public (non-sealed) channels are unchanged: edits write
        plaintext as before."""
        proc = _make_processor(_sealed_manager)
        env = MessageEnvelope(
            channel_id=PUBLIC_CHANNEL_ID,
            sender_hash=SENDER_HASH,
            timestamp=time.time(),
            type=MSG_TEXT,
            body="hello",
        )
        async with session_factory() as s:
            async with s.begin():
                original = await proc.ingest(s, env)

        edit_env = MessageEnvelope(
            channel_id=PUBLIC_CHANNEL_ID,
            sender_hash=SENDER_HASH,
            timestamp=time.time() + 1,
            type=MSG_EDIT,
            body="edited",
            reply_to=original.msg_hash,
        )
        async with session_factory() as s:
            async with s.begin():
                await proc.process_edit(s, edit_env)

        orig = await _fetch(session_factory, original.msg_hash)
        assert orig.body == "edited"
        assert orig.encrypted_body is None


# ── Pin system message path (sealed body must remain encrypted)


class TestPinSystemMessageSealed:
    async def test_sealed_pin_encrypts_system_body(
        self, session_factory, _channels, _sealed_manager
    ):
        """Pin/unpin creates a MSG_SYSTEM row whose body names the actor.
        Sealed channels must encrypt that body too."""
        proc = _make_processor(_sealed_manager)

        # Seed a target to pin
        target_env = MessageEnvelope(
            channel_id=SEALED_CHANNEL_ID,
            sender_hash=SENDER_HASH,
            timestamp=time.time(),
            type=MSG_TEXT,
            body="pin me",
        )
        async with session_factory() as s:
            async with s.begin():
                target = await proc.ingest(s, target_env)

        pin_env = MessageEnvelope(
            channel_id=SEALED_CHANNEL_ID,
            sender_hash=SENDER_HASH,
            timestamp=time.time() + 1,
            type=MSG_PIN,
            reply_to=target.msg_hash,
        )
        async with session_factory() as s:
            async with s.begin():
                sys_msg = await proc.process_pin(s, pin_env)

        stored = await _fetch(session_factory, sys_msg.msg_hash)
        assert stored.body is None, "sealed pin system body must not leak actor at rest"
        assert stored.encrypted_body is not None

    async def test_public_pin_still_writes_plaintext_system_body(
        self, session_factory, _channels, _sealed_manager
    ):
        proc = _make_processor(_sealed_manager)

        env = MessageEnvelope(
            channel_id=PUBLIC_CHANNEL_ID,
            sender_hash=SENDER_HASH,
            timestamp=time.time(),
            type=MSG_TEXT,
            body="t",
        )
        async with session_factory() as s:
            async with s.begin():
                target = await proc.ingest(s, env)

        pin_env = MessageEnvelope(
            channel_id=PUBLIC_CHANNEL_ID,
            sender_hash=SENDER_HASH,
            timestamp=time.time() + 1,
            type=MSG_PIN,
            reply_to=target.msg_hash,
        )
        async with session_factory() as s:
            async with s.begin():
                sys_msg = await proc.process_pin(s, pin_env)

        stored = await _fetch(session_factory, sys_msg.msg_hash)
        assert stored.body is not None and "pinned" in stored.body
        assert stored.encrypted_body is None


# ── Mirror-ingest path (peer pushes via ChannelMirror subscription)


class TestMirrorIngestSealed:
    async def test_rejects_plaintext_push_to_sealed_channel(self, session_factory, _channels):
        sequencer = MagicMock()
        sequencer.next_seq = AsyncMock(return_value=1)
        live = MagicMock()
        ing = MirrorMessageIngestor(
            session_factory, sequencer, live, require_signed_federation=False
        )
        msg = {
            "msg_hash": "m" + "1" * 63,
            "sender_hash": "c" * 32,
            "timestamp": time.time(),
            "type": 1,
            "body": "peer tried to push plaintext",
        }
        await ing.ingest(SEALED_CHANNEL_ID, msg, peer_hash="p" * 32)
        sequencer.next_seq.assert_not_called()
        live.push_message.assert_not_called()

        async with session_factory() as s:
            count = (
                await s.execute(
                    text("SELECT COUNT(*) FROM messages WHERE msg_hash = :h"),
                    {"h": "m" + "1" * 63},
                )
            ).scalar()
        assert count == 0, "plaintext sealed push is not persisted"

    async def test_live_push_decrypts_sealed_row_for_subscriber(
        self, session_factory, _channels, _sealed_manager
    ):
        """LiveSubscriptionManager.push_message must emit plaintext in the
        wire dict for a sealed row, even though the at-rest row has
        ``body=None``. Pre-2.5 this worked accidentally because the at-rest
        row carried plaintext (the exact leak we fixed). Post-2.5 requires
        server-side decrypt before wire serialization. Subscriber is an
        authenticated channel member, so plaintext on the Link-encrypted
        wire is within the documented threat model.
        """
        from hokora.protocol.live import LiveSubscriptionManager

        proc = _make_processor(_sealed_manager)
        env = MessageEnvelope(
            channel_id=SEALED_CHANNEL_ID,
            sender_hash=SENDER_HASH,
            timestamp=time.time(),
            type=MSG_TEXT,
            body="plaintext-for-live-push",
        )
        async with session_factory() as s:
            async with s.begin():
                msg = await proc.ingest(s, env)

        # Stored row: sealed invariant holds.
        stored = await _fetch(session_factory, msg.msg_hash)
        assert stored.body is None
        assert stored.encrypted_body is not None

        # Drive push_message; capture the payload it would emit.
        captured = {}
        lm = LiveSubscriptionManager(sealed_manager=_sealed_manager)
        lm.get_subscribers = MagicMock(return_value={MagicMock(): 1})

        def _capture(channel_id, subscribers, event_data, event_type, data_dict):
            captured["event_type"] = event_type
            captured["data_dict"] = data_dict

        lm._push_to_subscribers = _capture
        lm.push_message(SEALED_CHANNEL_ID, stored)

        assert captured["event_type"] == "message"
        assert captured["data_dict"]["body"] == "plaintext-for-live-push", (
            "live-push wire payload must carry decrypted plaintext for sealed rows"
        )

    async def test_live_push_without_sealed_manager_is_blank(
        self, session_factory, _channels, _sealed_manager
    ):
        """Sanity: without a sealed_manager, the wire serializer cannot
        decrypt and falls through to body=None → "". This is the exact
        regression we fixed — the test guards against accidentally
        reverting the plumbing."""
        from hokora.protocol.live import LiveSubscriptionManager

        proc = _make_processor(_sealed_manager)
        env = MessageEnvelope(
            channel_id=SEALED_CHANNEL_ID,
            sender_hash=SENDER_HASH,
            timestamp=time.time(),
            type=MSG_TEXT,
            body="plaintext-for-live-push",
        )
        async with session_factory() as s:
            async with s.begin():
                msg = await proc.ingest(s, env)
        stored = await _fetch(session_factory, msg.msg_hash)

        captured = {}
        lm_no_sealed = LiveSubscriptionManager(sealed_manager=None)
        lm_no_sealed.get_subscribers = MagicMock(return_value={MagicMock(): 1})
        lm_no_sealed._push_to_subscribers = lambda *a, **k: captured.update({"data_dict": a[4]})
        lm_no_sealed.push_message(SEALED_CHANNEL_ID, stored)
        assert captured["data_dict"]["body"] == "", (
            "without a sealed_manager, sealed row body serializes as empty"
        )

    async def test_accepts_ciphertext_push_to_sealed_channel_verbatim(
        self, session_factory, _channels
    ):
        sequencer = MagicMock()
        sequencer.next_seq = AsyncMock(return_value=1)
        live = MagicMock()
        ing = MirrorMessageIngestor(
            session_factory, sequencer, live, require_signed_federation=False
        )
        ciphertext = b"\xcc" * 48
        nonce = b"\xdd" * 12
        msg = {
            "msg_hash": "m" + "2" * 63,
            "sender_hash": "c" * 32,
            "timestamp": time.time(),
            "type": 1,
            "body": "",  # empty — correct for sealed wire format
            "encrypted_body": ciphertext,
            "encryption_nonce": nonce,
            "encryption_epoch": 1,
        }
        await ing.ingest(SEALED_CHANNEL_ID, msg, peer_hash="p" * 32)

        stored = await _fetch(session_factory, "m" + "2" * 63)
        assert stored.body is None
        assert bytes(stored.encrypted_body) == ciphertext, "ciphertext stored verbatim"
        assert bytes(stored.encryption_nonce) == nonce
        assert stored.encryption_epoch == 1
        assert stored.origin_node == "p" * 32


# ── Chokepoint integrity (proves the helpers are actually called)


class TestSealedInvariantChokepointIntegrity:
    """If a future refactor re-implements sealing inline on either path,
    these monkey-patch tests fail — proving ``security.sealed_invariant``
    is the load-bearing chokepoint."""

    async def test_origin_path_routes_through_seal_for_origin(
        self, session_factory, _channels, _sealed_manager, monkeypatch
    ):
        from hokora.security import sealed_invariant

        called = {"n": 0}
        real = sealed_invariant.seal_for_origin

        def _spy(channel, plaintext, sealed_manager):
            called["n"] += 1
            return real(channel, plaintext, sealed_manager)

        # core.message imports the helper lazily inside _seal_body_for_insert,
        # so patching the module attribute is sufficient.
        monkeypatch.setattr(sealed_invariant, "seal_for_origin", _spy)

        proc = _make_processor(_sealed_manager)
        env = MessageEnvelope(
            channel_id=SEALED_CHANNEL_ID,
            sender_hash=SENDER_HASH,
            timestamp=time.time(),
            type=MSG_TEXT,
            body="x",
        )
        async with session_factory() as s:
            async with s.begin():
                await proc.ingest(s, env)

        assert called["n"] >= 1, "ingest path must call seal_for_origin"

    async def test_mirror_path_routes_through_validate_mirror_payload(
        self, session_factory, _channels, monkeypatch
    ):
        from hokora.federation import mirror_ingestor as mi

        called = {"n": 0}
        real = mi.validate_mirror_payload

        def _spy(channel, body, enc_body, enc_nonce, enc_epoch):
            called["n"] += 1
            return real(channel, body, enc_body, enc_nonce, enc_epoch)

        # mirror_ingestor binds the helper at import time; patch the
        # module-level reference the call site actually resolves.
        monkeypatch.setattr(mi, "validate_mirror_payload", _spy)

        sequencer = MagicMock()
        sequencer.next_seq = AsyncMock(return_value=1)
        live = MagicMock()
        ing = MirrorMessageIngestor(
            session_factory, sequencer, live, require_signed_federation=False
        )
        msg = {
            "msg_hash": "m" + "3" * 63,
            "sender_hash": "c" * 32,
            "timestamp": time.time(),
            "type": 1,
            "body": "",
            "encrypted_body": b"\xcc" * 48,
            "encryption_nonce": b"\xdd" * 12,
            "encryption_epoch": 1,
        }
        await ing.ingest(SEALED_CHANNEL_ID, msg, peer_hash="p" * 32)
        assert called["n"] >= 1, "mirror path must call validate_mirror_payload"
