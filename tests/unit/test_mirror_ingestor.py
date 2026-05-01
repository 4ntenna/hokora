# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for ``MirrorMessageIngestor``."""

import time
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hokora.db.models import Channel, Message
from hokora.federation.mirror_ingestor import MirrorMessageIngestor


def _make_identity():
    import RNS

    return RNS.Identity()


# Fixed identity used for default fixture so every _base_msg() carries a
# wire-format-correct 32-char sender_hash. Tests that need a different
# (sender_hash, sender_rns_public_key) pairing override explicitly.
_DEFAULT_IDENTITY = _make_identity()
_DEFAULT_SENDER_HASH = _DEFAULT_IDENTITY.hexhash
_DEFAULT_RNS_PUBKEY = _DEFAULT_IDENTITY.get_public_key()


def _base_msg(**overrides) -> dict:
    msg = {
        "msg_hash": "a" * 64,
        "sender_hash": _DEFAULT_SENDER_HASH,
        "timestamp": time.time(),
        "type": 1,
        "body": "hi",
        "display_name": "alice",
    }
    msg.update(overrides)
    return msg


@pytest_asyncio.fixture
async def _channel(session_factory):
    async with session_factory() as s:
        async with s.begin():
            s.add(Channel(id="c" * 64, name="public"))
    return "c" * 64


@pytest.fixture
def sequencer():
    seq = MagicMock()
    seq.next_seq = AsyncMock(return_value=42)
    return seq


@pytest.fixture
def live_manager():
    lm = MagicMock()
    lm.push_message = MagicMock()
    return lm


class TestValidation:
    async def test_rejects_oversize_body(self, session_factory, sequencer, live_manager, _channel):
        ing = MirrorMessageIngestor(
            session_factory, sequencer, live_manager, require_signed_federation=False
        )
        msg = _base_msg(body="x" * 40_000)
        await ing.ingest(_channel, msg)
        sequencer.next_seq.assert_not_called()

    async def test_rejects_missing_sender_hash(
        self, session_factory, sequencer, live_manager, _channel
    ):
        ing = MirrorMessageIngestor(
            session_factory, sequencer, live_manager, require_signed_federation=False
        )
        msg = _base_msg(sender_hash=None)
        await ing.ingest(_channel, msg)
        sequencer.next_seq.assert_not_called()

    async def test_rejects_short_sender_hash(
        self, session_factory, sequencer, live_manager, _channel
    ):
        ing = MirrorMessageIngestor(
            session_factory, sequencer, live_manager, require_signed_federation=False
        )
        msg = _base_msg(sender_hash="abc")
        await ing.ingest(_channel, msg)
        sequencer.next_seq.assert_not_called()

    async def test_rejects_future_timestamp_beyond_drift(
        self, session_factory, sequencer, live_manager, _channel
    ):
        ing = MirrorMessageIngestor(
            session_factory, sequencer, live_manager, require_signed_federation=False
        )
        msg = _base_msg(timestamp=time.time() + 10_000)
        await ing.ingest(_channel, msg)
        sequencer.next_seq.assert_not_called()

    async def test_rejects_timestamp_older_than_30_days(
        self, session_factory, sequencer, live_manager, _channel
    ):
        ing = MirrorMessageIngestor(
            session_factory, sequencer, live_manager, require_signed_federation=False
        )
        msg = _base_msg(timestamp=time.time() - (31 * 86400))
        await ing.ingest(_channel, msg)
        sequencer.next_seq.assert_not_called()


class TestSignature:
    async def test_accepts_valid_signed_message(
        self, session_factory, sequencer, live_manager, _channel
    ):
        ing = MirrorMessageIngestor(
            session_factory, sequencer, live_manager, require_signed_federation=True
        )
        signed_part = b"original-payload"
        ed25519_priv = Ed25519PrivateKey.from_private_bytes(_DEFAULT_IDENTITY.sig_prv_bytes)
        sig = ed25519_priv.sign(signed_part)
        msg = _base_msg(
            lxmf_signature=sig,
            lxmf_signed_part=signed_part,
            sender_rns_public_key=_DEFAULT_RNS_PUBKEY,
        )
        await ing.ingest(_channel, msg, peer_hash="p" * 32)
        sequencer.next_seq.assert_awaited_once()

    async def test_rejects_invalid_signature(
        self, session_factory, sequencer, live_manager, _channel
    ):
        ing = MirrorMessageIngestor(
            session_factory, sequencer, live_manager, require_signed_federation=True
        )
        msg = _base_msg(
            lxmf_signature=b"\x00" * 64,
            lxmf_signed_part=b"original-payload",
            sender_rns_public_key=_DEFAULT_RNS_PUBKEY,
        )
        await ing.ingest(_channel, msg)
        sequencer.next_seq.assert_not_called()

    async def test_rejects_victim_substitution(
        self, session_factory, sequencer, live_manager, _channel
    ):
        """Trusted peer signs with own key but claims a victim's sender_hash."""
        ing = MirrorMessageIngestor(
            session_factory, sequencer, live_manager, require_signed_federation=True
        )
        attacker = _make_identity()
        signed_part = b"victim-attributed-content"
        attacker_priv = Ed25519PrivateKey.from_private_bytes(attacker.sig_prv_bytes)
        sig = attacker_priv.sign(signed_part)
        msg = _base_msg(
            sender_hash=_DEFAULT_SENDER_HASH,  # victim
            lxmf_signature=sig,
            lxmf_signed_part=signed_part,
            sender_rns_public_key=attacker.get_public_key(),
        )
        await ing.ingest(_channel, msg, peer_hash="p" * 32)
        sequencer.next_seq.assert_not_called()

    async def test_rejects_unsigned_when_require_signed_true(
        self, session_factory, sequencer, live_manager, _channel
    ):
        ing = MirrorMessageIngestor(
            session_factory, sequencer, live_manager, require_signed_federation=True
        )
        msg = _base_msg()  # no sig fields, no rns pubkey
        await ing.ingest(_channel, msg)
        sequencer.next_seq.assert_not_called()

    async def test_accepts_unsigned_when_require_signed_false(
        self, session_factory, sequencer, live_manager, _channel
    ):
        ing = MirrorMessageIngestor(
            session_factory, sequencer, live_manager, require_signed_federation=False
        )
        msg = _base_msg()
        await ing.ingest(_channel, msg, peer_hash="p" * 32)
        sequencer.next_seq.assert_awaited_once()


class TestIngestion:
    async def test_dedupes_by_msg_hash(self, session_factory, sequencer, live_manager, _channel):
        ing = MirrorMessageIngestor(
            session_factory, sequencer, live_manager, require_signed_federation=False
        )
        msg = _base_msg()
        # Pre-seed an existing message with the same hash
        async with session_factory() as s:
            async with s.begin():
                s.add(
                    Message(
                        msg_hash=msg["msg_hash"],
                        channel_id=_channel,
                        sender_hash=msg["sender_hash"],
                        seq=1,
                        timestamp=msg["timestamp"],
                        type=1,
                        body="old",
                    )
                )
        await ing.ingest(_channel, msg, peer_hash="peer" * 16)
        sequencer.next_seq.assert_not_called()
        live_manager.push_message.assert_not_called()

    async def test_assigns_local_seq_via_sequencer(
        self, session_factory, sequencer, live_manager, _channel
    ):
        ing = MirrorMessageIngestor(
            session_factory, sequencer, live_manager, require_signed_federation=False
        )
        msg = _base_msg()
        await ing.ingest(_channel, msg, peer_hash="peer" * 16)
        sequencer.next_seq.assert_awaited_once()

    async def test_sets_origin_node_from_peer_hash_not_payload(
        self, session_factory, sequencer, live_manager, _channel
    ):
        """Security property: never trust payload origin_node."""
        ing = MirrorMessageIngestor(
            session_factory, sequencer, live_manager, require_signed_federation=False
        )
        msg = _base_msg(origin_node="evil" * 16)
        real_peer = "peer" * 16
        await ing.ingest(_channel, msg, peer_hash=real_peer)

        async with session_factory() as s:
            from hokora.db.queries import MessageRepo

            stored = await MessageRepo(s).get_by_hash(msg["msg_hash"])
            assert stored is not None
            assert stored.origin_node == real_peer

    async def test_pushes_to_live_manager_when_present(
        self, session_factory, sequencer, live_manager, _channel
    ):
        ing = MirrorMessageIngestor(
            session_factory, sequencer, live_manager, require_signed_federation=False
        )
        msg = _base_msg()
        await ing.ingest(_channel, msg, peer_hash="peer" * 16)
        live_manager.push_message.assert_called_once()

    async def test_skips_live_push_when_manager_none(self, session_factory, sequencer, _channel):
        ing = MirrorMessageIngestor(
            session_factory, sequencer, None, require_signed_federation=False
        )
        msg = _base_msg()
        await ing.ingest(_channel, msg, peer_hash="peer" * 16)
        # no raise, insertion still happens
        sequencer.next_seq.assert_awaited_once()
