# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""End-to-end regression for the sender-pk wire-shape contract.

Locks in the contract that ``sender_public_key`` stored and sent on the
wire is always the 32-byte Ed25519 signing key (never the 64-byte RNS
concatenated blob). If a future refactor in ``lxmf_bridge`` or
``sync_utils`` silently regresses this shape, this test fails
immediately.

Covers the full path:

1. Real ``Ed25519PrivateKey`` signs a payload.
2. ``MessageProcessor`` ingests the message with the matching 32-byte pk.
3. ``identities`` row stores the 32-byte pk.
4. ``encode_messages_with_keys`` reads the row and puts the pk on the wire.
5. ``VerificationService.verify_ed25519_signature(pk, signed_part, sig)``
   returns True.

Step 4 is exercised because ``sync_utils.encode_messages_with_keys`` is
where the wire response shape is decided. If anyone ever puts the
64-byte blob there instead of the sliced key, step 5 fails.
"""

from __future__ import annotations

import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hokora.core.message import MessageEnvelope, MessageProcessor
from hokora.core.sequencer import SequenceManager
from hokora.db.queries import ChannelRepo, IdentityRepo
from hokora.db.models import Channel
from hokora.protocol.sync_utils import encode_messages_with_keys
from hokora.security.verification import VerificationService


async def test_full_sig_verify_roundtrip(session_factory):
    """End-to-end: ingest → store → wire-encode → verify."""
    # Real Ed25519 keypair — we sign a body and expect the wire to carry
    # the 32-byte sig pk so the response verifies.
    sk = Ed25519PrivateKey.generate()
    sig_pk_bytes = sk.public_key().public_bytes_raw()
    assert len(sig_pk_bytes) == 32, "contract sanity: Ed25519 pk is 32 bytes"

    sender_hash = "a" * 64
    channel_id = "roundtrip_ch"
    body = "sig-verify-canary"
    signed_part = body.encode("utf-8")
    signature = sk.sign(signed_part)

    # Seed channel row.
    async with session_factory() as session:
        async with session.begin():
            await ChannelRepo(session).create(
                Channel(id=channel_id, name="roundtrip", latest_seq=0)
            )

    # Ingest via MessageProcessor with the 32-byte sig pk.
    async with session_factory() as session:
        async with session.begin():
            processor = MessageProcessor(SequenceManager())
            envelope = MessageEnvelope(
                channel_id=channel_id,
                sender_hash=sender_hash,
                timestamp=time.time(),
                body=body,
                lxmf_signature=signature,
                lxmf_signed_part=signed_part,
                sender_public_key=sig_pk_bytes,
            )
            await processor.ingest(session, envelope)

    # Assert identities row stores exactly the 32-byte pk.
    async with session_factory() as session:
        ident = await IdentityRepo(session).get_by_hash(sender_hash)
        assert ident is not None
        assert len(ident.public_key) == 32, (
            "Persisted sender_public_key must be 32-byte Ed25519 key (not 64-byte RNS blob)"
        )
        assert ident.public_key == sig_pk_bytes

    # Wire encode response and confirm the pk on the wire is still 32 bytes
    # AND it verifies the signature.
    from sqlalchemy import select
    from hokora.db.models import Message

    async with session_factory() as session:
        rows = (
            (await session.execute(select(Message).where(Message.channel_id == channel_id)))
            .scalars()
            .all()
        )
        wire = await encode_messages_with_keys(session, list(rows))

    assert len(wire) == 1
    wire_msg = wire[0]
    assert "sender_public_key" in wire_msg
    wire_pk = wire_msg["sender_public_key"]
    assert len(wire_pk) == 32, f"wire pk length must be 32, got {len(wire_pk)}"

    # Final gate: the wire-carried key verifies the original signature.
    assert VerificationService.verify_ed25519_signature(wire_pk, signed_part, signature) is True


async def test_64_byte_pk_would_be_caught(session_factory):
    """Negative control: if a caller accidentally persists the 64-byte
    blob, the verify guard returns False (not a silent pass). Exercises
    the pk-length check in the verifier."""
    sk = Ed25519PrivateKey.generate()
    sig_pk = sk.public_key().public_bytes_raw()
    # Simulate the buggy shape: X25519 pk (random) prepended to Ed25519 pk.
    rns_blob = (b"\x11" * 32) + sig_pk
    assert len(rns_blob) == 64

    signed = b"some-payload"
    sig = sk.sign(signed)

    # Guard rejects 64-byte input.
    assert VerificationService.verify_ed25519_signature(rns_blob, signed, sig) is False
    # And the correctly-sliced half still verifies.
    assert VerificationService.verify_ed25519_signature(rns_blob[32:], signed, sig) is True
