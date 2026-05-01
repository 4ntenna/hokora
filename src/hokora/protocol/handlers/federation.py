# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Federation sync handlers: handshake, challenge, push messages."""

import asyncio
import logging
import time
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from hokora.db.models import Peer
from hokora.db.queries import MessageRepo
from hokora.exceptions import SyncError, RateLimitExceeded
from hokora.protocol.sync_utils import FederationContext

logger = logging.getLogger(__name__)


async def handle_federation_handshake(
    ctx: FederationContext,
    session: AsyncSession,
    nonce: bytes,
    payload: dict,
    channel_id: Optional[str],
    requester_hash: Optional[str] = None,
    link=None,
    # These are extra state held by SyncHandler (passed through from router)
    pending_counter_challenges: dict = None,
    challenges_lock: asyncio.Lock = None,
) -> dict:
    """Handle federation_handshake (0x0B): peer authentication handshake."""
    from hokora.federation.auth import (
        ED25519_PUBLIC_KEY_SIZE,
        FederationAuth,
        signing_public_key,
    )

    step = payload.get("step", 1)
    peer_identity_hash = payload.get("identity_hash")
    peer_node_name = payload.get("node_name", "unknown")

    # Every step in the handshake state machine relies on peer_identity_hash:
    # steps 1/3 use it to look up the Peer row for the trust gate, step 5
    # uses it to ``RNS.Identity.recall`` the peer for FS-frame signature
    # verification. The sender on every step is responsible for including it.
    if not peer_identity_hash:
        raise SyncError(f"Missing identity_hash in handshake step {step}")

    # Rate limit handshake attempts per peer
    if ctx.rate_limiter:
        try:
            ctx.rate_limiter.check_rate_limit(peer_identity_hash)
        except RateLimitExceeded as e:
            raise SyncError(f"Handshake rate limited: {e}")

    # Check if peer is trusted (or auto_trust is enabled). Step 5 reaches
    # this gate too — by step 5 the peer was set ``federation_trusted=True``
    # at step 3, so the gate passes naturally. The check is left in to
    # cover the edge where an admin runs ``hokora mirror untrust`` between
    # step 3 and step 5.
    auto_trust = ctx.config and getattr(ctx.config, "federation_auto_trust", False)

    result = await session.execute(select(Peer).where(Peer.identity_hash == peer_identity_hash))
    peer = result.scalar_one_or_none()

    if not peer and not auto_trust:
        logger.warning(
            f"Federation handshake rejected from untrusted peer "
            f"{peer_identity_hash[:16]} ({peer_node_name}). "
            f"Use 'hokora mirror trust' to trust this peer."
        )
        raise SyncError("Peer not trusted. Use 'hokora mirror trust' to allow.")

    if step == 1:
        challenge = payload.get("challenge")
        if not challenge or len(challenge) != 32:
            raise SyncError("Invalid challenge in handshake")

        # Sign the peer's challenge with our node identity
        challenge_response = None
        if ctx.node_rns_identity:
            challenge_response = ctx.node_rns_identity.sign(challenge)

        counter_challenge = FederationAuth.create_challenge()

        # Store counter_challenge so we can verify step 3
        from hokora.constants import MAX_PENDING_CHALLENGES

        async with challenges_lock:
            if len(pending_counter_challenges) >= MAX_PENDING_CHALLENGES:
                # Evict stale entries inline before rejecting
                now = time.time()
                stale = [k for k, (_, ts) in pending_counter_challenges.items() if now - ts > 300]
                for k in stale:
                    del pending_counter_challenges[k]
                if len(pending_counter_challenges) >= MAX_PENDING_CHALLENGES:
                    raise SyncError("Too many pending federation handshakes")
            pending_counter_challenges[peer_identity_hash] = (
                counter_challenge,
                time.time(),
            )

        # Create/update peer record (but don't mark trusted yet — wait for step 3)
        if not peer:
            peer = Peer(
                identity_hash=peer_identity_hash,
                node_name=peer_node_name,
                federation_trusted=False,
            )
            session.add(peer)
        else:
            peer.node_name = peer_node_name

        peer.last_handshake = time.time()

        response = {
            "action": "federation_handshake",
            "step": 2,
            "node_name": ctx.node_name,
            "identity_hash": ctx.node_identity,
            "counter_challenge": counter_challenge,
            "accepted": True,
        }
        if challenge_response:
            response["challenge_response"] = challenge_response
        # Include our public key so the initiator can verify our signature.
        # Use signing_public_key() for the bare 32-byte Ed25519 — never
        # RNS.Identity.get_public_key() (which returns a 64-byte X25519+Ed25519
        # concatenation that the initiator's verifier rejects on length).
        if ctx.node_rns_identity:
            response["peer_public_key"] = signing_public_key(ctx.node_rns_identity)
        return response

    elif step == 3:
        # Final step: verify the peer's signature of our counter_challenge
        counter_response = payload.get("counter_response")
        peer_public_key = payload.get("peer_public_key")
        async with challenges_lock:
            stored_entry = pending_counter_challenges.pop(
                peer_identity_hash,
                None,
            )
        stored_challenge = stored_entry[0] if stored_entry else None

        if not (stored_challenge and counter_response and peer_public_key):
            raise SyncError(
                "Federation handshake step 3 incomplete: missing challenge, "
                "counter_response, or peer_public_key"
            )
        # Wire-contract validation: peer_public_key must be a 32-byte Ed25519
        # public key. Reject malformed wire shapes early so the verifier path
        # only sees keys it can safely consume and the TOFU cache never gets
        # poisoned with a non-Ed25519-shaped value.
        if (
            not isinstance(peer_public_key, (bytes, bytearray))
            or len(peer_public_key) != ED25519_PUBLIC_KEY_SIZE
        ):
            raise SyncError(
                f"Federation handshake step 3: invalid peer_public_key length "
                f"({0 if peer_public_key is None else len(peer_public_key)} "
                f"bytes; expected {ED25519_PUBLIC_KEY_SIZE})"
            )
        if not FederationAuth.verify_response(
            stored_challenge,
            counter_response,
            peer_public_key,
        ):
            raise SyncError("Federation handshake failed: invalid counter_response signature")

        # Mark peer as trusted after successful handshake
        if peer:
            peer.last_handshake = time.time()
            peer.federation_trusted = True
            # Persist initiator's public key for TOFU cache
            peer.public_key = bytes(peer_public_key)

        fs_capable = bool(ctx.config and getattr(ctx.config, "fs_enabled", False))
        return {
            "action": "federation_handshake",
            "step": 4,
            "complete": True,
            "fs_capable": fs_capable,
        }

    elif step == 5:
        # Forward secrecy: handle EpochRotate from initiator
        from hokora.federation.epoch_manager import EpochManager

        epoch_rotate_frame = payload.get("epoch_rotate_frame")
        if not epoch_rotate_frame:
            raise SyncError("Missing epoch_rotate_frame in step 5")

        node_identity = ctx.node_rns_identity
        if not node_identity:
            raise SyncError("No node identity for epoch handshake")

        # Recall the peer's identity for signature verification
        import RNS as _RNS

        peer_identity = _RNS.Identity.recall(bytes.fromhex(peer_identity_hash))

        em = EpochManager(
            peer_identity_hash=peer_identity_hash,
            is_initiator=False,
            local_rns_identity=node_identity,
            epoch_duration=(ctx.config.fs_epoch_duration if ctx.config else 3600),
            session_factory=None,
            peer_rns_identity=peer_identity,
        )

        ack_frame = em.handle_epoch_rotate(epoch_rotate_frame)

        return {
            "action": "federation_handshake",
            "step": 6,
            "epoch_rotate_ack_frame": ack_frame,
            "_epoch_manager": em,
        }

    raise SyncError(f"Invalid handshake step: {step}")


async def handle_push_messages(
    ctx: FederationContext,
    session: AsyncSession,
    nonce: bytes,
    payload: dict,
    channel_id: Optional[str],
    requester_hash: Optional[str] = None,
    link=None,
) -> dict:
    """Handle push_messages (0x0C): receive pushed messages from a federated peer."""
    from hokora.federation.auth import verify_sender_binding
    from hokora.security.ban import is_blocked, record_ban_rejection

    push_channel_id = payload.get("channel_id", channel_id)
    messages = payload.get("messages", [])
    node_identity = payload.get("node_identity")

    if not push_channel_id:
        raise SyncError("No channel_id in push_messages")

    # Verify the pusher is a trusted peer
    if node_identity:
        result = await session.execute(select(Peer).where(Peer.identity_hash == node_identity))
        peer = result.scalar_one_or_none()
        if not peer or not peer.federation_trusted:
            raise SyncError("Push rejected: peer not trusted")
    else:
        raise SyncError("Push rejected: missing node_identity")

    received = []
    rejected = []

    require_signed = ctx.config and getattr(ctx.config, "require_signed_federation", True)

    # Resolve channel once for sealed-invariant enforcement. A sealed
    # channel must receive ciphertext on the wire — peers that do not
    # have the channel key cannot federate. We never re-encrypt at the
    # hop; end-to-end sealed semantics require the sender to encrypt.
    from hokora.db.queries import ChannelRepo as _ChannelRepo

    push_channel = await _ChannelRepo(session).get_by_id(push_channel_id)
    push_channel_is_sealed = bool(getattr(push_channel, "sealed", False))

    for msg_data in messages:
        msg_hash = msg_data.get("msg_hash", "")

        # Dedup by msg_hash
        repo = MessageRepo(session)
        existing = await repo.get_by_hash(msg_hash)
        if existing:
            received.append(msg_data.get("seq", 0))
            continue

        # Local ban gate: a trusted relay can carry messages from any
        # sender_hash they wish, so the receiver must enforce its own
        # ban list per-message. Skipped messages are not appended to
        # ``received`` — the pusher will see the gap in the ack and
        # treat it as silently dropped, which matches the existing
        # validation-failure path (see ``rejected`` below).
        sender_hash = msg_data.get("sender_hash")
        if sender_hash and await is_blocked(session, sender_hash):
            record_ban_rejection("federation_push")
            logger.info(
                f"Push rejected (sender banned) for {msg_hash[:16]} from {sender_hash[:16]}"
            )
            rejected.append(msg_hash)
            continue

        # Structural sender_hash <-> public_key binding + signature gate
        # (single chokepoint, see hokora.federation.auth.verify_sender_binding).
        ok, reason = verify_sender_binding(
            sender_hash=msg_data.get("sender_hash"),
            sender_rns_public_key=msg_data.get("sender_rns_public_key"),
            lxmf_signed_part=msg_data.get("lxmf_signed_part"),
            lxmf_signature=msg_data.get("lxmf_signature"),
            require_signed=bool(require_signed),
        )
        if not ok:
            logger.warning(f"Push rejected ({reason}) for {msg_hash}")
            rejected.append(msg_hash)
            continue

        # Validate message type
        from hokora.constants import VALID_MESSAGE_TYPES

        msg_type = msg_data.get("type", 1)
        if msg_type not in VALID_MESSAGE_TYPES:
            logger.warning(f"Push rejected: invalid message type {msg_type} for {msg_hash}")
            rejected.append(msg_hash)
            continue

        # Validate basics
        body = msg_data.get("body", "")
        body_bytes = body.encode("utf-8") if isinstance(body, str) else (body or b"")
        from hokora.constants import MAX_MESSAGE_BODY_SIZE

        if len(body_bytes) > MAX_MESSAGE_BODY_SIZE:
            rejected.append(msg_hash)
            continue

        # Sealed-channel invariant: store only ciphertext, never re-encrypt
        # at the hop, never accept plaintext. A push for a sealed channel
        # that does not carry ``encrypted_body`` is structurally invalid and
        # is rejected before sequence assignment to avoid seq gaps.
        enc_body = msg_data.get("encrypted_body")
        enc_nonce = msg_data.get("encryption_nonce")
        enc_epoch = msg_data.get("encryption_epoch")
        if push_channel_is_sealed:
            if body or not enc_body:
                logger.warning(
                    "Push rejected: sealed channel requires ciphertext "
                    f"(msg={msg_hash[:16]} body_len={len(body) if body else 0} "
                    f"enc_len={len(enc_body) if enc_body else 0})"
                )
                rejected.append(msg_hash)
                continue
            body_for_insert: Optional[str] = None
        else:
            body_for_insert = body
            enc_body = None
            enc_nonce = None
            enc_epoch = None

        # Ingest
        seq = await ctx.sequencer.next_seq(session, push_channel_id)
        from hokora.db.models import Message as MessageModel

        message = MessageModel(
            msg_hash=msg_hash,
            channel_id=push_channel_id,
            sender_hash=msg_data.get("sender_hash"),
            seq=seq,
            timestamp=msg_data.get("timestamp", 0),
            type=msg_type,
            body=body_for_insert,
            encrypted_body=enc_body,
            encryption_nonce=enc_nonce,
            encryption_epoch=enc_epoch,
            display_name=(msg_data.get("display_name") or "")[:64] or None,
            # Always use the authenticated pusher identity — never trust the
            # payload's origin_node, which could be spoofed to suppress
            # onward federation to a targeted peer.
            origin_node=node_identity,
        )
        session.add(message)
        received.append(seq)

        # Push to live subscribers
        if ctx.live_manager:
            ctx.live_manager.push_message(
                push_channel_id,
                message,
                sender_public_key=msg_data.get("sender_public_key"),
            )

    return {
        "action": "push_ack",
        "channel_id": push_channel_id,
        "received": received,
        "rejected": rejected,
    }
