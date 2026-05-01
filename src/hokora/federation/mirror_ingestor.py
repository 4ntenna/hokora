# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""MirrorMessageIngestor: validate + ingest federation-pushed messages.

No channel-rotation grace window applies here. Channel RNS identity is
not a signing key for per-message federation
pushes: ``handle_push_messages`` authenticates the pushing NODE via its
entry in the ``Peer`` table (populated by the Ed25519 handshake in
``FederationAuth``), and per-message signature verification below uses
the LXMF sender's Ed25519 key from ``sender_public_key``. Neither
surface involves the channel's RNS identity, so rotating a channel
doesn't create a signature-acceptance gap on the ingest path. The
rotation grace window lives at the announce-reception layer — see
``hokora.federation.channel_rotation_auth`` and
``hokora.federation.peering.PeerDiscovery._log_identity_mismatch``.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Optional

from hokora.constants import CLOCK_DRIFT_TOLERANCE, MAX_MESSAGE_BODY_SIZE
from hokora.db.models import Message as MessageModel
from hokora.db.queries import ChannelRepo, MessageRepo
from hokora.exceptions import SealedChannelError
from hokora.federation.auth import verify_sender_binding
from hokora.security.sealed_invariant import validate_mirror_payload

if TYPE_CHECKING:
    from hokora.core.sequencer import SequenceManager
    from hokora.protocol.live import LiveSubscriptionManager

logger = logging.getLogger(__name__)

# Federation mirror timestamps are accepted within CLOCK_DRIFT_TOLERANCE into
# the future and up to 30 days into the past (matches the existing daemon
# policy — tighter than messaging-layer retention).
_MIRROR_MAX_AGE_SECONDS = 30 * 86400


class MirrorMessageIngestor:
    """Validate + ingest a message pushed by a federation peer.

    Enforces body-size, sender-hash length, timestamp window, and Ed25519
    signature (when ``require_signed_federation`` is True). Dedupes by
    ``msg_hash``, assigns a local ``seq`` via the sequencer, pushes to
    live subscribers.
    """

    def __init__(
        self,
        session_factory,
        sequencer: "SequenceManager",
        live_manager: Optional["LiveSubscriptionManager"],
        require_signed_federation: bool,
    ) -> None:
        self._session_factory = session_factory
        self._sequencer = sequencer
        self._live_manager = live_manager
        self._require_signed = require_signed_federation

    async def ingest(
        self,
        channel_id: str,
        msg_data: dict,
        peer_hash: str = "",
    ) -> None:
        """Validate and store ``msg_data`` pushed by peer ``peer_hash``.

        ``peer_hash`` is authoritative for ``origin_node`` — we never trust
        the payload's origin_node field (prevents spoofed loop-prevention
        suppression).
        """
        try:
            body = msg_data.get("body", "")
            body_bytes = body.encode("utf-8") if isinstance(body, str) else (body or b"")
            if len(body_bytes) > MAX_MESSAGE_BODY_SIZE:
                logger.warning(f"Mirror ingest rejected: body too large ({len(body_bytes)} bytes)")
                return

            sender_hash = msg_data.get("sender_hash")
            if not sender_hash or len(str(sender_hash)) < 16:
                logger.warning("Mirror ingest rejected: missing or short sender_hash")
                return

            timestamp = msg_data.get("timestamp", 0)
            now = time.time()
            if timestamp > now + CLOCK_DRIFT_TOLERANCE or timestamp < now - _MIRROR_MAX_AGE_SECONDS:
                logger.warning(f"Mirror ingest rejected: timestamp {timestamp} out of range")
                return

            ok, reason = verify_sender_binding(
                sender_hash=sender_hash,
                sender_rns_public_key=msg_data.get("sender_rns_public_key"),
                lxmf_signed_part=msg_data.get("lxmf_signed_part"),
                lxmf_signature=msg_data.get("lxmf_signature"),
                require_signed=self._require_signed,
            )
            if not ok:
                logger.warning(f"Mirror rejected ({reason}) for {msg_data.get('msg_hash')}")
                return

            async with self._session_factory() as session:
                async with session.begin():
                    repo = MessageRepo(session)
                    existing = await repo.get_by_hash(msg_data.get("msg_hash", ""))
                    if existing:
                        return

                    # Mirror-side sealed chokepoint — reject plaintext-on-sealed
                    # before assigning a sequence (avoids seq gaps on drop).
                    channel = await ChannelRepo(session).get_by_id(channel_id)
                    try:
                        body_for_insert, enc_body, enc_nonce, enc_epoch = validate_mirror_payload(
                            channel,
                            body,
                            msg_data.get("encrypted_body"),
                            msg_data.get("encryption_nonce"),
                            msg_data.get("encryption_epoch"),
                        )
                    except SealedChannelError as exc:
                        logger.warning(
                            "Mirror rejected: %s (msg=%s)",
                            exc,
                            msg_data.get("msg_hash", "")[:16],
                        )
                        return

                    seq = await self._sequencer.next_seq(session, channel_id)
                    message = MessageModel(
                        msg_hash=msg_data.get("msg_hash", ""),
                        channel_id=channel_id,
                        sender_hash=sender_hash,
                        seq=seq,
                        timestamp=timestamp,
                        type=msg_data.get("type", 1),
                        body=body_for_insert,
                        encrypted_body=enc_body,
                        encryption_nonce=enc_nonce,
                        encryption_epoch=enc_epoch,
                        display_name=(msg_data.get("display_name") or "")[:64] or None,
                        # Authoritative peer_hash wins; payload origin_node is
                        # ignored on mirror ingest to block spoofed suppression.
                        origin_node=peer_hash or msg_data.get("origin_node"),
                    )
                    session.add(message)

                    if self._live_manager:
                        self._live_manager.push_message(
                            channel_id,
                            message,
                            sender_public_key=msg_data.get("sender_public_key"),
                        )
        except Exception:
            logger.exception("Mirror ingest error")
