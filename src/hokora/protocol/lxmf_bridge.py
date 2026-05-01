# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""LXMF reception -> signature verify -> MessageProcessor pipeline.

Creates one LXMRouter per channel so every channel receives direct
LXMF store-and-forward delivery (the LXMF library limits each router
to a single delivery identity).
"""

import logging
import os
import time
from typing import Any, Optional, Callable

import msgpack
import LXMF
import RNS

from hokora.core.message import MessageEnvelope
from hokora.constants import MSG_TEXT
from hokora.exceptions import VerificationError

logger = logging.getLogger(__name__)


class LXMFBridge:
    """Bridges LXMF message reception to the message processing pipeline.

    Manages one LXMRouter instance per channel to work around the LXMF
    limitation of a single delivery identity per router.
    """

    def __init__(
        self,
        base_storagepath: str,
        ingest_callback: Optional[Callable] = None,
        node_lxm_router: Optional[LXMF.LXMRouter] = None,
    ):
        self._base_storagepath = base_storagepath
        self.ingest_callback = ingest_callback
        self._node_lxm_router = node_lxm_router
        self._routers: dict[str, LXMF.LXMRouter] = {}
        self._registered_destinations: dict[str, Any] = {}

    def register_channel(
        self, channel_id: str, identity: RNS.Identity, destination: RNS.Destination
    ):
        """Register a channel for LXMF delivery with its own LXMRouter."""
        if channel_id in self._routers:
            logger.debug(f"Channel {channel_id} already registered with LXMF")
            return

        # Each channel gets its own LXMRouter and storage directory
        channel_storage = os.path.join(self._base_storagepath, channel_id)
        os.makedirs(channel_storage, exist_ok=True)

        router = LXMF.LXMRouter(identity=identity, storagepath=channel_storage)
        router.register_delivery_identity(identity, display_name=channel_id)
        router.register_delivery_callback(self._on_lxmf_delivery)

        self._routers[channel_id] = router
        self._registered_destinations[channel_id] = {
            "identity": identity,
            "destination": destination,
        }

        logger.info(f"Registered LXMF delivery for channel {channel_id}")

    def get_router(self, channel_id: str) -> Optional[LXMF.LXMRouter]:
        """Get the LXMRouter for a specific channel (for outbound LXMF)."""
        return self._routers.get(channel_id)

    def get_any_router(self) -> Optional[LXMF.LXMRouter]:
        """Get any available router for node-level LXMF operations.

        Prefers the node-level router if available, otherwise returns the
        first channel router. Used for non-channel-specific outbound like
        key exchange.
        """
        if self._node_lxm_router:
            return self._node_lxm_router
        if self._routers:
            return next(iter(self._routers.values()))
        return None

    def _on_lxmf_delivery(self, message: LXMF.LXMessage):
        """Handle incoming LXMF message."""
        try:
            # 1. Verify Ed25519 signature
            if message.signature_validated:
                logger.debug(f"LXMF signature valid from {message.source_hash}")
            elif (
                hasattr(message, "unverified_reason")
                and message.unverified_reason == LXMF.LXMessage.SOURCE_UNKNOWN
            ):
                # Source identity unknown — common for first contact from remote TUIs.
                # The message still has a valid signature, but we can't verify it
                # until we learn the sender's identity. Accept with warning.
                logger.info(
                    f"LXMF source unknown for {message.source_hash}, "
                    "accepting message (first contact)"
                )
            else:
                logger.warning(f"LXMF signature INVALID from {message.source_hash}, rejecting")
                raise VerificationError("LXMF signature verification failed")

            # 2. Extract sender public key for client-side verification.
            #
            # Must be the 32-byte Ed25519 signing key, NOT the 64-byte RNS
            # get_public_key() blob (which concatenates X25519 + Ed25519).
            # Storing the 64-byte blob historically broke every downstream
            # verify_ed25519_signature() call because Ed25519PublicKey
            # only accepts 32-byte inputs.
            sender_public_key = None
            if message.source and hasattr(message.source, "identity") and message.source.identity:
                ident = message.source.identity
                # RNS >=0.9 exposes sig_pub_bytes directly. Fallback to
                # slicing get_public_key()[32:] for older RNS builds.
                sender_public_key = getattr(ident, "sig_pub_bytes", None)
                if sender_public_key is None:
                    full = ident.get_public_key()
                    sender_public_key = full[32:] if full and len(full) == 64 else None
                    logger.warning(
                        "RNS Identity lacks sig_pub_bytes; derived Ed25519 key via fallback slice"
                    )

            # 3. Reconstruct LXMF signed part for client-side re-verification.
            #
            # Mirror LXMessage.unpack_from_bytes:733-752 exactly. Naively
            # re-packing ``message.payload`` via ``msgpack.packb``
            # produces different bytes than what was originally signed
            # when a stamp was appended to the payload after signing
            # (LXMessage.pack line 378 does exactly that) — every
            # re-verify downstream then fails with ``InvalidSignature``.
            #
            # Correct recipe (identical to LXMF's own inbound validator):
            #   1. Slice packed_payload out of message.packed at offset 96
            #      (DESTINATION_LENGTH + DESTINATION_LENGTH + SIGNATURE_LENGTH).
            #   2. Unpack; if >4 elements, strip the stamp at index 4 and
            #      msgpack.packb() the 4-element payload back (this is what
            #      the sender signed, before appending the stamp).
            #   3. hashed_part = dest_hash + source_hash + packed_payload.
            #   4. signed_part = hashed_part + full_hash(hashed_part).
            lxmf_signed_part = None
            if (
                hasattr(message, "hash")
                and message.hash
                and hasattr(message, "packed")
                and message.packed
                and len(message.packed) >= 96
            ):
                packed_payload = message.packed[96:]
                try:
                    unpacked = msgpack.unpackb(packed_payload)
                    # Strip stamp if present — LXMF appends it AFTER signing.
                    if isinstance(unpacked, list) and len(unpacked) > 4:
                        packed_payload = msgpack.packb(unpacked[:4])
                except Exception:
                    # Reconstruction failed — client-side re-verification
                    # will be unavailable for this message (lxmf_signed_part
                    # stays None). The daemon has already validated the
                    # signature via LXMF's own signature_validated flag at
                    # the top of this handler, so this is a defense-in-depth
                    # loss rather than a transport-layer authentication gap.
                    # Surface as a warning so recipients notice, because a
                    # run of these usually means LXMF payload schema drift.
                    logger.warning(
                        "lxmf_signed_part payload unpack failed; "
                        "client re-verify will be unavailable for this message",
                        exc_info=True,
                    )
                    packed_payload = None

                if packed_payload is not None:
                    dest_hash = (
                        message.destination_hash
                        if isinstance(message.destination_hash, bytes)
                        else b""
                    )
                    src_hash = (
                        message.source_hash if isinstance(message.source_hash, bytes) else b""
                    )
                    hashed_part = dest_hash + src_hash + packed_payload
                    # Sanity: reconstructed hash must match message.hash.
                    # If it drifts, LXMF's payload schema has changed and
                    # our reconstruction needs revisiting.
                    try:
                        recomputed = RNS.Identity.full_hash(hashed_part)
                        if recomputed != message.hash:
                            logger.warning(
                                "Reconstructed lxmf hashed_part does not match "
                                "message.hash — LXMF payload schema may have "
                                "drifted; sig verification will fail"
                            )
                    except Exception:
                        logger.debug("hashed_part recompute check failed", exc_info=True)
                    lxmf_signed_part = hashed_part + message.hash

            # 4. Determine target channel from destination
            channel_id = self._find_channel_for_destination(message.destination_hash)

            # 5. Decode content (needed for fallback channel lookup and envelope)
            content = self._decode_content(message)

            # Fallback: if destination hash didn't match (e.g., LXMF "delivery"
            # aspect hash differs from "hokora" aspect hash), extract
            # channel_id from the message content payload.
            if not channel_id:
                content_channel = content.get("channel_id")
                if content_channel and content_channel in self._routers:
                    channel_id = content_channel
                    logger.info(f"Matched channel from content: {channel_id}")
                else:
                    logger.warning(f"No channel for destination {message.destination_hash}")
                    return

            # 6. Construct MessageEnvelope — use identity hash (not LXMF dest hash)
            # for role/permission lookups. The source_hash is the LXMF destination
            # hash which differs from the identity hash used in role assignments.
            if message.source and hasattr(message.source, "identity") and message.source.identity:
                sender_hash = message.source.identity.hexhash
            else:
                sender_hash = RNS.hexrep(message.source_hash, delimit=False)

            envelope = MessageEnvelope(
                channel_id=channel_id,
                sender_hash=sender_hash,
                timestamp=message.timestamp if hasattr(message, "timestamp") else time.time(),
                type=content.get("type", MSG_TEXT),
                body=content.get("body"),
                media_path=content.get("media_path"),
                media_bytes=content.get("media_bytes"),
                reply_to=content.get("reply_to"),
                ttl=content.get("ttl"),
                lxmf_signature=message.signature if hasattr(message, "signature") else None,
                lxmf_signed_part=lxmf_signed_part,
                sender_public_key=sender_public_key,
                display_name=content.get("display_name"),
                mentions=content.get("mentions", []),
            )

            # 7. Call ingest callback
            if self.ingest_callback:
                self.ingest_callback(envelope)

        except VerificationError:
            raise
        except Exception:
            logger.exception("Error processing LXMF message")

    def _find_channel_for_destination(self, dest_hash) -> Optional[str]:
        """Find which channel a destination hash belongs to."""
        for channel_id, info in self._registered_destinations.items():
            dest = info["destination"]
            if dest.hash == dest_hash:
                return channel_id
        return None

    def _decode_content(self, message: LXMF.LXMessage) -> dict:
        """Decode LXMF message content."""
        content_bytes = message.content
        if not content_bytes:
            return {"body": "", "type": MSG_TEXT}

        try:
            # Try msgpack first
            return msgpack.unpackb(content_bytes, raw=False)
        except Exception:
            # Fall back to treating as plain text
            try:
                text = content_bytes.decode("utf-8")
                return {"body": text, "type": MSG_TEXT}
            except UnicodeDecodeError:
                return {"body": "", "type": MSG_TEXT}
