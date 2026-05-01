# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Channel and profile announce logic."""

import logging
import time
from typing import Optional

import msgpack

from hokora.constants import MAX_AVATAR_BYTES
from hokora.core.identity import IdentityManager

logger = logging.getLogger(__name__)


class AnnounceHandler:
    """Handles channel and profile announce creation and processing."""

    def __init__(self, identity_manager: IdentityManager):
        self.identity_manager = identity_manager

    def announce_channel(
        self,
        channel_id: str,
        channel_name: str,
        description: str = "",
        node_name: str = "",
    ):
        """Announce a channel's existence on the network."""
        dest = self.identity_manager.get_destination(channel_id)
        if not dest:
            logger.warning(f"No destination for channel {channel_id}")
            return

        app_data = msgpack.packb(
            {
                "type": "channel",
                "name": channel_name,
                "description": description,
                "node": node_name,
                "time": time.time(),
            }
        )

        dest.announce(app_data=app_data)
        logger.info(f"Announced channel '{channel_name}' ({channel_id})")

    @staticmethod
    def parse_announce(app_data: bytes) -> Optional[dict]:
        """Parse any Hokora announce and return a tagged payload.

        Dispatches by the ``type`` field to avoid every caller duplicating
        the msgpack-unpack + type-guard boilerplate. Supported types:

        * ``channel`` — channel presence (returned verbatim).
        * ``profile`` — profile announce (returned verbatim).
        * ``key_rotation`` — channel RNS identity rotation. The outer msgpack
          envelope is a dual-signed wrapper (old + new identity signatures);
          this method only recognises the type, routing callers to
          :func:`parse_key_rotation_announce` for signature verification.

        Returns ``None`` for an unknown type or malformed payload.
        """
        try:
            data = msgpack.unpackb(app_data, raw=False)
        except (msgpack.UnpackException, ValueError, TypeError) as e:
            logger.debug("Announce unpack failed: %s", e)
            return None

        if not isinstance(data, dict):
            return None

        announce_type = data.get("type")
        if announce_type in ("channel", "profile"):
            return data

        # key_rotation envelopes: outer dict is {payload, old_signature,
        # new_signature}. The inner payload carries type=key_rotation. We
        # normalise both encodings: if the outer is the rotation envelope,
        # peek into payload so parse_announce callers see type consistently.
        if announce_type is None and "payload" in data:
            try:
                inner = msgpack.unpackb(data["payload"], raw=False)
                if isinstance(inner, dict) and inner.get("type") == "key_rotation":
                    return {"type": "key_rotation", "envelope": data, "payload": inner}
            except (msgpack.UnpackException, ValueError, TypeError):
                return None

        return None

    @staticmethod
    def parse_channel_announce(app_data: bytes) -> Optional[dict]:
        """Parse channel announce app_data. Retained for backward compat;
        new call sites should prefer :func:`parse_announce`."""
        try:
            data = msgpack.unpackb(app_data, raw=False)
            if data.get("type") == "channel":
                return data
        except (msgpack.UnpackException, ValueError, TypeError, KeyError) as e:
            logger.debug("Failed to parse channel announce: %s", e)
        return None

    @staticmethod
    def parse_key_rotation_announce(app_data: bytes) -> Optional[dict]:
        """Verify a dual-signed channel key rotation announce.

        Thin wrapper around
        :meth:`hokora.federation.key_rotation.KeyRotationManager.verify_rotation`.
        Returns the inner payload ``{channel_id, old_hash, new_hash,
        timestamp, grace_period}`` on successful verification of both
        signatures, ``None`` otherwise.

        Delegating here avoids callers needing to import the federation
        layer directly and keeps the announce-parsing surface in one module.
        """
        from hokora.federation.key_rotation import KeyRotationManager

        return KeyRotationManager.verify_rotation(app_data)

    @staticmethod
    def build_profile_announce(
        display_name: str,
        status_text: str = "",
        bio: str = "",
        avatar: Optional[bytes] = None,
    ) -> bytes:
        """Build profile announce payload."""
        payload = {
            "type": "profile",
            "display_name": display_name,
            "status_text": status_text,
            "bio": bio,
            "time": time.time(),
        }
        if avatar and len(avatar) <= MAX_AVATAR_BYTES:
            payload["avatar"] = avatar
        return msgpack.packb(payload)
