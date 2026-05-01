# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Channel key rotation announce protocol (dual-signed)."""

import logging
import time
from typing import Optional

import msgpack
import RNS

logger = logging.getLogger(__name__)

# Grace period for old destination (seconds)
KEY_ROTATION_GRACE_PERIOD = 48 * 3600  # 48 hours


class KeyRotationManager:
    """Manages channel identity key rotation with dual-signed announces."""

    def __init__(self):
        self._pending_rotations: dict[str, dict] = {}

    def initiate_rotation(
        self,
        channel_id: str,
        old_identity: RNS.Identity,
        new_identity: RNS.Identity,
        old_destination: RNS.Destination,
    ) -> bytes:
        """Create a dual-signed key rotation announce.

        Both old and new keys sign the rotation payload to prove
        the operator controls both identities.
        """
        payload = {
            "type": "key_rotation",
            "channel_id": channel_id,
            "old_hash": old_identity.hexhash,
            "new_hash": new_identity.hexhash,
            "timestamp": time.time(),
            "grace_period": KEY_ROTATION_GRACE_PERIOD,
        }
        payload_bytes = msgpack.packb(payload, use_bin_type=True)

        # Sign with both keys
        old_sig = old_identity.sign(payload_bytes)
        new_sig = new_identity.sign(payload_bytes)

        announce_data = msgpack.packb(
            {
                "payload": payload_bytes,
                "old_signature": old_sig,
                "new_signature": new_sig,
            },
            use_bin_type=True,
        )

        # Cleanup expired entries before adding new one
        expired = [k for k, v in self._pending_rotations.items() if time.time() >= v["grace_end"]]
        for k in expired:
            del self._pending_rotations[k]

        self._pending_rotations[channel_id] = {
            "old_identity": old_identity,
            "new_identity": new_identity,
            "timestamp": time.time(),
            "grace_end": time.time() + KEY_ROTATION_GRACE_PERIOD,
        }

        # Announce via old destination
        old_destination.announce(app_data=announce_data)
        logger.info(f"Initiated key rotation for channel {channel_id}")

        return announce_data

    @staticmethod
    def verify_rotation(announce_data: bytes) -> Optional[dict]:
        """Verify a key rotation announce (both signatures must be valid)."""
        try:
            data = msgpack.unpackb(announce_data, raw=False)
            payload_bytes = data["payload"]
            old_sig = data["old_signature"]
            new_sig = data["new_signature"]

            payload = msgpack.unpackb(payload_bytes, raw=False)

            old_hash = payload["old_hash"]
            new_hash = payload["new_hash"]

            # Recall identities
            old_identity = RNS.Identity.recall(bytes.fromhex(old_hash))
            new_identity = RNS.Identity.recall(bytes.fromhex(new_hash))

            if not old_identity or not new_identity:
                logger.warning("Cannot recall identities for rotation verification")
                return None

            # Verify both signatures
            if not old_identity.validate(old_sig, payload_bytes):
                logger.warning("Old identity signature invalid in rotation")
                return None
            if not new_identity.validate(new_sig, payload_bytes):
                logger.warning("New identity signature invalid in rotation")
                return None

            return payload

        except Exception:
            logger.exception("Failed to verify key rotation")
            return None

    def is_in_grace_period(self, channel_id: str) -> bool:
        rotation = self._pending_rotations.get(channel_id)
        if not rotation:
            return False
        if time.time() >= rotation["grace_end"]:
            del self._pending_rotations[channel_id]
            return False
        return True
