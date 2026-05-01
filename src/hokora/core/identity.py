# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Identity management: RNS identity lifecycle per channel."""

import logging
from pathlib import Path
from typing import Optional

import RNS

from hokora.constants import DESTINATION_ASPECT
from hokora.security.fs import secure_identity_dir, write_identity_secure

logger = logging.getLogger(__name__)


class IdentityManager:
    """Manages RNS identities for the node and per-channel destinations."""

    def __init__(self, identity_dir: Path, reticulum: RNS.Reticulum):
        self.identity_dir = identity_dir
        self.reticulum = reticulum
        secure_identity_dir(self.identity_dir)
        self._identities: dict[str, RNS.Identity] = {}
        self._destinations: dict[str, RNS.Destination] = {}
        self._node_identity: Optional[RNS.Identity] = None

    def get_or_create_node_identity(self) -> RNS.Identity:
        """Load or create the node-level identity."""
        if self._node_identity:
            return self._node_identity

        node_id_path = self.identity_dir / "node_identity"
        if node_id_path.exists():
            self._node_identity = RNS.Identity.from_file(str(node_id_path))
            logger.info(f"Loaded node identity: {self._node_identity.hexhash}")
        else:
            self._node_identity = RNS.Identity()
            write_identity_secure(self._node_identity, node_id_path)
            logger.info(f"Created node identity: {self._node_identity.hexhash}")

        return self._node_identity

    def get_or_create_channel_identity(self, channel_id: str) -> RNS.Identity:
        """Load or create an identity for a specific channel."""
        if channel_id in self._identities:
            return self._identities[channel_id]

        id_path = self.identity_dir / f"channel_{channel_id}"
        if id_path.exists():
            identity = RNS.Identity.from_file(str(id_path))
            logger.info(f"Loaded channel identity for {channel_id}: {identity.hexhash}")
        else:
            identity = RNS.Identity()
            write_identity_secure(identity, id_path)
            logger.info(f"Created channel identity for {channel_id}: {identity.hexhash}")

        self._identities[channel_id] = identity
        return identity

    def register_channel_destination(
        self,
        channel_id: str,
        link_established_callback=None,
    ) -> RNS.Destination:
        """Create and register an RNS Destination for a channel."""
        identity = self.get_or_create_channel_identity(channel_id)

        destination = RNS.Destination(
            identity,
            RNS.Destination.IN,
            RNS.Destination.SINGLE,
            DESTINATION_ASPECT,
            channel_id,
        )

        if link_established_callback:
            destination.set_link_established_callback(link_established_callback)

        self._destinations[channel_id] = destination
        logger.info(
            f"Registered destination for channel {channel_id}: {RNS.prettyhexrep(destination.hash)}"
        )
        return destination

    def get_destination(self, channel_id: str) -> Optional[RNS.Destination]:
        return self._destinations.get(channel_id)

    def get_identity(self, channel_id: str) -> Optional[RNS.Identity]:
        return self._identities.get(channel_id)

    def get_node_identity(self) -> Optional[RNS.Identity]:
        """Return the node identity if loaded."""
        return self._node_identity

    def get_node_identity_hash(self) -> str:
        identity = self.get_or_create_node_identity()
        return identity.hexhash

    def get_signing_public_key(self) -> bytes:
        """Return this node's 32-byte Ed25519 signing public key.

        Wraps :func:`hokora.federation.auth.signing_public_key` against
        the node identity. Use this everywhere a peer_public_key field goes
        onto the federation wire, never RNS.Identity.get_public_key() (which
        returns a 64-byte X25519+Ed25519 concatenation).
        """
        from hokora.federation.auth import signing_public_key

        return signing_public_key(self.get_or_create_node_identity())

    def list_channel_ids(self) -> list[str]:
        return list(self._identities.keys())
