# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Channel management: CRUD, destination registration, announces."""

import asyncio
import binascii
import logging
import time
import uuid
from typing import Optional

import msgpack

from hokora.config import NodeConfig
from hokora.constants import ACCESS_PUBLIC
from hokora.core.identity import IdentityManager
from hokora.db.models import Channel
from hokora.db.queries import ChannelRepo

from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class ChannelManager:
    """Manages channel lifecycle, destinations, and announces."""

    def __init__(
        self,
        config: NodeConfig,
        identity_manager: IdentityManager,
    ):
        self.config = config
        self.identity_manager = identity_manager
        self._channels: dict[str, Channel] = {}
        self._lxmf_bridge = None  # Set by daemon after LXMF bridge is created

    async def create_channel(
        self,
        session: AsyncSession,
        name: str,
        description: str = "",
        access_mode: str = ACCESS_PUBLIC,
        category_id: Optional[str] = None,
        link_established_callback=None,
    ) -> Channel:
        """Create a new channel with its own RNS identity and destination."""
        channel_id = uuid.uuid4().hex[:16]

        # Register RNS destination
        self.identity_manager.register_channel_destination(channel_id, link_established_callback)
        identity = self.identity_manager.get_identity(channel_id)
        dest = self.identity_manager.get_destination(channel_id)
        dest_hash_hex = binascii.hexlify(dest.hash).decode() if dest else None

        channel = Channel(
            id=channel_id,
            name=name,
            description=description,
            access_mode=access_mode,
            category_id=category_id,
            identity_hash=identity.hexhash,
            destination_hash=dest_hash_hex,
            created_at=time.time(),
        )

        repo = ChannelRepo(session)
        await repo.create(channel)
        self._channels[channel_id] = channel

        logger.info(f"Created channel '{name}' ({channel_id})")
        return channel

    async def load_channels(
        self,
        session: AsyncSession,
        link_established_callback=None,
    ):
        """Load existing channels from DB and register destinations."""
        repo = ChannelRepo(session)
        channels = await repo.list_all()
        for ch in channels:
            self.identity_manager.register_channel_destination(ch.id, link_established_callback)
            self._channels[ch.id] = ch
            logger.info(f"Loaded channel '{ch.name}' ({ch.id})")

    async def announce_channels(self):
        """Announce all channels — both hokora and LXMF delivery destinations.

        All channels are announced for routing (including private/sealed).
        Visibility is controlled by node_meta (show_private_channels config).
        Access is enforced at the handler level (check_channel_read, _check_permissions).

        Announces are staggered by ``config.announce_stagger_ms`` (default
        50 ms) between each emission to bypass an RNS 1.1.9 regression: the
        per-interface announce-cap queue interacts with the new
        ``destinations_last_cleaned`` cleanup loop and silently evicts
        queue-tail entries' destination state. Staggering keeps every
        emission below the cap so RNS never queues, sidestepping the bug.
        Set ``announce_stagger_ms = 0`` to disable.
        """
        # Node identity hexhash lets clients disambiguate same-named channels
        # across different nodes in the Channels view (federation case).
        node_identity_hash = None
        try:
            node_identity_hash = self.identity_manager.get_or_create_node_identity().hexhash
        except Exception:
            # Non-fatal — channel announces still work without the hash; clients
            # just can't disambiguate same-named channels across nodes.
            logger.debug("node identity hash unavailable for announce", exc_info=True)

        stagger_s = self.config.announce_stagger_ms / 1000.0
        first = True

        for channel_id, channel in self._channels.items():
            # Announce hokora destination (for sync protocol)
            dest = self.identity_manager.get_destination(channel_id)
            if dest:
                if not first and stagger_s > 0:
                    await asyncio.sleep(stagger_s)
                first = False
                dest_hash_hex = binascii.hexlify(dest.hash).decode()
                app_data = msgpack.packb(
                    {
                        "type": "channel",
                        "name": channel.name,
                        "description": channel.description or "",
                        "node": self.config.node_name,
                        "node_identity_hash": node_identity_hash,
                        "channel_id": channel_id,
                        "destination_hash": dest_hash_hex,
                        "time": time.time(),
                        # Optional role hint — TUI surfaces it in the
                        # Discovery info panel as "Community Node ·
                        # Propagation Node". Older TUIs ignore the field.
                        "propagation_enabled": bool(self.config.propagation_enabled),
                    }
                )
                dest.announce(app_data=app_data)
                logger.info(f"Announced channel '{channel.name}'")

            # Announce LXMF delivery destination (for message delivery)
            if self._lxmf_bridge is not None:
                try:
                    router = self._lxmf_bridge.get_router(channel_id)
                    if router and hasattr(router, "delivery_destinations"):
                        for lxmf_dest in router.delivery_destinations.values():
                            if not first and stagger_s > 0:
                                await asyncio.sleep(stagger_s)
                            first = False
                            lxmf_dest.announce()
                        logger.info(f"Announced LXMF delivery for channel '{channel.name}'")
                except Exception as e:
                    logger.debug(f"Could not announce LXMF delivery for {channel_id}: {e}")

    def update_destination_hash(self, channel_id: str, dest_hash_hex: str) -> None:
        """Update the destination_hash on the in-memory Channel object."""
        channel = self._channels.get(channel_id)
        if channel:
            channel.destination_hash = dest_hash_hex

    def get_channel(self, channel_id: str) -> Optional[Channel]:
        return self._channels.get(channel_id)

    def list_channels(self) -> list[Channel]:
        return list(self._channels.values())

    def get_channel_id_by_destination(self, destination_hash: bytes) -> Optional[str]:
        """Find channel ID by its destination hash."""
        for ch_id in self._channels:
            dest = self.identity_manager.get_destination(ch_id)
            if dest and dest.hash == destination_hash:
                return ch_id
        return None
