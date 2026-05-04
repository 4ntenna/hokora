# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""ChannelLinkManager — owns RNS.Link lifecycle per channel.

Transport-agnostic: same code path for TCP, I2P, Tor, LoRa. All channels
for this client multiplex through one RNS.Link (RNS limits remote clients
to one active link per node); additional channels use register_channel()
to attach to the existing link.

Thread model: RNS fires link_established / link_closed / packet /
resource callbacks on RNS threads. Callbacks registered via the set_on_*
methods fire on those threads — handlers MUST hop to the urwid loop via
loop.set_alarm_in() before touching widgets.
"""

from __future__ import annotations

import logging
from typing import Callable, Optional

import RNS

from hokora_tui.sync.state import SyncState

logger = logging.getLogger(__name__)

# Per-hop Link establishment timeout floor (seconds). RNS's default is 6s,
# computed as bitrate-limited transmission time — accurate for TCP and LoRa
# but wrong for I2P/Tor where tunnel-setup RTT dominates and is independent
# of declared bitrate. We take max(RNS baseline, hops × this floor) so fast
# transports are unaffected while high-latency transports get breathing room.
LINK_ESTABLISHMENT_TIMEOUT_PER_HOP = 30


class ChannelLinkManager:
    """Owns RNS.Link lifecycle per channel."""

    def __init__(
        self,
        reticulum: RNS.Reticulum,
        identity: Optional[RNS.Identity],
        state: SyncState,
    ) -> None:
        self.reticulum = reticulum
        self.identity = identity
        self._state = state
        # channel_id -> RNS.Link
        self._links: dict[str, RNS.Link] = {}
        # Callback hooks — all fire on RNS threads
        self._on_established: Optional[Callable[[str, RNS.Link], None]] = None
        self._on_closed: Optional[Callable[[str, RNS.Link], None]] = None
        self._on_packet: Optional[Callable[[bytes, Optional[RNS.Packet]], None]] = None
        self._on_resource_concluded: Optional[Callable[[RNS.Resource], None]] = None

    # ── Public API ────────────────────────────────────────────────────

    def connect_channel(self, destination_hash: bytes, channel_id: str) -> None:
        """Establish a link to a channel's destination.

        Identity resolution priority:
          1. Already-cached identity in state.channel_identities[channel_id]
             (from node_meta or a previous pubkey-seeded invite).
          2. RNS.Identity.recall() — populated by announces.
          3. Pending pubkey in state.pending_pubkeys[dest_hex] — supplied by
             a 4-field invite token and consumed exactly once.
        """
        self._state.channel_dest_hashes[channel_id] = destination_hash
        dest_identity = self._state.channel_identities.get(channel_id)
        if not dest_identity:
            dest_identity = RNS.Identity.recall(destination_hash)
        if not dest_identity:
            dest_hex = destination_hash.hex()
            pk = self._state.pending_pubkeys.pop(dest_hex, None)
            if pk:
                try:
                    dest_identity = RNS.Identity(create_keys=False)
                    dest_identity.load_public_key(pk)
                    self._state.channel_identities[channel_id] = dest_identity
                    logger.info(
                        "Loaded identity from invite pubkey for %s",
                        RNS.prettyhexrep(destination_hash),
                    )
                except Exception as exc:
                    logger.warning("Failed to load invite pubkey: %s", exc)
                    dest_identity = None
        if not dest_identity:
            logger.info("Requesting path to %s", RNS.prettyhexrep(destination_hash))
            RNS.Transport.request_path(destination_hash)
            self._state.pending_connects[channel_id] = destination_hash
            return

        # Ensure path is in routing table (paths are not persisted across restarts).
        # Only defer for standalone RNS instances — shared instance clients don't
        # have paths in their table but links work through the daemon's socket.
        if not RNS.Transport.has_path(destination_hash):
            RNS.Transport.request_path(destination_hash)
            if not self.reticulum.is_connected_to_shared_instance:
                self._state.pending_connects[channel_id] = destination_hash
                return

        destination = RNS.Destination(
            dest_identity,
            RNS.Destination.OUT,
            RNS.Destination.SINGLE,
            "hokora",
            channel_id,
        )

        link = RNS.Link(destination)
        # Extend establishment timeout for high-latency transports (I2P, Tor,
        # LoRa multi-hop). RNS's default 6s/hop is bitrate-derived and misses
        # I2P tunnel-setup RTT.
        try:
            hops = max(1, RNS.Transport.hops_to(destination_hash))
            link.establishment_timeout = max(
                getattr(link, "establishment_timeout", 0) or 0,
                LINK_ESTABLISHMENT_TIMEOUT_PER_HOP * hops,
            )
        except Exception:
            logger.debug("Could not extend Link establishment_timeout", exc_info=True)
        link.set_link_established_callback(lambda lnk: self._handle_established(lnk, channel_id))
        link.set_link_closed_callback(lambda lnk: self._handle_closed(lnk, channel_id))
        if self._on_packet is not None:
            link.set_packet_callback(self._on_packet)

        # Accept resource transfers for large responses (> MDU)
        link.set_resource_strategy(RNS.Link.ACCEPT_ALL)
        if self._on_resource_concluded is not None:
            link.set_resource_concluded_callback(self._on_resource_concluded)

        self._links[channel_id] = link
        self._state.pending_connects.pop(channel_id, None)

    def register_channel(
        self,
        channel_id: str,
        destination_hash: Optional[bytes] = None,
        identity_public_key: Optional[bytes] = None,
    ) -> None:
        """Register an additional channel on an existing active link.

        RNS limits remote clients to one active link per node. All channels
        are multiplexed over a single link — the channel_id in each request
        payload routes to the correct handler on the daemon.
        """
        if destination_hash:
            self._state.channel_dest_hashes[channel_id] = destination_hash
            # Request LXMF delivery path for this channel
            try:
                ch_identity = RNS.Identity.recall(destination_hash)
                if not ch_identity and identity_public_key:
                    ch_identity = RNS.Identity(create_keys=False)
                    ch_identity.load_public_key(identity_public_key)
                    self._state.channel_identities[channel_id] = ch_identity
                if ch_identity:
                    lxmf_hash = RNS.Destination.hash_from_name_and_identity(
                        "lxmf.delivery", ch_identity
                    )
                    if not RNS.Transport.has_path(lxmf_hash):
                        RNS.Transport.request_path(lxmf_hash)
            except Exception:
                logger.debug("LXMF path pre-request failed for %s", channel_id, exc_info=True)
        if channel_id in self._links:
            return
        active_link = self.find_active_link()
        if not active_link:
            logger.warning("No active link to register channel %s", channel_id)
            return
        self._links[channel_id] = active_link
        logger.info("Registered channel %s on existing link", channel_id)

    def retry_pending_connects(self) -> None:
        """Retry connections for channels whose paths weren't resolved yet."""
        resolved = []
        for channel_id, dest_hash in list(self._state.pending_connects.items()):
            if channel_id in self._links:
                resolved.append(channel_id)
                continue
            have_identity = (
                self._state.channel_identities.get(channel_id) is not None
                or RNS.Identity.recall(dest_hash) is not None
            )
            if have_identity:
                resolved.append(channel_id)
                self.connect_channel(dest_hash, channel_id)
        for ch_id in resolved:
            self._state.pending_connects.pop(ch_id, None)
        if self._state.pending_connects:
            logger.info(
                "%d channels still awaiting path resolution",
                len(self._state.pending_connects),
            )

    def disconnect_channel(self, channel_id: str) -> None:
        link = self._links.pop(channel_id, None)
        if link:
            link.teardown()

    def disconnect_all(self) -> None:
        """Tear down every channel link. Safe to call multiple times."""
        torn_down = set()
        for _channel_id, link in list(self._links.items()):
            if id(link) not in torn_down:
                try:
                    link.teardown()
                except Exception:
                    logger.debug("link teardown during disconnect_all failed", exc_info=True)
                torn_down.add(id(link))
        self._links.clear()
        self._state.pending_connects.clear()

    def get_link(self, channel_id: str) -> Optional[RNS.Link]:
        return self._links.get(channel_id)

    def is_connected(self, channel_id: str) -> bool:
        link = self._links.get(channel_id)
        return link is not None and link.status == RNS.Link.ACTIVE

    def find_active_link(self) -> Optional[RNS.Link]:
        """Find any active link for requests not tied to a specific channel."""
        for link in self._links.values():
            if link.status == RNS.Link.ACTIVE:
                return link
        return None

    def any_active(self) -> bool:
        return self.find_active_link() is not None

    def link_count(self) -> int:
        return len(self._links)

    def links_snapshot(self) -> dict[str, RNS.Link]:
        """Live view of the internal map. Callers must not mutate the
        returned dict — use disconnect_channel / disconnect_all /
        connect_channel instead. Subsystems (HistoryClient, QueryClient,
        etc.) read this for ``find_active_link`` and iteration."""
        return self._links

    def resolve_channel_identity(
        self, channel_id: str, link: Optional[RNS.Link] = None
    ) -> Optional[RNS.Identity]:
        """Resolve the destination identity for a channel so callers can
        build an LXMF destination.

        Lookup order:
        1. Per-channel recall (from announce — has path).
        2. Any channel with a working recall (content fallback routes).
        3. Cached identity from node_meta / pubkey-seeded invite.
        4. ``link.destination.identity`` — last resort.
        """
        ch_dest_hash = self._state.channel_dest_hashes.get(channel_id)
        if ch_dest_hash:
            identity = RNS.Identity.recall(ch_dest_hash)
            if identity:
                return identity
        for other_hash in self._state.channel_dest_hashes.values():
            identity = RNS.Identity.recall(other_hash)
            if identity:
                return identity
        cached = self._state.channel_identities.get(channel_id)
        if cached:
            return cached
        return link.destination.identity if link else None

    # ── Callback hooks (set by SyncEngine) ────────────────────────────

    def set_on_established(self, cb: Callable[[str, RNS.Link], None]) -> None:
        self._on_established = cb

    def set_on_closed(self, cb: Callable[[str, RNS.Link], None]) -> None:
        self._on_closed = cb

    def set_on_packet(self, cb: Callable[[bytes, Optional[RNS.Packet]], None]) -> None:
        self._on_packet = cb

    def set_on_resource_concluded(self, cb: Callable[[RNS.Resource], None]) -> None:
        self._on_resource_concluded = cb

    # ── Internal callback handlers ────────────────────────────────────

    def _handle_established(self, link: RNS.Link, channel_id: str) -> None:
        logger.info("Connected to channel %s", channel_id)
        # Override keepalive for low-RTT links — RNS computes keepalive from
        # RTT; local shared-instance links (~1ms RTT) get 5s keepalive which
        # causes premature stale/closure. Minimum 120s.
        try:
            if hasattr(link, "keepalive") and isinstance(link.keepalive, (int, float)):
                link.keepalive = max(link.keepalive, 120)
        except Exception:
            logger.debug("keepalive override failed for %s", channel_id, exc_info=True)
        if self._on_established:
            try:
                self._on_established(channel_id, link)
            except Exception:
                logger.exception("on_established callback raised")

    def _handle_closed(self, link: RNS.Link, channel_id: str) -> None:
        logger.info("Disconnected from channel %s", channel_id)
        self._links.pop(channel_id, None)
        if self._on_closed:
            try:
                self._on_closed(channel_id, link)
            except Exception:
                logger.exception("on_closed callback raised")
