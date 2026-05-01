# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""RNS Link lifecycle and request handler registration."""

import asyncio
import logging
import threading
import time
from typing import Optional, Callable

import RNS

from hokora.protocol.wire import (
    decode_sync_request,
    encode_sync_response,
)
from hokora.exceptions import SyncError

logger = logging.getLogger(__name__)


class LinkContext:
    """Per-link state tracking."""

    def __init__(self, link: RNS.Link, channel_id: str):
        self.link = link
        self.channel_id = channel_id
        self.established_at = time.time()
        self.identity_hash: Optional[str] = None
        self.subscribed_channels: set[str] = set()

        if link.get_remote_identity():
            self.identity_hash = link.get_remote_identity().hexhash


class LinkManager:
    """Manages RNS Link lifecycle and request handler registration."""

    def __init__(self, async_loop: asyncio.AbstractEventLoop):
        self.loop = async_loop
        self._links: dict[bytes, LinkContext] = {}
        # threading.Lock (not asyncio.Lock): on_link_established and _on_packet
        # are called from RNS threads, not the asyncio event loop.
        self._links_lock = threading.Lock()
        self._sync_handler: Optional[Callable] = None
        # Optional hook invoked when a Link closes. Daemon wires this to
        # LiveSubscriptionManager.handle_link_death so the zombie-link push
        # buffer is flushed into the subscriber's deferred queue before the
        # subscription is torn down.
        self._closed_hook: Optional[Callable[[RNS.Link], None]] = None
        # Per-peer EpochManager registry keyed by "{identity_hash}:{channel_id}".
        # Populated by EpochOrchestrator.attach_to_link_manager() after
        # load_state. Empty until the orchestrator wires it — inbound epoch
        # frames arriving before that complete the lookup against an empty
        # dict and surface as a debug-logged drop instead of a silent one.
        self._epoch_managers: dict = {}

    def set_sync_handler(self, handler: Callable):
        """Set the async coroutine that handles sync requests."""
        self._sync_handler = handler

    def set_closed_hook(self, hook: Optional[Callable[[RNS.Link], None]]) -> None:
        """Register a callback fired from `_on_link_closed` with the dead
        Link. Used by the daemon to flush buffered pushes into the deferred
        queue when RNS finally confirms the link death."""
        self._closed_hook = hook

    def on_link_established(self, link: RNS.Link, channel_id: str):
        """Called when a new Link is established to a channel destination."""
        try:
            ctx = LinkContext(link, channel_id)
            with self._links_lock:
                self._links[link.link_id] = ctx

            link.set_link_closed_callback(self._on_link_closed)

            # Register sync request handler with size validation
            link.set_resource_strategy(RNS.Link.ACCEPT_APP)
            link.set_resource_callback(self._resource_filter)

            link.set_packet_callback(self._on_packet)

            link.set_remote_identified_callback(
                lambda lnk, identity: self._on_identified(lnk, identity)
            )

            # Prevent premature stale/closure on low-RTT links.
            # RNS calculates keepalive from RTT — local links get ~5s which
            # causes the daemon to mark the link stale before the client's
            # first keepalive arrives.
            try:
                if hasattr(link, "keepalive") and isinstance(link.keepalive, (int, float)):
                    link.keepalive = max(link.keepalive, 120)
            except Exception:
                logger.debug("keepalive override failed for channel %s", channel_id, exc_info=True)

            logger.info(
                f"Link established for channel {channel_id} from {ctx.identity_hash or 'anonymous'}"
            )
        except Exception:
            logger.exception(f"Error in on_link_established for {channel_id}")

    # Maximum inbound resource size (5 MB)
    MAX_RESOURCE_SIZE = 5 * 1024 * 1024

    def _resource_filter(self, resource: RNS.Resource) -> bool:
        """Accept or reject inbound resource transfers based on size."""
        if resource.data_size is not None and resource.data_size > self.MAX_RESOURCE_SIZE:
            logger.warning(
                f"Rejecting resource: size {resource.data_size} exceeds "
                f"limit {self.MAX_RESOURCE_SIZE}"
            )
            return False
        return True

    def _on_link_closed(self, link: RNS.Link):
        with self._links_lock:
            ctx = self._links.pop(link.link_id, None)
        if ctx:
            logger.info(f"Link closed for channel {ctx.channel_id}")
        # Notify the live layer so it can flush any pushes buffered against
        # this link during the zombie window (transport dead but RNS hadn't
        # detected it yet). Safe to call even if the link was never a live
        # subscriber.
        if self._closed_hook is not None:
            try:
                self._closed_hook(link)
            except Exception:
                logger.exception("closed_hook raised in _on_link_closed")

    def _on_identified(self, link: RNS.Link, identity: RNS.Identity):
        with self._links_lock:
            ctx = self._links.get(link.link_id)
        if ctx:
            ctx.identity_hash = identity.hexhash
            logger.info(f"Link identified: {identity.hexhash}")

        # Cache identity for LXMF delivery destination resolution.
        # The link identify proves the client owns this identity, but LXMF
        # messages arrive from the "lxmf.delivery" destination hash which
        # differs from the hokora link destination hash.  Without this,
        # the LXMF bridge can't resolve the sender for permission checks.
        try:
            lxmf_dest_hash = RNS.Destination.hash_from_name_and_identity("lxmf.delivery", identity)
            RNS.Identity.remember(None, lxmf_dest_hash, identity.get_public_key())
        except Exception:
            logger.debug(
                "LXMF delivery identity cache update failed for %s",
                identity.hexhash,
                exc_info=True,
            )

    def _on_packet(self, message: bytes, packet: RNS.Packet):
        """Handle incoming sync request packet."""
        if not self._sync_handler:
            logger.warning("No sync handler registered")
            return

        link = packet.link
        with self._links_lock:
            ctx = self._links.get(link.link_id) if link else None
        channel_id = ctx.channel_id if ctx else None

        # Forward secrecy: detect and decrypt epoch frames
        from hokora.federation.epoch_wire import is_epoch_frame
        from hokora.constants import EPOCH_DATA, EPOCH_ROTATE, EPOCH_ROTATE_ACK

        if is_epoch_frame(message):
            frame_type = message[0]
            identity_hash = ctx.identity_hash if ctx else None
            em_key = f"{identity_hash}:{channel_id}" if identity_hash and channel_id else None
            em = self._epoch_managers.get(em_key) if em_key else None

            if frame_type == EPOCH_DATA:
                if em is None:
                    # Frame arrived for a peer/channel whose EpochManager
                    # isn't wired (orchestrator not yet attached, or handshake
                    # never ran for this peer). Drop visibly — silent drop
                    # here would hide a federation handshake regression.
                    logger.debug("Dropping EPOCH_DATA frame: no manager for %s", em_key)
                    return
                try:
                    message = em.decrypt(message)
                except Exception:
                    logger.exception("Epoch decrypt failed")
                    return
            elif frame_type in (EPOCH_ROTATE, EPOCH_ROTATE_ACK):
                # Route to sync handler as step 5/6
                if em is None:
                    logger.debug(
                        "Dropping %s frame: no manager for %s",
                        "EPOCH_ROTATE" if frame_type == EPOCH_ROTATE else "EPOCH_ROTATE_ACK",
                        em_key,
                    )
                    return
                if frame_type == EPOCH_ROTATE:
                    try:
                        ack = em.handle_epoch_rotate(message)
                        RNS.Packet(link, ack).send()
                    except Exception:
                        logger.exception("Epoch rotate handling failed")
                return

        try:
            request = decode_sync_request(message)
            nonce = request["nonce"]
            action = request["action"]
            payload = request.get("payload", {})
            requester_hash = ctx.identity_hash if ctx else None

            # Resolve identity from link if callback hasn't fired yet (identify race)
            if not requester_hash and link:
                try:
                    remote_id = link.get_remote_identity()
                    if remote_id:
                        requester_hash = remote_id.hexhash
                        if ctx:
                            ctx.identity_hash = requester_hash
                        # Cache for LXMF delivery destination resolution.
                        # LXMF messages arrive keyed by "lxmf.delivery" dest
                        # hash, which differs from the hokora link dest hash.
                        try:
                            lxmf_hash = RNS.Destination.hash_from_name_and_identity(
                                "lxmf.delivery", remote_id
                            )
                            RNS.Identity.remember(None, lxmf_hash, remote_id.get_public_key())
                        except Exception:
                            logger.debug(
                                "LXMF identity cache update failed during packet handling",
                                exc_info=True,
                            )
                except Exception:
                    logger.debug("remote_identity resolution on packet failed", exc_info=True)

            # Bridge to asyncio — pass link for handlers that need it
            future = asyncio.run_coroutine_threadsafe(
                self._sync_handler(action, nonce, payload, channel_id, requester_hash, link=link),
                self.loop,
            )

            try:
                response_data = future.result(timeout=30)
                try:
                    response_bytes = encode_sync_response(
                        nonce, response_data, node_time=time.time()
                    )
                except SyncError as e:
                    logger.warning(f"Response too large, sending truncated: {e}")
                    response_data["truncated"] = True
                    # Remove bulk data to fit within frame
                    for key in ("messages", "results", "members"):
                        if key in response_data and isinstance(response_data[key], list):
                            response_data[key] = response_data[key][:10]
                    response_bytes = encode_sync_response(
                        nonce, response_data, node_time=time.time()
                    )

                # Send response back via the link
                # Send response back via the link
                if len(response_bytes) <= RNS.Link.MDU:
                    RNS.Packet(link, response_bytes).send()
                else:
                    # Use Resource for large responses
                    RNS.Resource(response_bytes, link)

            except TimeoutError:
                logger.error("Sync handler timed out")
            except Exception:
                logger.exception("Sync handler error")
                error_response = encode_sync_response(nonce, {"error": "Internal server error"})
                RNS.Packet(link, error_response).send()

        except SyncError as e:
            logger.warning(f"Invalid sync request: {e}")

    def get_link_context(self, link_id: bytes) -> Optional[LinkContext]:
        with self._links_lock:
            return self._links.get(link_id)

    def get_channel_links(self, channel_id: str) -> list[LinkContext]:
        with self._links_lock:
            return [ctx for ctx in self._links.values() if ctx.channel_id == channel_id]

    def get_all_links(self) -> list[LinkContext]:
        with self._links_lock:
            return list(self._links.values())
