# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Live subscription manager: push events to connected clients."""

import logging
import threading
import time
from typing import Callable, Optional

import RNS

from hokora.constants import (
    MAX_SUBSCRIBERS_PER_CHANNEL,
    MAX_TOTAL_SUBSCRIBERS,
    CDSP_PROFILE_FULL,
    CDSP_PROFILE_PRIORITIZED,
    CDSP_PROFILE_MINIMAL,
    CDSP_PROFILE_BATCHED,
)
from hokora.protocol.sync_utils import encode_message_for_wire, populate_sender_pubkey
from hokora.protocol.wire import encode_push_event
from hokora.protocol.zombie_link_buffer import ZombieLinkPushBuffer

logger = logging.getLogger(__name__)

# Event types that PRIORITIZED profile skips (non-critical)
_PRIORITIZED_SKIP_EVENTS = {"typing", "presence", "status_update"}


class LiveSubscriptionManager:
    """Manages live push subscriptions for connected clients."""

    def __init__(self, sealed_manager=None):
        # Decrypts sealed rows server-side before push; subscribe is membership-gated.
        self._sealed_manager = sealed_manager
        # channel_id -> {link: sync_profile}
        self._subscriptions: dict[str, dict] = {}
        # id(link) -> True for subscribers that decrypt sealed bodies at render-time.
        self._link_supports_sealed_at_rest: dict[int, bool] = {}
        # threading.Lock — push_message runs from RNS callback threads.
        self._lock = threading.Lock()
        # batch_key -> [(event_bytes, timestamp), ...] for BATCHED profile.
        self._batch_buffer: dict[str, list[tuple[bytes, float]]] = {}
        self._link_identities: dict[int, str] = {}  # id(link) -> identity_hash
        # Hook for events that can't be pushed because the Link is dead;
        # daemon wires it during start(). Signature:
        #   (identity_hash, channel_id, event_type, data_dict) -> None
        self._defer_hook: Optional[Callable[[str, str, str, dict], None]] = None
        # Buffers pushes during the zombie window (transport dead, RNS hasn't
        # detected yet); flushed via defer hook on link_closed. Client dedup
        # by msg_hash absorbs overlap with pushes that succeeded pre-drop.
        self._push_buffer = ZombieLinkPushBuffer(lock=self._lock)

    def subscribe(
        self,
        channel_id: str,
        link: RNS.Link,
        sync_profile: int = CDSP_PROFILE_FULL,
        identity_hash: str | None = None,
        supports_sealed_at_rest: bool = False,
    ) -> bool:
        """Subscribe a link to live updates for a channel.

        Returns True if subscribed, False if a limit was reached.
        MINIMAL profile is rejected (live push not allowed).
        """
        # MINIMAL profile: reject subscription
        if sync_profile == CDSP_PROFILE_MINIMAL:
            logger.info(f"MINIMAL profile: rejecting live subscription for channel {channel_id}")
            return False

        with self._lock:
            if channel_id not in self._subscriptions:
                self._subscriptions[channel_id] = {}

            # Idempotent: already subscribed (update profile)
            if link in self._subscriptions[channel_id]:
                self._subscriptions[channel_id][link] = sync_profile
                return True

            # Per-channel limit
            if len(self._subscriptions[channel_id]) >= MAX_SUBSCRIBERS_PER_CHANNEL:
                logger.warning(
                    f"Per-channel subscriber limit ({MAX_SUBSCRIBERS_PER_CHANNEL}) "
                    f"reached for channel {channel_id}"
                )
                return False

            # Global limit
            total = sum(len(s) for s in self._subscriptions.values())
            if total >= MAX_TOTAL_SUBSCRIBERS:
                logger.warning(f"Global subscriber limit ({MAX_TOTAL_SUBSCRIBERS}) reached")
                return False

            self._subscriptions[channel_id][link] = sync_profile
            if identity_hash:
                self._link_identities[id(link)] = identity_hash
            if supports_sealed_at_rest:
                self._link_supports_sealed_at_rest[id(link)] = True
        logger.info(
            f"Link subscribed to channel {channel_id} "
            f"(profile={sync_profile:#x}, sealed_at_rest={supports_sealed_at_rest})"
        )
        return True

    def unsubscribe(self, channel_id: str, link: RNS.Link):
        """Unsubscribe a link from a channel."""
        with self._lock:
            if channel_id in self._subscriptions:
                self._subscriptions[channel_id].pop(link, None)
                if not self._subscriptions[channel_id]:
                    del self._subscriptions[channel_id]

    def unsubscribe_all(self, link: RNS.Link):
        """Remove a link from all subscriptions."""
        with self._lock:
            for channel_id in list(self._subscriptions.keys()):
                self._subscriptions[channel_id].pop(link, None)
                if not self._subscriptions[channel_id]:
                    del self._subscriptions[channel_id]

    def get_subscribers(self, channel_id: str) -> dict:
        """Return {link: sync_profile} for a channel."""
        with self._lock:
            return dict(self._subscriptions.get(channel_id, {}))

    def set_defer_hook(self, hook: Optional[Callable[[str, str, str, dict], None]]) -> None:
        """Install the defer-on-dead-link hook (bridges into defer_sync_item)."""
        self._defer_hook = hook

    # Compat shims forwarding to ``self._push_buffer``; new code should call _push_buffer directly.
    @property
    def _recent_pushes(self) -> dict[int, "deque"]:  # noqa: F821 — runtime-only type
        return self._push_buffer._pushes

    @property
    def _push_retention_s(self) -> float:
        return self._push_buffer._retention_s

    @_push_retention_s.setter
    def _push_retention_s(self, value: float) -> None:
        self._push_buffer._retention_s = float(value)

    @property
    def _push_per_link_cap(self) -> int:
        return self._push_buffer._per_link_cap

    @_push_per_link_cap.setter
    def _push_per_link_cap(self, value: int) -> None:
        self._push_buffer._per_link_cap = int(value)

    def push_message(
        self,
        channel_id: str,
        message,
        sender_public_key: Optional[bytes] = None,
    ):
        """Push a message to all subscribers, encoding per capability for sealed rows.

        Sealed rows are encoded twice when both capable and legacy
        subscribers are present: ciphertext-on-wire for the former, decrypted
        body for the latter. ``sender_public_key`` is filled when supplied
        so subscribers can re-verify the LXMF signature end-to-end.
        """
        subscribers = self.get_subscribers(channel_id)
        if not subscribers:
            return

        has_ciphertext = (
            self._sealed_manager is not None
            and getattr(message, "encrypted_body", None)
            and getattr(message, "encryption_nonce", None)
        )
        if not has_ciphertext:
            data_dict = encode_message_for_wire(message, sealed_manager=self._sealed_manager)
            populate_sender_pubkey(data_dict, sender_public_key)
            event_data = encode_push_event("message", data_dict)
            self._push_to_subscribers(channel_id, subscribers, event_data, "message", data_dict)
            return

        # Sealed row — partition.
        with self._lock:
            cap_map = dict(self._link_supports_sealed_at_rest)
        capable: dict = {}
        legacy: dict = {}
        for link, profile in subscribers.items():
            if cap_map.get(id(link)):
                capable[link] = profile
            else:
                legacy[link] = profile

        if legacy:
            legacy_dict = encode_message_for_wire(message, sealed_manager=self._sealed_manager)
            populate_sender_pubkey(legacy_dict, sender_public_key)
            legacy_data = encode_push_event("message", legacy_dict)
            self._push_to_subscribers(channel_id, legacy, legacy_data, "message", legacy_dict)
        if capable:
            capable_dict = encode_message_for_wire(
                message,
                sealed_manager=self._sealed_manager,
                subscriber_supports_sealed_at_rest=True,
            )
            populate_sender_pubkey(capable_dict, sender_public_key)
            capable_data = encode_push_event("message", capable_dict)
            self._push_to_subscribers(channel_id, capable, capable_data, "message", capable_dict)

    def push_event(self, channel_id: str, event_type: str, data: dict):
        """Push a generic event to channel subscribers."""
        subscribers = self.get_subscribers(channel_id)
        if not subscribers:
            return

        event_data = encode_push_event(event_type, data)
        self._push_to_subscribers(channel_id, subscribers, event_data, event_type, data)

    def _record_push(
        self, link: "RNS.Link", channel_id: str, event_type: str, data_dict: dict
    ) -> None:
        """Delegate to the zombie-link buffer."""
        self._push_buffer.record(link, channel_id, event_type, data_dict)

    def handle_link_death(self, link: "RNS.Link") -> None:
        """Replay zombie-window pushes into the deferred queue and clean up state.

        Transport-agnostic; safe even if the link wasn't subscribed.
        """
        buffered = self._push_buffer.drain(link)
        with self._lock:
            identity_hash = self._link_identities.get(id(link))
        if buffered and identity_hash and self._defer_hook:
            logger.info(
                "Link death: replaying %d buffered push(es) to deferred queue for identity %s",
                len(buffered),
                identity_hash[:16] if identity_hash else "?",
            )
            for _ts, channel_id, event_type, data_dict in buffered:
                try:
                    self._defer_hook(identity_hash, channel_id, event_type, data_dict)
                except Exception:
                    logger.exception("Defer hook raised during zombie-link flush")
        self.unsubscribe_all(link)
        with self._lock:
            self._link_identities.pop(id(link), None)
            self._link_supports_sealed_at_rest.pop(id(link), None)

    def _defer_for_dead_link(
        self, link: "RNS.Link", channel_id: str, event_type: str, data_dict: dict
    ) -> None:
        """Enqueue an undeliverable event on the subscriber's deferred queue.

        Drops silently for anonymous subscribers; history-cursor sync recovers
        ``message`` events on reconnect.
        """
        if not self._defer_hook:
            return
        identity_hash = self._link_identities.get(id(link))
        if not identity_hash:
            return
        try:
            self._defer_hook(identity_hash, channel_id, event_type, data_dict)
        except Exception:
            logger.exception("Live-event defer hook raised")

    def _push_to_subscribers(
        self,
        channel_id: str,
        subscribers: dict,
        data: bytes,
        event_type: str,
        data_dict: Optional[dict] = None,
    ):
        """Send data to subscribers honouring sync profiles; dead-link defers go to defer hook."""
        dead_links = set()

        for link, profile in subscribers.items():
            try:
                if link.status != RNS.Link.ACTIVE:
                    dead_links.add(link)
                    if data_dict is not None:
                        self._defer_for_dead_link(link, channel_id, event_type, data_dict)
                    continue

                # PRIORITIZED: skip non-critical events
                if profile == CDSP_PROFILE_PRIORITIZED and event_type in _PRIORITIZED_SKIP_EVENTS:
                    continue

                # BATCHED: accumulate in buffer (capped at 1000 per session)
                if profile == CDSP_PROFILE_BATCHED:
                    batch_key = f"{channel_id}:{id(link)}"
                    if batch_key not in self._batch_buffer:
                        self._batch_buffer[batch_key] = []
                    buf = self._batch_buffer[batch_key]
                    buf.append((data, time.time()))
                    if len(buf) > 1000:
                        self._batch_buffer[batch_key] = buf[-1000:]
                    continue

                # FULL and PRIORITIZED (non-skipped): push immediately
                if len(data) <= RNS.Link.MDU:
                    RNS.Packet(link, data).send()
                else:
                    RNS.Resource(data, link)

                # Buffer for zombie-link recovery (RNS.send returns cleanly for
                # ~1–2 min after a silent transport drop).
                if data_dict is not None:
                    self._record_push(link, channel_id, event_type, data_dict)

            except Exception as e:
                logger.warning(f"Failed to push to link: {e}")
                dead_links.add(link)
                if data_dict is not None:
                    self._defer_for_dead_link(link, channel_id, event_type, data_dict)

        # Clean up dead links
        for link in dead_links:
            self.unsubscribe_all(link)

    def flush_batches(self, lxmf_router=None, cdsp_manager=None):
        """Flush BATCHED buffers; try Link first, fall back to LXMF store-and-forward."""
        import msgpack
        from hokora.constants import WIRE_VERSION

        with self._lock:
            buffers = dict(self._batch_buffer)
            self._batch_buffer.clear()

        for batch_key, events in buffers.items():
            if not events:
                continue

            parts = batch_key.split(":", 1)
            if len(parts) != 2:
                continue
            channel_id = parts[0]
            link_id_str = parts[1]

            # Try link-based delivery first
            sent_via_link = False
            subscribers = self.get_subscribers(channel_id)
            for link, profile in subscribers.items():
                if f"{channel_id}:{id(link)}" == batch_key and profile == CDSP_PROFILE_BATCHED:
                    try:
                        if link.status == RNS.Link.ACTIVE:
                            batch_data = msgpack.packb(
                                {
                                    "v": WIRE_VERSION,
                                    "event": "batch",
                                    "data": {
                                        "events": [e[0] for e in events],
                                        "count": len(events),
                                    },
                                },
                                use_bin_type=True,
                            )
                            if len(batch_data) <= RNS.Link.MDU:
                                RNS.Packet(link, batch_data).send()
                            else:
                                RNS.Resource(batch_data, link)
                            sent_via_link = True
                    except Exception as e:
                        logger.warning(f"Failed to flush batch via link: {e}")
                    break

            # LXMF fallback: send via store-and-forward if link is dead
            if not sent_via_link and lxmf_router and cdsp_manager:
                # Recover identity_hash from link_id
                try:
                    link_id_int = int(link_id_str)
                except (ValueError, TypeError):
                    continue
                identity_hash = self._link_identities.get(link_id_int)
                if identity_hash:
                    lxmf_dest_hex = cdsp_manager.get_lxmf_destination(identity_hash)
                    if lxmf_dest_hex:
                        self._send_batch_via_lxmf(lxmf_router, lxmf_dest_hex, events)

    def _send_batch_via_lxmf(self, lxmf_router, dest_hex: str, events):
        """Send batched events to a client via LXMF store-and-forward."""
        import binascii
        import msgpack
        import LXMF

        try:
            dest_hash = binascii.unhexlify(dest_hex)
            identity = RNS.Identity.recall(dest_hash)
            if not identity:
                logger.warning(f"Cannot recall identity for LXMF batch to {dest_hex[:16]}")
                return

            dest = RNS.Destination(
                identity,
                RNS.Destination.OUT,
                RNS.Destination.SINGLE,
                "lxmf",
                "delivery",
            )
            content = msgpack.packb(
                {
                    "type": "batch",
                    "events": [e[0] for e in events],
                    "count": len(events),
                },
                use_bin_type=True,
            )
            # current LXMF dropped get_delivery_destination(); read from delivery_destinations.
            sources = list(lxmf_router.delivery_destinations.values())
            if not sources:
                logger.warning(
                    "Cannot send LXMF batch: router has no registered delivery destination"
                )
                return
            source = sources[0]
            lxm = LXMF.LXMessage(dest, source, content)
            lxm.try_propagation_on_fail = True
            lxmf_router.handle_outbound(lxm)
            logger.info(f"Sent LXMF batch ({len(events)} events) to {dest_hex[:16]}")
        except Exception:
            logger.warning("Failed to send LXMF batch", exc_info=True)

    def _push_to_links(self, links: set, data: bytes):
        """Send data to a set of links, removing dead ones (legacy callers)."""
        dead_links = set()
        for link in links:
            try:
                if link.status == RNS.Link.ACTIVE:
                    if len(data) <= RNS.Link.MDU:
                        RNS.Packet(link, data).send()
                    else:
                        RNS.Resource(data, link)
                else:
                    dead_links.add(link)
            except Exception as e:
                logger.warning(f"Failed to push to link: {e}")
                dead_links.add(link)

        # Clean up dead links
        for link in dead_links:
            self.unsubscribe_all(link)
