# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""DmRouter — LXMF direct messaging.

Owns the ``LXMF.LXMRouter`` instance (must be created on the main thread —
signal handler constraint), the local ``lxmf/delivery`` destination, and
the inbound LXMF delivery callback. Routes DMs to the registered
delivery callback; routes BATCHED-profile batch deliveries to a
separately-registered batch handler (typically the sync engine's
``_on_packet``).

Other LXMF-using subsystems (RichMessageClient, MediaClient) receive
refs to ``lxm_router`` + ``lxmf_source`` and call
``router.handle_outbound`` via those refs.
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Optional

import msgpack
import LXMF
import RNS

if TYPE_CHECKING:
    from hokora_tui.sync.state import SyncState

logger = logging.getLogger(__name__)


class DmRouter:
    """LXMF direct messaging subsystem."""

    def __init__(
        self,
        identity: Optional[RNS.Identity],
        data_dir: Optional[Path],
        state: "SyncState",
    ) -> None:
        self.identity = identity
        self._data_dir = data_dir
        self._state = state
        self._lxm_router: Optional[LXMF.LXMRouter] = None
        self._lxmf_source: Optional[RNS.Destination] = None
        self._on_delivery: Optional[Callable[[str, Optional[str], str, float], None]] = None
        # Batch dispatch hook — invoked when LXMF delivers a BATCHED-profile
        # payload (``{"type": "batch", "events": [bytes, ...]}``). Each event
        # bytes entry is replayed through this callback as if it came from a
        # live packet. Step C's HistoryClient will own this dispatch.
        self._on_batch: Optional[Callable[[bytes, Optional[object]], None]] = None

    # ── Public API ────────────────────────────────────────────────────

    def start(self) -> None:
        """Create LXMRouter, register delivery identity + callback, announce.

        No-op when identity is ``None`` (anonymous TUI boot). Must be called
        on the main thread — LXMF.LXMRouter installs signal handlers.
        Idempotent: subsequent calls are a no-op if start already succeeded.
        """
        if self.identity is None:
            return
        if self._lxm_router is not None:
            return

        base = self._data_dir or (Path.home() / ".hokora-client")
        storage = str(base / "lxmf")
        os.makedirs(storage, exist_ok=True)
        self._lxm_router = LXMF.LXMRouter(
            identity=self.identity,
            storagepath=storage,
        )
        # Register delivery callback for incoming DMs.
        self._lxm_router.register_delivery_callback(self._on_lxmf_delivery)
        # Register delivery identity so we can RECEIVE DMs via LXMF.
        # Creates an IN/lxmf/delivery destination managed by LXMRouter.
        self._lxm_router.register_delivery_identity(
            self.identity, display_name=self._state.display_name
        )
        # Use the LXMRouter's delivery destination as source for outbound
        # and announce it so peers can find us for DMs.
        try:
            dests = self._lxm_router.delivery_destinations
            if dests and isinstance(dests, dict) and len(dests) > 0:
                self._lxmf_source = list(dests.values())[0]
                self._lxmf_source.announce()
        except Exception:
            # Delivery-destination discovery best-effort; falls through to
            # the OUT-destination fallback below.
            logger.debug("LXMF delivery destination discovery failed", exc_info=True)
        if self._lxmf_source is None:
            # Fallback: OUT destination (can send but won't receive DMs).
            self._lxmf_source = RNS.Destination(
                self.identity,
                RNS.Destination.OUT,
                RNS.Destination.SINGLE,
                "lxmf",
                "delivery",
            )

    def send_dm(self, peer_identity_hash: str, body: str) -> bool:
        """Send a direct LXMF message to a peer (not through a channel).

        Returns True on successful outbound queue; False if no router/identity
        or if the peer identity can't be recalled (in which case a path
        request is sent so a retry can succeed once the peer announces).
        """
        if not self._lxm_router or not self.identity:
            logger.error("No LXMRouter or identity — cannot send DM")
            return False

        content = msgpack.packb(
            {
                "type": "dm",
                "body": body,
                "sender_name": self._state.display_name,
            },
            use_bin_type=True,
        )

        try:
            peer_hash_bytes = bytes.fromhex(peer_identity_hash)
            dest_identity = RNS.Identity.recall(peer_hash_bytes, from_identity_hash=True)
            if not dest_identity:
                dest_identity = RNS.Identity.recall(peer_hash_bytes)
            if not dest_identity:
                logger.info(f"Requesting path to {peer_identity_hash} for DM")
                RNS.Transport.request_path(peer_hash_bytes)
                return False

            destination = RNS.Destination(
                dest_identity,
                RNS.Destination.OUT,
                RNS.Destination.SINGLE,
                "lxmf",
                "delivery",
            )
            if not RNS.Transport.has_path(destination.hash):
                RNS.Transport.request_path(destination.hash)

            lxm = LXMF.LXMessage(
                destination,
                self._lxmf_source,
                content,
                desired_method=LXMF.LXMessage.DIRECT,
            )
            lxm.try_propagation_on_fail = True
            self._lxm_router.handle_outbound(lxm)
            logger.info(f"Sent DM to {peer_identity_hash}")
            return True
        except Exception:
            logger.exception("DM send failed")
            return False

    def set_on_delivery(
        self,
        cb: Optional[Callable[[str, Optional[str], str, float], None]],
    ) -> None:
        """Register the DM delivery callback.

        Signature: ``callback(sender_hash, display_name, body, timestamp)``.
        Fires on RNS thread — handler MUST hop to urwid loop for UI updates.
        """
        self._on_delivery = cb

    def register_batch_dispatch(
        self, cb: Optional[Callable[[bytes, Optional[object]], None]]
    ) -> None:
        """Register the handler for LXMF BATCHED-profile batch deliveries.

        Each event in the batch is delivered to ``cb(event_bytes, None)``.
        Typically bound to ``HistoryClient._on_packet`` in Step C; during
        Step B it's ``SyncEngine._on_packet``.
        """
        self._on_batch = cb

    @property
    def lxm_router(self) -> Optional[LXMF.LXMRouter]:
        return self._lxm_router

    @lxm_router.setter
    def lxm_router(self, v: Optional[LXMF.LXMRouter]) -> None:
        """Tests set ``router.lxm_router = MagicMock()`` to inject a stub
        that intercepts ``handle_outbound`` calls without spinning up a
        real LXMRouter."""
        self._lxm_router = v

    @property
    def lxmf_source(self) -> Optional[RNS.Destination]:
        return self._lxmf_source

    @lxmf_source.setter
    def lxmf_source(self, v: Optional[RNS.Destination]) -> None:
        self._lxmf_source = v

    @property
    def on_delivery(self) -> Optional[Callable]:
        return self._on_delivery

    # ── Internal ──────────────────────────────────────────────────────

    def _on_lxmf_delivery(self, message) -> None:
        """Handle incoming LXMF messages.

        Routes:
        - ``type == "dm"`` → delivery callback (DM from peer)
        - ``type == "batch"`` → batch dispatch hook (events replayed as if
          they came from packets). Used by BATCHED-profile clients whose
          daemon fell back to LXMF store-and-forward.
        - Anything else is silently ignored here — channel messages are
          handled by LXMFBridge on the daemon side, not the TUI.
        """
        try:
            content = msgpack.unpackb(message.content, raw=False)

            # Direct message (not a channel message)
            if isinstance(content, dict) and content.get("type") == "dm":
                if (
                    message.source
                    and hasattr(message.source, "identity")
                    and message.source.identity
                ):
                    sender_hash = message.source.identity.hexhash
                else:
                    sender_hash = RNS.hexrep(message.source_hash, delimit=False)
                display_name = content.get("sender_name")
                body = content.get("body", "")
                ts = message.timestamp if hasattr(message, "timestamp") else time.time()

                logger.info(f"Received DM from {sender_hash}")

                if self._on_delivery:
                    self._on_delivery(sender_hash, display_name, body, ts)
                return

            # Batch delivery from daemon (BATCHED sync profile fallback)
            if isinstance(content, dict) and content.get("type") == "batch":
                events = content.get("events", [])
                logger.info(f"Received LXMF batch delivery: {len(events)} events")
                if self._on_batch:
                    for event_data in events:
                        if isinstance(event_data, bytes):
                            self._on_batch(event_data, None)
                return

            # Non-DM, non-batch LXMF messages are handled elsewhere.
        except Exception:
            logger.exception("Error handling incoming LXMF delivery")
