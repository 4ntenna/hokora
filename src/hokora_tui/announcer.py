# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Announcer — handles sending and receiving profile/channel announces."""

from __future__ import annotations

import json
import logging
import threading
import time
from typing import TYPE_CHECKING

import msgpack

if TYPE_CHECKING:
    from hokora_tui.app import HokoraTUI

logger = logging.getLogger(__name__)

# App name used for RNS announce handler registration
_APP_NAME = "hokora"


class _AnnounceListener:
    """RNS-compatible announce handler object.

    RNS requires an object with ``aspect_filter`` and ``received_announce()``.
    Setting ``aspect_filter = None`` receives ALL announces on the network.
    RNS calls ``received_announce()`` with keyword arguments.
    """

    def __init__(self, callback):
        self.aspect_filter = None  # Receive all announces
        self._callback = callback

    def received_announce(self, destination_hash=None, announced_identity=None, app_data=None):
        self._callback(destination_hash, announced_identity, app_data)


class Announcer:
    """Handles both SENDING and RECEIVING profile/channel announces.

    Registers an RNS announce callback to discover nodes and peers on the
    network, and provides methods to broadcast the local user's profile.
    """

    def __init__(self, app: HokoraTUI) -> None:
        self.app = app
        self._running = False
        self._auto_thread: threading.Thread | None = None
        # Single signal for both stop and wake: setting wakes the loop
        # immediately. ``_stopping`` distinguishes — if True after a
        # signal, the loop exits; otherwise it re-iterates. Single
        # primitive avoids the "wait on any of multiple events" problem
        # that ``threading.Event`` doesn't natively support.
        self._signal = threading.Event()
        self._stop_event = self._signal  # back-compat alias for `stop()`
        self._stopping = False
        self._listener: _AnnounceListener | None = None
        self._profile_dest = None  # Cached profile announce destination

    def start(self) -> None:
        """Register RNS announce callback and unconditionally start the
        auto-announce loop. The loop's per-iteration ``state.auto_announce``
        check handles the disabled case (skips the announce, sleeps, repeats),
        so this is safe even when the user has it toggled off — and it
        ensures a later toggle-ON takes effect without a restart.
        """
        try:
            import RNS

            self._listener = _AnnounceListener(self._on_announce)
            RNS.Transport.register_announce_handler(self._listener)
            logger.info("Registered RNS announce handler (aspect_filter=None)")
        except ImportError:
            logger.warning("RNS not available — announce handler not registered")
        except Exception as e:
            logger.warning(f"Failed to register announce handler: {e}")

        self._running = True

        # Always start the loop. State-based gating happens per-iteration.
        self._start_auto_announce()

    def wake(self) -> None:
        """Wake the auto-announce loop out of its interval-wait.

        Called by ``AppState.set_auto_announce(True)`` so the user sees
        an immediate announce on toggle rather than waiting for the
        current ``announce_interval`` to elapse.
        """
        self._signal.set()

    def _on_announce(self, destination_hash, announced_identity, app_data):
        """Callback for incoming RNS announces.

        Parses msgpack app_data and dispatches to node or peer discovery.
        """
        if not app_data:
            return

        try:
            data = msgpack.unpackb(app_data, raw=False)
        except (msgpack.UnpackException, ValueError, TypeError):
            return

        if not isinstance(data, dict):
            return

        import RNS

        announce_type = data.get("type")
        dest_hash = RNS.hexrep(destination_hash, delimit=False)
        now = time.time()

        # Hop count to the announcing destination, queried live from the
        # RNS path table. ``PATHFINDER_M`` is RNS's "no path" sentinel —
        # map it to None so the UI can render ``?h`` instead of ``128h``.
        # Any exception (RNS not initialised, lock contention) degrades
        # to None rather than failing the announce ingest.
        hops: int | None
        try:
            raw_hops = RNS.Transport.hops_to(destination_hash)
            hops = None if raw_hops >= RNS.Transport.PATHFINDER_M else raw_hops
        except Exception:
            hops = None

        if announce_type == "channel":
            node_name = data.get("node", "Unknown")
            channel_name = data.get("name", "")
            channel_id = data.get("channel_id", "")
            # node_identity_hash is emitted by current daemons; older
            # builds may omit it. Treat missing as None (no clash).
            node_identity_hash = data.get("node_identity_hash")
            announce_time = data.get("time", now)

            # Group channels by node name (not by destination hash,
            # since each channel has its own RNS destination).
            # Use node_name as the grouping key.
            node_key = node_name or dest_hash

            node = self.app.state.discovered_nodes.get(node_key, {})
            channels = node.get("channels") or []
            channel_dests = node.get("channel_dests") or {}

            if channel_name and channel_name not in channels:
                channels = channels + [channel_name]
            if channel_id and dest_hash:
                channel_dests[channel_id] = dest_hash

            # Optional role hint emitted by current daemons. Older daemons
            # omit the field — treat absence as "unknown / not advertised"
            # so the info panel falls back to "Community Node" only.
            propagation_enabled = data.get("propagation_enabled")

            node_dict = {
                "hash": node_key,
                "node_name": node_name,
                "node_identity_hash": node_identity_hash or node.get("node_identity_hash"),
                "channel_count": len(channels),
                "last_seen": announce_time,
                "channels": channels,
                "channel_dests": channel_dests,
                "primary_dest": dest_hash,
                "bookmarked": node.get("bookmarked", False),
                "hops": hops,
                "propagation_enabled": (
                    propagation_enabled
                    if propagation_enabled is not None
                    else node.get("propagation_enabled")
                ),
            }

            self.app.state.discovered_nodes[node_key] = node_dict
            self.app.state.emit("nodes_updated")
            self.app._schedule_redraw()

            # If we have a channel row cached for this channel_id, tag it
            # with the announcing node's identity_hash so the Channels view
            # can disambiguate same-named channels across nodes.
            if channel_id and node_identity_hash and self.app.db is not None:
                try:
                    existing = {ch.get("id"): ch for ch in self.app.db.get_channels()}
                    row = existing.get(channel_id)
                    if row and not row.get("node_identity_hash"):
                        row["node_identity_hash"] = node_identity_hash
                        self.app.db.store_channels([row])
                except Exception as e:
                    logger.debug(f"Could not tag channel with node_identity_hash: {e}")

            # Persist
            if self.app.db is not None:
                try:
                    self.app.db.store_discovered_node(
                        hash=node_key,
                        name=node_name,
                        channel_count=len(channels),
                        last_seen=announce_time,
                        channels_json=json.dumps(channels),
                        channel_dests_json=json.dumps(channel_dests),
                    )
                except Exception as e:
                    logger.debug(f"Failed to persist discovered node: {e}")

            logger.info(f"Discovered node: {node_name} ch={channel_name} ({dest_hash[:16]}...)")

            # Retry pending connects — the announce just populated the
            # identity cache, so deferred connects can now resolve.
            if self.app.sync_engine and self.app.sync_engine.has_pending_connects():
                self.app.sync_engine.retry_pending_connects()

        elif announce_type == "profile":
            display_name = data.get("display_name", "")
            status_text = data.get("status_text", "")
            announce_time = data.get("time", now)

            # Key peers by identity hash (stable across all destination aspects)
            # so DM conversations match regardless of which dest hash is used
            peer_key = announced_identity.hexhash if announced_identity else dest_hash

            existing = self.app.state.discovered_peers.get(peer_key, {})
            peer_dict = {
                "hash": peer_key,
                "display_name": display_name,
                "status_text": status_text,
                "last_seen": announce_time,
                "bookmarked": existing.get("bookmarked", False),
                "hops": hops,
            }

            self.app.state.discovered_peers[peer_key] = peer_dict
            self.app.state.emit("peers_updated")
            self.app._schedule_redraw()

            # Persist
            if self.app.db is not None:
                try:
                    self.app.db.store_discovered_peer(
                        hash=peer_key,
                        display_name=display_name,
                        status_text=status_text,
                        last_seen=announce_time,
                    )
                except Exception as e:
                    logger.debug(f"Failed to persist discovered peer: {e}")

            logger.info(f"Discovered peer: {display_name} ({peer_key[:16]}...)")

    def announce_profile(self) -> None:
        """Send a profile announce on the network.

        Uses hokora's build_profile_announce if available, otherwise
        builds the msgpack payload directly.
        """
        identity = self.app.state.identity
        if not identity:
            self.app.status.set_context("No RNS identity - cannot announce")
            self.app._schedule_redraw()
            return

        display_name = self.app.state.display_name or "Anonymous"
        status_text = self.app.state.status_text or ""

        try:
            from hokora.core.announce import AnnounceHandler

            app_data = AnnounceHandler.build_profile_announce(
                display_name=display_name,
                status_text=status_text,
            )
        except ImportError:
            app_data = msgpack.packb(
                {
                    "type": "profile",
                    "display_name": display_name,
                    "status_text": status_text,
                    "time": time.time(),
                }
            )

        try:
            import RNS

            # Reuse cached destination (RNS forbids duplicate registration)
            if self._profile_dest is None:
                self._profile_dest = RNS.Destination(
                    identity,
                    RNS.Destination.IN,
                    RNS.Destination.SINGLE,
                    _APP_NAME,
                    "profile",
                )
            self._profile_dest.announce(app_data=app_data)
            # Also announce LXMF delivery destination so peers can send DMs
            if hasattr(self.app, "sync_engine") and self.app.sync_engine:
                self.app.sync_engine.announce_lxmf_destination()
            logger.info(f"Announced profile: {display_name}")
            self.app.status.set_context(f"Profile announced: {display_name}")
            self.app._schedule_redraw()
        except ImportError:
            self.app.status.set_context("RNS not available - cannot announce")
            self.app._schedule_redraw()
        except Exception as e:
            logger.error(f"Profile announce failed: {e}")
            self.app.status.set_context(f"Announce failed: {e}")
            self.app._schedule_redraw()

    def _start_auto_announce(self) -> None:
        """Start the auto-announce daemon thread."""
        if self._auto_thread and self._auto_thread.is_alive():
            return
        self._stopping = False
        self._signal.clear()
        self._auto_thread = threading.Thread(target=self._auto_announce_loop, daemon=True)
        self._auto_thread.start()

    def _auto_announce_loop(self) -> None:
        """Periodically announce profile when auto_announce is enabled.

        The loop runs unconditionally; the per-iteration state check
        gates the actual announce. ``self._signal`` is a single shared
        event used for both stop (``stop()``) and wake (``wake()``);
        ``self._stopping`` distinguishes. Toggling auto-announce on via
        ``AppState.set_auto_announce(True)`` calls ``wake()`` so the
        user gets an immediate announce instead of waiting up to one
        ``announce_interval`` for the next iteration.
        """
        while not self._stopping:
            self._signal.clear()
            if self.app.state.auto_announce and self.app.state.identity:
                self.announce_profile()
            interval = self.app.state.announce_interval
            # Sleeps until either ``stop()`` or ``wake()`` fires the
            # signal, or the interval elapses. The loop head re-checks
            # ``_stopping`` to decide whether to exit; otherwise it
            # falls through to the next iteration which re-evaluates
            # ``state.auto_announce``.
            self._signal.wait(timeout=interval)

    def stop(self) -> None:
        """Stop the auto-announce loop."""
        self._running = False
        self._stopping = True
        self._signal.set()
        if self._auto_thread and self._auto_thread.is_alive():
            self._auto_thread.join(timeout=2)
        self._auto_thread = None
