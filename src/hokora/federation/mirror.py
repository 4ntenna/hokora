# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Channel mirroring: sync from remote, serve locally."""

from __future__ import annotations

import enum
import logging
import random
import threading
from typing import TYPE_CHECKING, Callable, Optional

import RNS

from hokora.constants import SYNC_HISTORY
from hokora.protocol.wire import (
    decode_sync_response,
    encode_sync_request,
    generate_nonce,
)

if TYPE_CHECKING:
    from hokora.federation.auth import FederationAuth
    from hokora.federation.epoch_manager import EpochManager

logger = logging.getLogger(__name__)


class MirrorState(str, enum.Enum):
    """Lifecycle states for a ChannelMirror.

    IDLE → CONNECTING on ``start()``; then LINKED on success or
    WAITING_FOR_PATH when ``Identity.recall`` returns None
    (cold-start race). LINKED → CLOSED on link-death. Both CLOSED
    and WAITING_FOR_PATH are recoverable via the backoff timer plus
    the announce-driven wake-up in MirrorLifecycleManager.

    String values round-trip cleanly through the Prometheus label sanitiser.
    """

    IDLE = "idle"
    CONNECTING = "connecting"
    LINKED = "linked"
    CLOSED = "closed"
    WAITING_FOR_PATH = "waiting_for_path"


# Cold-start path-table populates over multiple announces; warn only
# after persistent failures so operator attention isn't drawn early.
_RECALL_WARN_AFTER_ATTEMPTS = 5


class ChannelMirror:
    """Mirrors a remote channel locally by syncing messages."""

    def __init__(
        self,
        remote_destination_hash: bytes,
        channel_id: str,
        ingest_callback=None,
        initial_cursor: int = 0,
        cursor_callback: Optional[Callable[[str, int], None]] = None,
        attempt_callback: Optional[Callable[[str], None]] = None,
    ):
        self.remote_hash = remote_destination_hash
        self.channel_id = channel_id
        self.ingest_callback = ingest_callback
        self._link: Optional[RNS.Link] = None
        self._cursor: int = initial_cursor
        self._cursor_callback = cursor_callback
        self._running = False
        self._reconnect_timer: Optional[threading.Timer] = None

        # All transitions go through _set_state so timer + announce wake-ups can race safely.
        self._state: MirrorState = MirrorState.IDLE
        self._state_lock = threading.Lock()

        # Exponential backoff shared by post-link-death reconnect + cold-start retry.
        self._attempt: int = 0
        self._backoff_base: float = 5.0
        self._max_backoff: float = 300.0

        # Reset on transition out of WAITING_FOR_PATH so recovered mirrors
        # that go cold again log fresh INFO-level recall-None warnings.
        self._recall_none_attempts: int = 0

        # Optional telemetry hook ("success", "recall_none", "link_failed", "handshake_failed").
        self._attempt_callback = attempt_callback

        # Federation auth (set externally after handshake)
        self._authenticated: bool = False
        self._federation_auth: Optional["FederationAuth"] = None
        self._handshake_callback: Optional[Callable[["ChannelMirror"], None]] = None
        self._handshake_response_callback: Optional[Callable[["ChannelMirror", dict], None]] = None
        self._push_ack_callback: Optional[Callable[["ChannelMirror", dict], None]] = None
        self._epoch_manager: Optional["EpochManager"] = None  # Set by daemon for forward secrecy
        self._pending_challenge: Optional[bytes] = None  # Set by handshake orchestrator

    # ────────────────────────────── state ──────────────────────────────

    @property
    def state(self) -> MirrorState:
        return self._state

    def _set_state(self, new_state: MirrorState) -> None:
        """Transition state; caller holds the lock for race-sensitive moves."""
        self._state = new_state

    def _record_attempt(self, result: str) -> None:
        cb = self._attempt_callback
        if cb is None:
            return
        try:
            cb(result)
        except Exception:
            logger.exception("attempt_callback raised; ignored")

    def _get_backoff_delay(self) -> float:
        """Calculate backoff delay with ±25% jitter."""
        delay = min(self._backoff_base * (2**self._attempt), self._max_backoff)
        jitter = delay * 0.25
        return delay + random.uniform(-jitter, jitter)

    # ──────────────────────────── lifecycle ────────────────────────────

    def start(self, reticulum: RNS.Reticulum):
        """Start mirroring by establishing a link to the remote destination."""
        self._running = True
        self._reticulum = reticulum
        self._connect()

    def _connect(self):
        """Establish a link; idempotent under timer + announce-wake races.

        Outcomes: recall() ok → LINKED via callback; recall() None →
        WAITING_FOR_PATH (cold-start, retried by timer or announce wake);
        Link() raises → CLOSED so the existing _on_closed retry handles it.
        """
        with self._state_lock:
            if not self._running:
                return
            if self._state in (MirrorState.CONNECTING, MirrorState.LINKED):
                # Another path beat us to it; nothing to do.
                return
            self._set_state(MirrorState.CONNECTING)

        dest_identity = RNS.Identity.recall(self.remote_hash)
        if not dest_identity:
            self._handle_recall_none()
            return

        try:
            destination = RNS.Destination(
                dest_identity,
                RNS.Destination.OUT,
                RNS.Destination.SINGLE,
                "hokora",
                self.channel_id,
            )

            link = RNS.Link(destination)
            link.set_link_established_callback(self._on_linked)
            link.set_link_closed_callback(self._on_closed)
        except Exception:
            logger.exception("Failed to construct Link for channel %s; will retry", self.channel_id)
            self._record_attempt("link_failed")
            with self._state_lock:
                self._set_state(MirrorState.CLOSED)
            self._schedule_retry()
            return

        with self._state_lock:
            self._link = link

    def _handle_recall_none(self) -> None:
        """Park in WAITING_FOR_PATH; log severity escalates after persistent failures."""
        self._recall_none_attempts += 1
        self._record_attempt("recall_none")
        if self._recall_none_attempts >= _RECALL_WARN_AFTER_ATTEMPTS:
            logger.warning(
                "Cannot recall identity for %s (channel=%s, attempt=%d) — "
                "peer may be offline or path table stale",
                self.remote_hash.hex(),
                self.channel_id,
                self._recall_none_attempts,
            )
        else:
            logger.info(
                "Cannot recall identity for %s (channel=%s, attempt=%d) — "
                "waiting for announce or backoff retry",
                self.remote_hash.hex(),
                self.channel_id,
                self._recall_none_attempts,
            )
        with self._state_lock:
            self._set_state(MirrorState.WAITING_FOR_PATH)
        self._schedule_retry()

    def _schedule_retry(self) -> None:
        """Backoff-retry ``_connect``; idempotent under wake() race via state lock."""
        if not self._running:
            return
        # Cancel any pre-existing timer so backoff doesn't compound.
        if self._reconnect_timer is not None:
            try:
                self._reconnect_timer.cancel()
            except Exception:
                pass
        delay = self._get_backoff_delay()
        self._attempt += 1
        logger.info(
            "Reconnecting mirror for channel %s in %.1fs (attempt %d, state=%s)",
            self.channel_id,
            delay,
            self._attempt,
            self._state.value,
        )
        self._reconnect_timer = threading.Timer(delay, self._reconnect)
        self._reconnect_timer.daemon = True
        self._reconnect_timer.start()

    def wake(self) -> bool:
        """Announce-triggered reconnect; returns True iff a connect was kicked off.

        Only WAITING_FOR_PATH and CLOSED are wake-eligible — LINKED /
        CONNECTING already have a link; IDLE pre-dates ``start()``.
        """
        if not self._running:
            return False
        with self._state_lock:
            if self._state not in (MirrorState.WAITING_FOR_PATH, MirrorState.CLOSED):
                return False
        # Cancel the backoff timer so we attempt immediately.
        if self._reconnect_timer is not None:
            try:
                self._reconnect_timer.cancel()
            except Exception:
                pass
            self._reconnect_timer = None
        self._connect()
        return True

    def stop(self):
        self._running = False
        if self._reconnect_timer:
            self._reconnect_timer.cancel()
            self._reconnect_timer = None
        if self._link:
            self._link.teardown()

    def _on_linked(self, link: RNS.Link):
        logger.info(f"Mirror link established for channel {self.channel_id}")
        self._attempt = 0  # Reset backoff on successful link
        self._recall_none_attempts = 0
        self._record_attempt("success")
        with self._state_lock:
            self._set_state(MirrorState.LINKED)
        self._link.set_packet_callback(self._on_packet)

        # Perform federation handshake if auth is configured
        if self._federation_auth and self._handshake_callback:
            self._handshake_callback(self)
        else:
            self._sync_history()

    def _on_closed(self, link: RNS.Link):
        logger.info(f"Mirror link closed for channel {self.channel_id}")
        self._authenticated = False
        with self._state_lock:
            self._set_state(MirrorState.CLOSED)
            self._link = None
        if self._running:
            self._schedule_retry()

    def _reconnect(self):
        """Attempt to re-establish the mirror link after a delay."""
        if self._running and hasattr(self, "_reticulum"):
            self._connect()

    def _on_packet(self, message, packet):
        """Handle incoming packets on the mirror link."""
        self.handle_response(message)

    def _sync_history(self):
        """Request message history from remote."""
        if not self._link:
            return

        nonce = generate_nonce()
        request = encode_sync_request(
            SYNC_HISTORY,
            nonce,
            {
                "channel_id": self.channel_id,
                "since_seq": self._cursor,
                "limit": 100,
            },
        )

        RNS.Packet(self._link, request).send()

    def handle_response(self, data: bytes):
        """Route handshake responses to the daemon; treat the rest as history sync."""
        try:
            # Forward secrecy: detect and decrypt epoch frames
            from hokora.federation.epoch_wire import is_epoch_frame
            from hokora.constants import EPOCH_ROTATE, EPOCH_ROTATE_ACK, EPOCH_DATA

            if is_epoch_frame(data):
                frame_type = data[0]
                if frame_type == EPOCH_DATA and self._epoch_manager:
                    data = self._epoch_manager.decrypt(data)
                elif frame_type in (EPOCH_ROTATE, EPOCH_ROTATE_ACK):
                    # Rotation frames are part of the handshake state machine.
                    if self._handshake_response_callback:
                        if frame_type == EPOCH_ROTATE_ACK:
                            self._handshake_response_callback(
                                self,
                                {
                                    "action": "federation_handshake",
                                    "step": 6,
                                    "epoch_rotate_ack_frame": data,
                                },
                            )
                        else:
                            # Mid-session rotation from peer.
                            if self._epoch_manager:
                                ack = self._epoch_manager.handle_epoch_rotate(data)
                                if self._link:
                                    RNS.Packet(self._link, ack).send()
                    return

            response = decode_sync_response(data)
            resp_data = response.get("data", {})

            # Route federation handshake responses to the daemon
            if resp_data.get("action") == "federation_handshake":
                if self._handshake_response_callback:
                    self._handshake_response_callback(self, resp_data)
                else:
                    logger.warning(
                        f"Received handshake response but no callback set "
                        f"for channel {self.channel_id}"
                    )
                return

            if resp_data.get("action") == "push_ack":
                if self._push_ack_callback:
                    self._push_ack_callback(self, resp_data)
                return

            messages = resp_data.get("messages", [])
            has_more = resp_data.get("has_more", False)

            for msg_data in messages:
                seq = msg_data.get("seq", 0)
                if seq and seq > self._cursor:
                    self._cursor = seq
                if self.ingest_callback:
                    self.ingest_callback(msg_data)

            if messages and self._cursor_callback:
                self._cursor_callback(self.channel_id, self._cursor)

            if messages:
                logger.info(
                    f"Mirror ingested {len(messages)} messages for "
                    f"{self.channel_id}, cursor={self._cursor}"
                )

            if has_more and self._running:
                self._sync_history()

        except Exception:
            logger.exception("Error handling mirror response")
