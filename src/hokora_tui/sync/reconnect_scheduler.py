# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""ReconnectScheduler — exponential-backoff reconnect driver.

Transport-agnostic. Activated by ChannelLinkManager's on_closed callback
when reconnect targets remain and the user didn't explicitly disconnect.
Works identically for TCP resets, I2P tunnel rebuilds, LoRa dropouts.

Thread model: the backoff loop runs on a daemon thread (hokora-reconnect).
Stop signaling uses a threading.Event so a sleep is interruptible. The
loop exits cleanly when a link becomes live again or the user disconnects.
"""

from __future__ import annotations

import logging
import random
import threading
from typing import TYPE_CHECKING, Callable, Optional

if TYPE_CHECKING:
    from hokora_tui.sync.link_manager import ChannelLinkManager

logger = logging.getLogger(__name__)


class ReconnectScheduler:
    """Exponential-backoff reconnect driver."""

    BACKOFF_SCHEDULE: tuple[int, ...] = (1, 2, 5, 10, 30, 60)
    BACKOFF_JITTER: float = 0.2  # ±20% jitter per step to avoid thundering herd

    def __init__(
        self,
        link_manager: "ChannelLinkManager",
        on_recovering: Optional[Callable[[dict], None]] = None,
    ) -> None:
        self._link_manager = link_manager
        self._on_recovering = on_recovering
        # channel_id -> destination_hash; every target we want to keep alive
        self._targets: dict[str, bytes] = {}
        # Set only by explicit user teardown; disambiguates transient drop
        # from user quit.
        self._user_disconnected: bool = False
        self._reconnect_thread: Optional[threading.Thread] = None
        self._reconnect_stop: threading.Event = threading.Event()
        self._reconnect_attempt: int = 0

    # ── Public API ────────────────────────────────────────────────────

    def add_target(self, channel_id: str, destination_hash: bytes) -> None:
        self._targets[channel_id] = destination_hash

    def remove_target(self, channel_id: str) -> None:
        self._targets.pop(channel_id, None)

    def clear_targets(self) -> None:
        self._targets.clear()

    def targets_snapshot(self) -> dict[str, bytes]:
        """Live reference to targets (for backward-compat shim). Callers must
        not mutate — use add_target / remove_target / clear_targets."""
        return self._targets

    def mark_user_disconnected(self) -> None:
        """Called on explicit user teardown (disconnect_all). Suppresses
        auto-reconnect and signals the loop to exit."""
        self._user_disconnected = True
        self._reconnect_stop.set()

    def reset_user_disconnected(self) -> None:
        """Called on a new user-initiated connect — clears the flag so the
        scheduler becomes eligible again."""
        self._user_disconnected = False

    def is_user_disconnected(self) -> bool:
        return self._user_disconnected

    def reset_attempt(self) -> None:
        """Clear backoff counter; call after a successful reconnect so the
        next drop starts fast again."""
        self._reconnect_attempt = 0
        self._reconnect_stop.set()

    def trigger(self) -> None:
        """Decide whether to start the backoff loop.

        Idempotent: if a loop is already running, does nothing. Starts a
        new loop only when: (a) we still have targets to keep alive,
        (b) the user didn't explicitly disconnect, (c) no thread is running.
        """
        if not self._targets or self._user_disconnected:
            return
        if self._reconnect_thread and self._reconnect_thread.is_alive():
            return
        self._reconnect_stop.clear()
        self._reconnect_attempt = 0
        t = threading.Thread(
            target=self._loop,
            name="hokora-reconnect",
            daemon=True,
        )
        self._reconnect_thread = t
        t.start()

    def stop(self) -> None:
        """Signal the backoff loop to exit. Safe to call whether or not a
        loop is running."""
        self._reconnect_stop.set()

    def set_on_recovering(self, cb: Callable[[dict], None]) -> None:
        self._on_recovering = cb

    @property
    def stop_event(self) -> threading.Event:
        """Expose the stop event for backward-compat shim on SyncEngine
        (existing callers may read ``engine._reconnect_stop``)."""
        return self._reconnect_stop

    # ── Internal backoff loop ─────────────────────────────────────────

    def _loop(self) -> None:
        max_step = len(self.BACKOFF_SCHEDULE) - 1
        while not self._reconnect_stop.is_set():
            # Exit if the user explicitly disconnected while we were sleeping.
            if self._user_disconnected or not self._targets:
                return
            # Already recovered? (another channel reconnect succeeded)
            if self._link_manager.any_active():
                logger.info("Reconnect loop: a link is live again, exiting")
                self._reconnect_attempt = 0
                return

            step = min(self._reconnect_attempt, max_step)
            base = self.BACKOFF_SCHEDULE[step]
            jitter = base * self.BACKOFF_JITTER
            delay = max(0.1, base + random.uniform(-jitter, jitter))
            self._reconnect_attempt += 1

            if self._on_recovering:
                try:
                    self._on_recovering(
                        {
                            "attempt": self._reconnect_attempt,
                            "next_retry_in": delay,
                            "targets": list(self._targets.keys()),
                        }
                    )
                except Exception:
                    logger.exception("on_recovering callback raised")

            # Interruptible wait for the backoff interval.
            if self._reconnect_stop.wait(delay):
                return

            # Attempt to reconnect every target that isn't currently connected.
            for ch_id, dest_hash in list(self._targets.items()):
                if self._reconnect_stop.is_set() or self._user_disconnected:
                    return
                if self._link_manager.is_connected(ch_id):
                    continue
                try:
                    logger.info(
                        "Reconnect attempt %d for channel %s",
                        self._reconnect_attempt,
                        ch_id,
                    )
                    self._link_manager.connect_channel(dest_hash, ch_id)
                except Exception:
                    logger.exception("Reconnect attempt failed for channel %s", ch_id)
