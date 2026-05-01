# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Centralized reactive state store with observer pattern."""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable

logger = logging.getLogger(__name__)


@dataclass
class AppState:
    """Application-wide reactive state container.

    All state fields live here. UI components subscribe to events via
    ``on(event, callback)`` and get notified when ``emit(event)`` is called.
    Thread-safe redraws are ensured by scheduling through the urwid main loop.
    """

    # Connection
    connection_status: str = "disconnected"  # connected | disconnected | connecting
    connected_node_name: str = ""
    connected_node_hash: str = ""

    # Identity (placeholder until RNS.Identity wiring lands)
    identity: Any = None
    display_name: str = ""
    status_text: str = ""
    auto_announce: bool = False
    announce_interval: int = 300

    # Channels
    channels: list = field(default_factory=list)
    categories: list = field(default_factory=list)
    current_channel_id: str | None = None
    unread_counts: dict = field(default_factory=dict)
    messages: dict = field(default_factory=dict)  # channel_id -> list
    has_more: dict = field(default_factory=dict)  # channel_id -> bool

    # Discovery
    discovered_nodes: dict = field(default_factory=dict)
    discovered_peers: dict = field(default_factory=dict)
    bookmarks: list = field(default_factory=list)

    # Conversations (DMs)
    conversations: list = field(default_factory=list)
    current_conversation_peer: str | None = None
    dm_messages: dict = field(default_factory=dict)  # peer_hash -> list

    # Sync
    sync_profile: dict | None = None
    sync_progress: float = 0.0

    # Internal — not serialized
    _observers: dict[str, list[Callable]] = field(default_factory=lambda: defaultdict(list))
    _loop: Any = None
    _wake_fn: Callable | None = None
    _setting_persister: Callable[[str, str], None] | None = None
    _announcer: Any = None

    def set_loop(self, loop: Any, wake_fn: Callable | None = None) -> None:
        """Register the urwid MainLoop and optional wake function."""
        self._loop = loop
        self._wake_fn = wake_fn

    def set_setting_persister(self, persister: Callable[[str, str], None]) -> None:
        """Inject the client_db persister so settings chokepoints can save.

        Called once during ``HokoraTUI._init_client_db`` after the DB is open.
        Decoupled via injection so ``AppState`` doesn't import ``ClientDB``.
        """
        self._setting_persister = persister

    def set_announcer(self, announcer: Any) -> None:
        """Inject the Announcer reference so lifecycle hooks can be called.

        Used by ``set_auto_announce`` to wake the announce loop on toggle-ON
        for responsive behaviour (otherwise the user waits up to one
        ``announce_interval`` for the next iteration).
        """
        self._announcer = announcer

    # ── Setting chokepoints ──────────────────────────────────────────
    #
    # Single chokepoint per setting: writes the field, persists via the
    # injected DB persister, fires the matching observer event so any
    # subscribed widget across tabs re-renders. Mirrors the chokepoint
    # pattern used elsewhere in the codebase (e.g. sealed_invariant,
    # verify_message_signature, populate_sender_pubkey).

    def set_auto_announce(self, value: bool) -> None:
        """Toggle auto-announce. Persists, broadcasts, wakes the loop."""
        value = bool(value)
        self.auto_announce = value
        if self._setting_persister is not None:
            try:
                self._setting_persister("auto_announce", "true" if value else "false")
            except Exception:
                logger.debug("auto_announce persist failed", exc_info=True)
        if value and self._announcer is not None:
            wake = getattr(self._announcer, "wake", None)
            if callable(wake):
                try:
                    wake()
                except Exception:
                    logger.debug("announcer wake failed", exc_info=True)
        self.emit("auto_announce_changed", value)

    def set_announce_interval(self, value: int) -> int:
        """Set announce interval (seconds). Clamps to [30, 86400], persists,
        broadcasts. Returns the clamped value the caller should display.
        """
        try:
            ival = int(value)
        except (TypeError, ValueError):
            ival = 300
        clamped = max(30, min(ival, 86400))
        self.announce_interval = clamped
        if self._setting_persister is not None:
            try:
                self._setting_persister("announce_interval", str(clamped))
            except Exception:
                logger.debug("announce_interval persist failed", exc_info=True)
        self.emit("announce_interval_changed", clamped)
        return clamped

    def on(self, event: str, callback: Callable) -> None:
        """Subscribe *callback* to *event*."""
        self._observers[event].append(callback)

    def off(self, event: str, callback: Callable) -> None:
        """Unsubscribe *callback* from *event*."""
        try:
            self._observers[event].remove(callback)
        except ValueError:
            pass

    def emit(self, event: str, data: Any = None) -> None:
        """Notify all subscribers of *event*.

        If the urwid loop has been registered, the notification is scheduled
        via ``set_alarm_in(0, ...)`` so it is safe to call from any thread.
        A screen redraw is also scheduled to ensure UI reflects the change.
        """
        if self._loop is not None:
            self._loop.set_alarm_in(0, lambda _loop, _data: self._dispatch_and_redraw(event, data))
            # Wake the event loop so it processes the alarm immediately
            if self._wake_fn:
                self._wake_fn()
        else:
            self._dispatch(event, data)

    def _dispatch(self, event: str, data: Any = None) -> None:
        for cb in list(self._observers.get(event, [])):
            cb(data)

    def _dispatch_and_redraw(self, event: str, data: Any = None) -> None:
        self._dispatch(event, data)
        if self._loop is not None:
            try:
                self._loop.set_alarm_in(0, lambda *_: self._loop.draw_screen())
            except Exception:
                # Loop already shutting down or redraw unavailable — safe to skip.
                logger.debug("redraw schedule failed for event %s", event, exc_info=True)
