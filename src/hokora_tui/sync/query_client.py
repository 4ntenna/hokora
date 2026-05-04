# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""QueryClient — read-side sync queries: search, threads, pins, member list.

Owns four request senders and four response handlers + four callback
setters. Each response handler fires its registered callback (for
consumers like SearchView) and the event_callback supplied by
SyncEngine at dispatch time (for views that subscribe via on_event).
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Callable, Optional

import RNS

from hokora.constants import (
    SYNC_GET_MEMBER_LIST,
    SYNC_GET_PINS,
    SYNC_SEARCH,
    SYNC_THREAD,
)
from hokora.protocol.wire import encode_sync_request, generate_nonce

if TYPE_CHECKING:
    from hokora_tui.sync.link_manager import ChannelLinkManager
    from hokora_tui.sync.state import SyncState

logger = logging.getLogger(__name__)


class QueryClient:
    """Read-side queries subsystem."""

    def __init__(
        self,
        link_manager: "ChannelLinkManager",
        state: "SyncState",
    ) -> None:
        self._link_manager = link_manager
        self._state = state
        self._on_search: Optional[Callable] = None
        self._on_thread: Optional[Callable] = None
        self._on_pins: Optional[Callable] = None
        self._on_member_list: Optional[Callable] = None

    # ── Sync requests ─────────────────────────────────────────────────

    def search(self, channel_id: str, query: str, limit: int = 20) -> None:
        """Send SYNC_SEARCH to search messages in a channel."""
        link = self._link_manager.get_link(channel_id)
        if not link or link.status != RNS.Link.ACTIVE:
            logger.warning("No active link for channel %s", channel_id)
            return
        self._state.cleanup_stale_nonces()
        nonce = generate_nonce()
        self._state.pending_nonces[nonce] = time.time()
        request = encode_sync_request(
            SYNC_SEARCH,
            nonce,
            {
                "channel_id": channel_id,
                "query": query,
                "limit": limit,
            },
        )
        RNS.Packet(link, request).send()

    def get_thread(self, root_hash: str, limit: int = 50) -> None:
        """Send SYNC_THREAD to fetch thread messages. Uses any active link."""
        link = self._link_manager.find_active_link()
        if not link:
            logger.warning("No active link for thread request")
            return
        self._state.cleanup_stale_nonces()
        nonce = generate_nonce()
        self._state.pending_nonces[nonce] = time.time()
        request = encode_sync_request(
            SYNC_THREAD,
            nonce,
            {"root_hash": root_hash, "limit": limit},
        )
        RNS.Packet(link, request).send()

    def get_pins(self, channel_id: str) -> None:
        """Send SYNC_GET_PINS to fetch pinned messages for a channel."""
        link = self._link_manager.get_link(channel_id)
        if not link or link.status != RNS.Link.ACTIVE:
            logger.warning("No active link for channel %s", channel_id)
            return
        self._state.cleanup_stale_nonces()
        nonce = generate_nonce()
        self._state.pending_nonces[nonce] = time.time()
        request = encode_sync_request(
            SYNC_GET_PINS,
            nonce,
            {"channel_id": channel_id},
        )
        RNS.Packet(link, request).send()

    def get_member_list(self, channel_id: str, limit: int = 50, offset: int = 0) -> None:
        """Send SYNC_GET_MEMBER_LIST to fetch channel members."""
        link = self._link_manager.get_link(channel_id)
        if not link or link.status != RNS.Link.ACTIVE:
            logger.warning("No active link for channel %s", channel_id)
            return
        self._state.cleanup_stale_nonces()
        nonce = generate_nonce()
        self._state.pending_nonces[nonce] = time.time()
        request = encode_sync_request(
            SYNC_GET_MEMBER_LIST,
            nonce,
            {"channel_id": channel_id, "limit": limit, "offset": offset},
        )
        RNS.Packet(link, request).send()

    # ── Callback setters ──────────────────────────────────────────────

    def set_on_search(self, cb: Optional[Callable]) -> None:
        self._on_search = cb

    def set_on_thread(self, cb: Optional[Callable]) -> None:
        self._on_thread = cb

    def set_on_pins(self, cb: Optional[Callable]) -> None:
        self._on_pins = cb

    def set_on_member_list(self, cb: Optional[Callable]) -> None:
        self._on_member_list = cb

    # ── Response handlers ────────────────────────────────────────────

    def handle_search(self, data: dict, event_callback: Optional[Callable]) -> None:
        if self._on_search:
            self._on_search(data)
        if event_callback:
            event_callback("search_results", data)

    def handle_thread(self, data: dict, event_callback: Optional[Callable]) -> None:
        if self._on_thread:
            self._on_thread(data)
        if event_callback:
            event_callback("thread_messages", data)

    def handle_pins(self, data: dict, event_callback: Optional[Callable]) -> None:
        if self._on_pins:
            self._on_pins(data)
        if event_callback:
            event_callback("pinned_messages", data)

    def handle_member_list(self, data: dict, event_callback: Optional[Callable]) -> None:
        if self._on_member_list:
            self._on_member_list(data)
        if event_callback:
            event_callback("member_list", data)
