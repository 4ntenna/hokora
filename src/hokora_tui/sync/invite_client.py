# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""InviteClient — invite lifecycle: create, list, redeem.

Three send methods + three response handlers + one callback registry.
``handle_invite_created`` and ``handle_invite_list`` share a single
``invite_callback`` registry but emit different event types to the
SyncEngine event_callback so views can disambiguate.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Callable, Optional

import RNS

from hokora.constants import (
    SYNC_CREATE_INVITE,
    SYNC_LIST_INVITES,
    SYNC_REDEEM_INVITE,
)
from hokora.protocol.wire import encode_sync_request, generate_nonce

if TYPE_CHECKING:
    from hokora_tui.sync.link_manager import ChannelLinkManager
    from hokora_tui.sync.state import SyncState

logger = logging.getLogger(__name__)


class InviteClient:
    """Invite lifecycle subsystem."""

    def __init__(
        self,
        link_manager: "ChannelLinkManager",
        state: "SyncState",
    ) -> None:
        self._link_manager = link_manager
        self._state = state
        self._on_result: Optional[Callable] = None

    # ── Sync requests ─────────────────────────────────────────────────

    def create_invite(self, channel_id: str, max_uses: int = 1, expiry_hours: int = 72) -> None:
        """Send SYNC_CREATE_INVITE. Uses any active link."""
        link = self._link_manager.find_active_link()
        if not link:
            logger.warning("No active link for create_invite")
            return
        nonce = generate_nonce()
        self._state.pending_nonces[nonce] = time.time()
        request = encode_sync_request(
            SYNC_CREATE_INVITE,
            nonce,
            {
                "channel_id": channel_id,
                "max_uses": max_uses,
                "expiry_hours": expiry_hours,
            },
        )
        RNS.Packet(link, request).send()

    def list_invites(self, channel_id: Optional[str] = None) -> None:
        """Send SYNC_LIST_INVITES. Uses any active link."""
        link = self._link_manager.find_active_link()
        if not link:
            logger.warning("No active link for list_invites")
            return
        nonce = generate_nonce()
        self._state.pending_nonces[nonce] = time.time()
        request = encode_sync_request(
            SYNC_LIST_INVITES,
            nonce,
            {"channel_id": channel_id},
        )
        RNS.Packet(link, request).send()

    def redeem_invite(self, channel_id: str, token: str) -> None:
        """Send an invite redemption request over a channel link."""
        link = self._link_manager.get_link(channel_id)
        if not link or link.status != RNS.Link.ACTIVE:
            logger.warning("No active link for channel %s", channel_id)
            return
        nonce = generate_nonce()
        self._state.pending_nonces[nonce] = time.time()
        request = encode_sync_request(
            SYNC_REDEEM_INVITE,
            nonce,
            {"token": token},
        )
        RNS.Packet(link, request).send()

    # ── Callback registry ─────────────────────────────────────────────

    def set_on_result(self, cb: Optional[Callable]) -> None:
        self._on_result = cb

    # ── Response handlers ─────────────────────────────────────────────

    def handle_invite_created(self, data: dict, event_callback: Optional[Callable]) -> None:
        if self._on_result:
            self._on_result(data)
        if event_callback:
            event_callback("invite_created", data)

    def handle_invite_list(self, data: dict, event_callback: Optional[Callable]) -> None:
        if self._on_result:
            self._on_result(data)
        if event_callback:
            event_callback("invite_list", data)

    def handle_invite_redeemed(self, data: dict, event_callback: Optional[Callable]) -> None:
        # No on_result for redeems — event_callback is the only path.
        if event_callback:
            event_callback("invite_redeemed", data)
