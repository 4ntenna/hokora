# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""CdspClient — CDSP session lifecycle + profile updates + deferred-item replay.

CDSP (Client Data Sync Profile) lets the daemon serve bandwidth-adapted
sync profiles (FULL / PRIORITIZED / MINIMAL / BATCHED). This client:

  - sends SYNC_CDSP_SESSION_INIT on link establishment
  - preserves ``resume_token`` across reconnects so the daemon can flush
    deferred events on resume
  - sends SYNC_CDSP_PROFILE_UPDATE when the user changes profile
  - extracts state from ``cdsp_session_ack`` / ``cdsp_profile_ack`` /
    ``cdsp_session_reject`` responses and returns the ``flushed_items``
    list to the caller for replay into the event pipeline

State (session_id, resume_token, sync_profile, deferred_count) lives in
``SyncState`` and is shared with other subsystems; this class is a thin
accessor + wire-sender.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Optional

import RNS

from hokora.constants import (
    CDSP_PROFILE_FULL,
    CDSP_VERSION,
    SYNC_CDSP_PROFILE_UPDATE,
    SYNC_CDSP_SESSION_INIT,
)
from hokora.protocol.wire import encode_sync_request, generate_nonce

if TYPE_CHECKING:
    from hokora_tui.sync.dm_router import DmRouter
    from hokora_tui.sync.link_manager import ChannelLinkManager
    from hokora_tui.sync.state import SyncState

logger = logging.getLogger(__name__)


class CdspClient:
    """CDSP session lifecycle subsystem."""

    def __init__(
        self,
        link_manager: "ChannelLinkManager",
        dm_router: "DmRouter",
        state: "SyncState",
    ) -> None:
        self._link_manager = link_manager
        self._dm_router = dm_router
        self._state = state

    # ── Public API ────────────────────────────────────────────────────

    def set_profile(self, profile: int) -> None:
        """Update desired profile for new/future session inits. Does not
        push the update to the daemon — call ``update_profile_all`` for
        that."""
        self._state.sync_profile = profile

    def current_profile(self) -> int:
        return self._state.sync_profile

    def session_id(self) -> Optional[str]:
        return self._state.cdsp_session_id

    def resume_token(self) -> Optional[bytes]:
        return self._state.resume_token

    def deferred_count(self) -> int:
        return self._state.deferred_count

    def init_session(self, channel_id: str) -> None:
        """Send SYNC_CDSP_SESSION_INIT. Carries resume_token if present."""
        link = self._link_manager.get_link(channel_id)
        if not link or link.status != RNS.Link.ACTIVE:
            return

        nonce = generate_nonce()
        self._state.pending_nonces[nonce] = time.time()

        lxmf_source = self._dm_router.lxmf_source
        payload = {
            "cdsp_version": CDSP_VERSION,
            "sync_profile": self._state.sync_profile,
            "lxmf_destination": lxmf_source.hexhash if lxmf_source else None,
        }
        if self._state.resume_token:
            payload["resume_token"] = self._state.resume_token

        request = encode_sync_request(SYNC_CDSP_SESSION_INIT, nonce, payload)
        RNS.Packet(link, request).send()

    def update_profile(self, channel_id: str, new_profile: int) -> None:
        """Send SYNC_CDSP_PROFILE_UPDATE. No-op if no active session."""
        link = self._link_manager.get_link(channel_id)
        if not link or link.status != RNS.Link.ACTIVE:
            return
        if not self._state.cdsp_session_id:
            logger.warning("No CDSP session — cannot update profile")
            return

        nonce = generate_nonce()
        self._state.pending_nonces[nonce] = time.time()

        request = encode_sync_request(
            SYNC_CDSP_PROFILE_UPDATE,
            nonce,
            {
                "session_id": self._state.cdsp_session_id,
                "sync_profile": new_profile,
            },
        )
        RNS.Packet(link, request).send()
        self._state.sync_profile = new_profile

    def update_profile_all(self, new_profile: int) -> None:
        """Apply profile update to every active channel link."""
        self._state.sync_profile = new_profile
        for ch_id in list(self._link_manager.links_snapshot().keys()):
            self.update_profile(ch_id, new_profile)

    # ── Response handlers ────────────────────────────────────────────

    def handle_session_ack(self, data: dict) -> list[dict]:
        """Extract session state from an ack. Returns ``flushed_items`` (may
        be empty) for the caller to replay into the event pipeline."""
        self._state.cdsp_session_id = data.get("session_id")
        # Resume token only present on fresh sessions; preserve the prior
        # token across resumes so the next reconnect can also resume.
        new_token = data.get("resume_token")
        if new_token is not None:
            self._state.resume_token = new_token
        self._state.deferred_count = data.get("deferred_count", 0)
        self._state.sync_profile = data.get("accepted_profile", CDSP_PROFILE_FULL)
        logger.info(
            "CDSP session established: %s profile=%#x deferred=%d",
            self._state.cdsp_session_id,
            self._state.sync_profile,
            self._state.deferred_count,
        )
        return data.get("flushed_items") or []

    def handle_profile_ack(self, data: dict) -> None:
        self._state.sync_profile = data.get("accepted_profile", self._state.sync_profile)
        self._state.deferred_count = data.get("deferred_count", 0)
        logger.info("CDSP profile updated to %#x", self._state.sync_profile)

    def handle_session_reject(self, data: dict) -> None:
        logger.warning("CDSP session rejected: error_code=%s", data.get("error_code"))
