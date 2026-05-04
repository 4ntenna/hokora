# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""RichMessageClient — LXMF send for user-facing message actions.

Six public methods (send_message + 5 send_typed variants) that all
share the same outbound LXMF construction pattern. Receives DmRouter
ref to access ``lxm_router`` and ``lxmf_source`` for ``handle_outbound``;
receives ChannelLinkManager for link lookup + identity resolution.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Optional

import LXMF
import msgpack
import RNS

from hokora.constants import (
    MSG_DELETE,
    MSG_EDIT,
    MSG_PIN,
    MSG_REACTION,
    MSG_TEXT,
    MSG_THREAD_REPLY,
)

if TYPE_CHECKING:
    from hokora_tui.sync.dm_router import DmRouter
    from hokora_tui.sync.link_manager import ChannelLinkManager
    from hokora_tui.sync.state import SyncState

logger = logging.getLogger(__name__)


class RichMessageClient:
    """LXMF outbound for text + reaction + edit + delete + pin + thread reply."""

    def __init__(
        self,
        link_manager: "ChannelLinkManager",
        dm_router: "DmRouter",
        state: "SyncState",
        identity: Optional[RNS.Identity],
    ) -> None:
        self._link_manager = link_manager
        self._dm_router = dm_router
        self._state = state
        self.identity = identity

    # ── Public API ────────────────────────────────────────────────────

    def send_message(self, channel_id: str, message_data: dict) -> bool:
        """Send a text message via LXMF delivery to the daemon.

        Routed through the daemon's MessageProcessor.ingest() pipeline
        which handles permissions, rate limiting, body validation,
        dedup, sequencing, and live push.
        """
        link = self._link_manager.get_link(channel_id)
        if not link or link.status != RNS.Link.ACTIVE:
            logger.warning("No active link for channel %s, cannot send", channel_id)
            return False

        if not self._dm_router.lxm_router or not self.identity:
            logger.error("No LXMRouter or identity — cannot send LXMF message")
            return False

        self._state.cleanup_stale_nonces()

        # Build msgpack content matching LXMFBridge._decode_content() expectations
        content_dict = {
            "type": message_data.get("type", MSG_TEXT),
            "body": message_data.get("body", ""),
            "display_name": message_data.get("display_name"),
            "channel_id": channel_id,
        }
        if message_data.get("reply_to"):
            content_dict["reply_to"] = message_data["reply_to"]
        content = msgpack.packb(content_dict, use_bin_type=True)

        try:
            dest_identity = self._link_manager.resolve_channel_identity(channel_id, link)
            if not dest_identity:
                logger.warning("No identity for channel %s", channel_id)
                return False

            destination = RNS.Destination(
                dest_identity,
                RNS.Destination.OUT,
                RNS.Destination.SINGLE,
                "lxmf",
                "delivery",
            )

            # Request LXMF path if not yet known
            if not RNS.Transport.has_path(destination.hash):
                RNS.Transport.request_path(destination.hash)

            lxm = LXMF.LXMessage(
                destination,
                self._dm_router.lxmf_source,
                content,
                desired_method=LXMF.LXMessage.DIRECT,
            )
            lxm.try_propagation_on_fail = True
            self._dm_router.lxm_router.handle_outbound(lxm)
            logger.info("Sent LXMF message to channel %s", channel_id)
            return True
        except Exception:
            logger.exception("LXMF send failed")
            return False

    def send_reaction(self, channel_id: str, msg_hash: str, emoji: str) -> bool:
        return self._send_typed_lxmf(channel_id, MSG_REACTION, msg_hash, emoji)

    def send_edit(self, channel_id: str, msg_hash: str, new_body: str) -> bool:
        return self._send_typed_lxmf(channel_id, MSG_EDIT, msg_hash, new_body)

    def send_delete(self, channel_id: str, msg_hash: str) -> bool:
        return self._send_typed_lxmf(channel_id, MSG_DELETE, msg_hash, "")

    def send_pin(self, channel_id: str, msg_hash: str) -> bool:
        return self._send_typed_lxmf(channel_id, MSG_PIN, msg_hash, "")

    def send_thread_reply(self, channel_id: str, root_hash: str, body: str) -> bool:
        return self._send_typed_lxmf(channel_id, MSG_THREAD_REPLY, root_hash, body)

    # ── Internal ──────────────────────────────────────────────────────

    def _send_typed_lxmf(self, channel_id: str, msg_type: int, reply_to: str, body: str) -> bool:
        """Send a typed LXMF message (reaction, edit, delete, pin, thread reply)."""
        link = self._link_manager.get_link(channel_id)
        if not link or link.status != RNS.Link.ACTIVE:
            logger.warning("No active link for channel %s, cannot send", channel_id)
            return False

        if not self._dm_router.lxm_router or not self.identity:
            logger.error("No LXMRouter or identity — cannot send LXMF message")
            return False

        self._state.cleanup_stale_nonces()

        content = msgpack.packb(
            {
                "type": msg_type,
                "reply_to": reply_to,
                "body": body,
                "channel_id": channel_id,
                "display_name": self._state.display_name,
            },
            use_bin_type=True,
        )

        try:
            dest_identity = self._link_manager.resolve_channel_identity(channel_id, link)
            if not dest_identity:
                logger.warning("No identity for channel %s", channel_id)
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
                time.sleep(2)

            lxm = LXMF.LXMessage(
                destination,
                self._dm_router.lxmf_source,
                content,
                desired_method=LXMF.LXMessage.DIRECT,
            )
            lxm.try_propagation_on_fail = True
            self._dm_router.lxm_router.handle_outbound(lxm)
            logger.info("Sent LXMF type=%#x to channel %s", msg_type, channel_id)
            return True
        except Exception:
            logger.exception("LXMF send (type=%#x) failed", msg_type)
            return False
