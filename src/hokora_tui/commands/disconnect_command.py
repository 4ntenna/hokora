# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""DisconnectCommand — tear down sync engine links + clear connection state."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hokora_tui.commands._base import CommandContext

logger = logging.getLogger(__name__)


class DisconnectCommand:
    """``/disconnect`` — tear down channel links + clear UI connection state.

    Keeps the sync engine alive (LXMRouter and RNS identity must persist
    so a subsequent ``/connect`` doesn't hit "already registered
    destination" errors).
    """

    name = "disconnect"
    aliases: tuple[str, ...] = ()
    summary = "Disconnect from current node"

    def execute(self, ctx: "CommandContext", args: str) -> None:
        logger.info("/disconnect: tearing down connections")

        if ctx.engine is not None:
            try:
                ctx.engine.disconnect_all()
            except Exception as exc:
                logger.warning("/disconnect: disconnect_all error: %s", exc)
            logger.info("/disconnect: links torn down, engine kept alive")

        ctx.state.channels = []
        ctx.state.messages = {}
        ctx.state.current_channel_id = None
        ctx.state.connection_status = "disconnected"
        ctx.state.connected_node_name = ""
        ctx.state.connected_node_hash = ""
        ctx.state.unread_counts = {}

        ctx.state.emit("channels_updated")

        ctx.status.set_connection("disconnected")
        ctx.status.set_context("Disconnected.")

        messages_view = getattr(ctx.app, "messages_view", None)
        if messages_view is not None:
            messages_view.clear()

        ctx.app._schedule_redraw()
