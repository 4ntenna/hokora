# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""DmCommand — open a DM conversation, optionally with an initial message."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hokora_tui.commands._base import CommandContext


class DmCommand:
    """``/dm <peer_hash> [message]`` — open a DM conversation.

    With only ``peer_hash``: opens the conversation in the Conversations
    tab. With both: also sends ``message`` immediately.
    """

    name = "dm"
    aliases: tuple[str, ...] = ()
    summary = "Open a direct-message conversation (/dm <hash> [message])"

    def execute(self, ctx: "CommandContext", args: str) -> None:
        if not args.strip():
            ctx.status.set_notice("Usage: /dm <peer_hash> [message]", level="warn", duration=5.0)
            return

        parts = args.strip().split(None, 1)
        peer_hash = parts[0]
        message = parts[1] if len(parts) > 1 else None

        # Validate hash format (hex string + length); RNS hashes are 32 hex chars.
        try:
            int(peer_hash, 16)
            if len(peer_hash) != 32:
                raise ValueError("expected 32 hex chars")
        except ValueError:
            ctx.status.set_notice(
                f"Invalid peer hash: {peer_hash}",
                level="error",
                duration=5.0,
            )
            return

        # Switch to Conversations tab (index 4)
        if hasattr(ctx.app, "nav"):
            ctx.app.nav.switch_to(4)

        conversations_view = getattr(ctx.app, "conversations_view", None)
        if conversations_view is not None:
            conversations_view.open_dm(peer_hash, initial_message=message)
        else:
            ctx.status.set_notice(
                "Conversations view not available.",
                level="error",
            )

        ctx.app._schedule_redraw()
