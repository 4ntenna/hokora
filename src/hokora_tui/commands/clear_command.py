# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""ClearCommand — clear the current channel's message view."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hokora_tui.commands._base import CommandContext


class ClearCommand:
    """``/clear`` — clear the current channel's message view.

    Resets the on-screen message list (does not touch the client DB).
    Useful when the buffer is full of stale chatter and the user wants
    a clean slate before sending or following along.
    """

    name = "clear"
    aliases: tuple[str, ...] = ()
    summary = "Clear the current channel's message view"

    def execute(self, ctx: "CommandContext", args: str) -> None:
        messages_view = getattr(ctx.app, "messages_view", None)
        if messages_view is not None:
            messages_view.clear()
        ctx.status.set_context("Messages cleared.")
        ctx.app._schedule_redraw()
