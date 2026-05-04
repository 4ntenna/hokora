# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""SyncCommand — re-sync the current channel's history."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hokora_tui.commands._base import CommandContext


class SyncCommand:
    """``/sync`` — request a fresh history sync for the current channel.

    Useful when the user suspects the local cache is missing messages
    (e.g. after a long disconnect or a manual cursor reset).
    """

    name = "sync"
    aliases: tuple[str, ...] = ()
    summary = "Re-sync the current channel's message history"

    def execute(self, ctx: "CommandContext", args: str) -> None:
        channel_id = ctx.state.current_channel_id
        if not channel_id:
            ctx.status.set_context("No channel selected.")
            return
        if ctx.engine is not None:
            ctx.engine.sync_history(channel_id)
            ctx.status.set_context("Syncing...")
        else:
            ctx.status.set_context("No sync engine connected.")
