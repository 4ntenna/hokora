# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""ThreadCommand — open a thread overlay rooted at a message hash."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hokora_tui.commands._base import CommandContext


class ThreadCommand:
    """``/thread <msg_hash>`` — open a thread overlay rooted at the message."""

    name = "thread"
    aliases: tuple[str, ...] = ()
    summary = "Open a thread (/thread <msg_hash>)"

    def execute(self, ctx: "CommandContext", args: str) -> None:
        msg_hash = args.strip()
        if not msg_hash:
            ctx.status.set_context("Usage: /thread <msg_hash>")
            return
        ctx.app.open_thread(msg_hash)
        ctx.app._schedule_redraw()
