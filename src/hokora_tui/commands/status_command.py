# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""StatusCommand — update status text persisted to client DB."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hokora_tui.commands._base import CommandContext


class StatusCommand:
    """``/status <text>`` — set the status text broadcast in profile announces."""

    name = "status"
    aliases: tuple[str, ...] = ()
    summary = "Set your status text (/status <text>)"

    def execute(self, ctx: "CommandContext", args: str) -> None:
        new_status = args.strip()
        if not new_status:
            ctx.status.set_context("Usage: /status <text>")
            return
        ctx.state.status_text = new_status
        if ctx.db is not None:
            ctx.db.set_setting("status_text", new_status)
        ctx.status.set_context(f"Status set to: {new_status}")
