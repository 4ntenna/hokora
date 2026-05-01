# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""DmsCommand — switch to the Conversations tab."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hokora_tui.commands._base import CommandContext


class DmsCommand:
    """``/dms`` — switch to the Conversations tab to view all DM threads."""

    name = "dms"
    aliases: tuple[str, ...] = ()
    summary = "Switch to the Conversations tab"

    def execute(self, ctx: "CommandContext", args: str) -> None:
        if hasattr(ctx.app, "nav"):
            ctx.app.nav.switch_to(4)
        ctx.status.set_context("Conversations")
        ctx.app._schedule_redraw()
