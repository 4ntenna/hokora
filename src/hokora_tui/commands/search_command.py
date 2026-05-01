# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""SearchCommand — open the search overlay."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hokora_tui.commands._base import CommandContext


class SearchCommand:
    """``/search`` — open the search overlay on the Channels tab."""

    name = "search"
    aliases: tuple[str, ...] = ()
    summary = "Open message search"

    def execute(self, ctx: "CommandContext", args: str) -> None:
        # Switch to Channels tab if not there
        if hasattr(ctx.app, "nav") and ctx.app.nav.active_tab != 3:
            ctx.app.nav.switch_to(3)
        ctx.app.open_search()
        ctx.app._schedule_redraw()
