# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""MembersCommand — request the current channel's member list."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hokora_tui.commands._base import CommandContext


class MembersCommand:
    """``/members`` — request the member list for the current channel."""

    name = "members"
    aliases: tuple[str, ...] = ()
    summary = "Show channel members"

    def execute(self, ctx: "CommandContext", args: str) -> None:
        channel_id = ctx.state.current_channel_id
        if not channel_id:
            ctx.status.set_notice("Select a channel first.", level="warn")
            return
        if ctx.engine is not None:
            ctx.engine.get_member_list(channel_id)
            ctx.status.set_notice("Requesting member list...", level="info")
        else:
            ctx.status.set_notice("Not connected.", level="warn")
