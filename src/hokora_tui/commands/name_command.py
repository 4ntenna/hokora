# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""NameCommand — update display name persisted to client DB + sync engine."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hokora_tui.commands._base import CommandContext


class NameCommand:
    """``/name <new_name>`` — set the display name shown to peers.

    Persists to the client DB and pushes to the sync engine so subsequent
    LXMF messages carry the new name.
    """

    name = "name"
    aliases: tuple[str, ...] = ()
    summary = "Set your display name (/name <text>)"

    def execute(self, ctx: "CommandContext", args: str) -> None:
        new_name = args.strip()
        if not new_name:
            ctx.status.set_context("Usage: /name <display_name>")
            return
        ctx.state.display_name = new_name
        if ctx.engine is not None:
            ctx.engine.set_display_name(new_name)
        if ctx.db is not None:
            ctx.db.set_setting("display_name", new_name)
        ctx.status.set_context(f"Display name set to: {new_name}")
