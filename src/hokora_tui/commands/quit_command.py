# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""QuitCommand — exit the TUI."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hokora_tui.commands._base import CommandContext


class QuitCommand:
    """``/quit`` (alias ``/q``) — clean shutdown of the TUI.

    Calls ``app.quit()`` which tears down the sync engine, stops the
    announcer, and exits the urwid main loop.
    """

    name = "quit"
    aliases: tuple[str, ...] = ("q",)
    summary = "Exit the TUI"

    def execute(self, ctx: "CommandContext", args: str) -> None:
        ctx.app.quit()
