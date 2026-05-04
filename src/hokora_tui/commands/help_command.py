# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""HelpCommand — list registered /commands."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hokora_tui.commands._base import CommandContext
    from hokora_tui.commands.router import CommandRouter


class HelpCommand:
    """``/help`` — show all registered commands.

    Holds a reference to the router so we can enumerate commands at
    invocation time (rather than baking the list into a string at
    package-import time).
    """

    name = "help"
    aliases: tuple[str, ...] = ()
    summary = "Show this help message"

    def __init__(self, router: "CommandRouter") -> None:
        self._router = router

    def execute(self, ctx: "CommandContext", args: str) -> None:
        names = sorted("/" + cmd.name for cmd in self._router.known_commands())
        ctx.status.set_context("Commands: " + " ".join(names))
