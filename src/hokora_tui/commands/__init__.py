# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Command subsystem for the Hokora TUI.

Each /slash command is a separate ``Command`` class in its own file
under this package; the ``CommandRouter`` parses /cmd input and
dispatches to the matching command. ``CommandContext`` carries the
collaborators each command needs (state, db, engine, gate, log) so
commands stay testable in isolation. Shared cross-command helpers
live in ``commands/helpers.py``.
"""

from hokora_tui.commands._base import Command, CommandContext, UIGate
from hokora_tui.commands.router import CommandRouter

__all__ = [
    "Command",
    "CommandContext",
    "UIGate",
    "CommandRouter",
]
