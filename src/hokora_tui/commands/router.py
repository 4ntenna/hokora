# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""CommandRouter — parses /cmd input and dispatches to the registered Command."""

from __future__ import annotations

import logging
from typing import Optional

from hokora_tui.commands._base import Command, CommandContext

logger = logging.getLogger(__name__)


class CommandRouter:
    """Parses ``/cmd args`` strings and dispatches to a registered Command.

    ``dispatch`` returns False for unrecognised commands — callers may
    use that signal to show an "unknown command" message (app.py
    currently just ignores the return).
    """

    def __init__(self, ctx: CommandContext) -> None:
        self._ctx = ctx
        # name -> Command instance (aliases also resolve here via register)
        self._commands: dict[str, Command] = {}

    # ── Registration ──────────────────────────────────────────────────

    def register(self, command: Command) -> None:
        """Register a Command instance. Indexes by name + every alias."""
        self._commands[command.name] = command
        for alias in command.aliases:
            self._commands[alias] = command

    def register_builtins(self) -> None:
        """Construct + register the built-in commands.

        All 17 /commands flow through CommandRouter.
        """
        from hokora_tui.commands.clear_command import ClearCommand
        from hokora_tui.commands.connect_command import ConnectCommand
        from hokora_tui.commands.disconnect_command import DisconnectCommand
        from hokora_tui.commands.dm_command import DmCommand
        from hokora_tui.commands.dms_command import DmsCommand
        from hokora_tui.commands.download_command import DownloadCommand
        from hokora_tui.commands.help_command import HelpCommand
        from hokora_tui.commands.invite_command import InviteCommand
        from hokora_tui.commands.local_command import LocalCommand
        from hokora_tui.commands.members_command import MembersCommand
        from hokora_tui.commands.name_command import NameCommand
        from hokora_tui.commands.quit_command import QuitCommand
        from hokora_tui.commands.search_command import SearchCommand
        from hokora_tui.commands.status_command import StatusCommand
        from hokora_tui.commands.sync_command import SyncCommand
        from hokora_tui.commands.thread_command import ThreadCommand
        from hokora_tui.commands.upload_command import UploadCommand

        # Help needs a router ref so it can enumerate registered commands.
        self.register(HelpCommand(self))
        self.register(QuitCommand())
        self.register(ClearCommand())
        self.register(DisconnectCommand())
        self.register(SyncCommand())
        self.register(NameCommand())
        self.register(StatusCommand())
        self.register(LocalCommand())
        self.register(ConnectCommand())
        self.register(DmCommand())
        self.register(DmsCommand())
        self.register(InviteCommand())
        self.register(SearchCommand())
        self.register(ThreadCommand())
        self.register(MembersCommand())
        self.register(UploadCommand())
        self.register(DownloadCommand())

    def known_commands(self) -> list[Command]:
        """Distinct registered Commands (not duplicated by alias)."""
        seen: dict[int, Command] = {}
        for cmd in self._commands.values():
            seen.setdefault(id(cmd), cmd)
        return list(seen.values())

    # ── Dispatch ──────────────────────────────────────────────────────

    def dispatch(self, text: str) -> bool:
        """Parse a leading ``/cmd`` token and dispatch to its Command.

        Returns True if a registered command handled the input; False if
        the input did not start with a known /cmd, letting callers fall
        through to a non-router dispatch path.

        Any exception raised by a command is logged and swallowed —
        commands run on the urwid event loop and an unhandled raise
        would terminate the TUI.
        """
        parsed = self._parse(text)
        if parsed is None:
            return False
        name, args = parsed
        cmd = self._commands.get(name)
        if cmd is None:
            return False
        try:
            cmd.execute(self._ctx, args)
        except Exception:
            logger.exception("Command /%s raised", name)
        return True

    def _parse(self, text: str) -> Optional[tuple[str, str]]:
        """Split ``/cmd args...`` into (name_without_slash, args_str).

        Returns None if ``text`` is empty or doesn't start with ``/``.
        Command names are case-insensitive; args are passed through verbatim
        (commands handle their own arg parsing).
        """
        text = text.strip()
        if not text or not text.startswith("/"):
            return None
        parts = text[1:].split(None, 1)
        if not parts:
            return None
        name = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""
        return name, args
