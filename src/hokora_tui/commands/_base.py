# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Base types for the command subsystem: Command Protocol, CommandContext, UIGate."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Optional, Protocol, runtime_checkable

if TYPE_CHECKING:
    import urwid

    from hokora_tui.app import HokoraTUI


@runtime_checkable
class Command(Protocol):
    """One /slash command implemented as one class.

    Lifecycle: ``CommandRouter`` parses ``/cmd args`` from a keypress,
    looks up the registered Command instance by ``name`` (or alias),
    and calls ``execute(ctx, args)``. The command may spawn background
    threads for I/O; all UI updates must be marshalled through
    ``ctx.gate`` to the urwid main loop.
    """

    name: str
    """Canonical command name without the leading slash, e.g. ``"local"``."""

    aliases: tuple[str, ...]
    """Alternate names for the same command, also without leading slash.
    For example, ``/q`` is an alias for ``/quit``."""

    summary: str
    """One-line help text displayed by ``/help``."""

    def execute(self, ctx: "CommandContext", args: str) -> None:
        """Execute the command. ``args`` is the raw remainder string after
        ``/cmd``; the command parses it however it likes (most commands
        treat it as a single argument).

        Sync by design: most commands do their own background-thread
        spawning for I/O and use ``ctx.gate`` to marshal results back
        to the urwid loop.
        """
        ...


@dataclass
class CommandContext:
    """Everything a command needs. Injected at dispatch time, not closed over.

    Passing ``CommandContext`` to ``execute`` at dispatch time — rather
    than having commands close over ``app`` — eliminates late-binding
    hazards when background callbacks run on a later urwid tick and
    makes commands trivially testable with ``MagicMock`` injection.
    """

    app: "HokoraTUI"
    """The TUI root. Prefer the narrower fields (state, db, engine) when
    they're sufficient; ``app`` is here for handlers that need broader
    reach."""

    state: Any
    """The application state container (hokora_tui.state.AppState)."""

    db: Any
    """The client-side SQLite cache (hokora_tui.client_db.ClientDB)."""

    engine: Any
    """The sync engine facade (hokora_tui.sync_engine.SyncEngine)."""

    gate: "UIGate"
    """Helper for marshalling state-mutating callables to the urwid main
    loop tick. Use this from any background thread."""

    log: logging.Logger
    """Per-command logger; the router supplies one named after the command."""

    status: Any
    """The status-area widget for setting context/connection text."""

    emit: Callable[[str, dict], None]
    """Forward an event into the app's state event bus. Views subscribe
    to events to refresh themselves."""


class UIGate:
    """Marshal a state-mutating callable to the urwid main loop tick.

    All RNS-thread / background-thread updates that touch widgets MUST
    go through here — urwid is single-threaded.
    """

    def __init__(self, loop: Optional["urwid.MainLoop"]) -> None:
        self._loop = loop

    def schedule(self, fn: Callable[..., None], *args: Any, delay: float = 0.0) -> None:
        """Schedule ``fn(*args)`` to run on the urwid main thread.

        ``delay`` is seconds; 0 means "next tick". A None loop (e.g. in
        tests) silently no-ops — the test will assert on calls a different
        way (mocked gate, or directly invoking fn).
        """
        if self._loop is None:
            return
        self._loop.set_alarm_in(delay, lambda _loop, _data: fn(*args))
