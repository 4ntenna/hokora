# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Multi-line status footer widget.

Two-tier context model
----------------------

The middle line carries two kinds of text that fight for the same slot:

* **Context** (background, persistent) — channel breadcrumb, connection
  state, "Resolving path...", etc. Set via :meth:`set_context`. Anyone
  may overwrite at any time; the periodic UI refresh job does so every
  ~2s. This is the steady-state line.

* **Notices** (foreground, sticky) — transient user-facing messages
  ("This channel is read-only", "Message too long", "Cache cleared")
  that must remain readable for a few seconds before the refresh job
  or the next event clobbers them. Set via :meth:`set_notice`.

While a notice is live, ``set_context`` updates the *underlying*
context text but does not render — preserving readability. When the
notice's TTL expires, the latest context text is restored, so the
user sees current state, not stale text.

A second ``set_notice`` cancels the first's pending alarm and replaces
text immediately — replacement is the right default for a TUI footer
where queueing would force the user to read stale messages.

Level styling is text-only: ``warn`` and ``error`` notices get a
``[warn]`` / ``[error]`` prefix plus a distinct palette colour. ``info``
notices render unprefixed with the default info colour. No emoji or
unicode glyphs are used in the rendered notice — operator preference,
to keep the status footer consistent with the daemon's plain-text
log idiom.
"""

from __future__ import annotations

from typing import Any, Optional

import urwid

_DEFAULT_HINT = "Ctrl+Q quit | Tab switch | ? help"

_NOTICE_PREFIX = {
    "info": "",
    "warn": "[warn] ",
    "error": "[error] ",
}

_NOTICE_ATTR = {
    "info": "status_info",
    "warn": "status_connecting",
    "error": "status_error",
}

DEFAULT_NOTICE_DURATION = 4.0


class StatusArea:
    """Three-line footer: connection status, context info, key hints."""

    def __init__(self) -> None:
        self._connection = urwid.Text(("status_disconnected", "○ Disconnected"))
        self._context = urwid.Text(("status_info", ""))
        self._hint = urwid.Text(("default", _DEFAULT_HINT))

        self.widget = urwid.Pile(
            [
                self._connection,
                self._context,
                self._hint,
            ]
        )

        # Two-tier context state.
        self._context_text: str = ""
        self._notice_text: Optional[str] = None
        self._notice_alarm: Any = None  # urwid alarm handle for cancel
        self._loop: Any = None  # urwid.MainLoop, set after construction

    def set_loop(self, loop: Any) -> None:
        """Attach the urwid MainLoop so notice TTLs can be scheduled.

        Called by the app once :meth:`urwid.MainLoop` is constructed —
        same wiring point used by :class:`AppState`. Before the loop is
        attached, ``set_notice`` falls back to immediate render with no
        TTL (the constructor and any pre-loop call sites still work).
        """
        self._loop = loop

    def set_connection(self, status: str, node_name: str = "") -> None:
        """Update the connection indicator line.

        Parameters
        ----------
        status : str
            One of ``"connected"``, ``"disconnected"``, ``"connecting"``,
            ``"recovering"``.
        node_name : str, optional
            Display name of the connected node.
        """
        if status == "connected":
            suffix = f" {node_name}" if node_name else ""
            self._connection.set_text(("status_connected", f"● Connected{suffix}"))
        elif status == "connecting":
            self._connection.set_text(("status_connecting", "◌ Connecting…"))
        elif status == "recovering":
            self._connection.set_text(("status_connecting", "◌ Reconnecting…"))
        else:
            self._connection.set_text(("status_disconnected", "○ Disconnected"))

    def set_context(self, text: str) -> None:
        """Update the persistent context line (channel, peer, etc.).

        While a notice is active, the new text is stored but not
        rendered — the notice keeps the slot until its TTL expires,
        at which point the latest context text is restored.
        """
        self._context_text = text
        if self._notice_text is None:
            self._context.set_text(("status_info", text))

    def set_notice(
        self,
        text: str,
        level: str = "info",
        duration: float = DEFAULT_NOTICE_DURATION,
    ) -> None:
        """Show a sticky transient notice for ``duration`` seconds.

        Parameters
        ----------
        text : str
            The notice text. A level glyph is prepended automatically.
        level : str
            One of ``"info"``, ``"warn"``, ``"error"``. Selects the
            palette attribute and prefix glyph.
        duration : float
            Seconds to remain visible before reverting to the latest
            context text. Clamped to a sane minimum of 0.5s.
        """
        if duration < 0.5:
            duration = 0.5

        prefix = _NOTICE_PREFIX.get(level, _NOTICE_PREFIX["info"])
        attr = _NOTICE_ATTR.get(level, _NOTICE_ATTR["info"])
        self._notice_text = text
        self._context.set_text((attr, f"{prefix}{text}"))

        # Cancel any pending notice expiry — replacement, not queue.
        if self._notice_alarm is not None and self._loop is not None:
            try:
                self._loop.remove_alarm(self._notice_alarm)
            except Exception:
                pass
            self._notice_alarm = None

        if self._loop is not None:
            self._notice_alarm = self._loop.set_alarm_in(
                duration, lambda _l, _d: self._clear_notice()
            )
        # Without a loop (early init / tests), the notice persists until
        # the next set_notice or set_context replaces it. Acceptable —
        # call sites that need TTL run after loop attach.

    def _clear_notice(self) -> None:
        """Internal: revert to the latest context text after TTL expiry."""
        self._notice_text = None
        self._notice_alarm = None
        self._context.set_text(("status_info", self._context_text))

    def set_hint(self, text: str) -> None:
        """Update the keyboard hints line."""
        self._hint.set_text(("default", text))
