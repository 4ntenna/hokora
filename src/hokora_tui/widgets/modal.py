# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Modal overlay system for the TUI."""

from __future__ import annotations

from typing import TYPE_CHECKING

import urwid

if TYPE_CHECKING:
    from hokora_tui.app import HokoraTUI


class Modal:
    """Static utility for showing/closing modal overlays on the app frame."""

    # Store the saved body so close() can restore it
    _saved_body: urwid.Widget | None = None

    @staticmethod
    def show(
        app: HokoraTUI,
        title: str,
        body_widget: urwid.Widget,
        width: int = 60,
        height: int = 20,
    ) -> None:
        """Show a modal overlay centered on the screen.

        Parameters
        ----------
        app : HokoraTUI
            The application instance.
        title : str
            Title for the LineBox border.
        body_widget : urwid.Widget
            The widget to display inside the modal.
        width : int
            Width as a relative percentage (0-100).
        height : int
            Height as a relative percentage (0-100).
        """
        Modal._saved_body = app.frame.body

        linebox = urwid.LineBox(body_widget, title=title)
        styled = urwid.AttrMap(linebox, "modal_border")

        overlay = urwid.Overlay(
            styled,
            Modal._saved_body,
            align="center",
            width=("relative", width),
            valign="middle",
            height=("relative", height),
        )

        app.frame.body = overlay
        app._schedule_redraw()

    @staticmethod
    def close(app: HokoraTUI) -> None:
        """Close the current modal and restore the previous body."""
        if Modal._saved_body is not None:
            app.frame.body = Modal._saved_body
            Modal._saved_body = None
            app._schedule_redraw()
