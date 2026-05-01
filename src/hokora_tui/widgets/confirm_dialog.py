# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Confirm dialog — Yes/No modal using the Modal system."""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable

import urwid

from hokora_tui.widgets.hokora_button import HokoraButton
from hokora_tui.widgets.modal import Modal

if TYPE_CHECKING:
    from hokora_tui.app import HokoraTUI


class ConfirmDialog:
    """Static utility for showing a Yes/No confirmation dialog."""

    @staticmethod
    def show(
        app: HokoraTUI,
        message: str,
        on_confirm: Callable[[], None],
        on_cancel: Callable[[], None] | None = None,
    ) -> None:
        """Show a confirmation dialog with Yes/No buttons.

        Parameters
        ----------
        app : HokoraTUI
            The application instance.
        message : str
            The message to display.
        on_confirm : Callable
            Called when the user selects Yes.
        on_cancel : Callable, optional
            Called when the user selects No. Defaults to just closing.
        """

        def _on_yes(button: urwid.Button) -> None:
            Modal.close(app)
            on_confirm()

        def _on_no(button: urwid.Button) -> None:
            Modal.close(app)
            if on_cancel is not None:
                on_cancel()

        msg_text = urwid.Text(("modal_body", message), align="center")

        yes_btn = urwid.AttrMap(
            HokoraButton("Yes", on_press=_on_yes), "button_normal", "button_focus"
        )
        no_btn = urwid.AttrMap(HokoraButton("No", on_press=_on_no), "button_normal", "button_focus")

        buttons = urwid.Columns(
            [
                ("weight", 1, urwid.Padding(yes_btn, align="center", width=10)),
                ("weight", 1, urwid.Padding(no_btn, align="center", width=10)),
            ]
        )

        body = urwid.Filler(
            urwid.Pile(
                [
                    urwid.Divider(),
                    msg_text,
                    urwid.Divider(),
                    buttons,
                ]
            ),
            valign="middle",
        )

        Modal.show(app, "Confirm", body, width=40, height=20)
