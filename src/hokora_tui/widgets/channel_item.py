# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Single channel item widget for the sidebar."""

from __future__ import annotations

from typing import Callable

import urwid

from hokora_tui.widgets.hokora_button import HokoraButton


class ChannelItem(urwid.WidgetWrap):
    """Selectable channel button for the sidebar list.

    Format: ``# channel-name (N)`` where N is unread count if > 0.
    Sealed channels show a lock prefix.
    """

    signals = ["click"]

    def __init__(
        self,
        channel_dict: dict,
        on_select_callback: Callable[[str], None],
        unread: int = 0,
    ) -> None:
        self.channel_id = channel_dict.get("id", "")
        self.channel_name = channel_dict.get("name", "unknown")
        self.sealed = bool(channel_dict.get("sealed"))
        self._on_select = on_select_callback
        self._unread = unread

        self._button = HokoraButton("", on_press=self._clicked)
        self._update_label()

        # Base attr map — will be updated on selection state changes
        self._attr = urwid.AttrMap(self._button, "channel", "channel_selected")
        super().__init__(self._attr)

    def _clicked(self, button: urwid.Button) -> None:
        self._on_select(self.channel_id)

    def _update_label(self) -> None:
        """Rebuild the button label with current unread count."""
        prefix = "\U0001f512 " if self.sealed else "# "
        label = f"{prefix}{self.channel_name}"
        if self._unread > 0:
            label += f" ({self._unread})"
        self._button.set_label(label)

    def set_unread(self, count: int) -> None:
        """Update the unread count badge and refresh the label."""
        self._unread = count
        self._update_label()

    def selectable(self) -> bool:
        return True
