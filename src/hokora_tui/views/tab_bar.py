# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Top tab bar widget."""

from __future__ import annotations

import urwid

from hokora_tui.navigation import TAB_NAMES


class TabBarView:
    """Horizontal row of tab labels rendered as urwid.Columns."""

    def __init__(self) -> None:
        self._tabs: list[urwid.Text] = []
        self._active: int = 3  # default = Channels

        for i, name in enumerate(TAB_NAMES):
            label = f" {name} "
            attr = "tab_active" if i == self._active else "tab_inactive"
            self._tabs.append(urwid.Text((attr, label)))

        col_widgets = []
        for txt in self._tabs:
            raw = txt.text
            if isinstance(raw, str):
                width = len(raw)
            else:
                # list of (attr, text) tuples
                width = sum(len(s) for _a, s in raw)
            col_widgets.append((width, txt))

        # Bare Columns - no surrounding AttrMap. Each tab Text owns its
        # own attribute (tab_active / tab_inactive) so per-tab styling
        # works without a wrapper, and the trailing fill space inherits
        # the Frame's default background rather than carrying a coloured
        # fill out to the right edge.
        self._columns = urwid.Columns(col_widgets)
        self.widget = self._columns

    def set_active(self, index: int) -> None:
        """Update which tab is highlighted."""
        if index < 0 or index >= len(self._tabs):
            return

        for i, tab in enumerate(self._tabs):
            name = TAB_NAMES[i]
            label = f" {name} "
            if i == index:
                tab.set_text(("tab_active", label))
            else:
                tab.set_text(("tab_inactive", label))

        self._active = index
