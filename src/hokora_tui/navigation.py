# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tab switching controller."""

from __future__ import annotations

from typing import Any

TAB_NAMES: list[str] = [
    "Identity",
    "Network",
    "Discovery",
    "Channels",
    "Conversations",
    "Settings",
]

DEFAULT_TAB = 3  # Channels


class NavigationController:
    """Manages active tab state and swaps the frame body widget."""

    def __init__(self, views: list[Any], frame: Any, tab_bar: Any) -> None:
        """
        Parameters
        ----------
        views : list
            Six view instances, each with a ``.widget`` attribute.
        frame : urwid.Frame
            The top-level frame whose ``body`` is swapped on tab change.
        tab_bar : TabBarView
            Tab bar widget to update highlights.
        """
        self.views = views
        self.frame = frame
        self.tab_bar = tab_bar
        self.active_tab: int = DEFAULT_TAB

    def switch_to(self, index: int) -> None:
        """Activate the tab at *index* (0-based)."""
        if index < 0 or index >= len(self.views):
            return
        self.active_tab = index
        view = self.views[index]
        self.frame.body = view.widget
        self.tab_bar.set_active(index)
        # Notify the view it's now active (for lazy refresh)
        if hasattr(view, "on_activate"):
            view.on_activate()

    def next_tab(self) -> None:
        """Cycle to the next tab (wraps around)."""
        self.switch_to((self.active_tab + 1) % len(self.views))

    def prev_tab(self) -> None:
        """Cycle to the previous tab (wraps around)."""
        self.switch_to((self.active_tab - 1) % len(self.views))
