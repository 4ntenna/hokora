# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Enhanced text input widget with history support."""

from __future__ import annotations

import urwid

_MAX_HISTORY = 100


class TextInput(urwid.Edit):
    """Enhanced Edit widget with input history (up/down arrow navigation)."""

    def __init__(self, caption: str = "", edit_text: str = "", **kwargs) -> None:
        super().__init__(caption=caption, edit_text=edit_text, **kwargs)
        self._history: list[str] = []
        self._history_index: int = -1
        self._current_text: str = ""

    def keypress(self, size: tuple, key: str) -> str | None:
        if key == "up":
            if self._history:
                if self._history_index == -1:
                    self._current_text = self.get_edit_text()
                    self._history_index = len(self._history) - 1
                elif self._history_index > 0:
                    self._history_index -= 1
                self.set_edit_text(self._history[self._history_index])
                self.set_edit_pos(len(self.get_edit_text()))
                return None

        if key == "down":
            if self._history_index >= 0:
                if self._history_index < len(self._history) - 1:
                    self._history_index += 1
                    self.set_edit_text(self._history[self._history_index])
                else:
                    self._history_index = -1
                    self.set_edit_text(self._current_text)
                self.set_edit_pos(len(self.get_edit_text()))
                return None

        return super().keypress(size, key)

    def add_to_history(self, text: str) -> None:
        """Add a text entry to the input history."""
        if text and (not self._history or self._history[-1] != text):
            self._history.append(text)
            if len(self._history) > _MAX_HISTORY:
                self._history.pop(0)
        self._history_index = -1
        self._current_text = ""

    def get_history(self) -> list[str]:
        """Return a copy of the input history."""
        return list(self._history)

    def clear(self) -> None:
        """Clear the edit text and reset history navigation."""
        self.set_edit_text("")
        self._history_index = -1
        self._current_text = ""
