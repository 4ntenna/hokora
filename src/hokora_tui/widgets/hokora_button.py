# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Cursor-suppressed Button.

urwid's ``Button`` builds its label as a ``SelectableIcon`` with
``cursor_position=0``. ``SelectableIcon.render`` then draws the terminal
hardware cursor on the first cell of the label whenever the widget is
focused. On any focus background palette pair (e.g. ``button_focus`` -
white,bold on dark gray) the cursor inverts that single cell, producing
a one-character highlight artefact distinct from the rest of the row.

This subclass relocates the cursor past end-of-text so
``SelectableIcon.get_cursor_coords`` returns ``None`` and no cursor is
drawn. ``Button.set_label`` only mutates the existing label's text in
place (it does not rebuild the ``SelectableIcon``), so a single
post-construction tweak survives subsequent re-labels - we re-apply
defensively in ``set_label`` anyway to keep the invariant local.
"""

from __future__ import annotations

from collections.abc import Hashable
from typing import Any, Callable

import urwid

# Sentinel cursor position past any plausible label length. SelectableIcon
# returns None from get_cursor_coords when _cursor_position > len(text).
# 1 << 24 is comfortably larger than any UI label we will ever emit and
# stays an int (no float coercion in urwid's comparison path).
_NO_CURSOR_POSITION = 1 << 24


class HokoraButton(urwid.Button):
    """``urwid.Button`` with the focus-time hardware cursor suppressed."""

    def __init__(
        self,
        label: str | tuple[Hashable, str] | list[str | tuple[Hashable, str]],
        on_press: Callable[..., Any] | None = None,
        user_data: Any = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(label, on_press=on_press, user_data=user_data, **kwargs)
        self._label._cursor_position = _NO_CURSOR_POSITION

    def set_label(
        self,
        label: str | tuple[Hashable, str] | list[str | tuple[Hashable, str]],
    ) -> None:
        super().set_label(label)
        # Defensive re-apply: set_label only mutates text today, but pin the
        # invariant locally so any future urwid behaviour change does not
        # silently re-introduce the cursor artefact.
        self._label._cursor_position = _NO_CURSOR_POSITION
