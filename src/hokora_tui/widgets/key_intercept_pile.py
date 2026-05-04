# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Pile that delegates certain keys to a handler before normal processing.

Reusable "inspect the key first, fall through on None" pattern — used
where a parent view needs to claim a few keys (e.g. arrow-key
sub-tab navigation) before the focused widget gets a chance.
"""

from __future__ import annotations

import urwid


class KeyInterceptPile(urwid.Pile):
    """Pile variant that runs an optional ``handler`` on every keypress.

    The handler's return value gates the normal ``Pile.keypress`` path:
      * ``None`` — the handler consumed the key; do not forward.
      * anything else (including the key itself) — the handler declined
        or partially handled; let Pile run its standard dispatch.
    """

    def __init__(self, widget_list, handler=None):
        super().__init__(widget_list)
        self._key_handler = handler

    def keypress(self, size: tuple, key: str) -> str | None:
        if self._key_handler is not None:
            result = self._key_handler(size, key)
            if result is None:
                return None
        return super().keypress(size, key)
