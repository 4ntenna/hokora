# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Single conversation item widget for the Conversations tab."""

from __future__ import annotations

import time
from typing import Callable

import urwid

from hokora_tui.palette import make_full_focus_map


# Full-row highlight on focus. ConversationItem renders dm_* attributes
# alongside ``default``-attributed fill, so a prefix-only focus map would
# leak the unattributed segments — the row would highlight only on the
# pieces that happen to share the prefix. ``make_full_focus_map`` derives
# from the entire palette, so adding any new palette entry this widget
# happens to render automatically participates.
_CONVO_FOCUS_MAP = make_full_focus_map("channel_selected")


class ConversationItem(urwid.WidgetWrap):
    """Selectable item displaying a DM conversation summary.

    Display format: ``alice    Hello, how are you?    2m ago    (3)``
    where (3) is the unread badge.
    """

    def __init__(self, convo_dict: dict, on_select: Callable[[dict], None]) -> None:
        self.convo_dict = convo_dict
        self._on_select = on_select

        raw_name = convo_dict.get("peer_name", "")
        peer_hash = convo_dict.get("peer_hash", "???")
        short_hash = peer_hash[:8]
        if raw_name and raw_name != peer_hash[:12] and not raw_name.startswith(peer_hash[:8]):
            peer_name = f"{raw_name} ({short_hash})"
        else:
            peer_name = short_hash
        last_msg_time = convo_dict.get("last_message_time", 0)
        unread = convo_dict.get("unread_count", 0)
        last_body = convo_dict.get("last_body", "")

        # Truncate preview
        preview = last_body[:40] + "..." if len(last_body) > 40 else last_body
        time_str = _format_time_ago(last_msg_time)

        parts: list[tuple] = [
            ("weight", 1, urwid.Text(("dm_peer", peer_name))),
            ("weight", 2, urwid.Text(("default", preview))),
            ("pack", urwid.Text(("dm_time", f"  {time_str}  "))),
        ]

        if unread > 0:
            parts.append(("pack", urwid.Text(("dm_unread", f"({unread})"))))

        cols = urwid.Columns(parts)
        self._attr = urwid.AttrMap(cols, None, focus_map=_CONVO_FOCUS_MAP)
        super().__init__(self._attr)

    def selectable(self) -> bool:
        return True

    def keypress(self, size: tuple, key: str) -> str | None:
        if key == "enter":
            self._on_select(self.convo_dict)
            return None
        return key


def _format_time_ago(timestamp: float) -> str:
    """Format a timestamp as a human-readable relative time string."""
    if not timestamp:
        return "never"
    age = time.time() - timestamp
    if age < 0:
        return "now"
    if age < 60:
        return f"{int(age)}s ago"
    if age < 3600:
        return f"{int(age / 60)}m ago"
    if age < 86400:
        return f"{int(age / 3600)}h ago"
    return ">1d"
