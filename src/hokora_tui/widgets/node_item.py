# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Single discovered node widget for the Discovery tab."""

from __future__ import annotations

import time
from typing import Callable

import urwid

from hokora_tui.palette import make_full_focus_map


# Full-row highlight on focus. NodeItem mixes node_*, default, and
# msg_thread attributes across its two-row pile; ``make_full_focus_map``
# covers every palette entry the widget could render, drift-free.
_NODE_FOCUS_MAP = make_full_focus_map("channel_selected")


class NodeItem(urwid.WidgetWrap):
    """Selectable item displaying a discovered Hokora node.

    Display format::

        Row 1: [*] NodeName    abc123...    3 ch    direct    12s ago
        Row 2:     #general  #community-chat  #sealed-ops

    The hop column shows ``direct`` for 0 hops, ``Nh`` for >0, and
    ``?h`` when the path is unknown (RNS path table miss). Hops are
    queried live from ``RNS.Transport.path_table`` on every announce
    and are not persisted — see ``Announcer._on_announce``.

    The star is shown only if the node is bookmarked.
    """

    def __init__(self, node_dict: dict, on_select: Callable[[dict], None]) -> None:
        self.node_dict = node_dict
        self._on_select = on_select

        node_hash = node_dict.get("hash", "")
        node_name = node_dict.get("node_name", "Unknown")
        channel_count = node_dict.get("channel_count", 0)
        last_seen = node_dict.get("last_seen", 0)
        bookmarked = node_dict.get("bookmarked", False)
        channels = node_dict.get("channels") or []
        hops = node_dict.get("hops")

        # Build display columns
        star = ("node_bookmarked", "\u2605 ") if bookmarked else ("default", "  ")
        short_hash = f"{node_hash[:12]}..." if len(node_hash) > 12 else node_hash

        # Determine staleness (>5min = stale)
        age = time.time() - last_seen if last_seen else float("inf")
        time_style = "node_recent" if age < 300 else "node_stale"
        time_str = _format_time_ago(last_seen)

        ch_str = f"{channel_count} ch"
        hops_str, hops_style = _format_hops(hops)

        row1 = urwid.Columns(
            [
                ("pack", urwid.Text(star)),
                ("weight", 2, urwid.Text(("node_name", node_name))),
                ("weight", 1, urwid.Text(("node_hash", short_hash))),
                ("pack", urwid.Text(("default", f"  {ch_str}  "))),
                ("pack", urwid.Text((hops_style, f"{hops_str}  "))),
                ("pack", urwid.Text((time_style, time_str))),
            ]
        )

        # Build second row with channel names
        rows = [row1]
        if channels:
            ch_names = "    " + "  ".join(f"#{name}" for name in channels[:6])
            if len(channels) > 6:
                ch_names += f"  +{len(channels) - 6} more"
            row2 = urwid.Text(("msg_thread", ch_names))
            rows.append(row2)

        pile = urwid.Pile(rows)
        self._attr = urwid.AttrMap(pile, None, focus_map=_NODE_FOCUS_MAP)
        super().__init__(self._attr)

    def selectable(self) -> bool:
        return True

    def keypress(self, size: tuple, key: str) -> str | None:
        if key == "enter":
            self._on_select(self.node_dict)
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


def _format_hops(hops: int | None) -> tuple[str, str]:
    """Render an RNS hop count as (label, urwid-style)."""
    if hops is None:
        return "?h", "node_stale"
    if hops == 0:
        return "direct", "node_recent"
    return f"{hops}h", "default"
