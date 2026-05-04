# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Single discovered peer widget for the Discovery tab."""

from __future__ import annotations

import time
from typing import Callable

import urwid

from hokora_tui.palette import make_full_focus_map


# Full-row highlight on focus. PeerItem mixes peer_*, node_*, and
# default attributes; ``make_full_focus_map`` covers every palette
# entry the widget could render, drift-free.
_PEER_FOCUS_MAP = make_full_focus_map("channel_selected")


class PeerItem(urwid.WidgetWrap):
    """Selectable item displaying a discovered peer on the network.

    Display format: ``[*] alice  <full-identity-hash>  Online  direct  30s ago``
    The star is shown only if the peer is bookmarked. The hop column
    shows ``direct`` for 0 hops, ``Nh`` for >0, and ``?h`` when the
    path is unknown (RNS path-table miss). Hops are queried live from
    ``RNS.Transport.path_table`` on every announce and are not persisted.
    """

    def __init__(self, peer_dict: dict, on_select: Callable[[dict], None]) -> None:
        self.peer_dict = peer_dict
        self._on_select = on_select

        peer_hash = peer_dict.get("hash", "")
        display_name = peer_dict.get("display_name", "Unknown")
        status_text = peer_dict.get("status_text", "") or "Online"
        last_seen = peer_dict.get("last_seen", 0)
        bookmarked = peer_dict.get("bookmarked", False)
        hops = peer_dict.get("hops")

        star = ("node_bookmarked", "\u2605 ") if bookmarked else ("default", "  ")
        time_str = _format_time_ago(last_seen)
        hops_str, hops_style = _format_hops(hops)

        cols = urwid.Columns(
            [
                ("pack", urwid.Text(star)),
                ("weight", 2, urwid.Text(("peer_name", display_name))),
                ("weight", 3, urwid.Text(("peer_hash", peer_hash))),
                ("weight", 1, urwid.Text(("peer_status", status_text))),
                ("pack", urwid.Text((hops_style, f"  {hops_str}"))),
                ("pack", urwid.Text(("node_stale", f"  {time_str}"))),
            ]
        )

        self._attr = urwid.AttrMap(cols, None, focus_map=_PEER_FOCUS_MAP)
        super().__init__(self._attr)

    def selectable(self) -> bool:
        return True

    def keypress(self, size: tuple, key: str) -> str | None:
        if key == "enter":
            self._on_select(self.peer_dict)
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
