# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Nodes sub-tab of the Discovery view.

Owns the nodes walker + listbox + the per-item actions
(toggle-bookmark, show-info). ``refresh(filter_text)`` rebuilds the
walker from ``app.state.discovered_nodes`` under the current filter.

The parent ``DiscoveryView`` passes in a single ``on_node_selected``
callback — the one-shot handler the parent uses to route Enter on a
node to connect/local logic, including the local-daemon probe.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Callable

import urwid

from hokora_tui.widgets.info_panel import build_node_info_panel
from hokora_tui.widgets.modal import Modal
from hokora_tui.widgets.node_item import NodeItem

if TYPE_CHECKING:
    from hokora_tui.app import HokoraTUI

logger = logging.getLogger(__name__)


class NodesSubView:
    def __init__(self, app: "HokoraTUI", on_node_selected: Callable[[dict], None]) -> None:
        self.app = app
        self._on_node_selected = on_node_selected
        self.walker = urwid.SimpleFocusListWalker([])
        self.listbox = urwid.ListBox(self.walker)

    def refresh(self, filter_text: str) -> None:
        """Rebuild the walker from ``app.state.discovered_nodes``."""
        self.walker.clear()

        nodes = sorted(
            self.app.state.discovered_nodes.values(),
            key=lambda n: n.get("last_seen", 0),
            reverse=True,
        )

        if not nodes:
            self.walker.append(
                urwid.Text(("default", "  No nodes discovered. Waiting for announces..."))
            )
            return

        for node in nodes:
            name = node.get("node_name", "").lower()
            h = node.get("hash", "").lower()
            if filter_text and filter_text not in name and filter_text not in h:
                continue
            self.walker.append(NodeItem(node, self._on_node_selected))

        if not self.walker:
            self.walker.append(urwid.Text(("default", "  No nodes match filter.")))

    def toggle_bookmark_focused(self) -> None:
        """Toggle the bookmark on the currently focused NodeItem."""
        focus_widget, _ = self.walker.get_focus()
        if not isinstance(focus_widget, NodeItem):
            return
        h = focus_widget.node_dict.get("hash", "")
        if not h or self.app.db is None:
            return
        new_state = self.app.db.toggle_node_bookmark(h)
        if h in self.app.state.discovered_nodes:
            self.app.state.discovered_nodes[h]["bookmarked"] = new_state
        self.app.status.set_context("Node bookmarked ★" if new_state else "Node unbookmarked")

    def show_info_focused(self) -> None:
        """Open a NomadNet-style info modal for the focused NodeItem.

        Snapshot of the node's identity, transport, and announced
        channels at the moment ``i`` is pressed. Esc closes via the
        existing keybinding handler. Re-press ``i`` after closing to
        refresh against fresh announcer state.
        """
        focus_widget, _ = self.walker.get_focus()
        if not isinstance(focus_widget, NodeItem):
            return
        nd = focus_widget.node_dict
        title = f"Node: {nd.get('node_name') or 'unknown'}"
        Modal.show(
            self.app,
            title,
            build_node_info_panel(nd, sync_engine=self.app.sync_engine),
            width=70,
            height=70,
        )
