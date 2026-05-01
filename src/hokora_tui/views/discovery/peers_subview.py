# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Peers sub-tab of the Discovery view.

Owns the peers walker + listbox + the per-item actions
(toggle-bookmark, show-info). Mirrors ``NodesSubView`` but for
``PeerItem`` widgets backed by ``app.state.discovered_peers``.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Callable

import urwid

from hokora_tui.widgets.info_panel import build_peer_info_panel
from hokora_tui.widgets.modal import Modal
from hokora_tui.widgets.peer_item import PeerItem

if TYPE_CHECKING:
    from hokora_tui.app import HokoraTUI

logger = logging.getLogger(__name__)


class PeersSubView:
    def __init__(self, app: "HokoraTUI", on_peer_selected: Callable[[dict], None]) -> None:
        self.app = app
        self._on_peer_selected = on_peer_selected
        self.walker = urwid.SimpleFocusListWalker([])
        self.listbox = urwid.ListBox(self.walker)

    def refresh(self, filter_text: str) -> None:
        """Rebuild the walker from ``app.state.discovered_peers``."""
        self.walker.clear()

        peers = sorted(
            self.app.state.discovered_peers.values(),
            key=lambda p: p.get("last_seen", 0),
            reverse=True,
        )

        if not peers:
            self.walker.append(
                urwid.Text(("default", "  No peers discovered. Waiting for announces..."))
            )
            return

        for peer in peers:
            name = peer.get("display_name", "").lower()
            h = peer.get("hash", "").lower()
            if filter_text and filter_text not in name and filter_text not in h:
                continue
            self.walker.append(PeerItem(peer, self._on_peer_selected))

        if not self.walker:
            self.walker.append(urwid.Text(("default", "  No peers match filter.")))

    def toggle_bookmark_focused(self) -> None:
        """Toggle the bookmark on the currently focused PeerItem."""
        focus_widget, _ = self.walker.get_focus()
        if not isinstance(focus_widget, PeerItem):
            return
        h = focus_widget.peer_dict.get("hash", "")
        if not h or self.app.db is None:
            return
        new_state = self.app.db.toggle_peer_bookmark(h)
        if h in self.app.state.discovered_peers:
            self.app.state.discovered_peers[h]["bookmarked"] = new_state
        self.app.status.set_context("Peer bookmarked ★" if new_state else "Peer unbookmarked")

    def show_info_focused(self) -> None:
        """Open a NomadNet-style info modal for the focused PeerItem.

        Surfaces identity hash, transport interface, hops, and the
        B-lite TOFU verify-state from ``SyncEngine.identity_keys``.
        Snapshot semantics — Esc to close, re-press ``i`` to refresh.
        """
        focus_widget, _ = self.walker.get_focus()
        if not isinstance(focus_widget, PeerItem):
            return
        pd = focus_widget.peer_dict
        title = f"Peer: {pd.get('display_name') or 'unknown'}"
        Modal.show(
            self.app,
            title,
            build_peer_info_panel(pd, sync_engine=self.app.sync_engine),
            width=70,
            height=70,
        )
