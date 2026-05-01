# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Favorites sub-tab of the Discovery view.

Favorites are persistent (survive TUI restarts) and are stored via the
client DB's ``bookmarked`` flag on discovered nodes + peers. This
sub-view also owns the invite-redemption row — typing an invite code
+ pressing Redeem decodes the token and fires ``/connect``.

Reuses ``NodeItem`` / ``PeerItem`` widgets — a favorite is displayed
with the same row widget as its live-discovery counterpart, just
rebuilt each refresh from the DB rather than from ``app.state``.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Callable

import urwid

from hokora_tui.widgets.hokora_button import HokoraButton
from hokora_tui.widgets.info_panel import build_node_info_panel, build_peer_info_panel
from hokora_tui.widgets.modal import Modal
from hokora_tui.widgets.node_item import NodeItem
from hokora_tui.widgets.peer_item import PeerItem

if TYPE_CHECKING:
    from hokora_tui.app import HokoraTUI

logger = logging.getLogger(__name__)


class FavoritesSubView:
    def __init__(
        self,
        app: "HokoraTUI",
        on_node_selected: Callable[[dict], None],
        on_peer_selected: Callable[[dict], None],
    ) -> None:
        self.app = app
        self._on_node_selected = on_node_selected
        self._on_peer_selected = on_peer_selected
        self.walker = urwid.SimpleFocusListWalker([])
        self.listbox = urwid.ListBox(self.walker)

        # Invite input row — sits at the top of the favorites list.
        self._invite_edit = urwid.Edit(("input_prompt", "Invite: "))
        self._invite_btn = urwid.AttrMap(
            HokoraButton("Redeem", on_press=lambda _: self.redeem_invite()),
            "button_normal",
            "button_focus",
        )
        self._invite_row = urwid.Columns(
            [
                ("weight", 3, urwid.AttrMap(self._invite_edit, "input_text")),
                ("pack", self._invite_btn),
            ]
        )

    # ── Invite input accessors (used by parent keypress logic) ──────

    @property
    def invite_edit(self) -> urwid.Edit:
        return self._invite_edit

    def invite_has_text(self) -> bool:
        return bool(self._invite_edit.get_edit_text().strip())

    # ── Refresh ─────────────────────────────────────────────────────

    def refresh(self, filter_text: str) -> None:
        """Rebuild the favorites walker from the client DB.

        Merges the persisted (DB) state with any live (state) updates
        for the same identity, so favorites reflect the freshest
        last_seen + channel_dests even for rows sourced only from the
        persisted DB row.
        """
        self.walker.clear()

        # Invite input always stays at the top.
        self.walker.append(self._invite_row)
        self.walker.append(urwid.Divider("─"))

        fav_nodes: list[dict] = []
        fav_peers: list[dict] = []

        if self.app.db is not None:
            try:
                for node in self.app.db.get_discovered_nodes():
                    if not node.get("bookmarked"):
                        continue
                    channels = []
                    if node.get("channels_json"):
                        try:
                            channels = json.loads(node["channels_json"])
                        except (json.JSONDecodeError, TypeError):
                            pass
                    db_channel_dests: dict = {}
                    if node.get("channel_dests_json"):
                        try:
                            db_channel_dests = json.loads(node["channel_dests_json"])
                        except (json.JSONDecodeError, TypeError):
                            pass
                    live = self.app.state.discovered_nodes.get(node["hash"], {})
                    channel_dests = live.get("channel_dests") or db_channel_dests
                    fav_nodes.append(
                        {
                            "hash": node["hash"],
                            "node_name": node.get("node_name", "Unknown"),
                            "channel_count": node.get("channel_count", 0),
                            "last_seen": live.get("last_seen", node.get("last_seen", 0)),
                            "channels": live.get("channels") or channels,
                            "channel_dests": channel_dests,
                            "primary_dest": live.get("primary_dest")
                            or (
                                next(iter(channel_dests.values()), None) if channel_dests else None
                            ),
                            "bookmarked": True,
                        }
                    )
            except Exception:
                logger.debug("failed to build favorite-nodes list", exc_info=True)

            try:
                for peer in self.app.db.get_discovered_peers():
                    if not peer.get("bookmarked"):
                        continue
                    live = self.app.state.discovered_peers.get(peer["hash"], {})
                    fav_peers.append(
                        {
                            "hash": peer["hash"],
                            "display_name": live.get("display_name")
                            or peer.get("display_name", ""),
                            "status_text": live.get("status_text") or peer.get("status_text", ""),
                            "last_seen": live.get("last_seen", peer.get("last_seen", 0)),
                            "bookmarked": True,
                        }
                    )
            except Exception:
                logger.debug("failed to build favorite-peers list", exc_info=True)

        all_favs = sorted(
            [(n, "node") for n in fav_nodes] + [(p, "peer") for p in fav_peers],
            key=lambda x: x[0].get("last_seen", 0),
            reverse=True,
        )

        if not all_favs:
            self.walker.append(
                urwid.Text(
                    ("default", "  No favorites yet. Press [b] on a node or peer to bookmark it.")
                )
            )
            return

        for item, item_type in all_favs:
            if item_type == "node":
                name = item.get("node_name", "").lower()
                h = item.get("hash", "").lower()
                if filter_text and filter_text not in name and filter_text not in h:
                    continue
                self.walker.append(NodeItem(item, self._on_node_selected))
            else:
                name = item.get("display_name", "").lower()
                h = item.get("hash", "").lower()
                if filter_text and filter_text not in name and filter_text not in h:
                    continue
                self.walker.append(PeerItem(item, self._on_peer_selected))

        # 2 = invite row + divider; if nothing else was added, show empty hint
        if len(self.walker) <= 2:
            self.walker.append(
                urwid.Text(
                    (
                        "default",
                        "  No favorites yet. Press [b] on a node to bookmark, or paste an invite above.",
                    )
                )
            )

    # ── Item-level actions (mirror Nodes/Peers subviews) ────────────

    def toggle_bookmark_focused(self) -> None:
        """Un-favorite the focused NodeItem or PeerItem."""
        focus_widget, _ = self.walker.get_focus()
        if isinstance(focus_widget, NodeItem):
            h = focus_widget.node_dict.get("hash", "")
            if h and self.app.db is not None:
                new_state = self.app.db.toggle_node_bookmark(h)
                if h in self.app.state.discovered_nodes:
                    self.app.state.discovered_nodes[h]["bookmarked"] = new_state
                self.app.status.set_context(
                    "Node bookmarked ★" if new_state else "Node unbookmarked"
                )
        elif isinstance(focus_widget, PeerItem):
            h = focus_widget.peer_dict.get("hash", "")
            if h and self.app.db is not None:
                new_state = self.app.db.toggle_peer_bookmark(h)
                if h in self.app.state.discovered_peers:
                    self.app.state.discovered_peers[h]["bookmarked"] = new_state
                self.app.status.set_context(
                    "Peer bookmarked ★" if new_state else "Peer unbookmarked"
                )

    def show_info_focused(self) -> None:
        """Open a NomadNet-style info modal for the focused favorite.

        Branches on item type — the favorites tab can hold both nodes
        and peers (bookmarked from the live-discovery sub-tabs). Snapshot
        semantics; Esc closes, re-press ``i`` to refresh.
        """
        focus_widget, _ = self.walker.get_focus()
        if isinstance(focus_widget, NodeItem):
            nd = focus_widget.node_dict
            Modal.show(
                self.app,
                f"Node: {nd.get('node_name') or 'unknown'}",
                build_node_info_panel(nd, sync_engine=self.app.sync_engine),
                width=70,
                height=70,
            )
        elif isinstance(focus_widget, PeerItem):
            pd = focus_widget.peer_dict
            Modal.show(
                self.app,
                f"Peer: {pd.get('display_name') or 'unknown'}",
                build_peer_info_panel(pd, sync_engine=self.app.sync_engine),
                width=70,
                height=70,
            )

    # ── Invite redemption ───────────────────────────────────────────

    def redeem_invite(self) -> None:
        """Decode an invite code from ``invite_edit`` and connect."""
        code = self._invite_edit.get_edit_text().strip()
        if not code:
            return
        logger.info(f"Redeeming invite code: {code[:20]}...")

        token_hex: str | None = None
        dest_hash_hex: str | None = None
        pubkey_hex: str | None = None
        channel_id: str | None = None

        try:
            from hokora.security.invite_codes import decode_invite

            token_hex, dest_hash_hex = decode_invite(code)
        except Exception:
            logger.debug("invite short-code decode failed", exc_info=True)

        # Fallback: raw composite formats
        #   3-field legacy: token : dest_hash : channel_id
        #   4-field:        token : dest_hash : pubkey : channel_id
        if not token_hex and ":" in code:
            parts = code.split(":")
            if len(parts) >= 2 and len(parts[0]) >= 16 and len(parts[1]) >= 16:
                token_hex = parts[0]
                dest_hash_hex = parts[1]
                if len(parts) >= 4 and len(parts[2]) >= 64:
                    pubkey_hex = parts[2]
                    channel_id = parts[3] or None
                elif len(parts) >= 3 and parts[2]:
                    channel_id = parts[2]

        if not token_hex or not dest_hash_hex:
            self.app.status.set_context("Invalid invite code")
            return

        try:
            bytes.fromhex(dest_hash_hex)
        except ValueError:
            self.app.status.set_context("Invalid invite code (bad destination hash)")
            return

        if not channel_id:
            for node in self.app.state.discovered_nodes.values():
                for ch_id, dh in node.get("channel_dests", {}).items():
                    if dh == dest_hash_hex:
                        channel_id = ch_id
                        break
                if channel_id:
                    break

        if not channel_id:
            self.app.status.set_context(
                "Invite missing channel ID. Use raw format: token:dest_hash:channel_id"
            )
            return

        self._invite_edit.set_edit_text("")
        self.app.status.set_context("Connecting via invite...")
        self.app._schedule_redraw()

        def _store_and_connect(_loop=None, _data=None):
            from hokora_tui.commands.helpers import ensure_sync_engine

            ensure_sync_engine(self.app)
            engine = self.app.sync_engine
            if engine:
                engine.set_pending_redeem("__node__", token_hex)
                if pubkey_hex:
                    try:
                        engine.set_pending_pubkey(dest_hash_hex, bytes.fromhex(pubkey_hex))
                    except ValueError:
                        logger.warning("Invite pubkey is not valid hex; ignoring")
            logger.info(f"Invite: /connect {dest_hash_hex[:16]} {channel_id}")
            self.app.handle_command(f"/connect {dest_hash_hex} {channel_id}")

        if self.app.loop:
            self.app.loop.set_alarm_in(0, _store_and_connect)
            self.app._wake_loop()
        else:
            _store_and_connect()
