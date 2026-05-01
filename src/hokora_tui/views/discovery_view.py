# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Discovery tab — composes Nodes, Peers, and Favorites sub-views.

Per-sub-view concerns live in:

* ``views/discovery/nodes_subview.py``       (walker + refresh + actions)
* ``views/discovery/peers_subview.py``       (walker + refresh + actions)
* ``views/discovery/favorites_subview.py``   (walker + refresh + invite)
* ``widgets/key_intercept_pile.py``          (shared keypress-delegation widget)

This module is the top-level composition: it owns the filter edit, the
sub-tab buttons, the active-list placeholder, and routes keypresses to
the correct sub-view. The cross-cutting connect flow (local-daemon
probe, /connect vs /local decision) stays here because it's the glue
between a chosen node and the command layer, not a sub-view concern.
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

import urwid

from hokora_tui.views.discovery.favorites_subview import FavoritesSubView
from hokora_tui.views.discovery.nodes_subview import NodesSubView
from hokora_tui.views.discovery.peers_subview import PeersSubView
from hokora_tui.widgets.hokora_button import HokoraButton
from hokora_tui.widgets.key_intercept_pile import KeyInterceptPile
from hokora_tui.widgets.node_item import NodeItem
from hokora_tui.widgets.peer_item import PeerItem

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from hokora_tui.app import HokoraTUI


class DiscoveryView:
    """Discovery view with sub-tabs for Nodes, Peers, and Favorites."""

    _SUB_TABS = ("nodes", "peers", "favorites")

    def __init__(self, app: HokoraTUI) -> None:
        self.app = app
        self._sub_tab = "nodes"

        # Filter input — shared across all three sub-views.
        self._filter_edit = urwid.Edit(("input_prompt", "Filter: "))

        # Sub-tab buttons.
        self._nodes_btn = urwid.AttrMap(
            HokoraButton("Nodes", on_press=lambda _: self._switch_sub_tab("nodes")),
            "tab_active",
        )
        self._peers_btn = urwid.AttrMap(
            HokoraButton("Peers", on_press=lambda _: self._switch_sub_tab("peers")),
            "tab_inactive",
        )
        self._favorites_btn = urwid.AttrMap(
            HokoraButton(
                "★ Favorites",
                on_press=lambda _: self._switch_sub_tab("favorites"),
            ),
            "tab_inactive",
        )

        self._refresh_btn = urwid.AttrMap(
            HokoraButton("Refresh", on_press=lambda _: self._refresh_active()),
            "button_normal",
            "button_focus",
        )

        top_bar = urwid.Columns(
            [
                ("weight", 2, urwid.AttrMap(self._filter_edit, "input_text")),
                ("pack", self._nodes_btn),
                ("pack", self._peers_btn),
                ("pack", self._favorites_btn),
                ("pack", self._refresh_btn),
            ]
        )

        # Sub-views — each owns its walker/listbox and refresh logic.
        self._nodes = NodesSubView(app, self._on_node_selected)
        self._peers = PeersSubView(app, self._on_peer_selected)
        self._favorites = FavoritesSubView(
            app,
            on_node_selected=self._on_node_selected,
            on_peer_selected=self._on_peer_selected,
        )

        # Active list placeholder starts on nodes.
        self._active_list = urwid.WidgetPlaceholder(self._nodes.listbox)

        self._hint = urwid.Text(
            (
                "default",
                "[Enter] Connect/DM | [b] Bookmark | [i] Info | [Left/Right] Nodes/Peers/Favorites",
            )
        )

        self.widget = KeyInterceptPile(
            [
                ("pack", top_bar),
                ("pack", urwid.Divider("─")),
                ("weight", 1, self._active_list),
                ("pack", urwid.Divider("─")),
                ("pack", self._hint),
            ],
            handler=self.handle_key,
        )

        # Subscribe to state events so live announces refresh the right sub-view.
        app.state.on("nodes_updated", lambda _=None: self._refresh_nodes())
        app.state.on("peers_updated", lambda _=None: self._refresh_peers())

        # Discovery starts empty — nodes only appear from live announces.
        # Favorites are loaded from DB separately.

    # ── Persistence hydration (called once from app init) ────────────

    def _load_persisted(self) -> None:
        """Load previously discovered nodes and peers from the client DB.

        Populates ``app.state.discovered_nodes`` / ``discovered_peers``
        from the persisted DB rows so the Discovery view has context on
        startup instead of waiting for the first live announce.
        """
        if self.app.db is None:
            return

        import json

        try:
            for node in self.app.db.get_discovered_nodes():
                h = node["hash"]
                channels = []
                if node.get("channels_json"):
                    try:
                        channels = json.loads(node["channels_json"])
                    except (json.JSONDecodeError, TypeError):
                        pass
                self.app.state.discovered_nodes[h] = {
                    "hash": h,
                    "node_name": node.get("node_name", "Unknown"),
                    "channel_count": node.get("channel_count", 0),
                    "last_seen": node.get("last_seen", 0),
                    "channels": channels,
                    "channel_dests": {},
                    "primary_dest": None,
                    "bookmarked": bool(node.get("bookmarked", 0)),
                }
        except Exception:
            logger.debug("failed to load discovered nodes from DB", exc_info=True)

        try:
            for peer in self.app.db.get_discovered_peers():
                h = peer["hash"]
                self.app.state.discovered_peers[h] = {
                    "hash": h,
                    "display_name": peer.get("display_name", ""),
                    "status_text": peer.get("status_text", ""),
                    "last_seen": peer.get("last_seen", 0),
                    "bookmarked": bool(peer.get("bookmarked", 0)),
                }
        except Exception:
            logger.debug("failed to load discovered peers from DB", exc_info=True)

        self._refresh_nodes()
        self._refresh_peers()
        self._refresh_favorites()

    # ── Sub-tab plumbing ─────────────────────────────────────────────

    def _switch_sub_tab(self, tab: str) -> None:
        """Switch between nodes, peers, and favorites sub-tabs."""
        self._sub_tab = tab

        if tab == "nodes":
            self._active_list.original_widget = self._nodes.listbox
            self._refresh_nodes()
        elif tab == "peers":
            self._active_list.original_widget = self._peers.listbox
            self._refresh_peers()
        else:
            self._active_list.original_widget = self._favorites.listbox
            self._refresh_favorites()

        self._nodes_btn.set_attr_map({None: "tab_active" if tab == "nodes" else "tab_inactive"})
        self._peers_btn.set_attr_map({None: "tab_active" if tab == "peers" else "tab_inactive"})
        self._favorites_btn.set_attr_map(
            {None: "tab_active" if tab == "favorites" else "tab_inactive"}
        )
        self.app._schedule_redraw()

    def _refresh_active(self) -> None:
        """Refresh whichever sub-tab is currently active."""
        if self._sub_tab == "nodes":
            self._refresh_nodes()
        elif self._sub_tab == "peers":
            self._refresh_peers()
        else:
            self._refresh_favorites()

    def on_activate(self) -> None:
        """Called when this tab becomes active. Refresh from current state."""
        self._refresh_active()

    def update(self):
        """Called periodically by refresh job."""
        self._refresh_active()

    def _get_filter_text(self) -> str:
        return self._filter_edit.get_edit_text().strip().lower()

    def _refresh_nodes(self) -> None:
        self._nodes.refresh(self._get_filter_text())

    def _refresh_peers(self) -> None:
        self._peers.refresh(self._get_filter_text())

    def _refresh_favorites(self) -> None:
        self._favorites.refresh(self._get_filter_text())

    # ── Connect routing (cross-cutting, stays on parent) ────────────

    def _is_local_daemon_node(self, node_dict: dict) -> bool:
        """Check if an announced node is a locally-running daemon.

        Matches by ``node_identity_hash`` (stable, unforgeable) against
        live PID files under ``~/.hokora*/hokorad.pid``. On match,
        sets ``HOKORA_CONFIG`` so ``/local`` reads the right DB.

        Falls back to node_name matching only when HOKORA_CONFIG is
        already set by the user (explicit override wins).
        """
        from pathlib import Path

        node_identity_hash = node_dict.get("node_identity_hash")

        config_path = os.environ.get("HOKORA_CONFIG")
        if config_path:
            return self._config_matches(config_path, node_identity_hash, node_dict.get("node_name"))

        # Require identity_hash for discovery — older announces without it
        # can't be safely matched by name alone (two nodes could share a name).
        if not node_identity_hash:
            return False

        home = Path.home()
        for pid_file in sorted(home.glob(".hokora*/hokorad.pid")):
            try:
                pid = int(pid_file.read_text().strip())
            except (ValueError, OSError):
                continue
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                continue
            except PermissionError:
                pass  # process exists, can't signal — treat as alive
            toml_path = pid_file.parent / "hokora.toml"
            if not toml_path.exists():
                continue
            if self._config_matches(str(toml_path), node_identity_hash, None):
                os.environ["HOKORA_CONFIG"] = str(toml_path)
                return True

        return False

    @staticmethod
    def _config_matches(
        config_path: str,
        node_identity_hash: str | None,
        node_name: str | None,
    ) -> bool:
        """True if the daemon at ``config_path`` has the given identity hash
        (preferred) or, as a fallback, the given node_name."""
        from pathlib import Path

        if not Path(config_path).exists():
            return False

        data_dir = None
        file_node_name = None
        try:
            with open(config_path) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("data_dir"):
                        data_dir = line.split("=", 1)[1].strip().strip('"').strip("'")
                    elif line.startswith("node_name"):
                        file_node_name = line.split("=", 1)[1].strip().strip('"').strip("'")
        except Exception:
            return False

        if node_identity_hash and data_dir:
            id_path = Path(data_dir) / "identities" / "node_identity"
            if id_path.exists():
                try:
                    import RNS

                    ident = RNS.Identity.from_file(str(id_path))
                    return ident.hexhash == node_identity_hash
                except Exception:
                    logger.debug("identity file probe failed: %s", id_path, exc_info=True)

        if node_name and file_node_name:
            return file_node_name == node_name
        return False

    def _on_node_selected(self, node_dict: dict) -> None:
        """Handle Enter on a node — unified connect action.

        For nodes with channel_dests: connect via RNS (/connect).
        For local daemon nodes without channel_dests: use /local.
        If already connected to this node: just switch to Channels tab.
        """
        if not node_dict:
            return

        channel_dests = node_dict.get("channel_dests") or {}
        channels = node_dict.get("channels") or []
        node_name = node_dict.get("node_name") or "Unknown"

        if (
            self.app.state.connection_status == "connected"
            and self.app.state.connected_node_name == node_name
            and self.app.state.channels
        ):
            self.app.nav.switch_to(3)
            self.app.status.set_context(f"Already connected to {node_name}")
            self.app._schedule_redraw()
            return

        # Check if this is the local daemon FIRST — /local reads all channels
        # from DB which is better than /connect (single channel only).
        if self._is_local_daemon_node(node_dict):
            self.app.status.set_context(f"Loading channels from {node_name}...")
            self.app._schedule_redraw()
            self.app.handle_command("/local")
            return

        if channel_dests:
            first_channel_id = next(iter(channel_dests))
            dest_hash = channel_dests.get(first_channel_id) or ""

            if not dest_hash:
                self.app.status.set_context(
                    f"No valid destination hash for {node_name}. Try refreshing."
                )
                self.app._schedule_redraw()
                return

            try:
                bytes.fromhex(dest_hash)
            except (ValueError, TypeError):
                self.app.status.set_context(
                    f"Invalid destination hash for {node_name}: {dest_hash!r}"
                )
                self.app._schedule_redraw()
                return

            ch_name = channels[0] if channels else first_channel_id
            self.app.status.set_context(f"Connecting to {node_name} #{ch_name}...")
            self.app._schedule_redraw()

            self.app.handle_command(f"/connect {dest_hash} {first_channel_id}")
            return

        if self._is_local_daemon_node(node_dict):
            # Shouldn't reach here (checked above), but handle anyway.
            self.app.handle_command("/local")
            return

        # Try primary_dest as fallback.
        primary = node_dict.get("primary_dest")
        if primary and isinstance(primary, str) and len(primary) >= 8:
            self.app.status.set_context(f"Connecting to {node_name}...")
            self.app._schedule_redraw()
            self.app.handle_command(f"/connect {primary}")
            return

        self.app.status.set_context(
            f"Waiting for {node_name} to announce channel destinations. Try again shortly."
        )
        self.app._schedule_redraw()

    def _on_peer_selected(self, peer_dict: dict) -> None:
        """Handle Enter on a peer — open DM conversation."""
        peer_hash = peer_dict.get("hash", "")
        if peer_hash:
            self.app.handle_command(f"/dm {peer_hash}")

    # ── Keypress dispatch ───────────────────────────────────────────

    def _active_subview(self):
        """Return the currently-active sub-view instance."""
        if self._sub_tab == "nodes":
            return self._nodes
        if self._sub_tab == "peers":
            return self._peers
        return self._favorites

    def _toggle_bookmark_focused(self) -> None:
        sub = self._active_subview()
        sub.toggle_bookmark_focused()
        self._refresh_active()
        self.app._schedule_redraw()

    def _show_info_focused(self) -> None:
        self._active_subview().show_info_focused()
        self.app._schedule_redraw()

    def handle_key(self, size: tuple, key: str) -> str | None:
        """Handle discovery-specific keys before the Pile processes them."""
        if key == "enter":
            # If favorites invite edit has focus and text, trigger redeem.
            if self._sub_tab == "favorites" and self._favorites.invite_has_text():
                self._favorites.redeem_invite()
                return None
            # Delegate Enter directly to the focused item in the active walker.
            active = self._active_subview()
            focus_widget, _ = active.walker.get_focus()
            if focus_widget is not None and hasattr(focus_widget, "keypress"):
                result = focus_widget.keypress((size[0],), key)
                if result is None:
                    return None
            return key
        if key in ("left", "right"):
            tabs = self._SUB_TABS
            idx = tabs.index(self._sub_tab) if self._sub_tab in tabs else 0
            if key == "right":
                idx = (idx + 1) % len(tabs)
            else:
                idx = (idx - 1) % len(tabs)
            self._switch_sub_tab(tabs[idx])
            return None
        # Don't intercept single-char hotkeys when invite input has focus.
        if self._sub_tab == "favorites" and self._favorites.invite_edit.get_edit_text() != "":
            return key
        if key in ("b", "B"):
            self._toggle_bookmark_focused()
            return None
        if key in ("i", "I"):
            self._show_info_focused()
            return None
        return key  # Not handled — let Pile process it.


# Re-exports: callers that import these symbols from this module
# directly continue to work.
__all__ = ["DiscoveryView", "NodeItem", "PeerItem"]
