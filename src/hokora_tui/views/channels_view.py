# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Channels tab — sidebar + messages area + compose box + thread/search overlays."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import urwid

from hokora_tui.widgets.channel_item import ChannelItem

if TYPE_CHECKING:
    from hokora_tui.app import HokoraTUI

logger = logging.getLogger(__name__)


class ChannelsView:
    """Two-pane layout: channel sidebar (left) and messages + compose (right).

    Supports thread and search overlays that temporarily replace the right panel.
    """

    def __init__(self, app: HokoraTUI) -> None:
        self.app = app

        # --- Sidebar ---
        self._sidebar_walker = urwid.SimpleFocusListWalker([])
        self._sidebar_listbox = urwid.ListBox(self._sidebar_walker)
        self._sidebar_box = urwid.LineBox(self._sidebar_listbox, title="Channels")

        # Channel item lookup: channel_id -> ChannelItem
        self._channel_items: dict[str, ChannelItem] = {}

        # --- Welcome placeholder (shown until a channel is selected) ---
        placeholder_text = "Press F3 (Discovery) to find and connect to a node"
        self._placeholder = urwid.Filler(
            urwid.Text(("bold", placeholder_text), align="center"),
            valign="middle",
        )

        # Border the messages list directly. Layered chain
        # (LineBox→WidgetPlaceholder→WidgetWrap→ListBox) breaks keypress
        # delegation to the body ListBox under urwid 2.6.x — actions like
        # r/e/d/p/t/+/f never reach the message handler. Wrapping the
        # listbox-wrapper directly (depth-1, same as the sidebar
        # `LineBox(_sidebar_listbox)`) keeps the keypress path intact.
        # The empty-state swap happens at `_right_area` level, NOT inside
        # the LineBox.
        self._messages_box = urwid.LineBox(app.messages_view.widget, title="Messages")

        # --- Compose box — wrapped in WidgetPlaceholder for dynamic updates ---
        self._compose_area = urwid.WidgetPlaceholder(app.compose_box)

        self._right_frame = urwid.Frame(
            body=self._messages_box,
            footer=self._compose_area,
        )

        # Wire compose box to parent frame for focus switching
        app.compose_box._parent_frame = self._right_frame

        # Save the normal right frame for overlay restoration
        self._normal_right_pile = self._right_frame

        # Right panel placeholder — starts on welcome text, swaps to the
        # bordered Frame on first channel select; thread/search overlays
        # also swap here.
        self._right_area = urwid.WidgetPlaceholder(self._placeholder)

        # Two-column layout
        columns = urwid.Columns(
            [
                ("weight", 1, self._sidebar_box),
                ("weight", 3, self._right_area),
            ]
        )

        self.widget = columns

        # Overlay state
        self._thread_view = None
        self._search_view = None
        self._overlay_active: str | None = None  # "thread" | "search" | None

        # Subscribe to state events
        app.state.on("channels_updated", self._on_channels_updated)

    def on_activate(self):
        """Called when Channels tab becomes active."""
        self.refresh_channels()

    def _on_channels_updated(self, data=None) -> None:
        """Rebuild sidebar when channels change. Auto-select first channel if none selected."""
        logger.info(
            "_on_channels_updated: received event, channels=%d",
            len(self.app.state.channels) if self.app.state.channels else 0,
        )
        self.refresh_channels()

        # Auto-select first channel if none currently selected
        if not self.app.state.current_channel_id and self.app.state.channels:
            first_ch = self.app.state.channels[0].get("id")
            if first_ch:
                self.select_channel(first_ch)

    def refresh_channels(self) -> None:
        """Rebuild the sidebar channel list from app.state.channels.

        When multiple nodes advertise channels with the same human-readable
        name (federation / multi-node dev), each clashing row is labelled
        ``NodeName · channel`` so the user can tell them apart. Orphan rows
        with no known owning node are prefixed with ``?``.
        """
        self._sidebar_walker.clear()
        self._channel_items.clear()

        channels = self.app.state.channels
        if channels is None:
            channels = []
        if not channels:
            self._sidebar_walker.append(urwid.Text(("default", "  No channels.")))
            return

        # Clash detection: a channel name "clashes" iff more than one distinct
        # node_identity_hash (including None) owns a channel with that name.
        name_to_node_hashes: dict[str, set] = {}
        for ch in channels:
            name = ch.get("name", "")
            name_to_node_hashes.setdefault(name, set()).add(ch.get("node_identity_hash"))

        # node_identity_hash → node_name lookup built from discovered_nodes.
        # Falls back to an 8-char hex abbreviation if the node isn't indexed.
        node_name_by_hash: dict[str, str] = {}
        for node in (self.app.state.discovered_nodes or {}).values():
            nh = node.get("node_identity_hash")
            nn = node.get("node_name")
            if nh and nn:
                node_name_by_hash[nh] = nn

        def _display_name(ch: dict) -> str:
            name = ch.get("name", "")
            nhash = ch.get("node_identity_hash")
            if nhash is None:
                return f"? {name}"
            if len(name_to_node_hashes.get(name, set())) > 1:
                nn = node_name_by_hash.get(nhash) or nhash[:8]
                return f"{nn} \u00b7 {name}"
            return name

        # Group by category
        categories: dict[str | None, list[dict]] = {}
        for ch in channels:
            cat = ch.get("category_id")
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(ch)

        for cat_id, cat_channels in categories.items():
            # Category header
            if cat_id:
                header = urwid.Text(("category_header", f"  {cat_id}"))
                self._sidebar_walker.append(header)

            for ch in cat_channels:
                unread = self.app.state.unread_counts.get(ch["id"], 0)
                # Pass a shallow-copied dict with the disambiguated display
                # name so the widget's label uses it. click-through still
                # uses the original channel_id, no ambiguity.
                display_ch = {**ch, "name": _display_name(ch)}
                item = ChannelItem(display_ch, self.select_channel, unread=unread)
                self._channel_items[ch["id"]] = item
                self._sidebar_walker.append(item)

        self.app._schedule_redraw()

    def select_channel(self, channel_id: str) -> None:
        """Select a channel: update state, load messages, wire views."""
        self.app.state.current_channel_id = channel_id

        # Reset unread count
        self.app.state.unread_counts[channel_id] = 0
        if hasattr(self.app, "db") and self.app.db is not None:
            self.app.db.reset_channel_unread(channel_id)

        # Update channel item badge
        item = self._channel_items.get(channel_id)
        if item:
            item.set_unread(0)

        # Load messages from state (populated by /local or sync)
        state_messages = self.app.state.messages
        if state_messages is None:
            state_messages = {}
        messages = state_messages.get(channel_id)
        if messages is None:
            messages = []

        # Populate the message list (wired into _messages_box at __init__).
        self.app.messages_view.set_messages(messages)

        # First channel select: swap right pane from welcome placeholder to
        # the bordered chat Frame. Overlays (thread/search) re-use this
        # placeholder, so closing them restores `_normal_right_pile`.
        if self._right_area.original_widget is not self._right_frame:
            self._right_area.original_widget = self._right_frame

        self._compose_area.original_widget = self.app.compose_box

        # Find channel name for status line
        ch_name = channel_id
        for ch in self.app.state.channels:
            if ch["id"] == channel_id:
                ch_name = ch.get("name", channel_id)
                break

        self._messages_box.set_title(f"# {ch_name}")

        # Switch Columns focus to right panel, Frame focus to compose
        try:
            self.widget.focus_position = 1
            self._right_frame.focus_position = "footer"
        except (IndexError, AttributeError):
            pass

        self.app.status.set_context(f"# {ch_name}")
        self.app._schedule_redraw()

    def update_unread(self, channel_id: str, count: int) -> None:
        """Update the unread badge for a specific channel."""
        item = self._channel_items.get(channel_id)
        if item:
            item.set_unread(count)

    # ------------------------------------------------------------------
    # Thread overlay
    # ------------------------------------------------------------------

    def open_thread(self, msg_hash: str) -> None:
        """Open the thread overlay for a given root message hash."""
        from hokora_tui.views.thread_view import ThreadView

        if self._thread_view is None:
            self._thread_view = ThreadView(self.app)

        self._thread_view.open_thread(msg_hash)
        self._right_area.original_widget = self._thread_view.widget
        self._overlay_active = "thread"
        self.app.status.set_context(f"Thread: {msg_hash[:12]}... | Esc to close")
        self.app._schedule_redraw()

    def close_thread(self) -> None:
        """Close the thread overlay and restore normal messages view."""
        self._right_area.original_widget = self._normal_right_pile
        self._overlay_active = None
        # Restore status context
        channel_id = self.app.state.current_channel_id
        if channel_id:
            ch_name = channel_id
            for ch in self.app.state.channels:
                if ch["id"] == channel_id:
                    ch_name = ch.get("name", channel_id)
                    break
            self.app.status.set_context(f"# {ch_name}")
        self.app._schedule_redraw()

    # ------------------------------------------------------------------
    # Search overlay
    # ------------------------------------------------------------------

    def open_search(self) -> None:
        """Open the search overlay for the current channel."""
        from hokora_tui.views.search_view import SearchView

        channel_id = self.app.state.current_channel_id
        if not channel_id:
            self.app.status.set_context("Select a channel first to search.")
            return

        if self._search_view is None:
            self._search_view = SearchView(self.app)

        self._search_view.open_search(channel_id)
        self._right_area.original_widget = self._search_view.widget
        self._overlay_active = "search"
        self.app._schedule_redraw()

    def close_search(self) -> None:
        """Close the search overlay and restore normal messages view."""
        self._right_area.original_widget = self._normal_right_pile
        self._overlay_active = None
        channel_id = self.app.state.current_channel_id
        if channel_id:
            ch_name = channel_id
            for ch in self.app.state.channels:
                if ch["id"] == channel_id:
                    ch_name = ch.get("name", channel_id)
                    break
            self.app.status.set_context(f"# {ch_name}")
        self.app._schedule_redraw()
