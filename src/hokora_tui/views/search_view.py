# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Search view — overlay within Channels tab for searching messages."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import urwid

from hokora_tui.widgets.hokora_button import HokoraButton
from hokora_tui.widgets.message_widget import MessageWidget

if TYPE_CHECKING:
    from hokora_tui.app import HokoraTUI

logger = logging.getLogger(__name__)


class SearchView:
    """Overlay that provides message search within a channel."""

    def __init__(self, app: HokoraTUI) -> None:
        self.app = app
        self._channel_id: str | None = None
        self._query: str = ""
        self._result_messages: list[dict] = []

        # Search input
        self._search_edit = urwid.Edit(("input_prompt", "Search: "))
        self._search_styled = urwid.AttrMap(self._search_edit, "input_text")

        # Buttons
        search_btn = urwid.AttrMap(
            HokoraButton("Search", on_press=self._on_search_press), "button_normal", "button_focus"
        )
        close_btn = urwid.AttrMap(
            HokoraButton("Close", on_press=self._on_close_press), "button_normal", "button_focus"
        )

        # Top row: search input + buttons
        self._top_row = urwid.Columns(
            [
                ("weight", 3, self._search_styled),
                ("weight", 1, urwid.Padding(search_btn, left=1, right=1)),
                ("weight", 1, urwid.Padding(close_btn, left=1, right=1)),
            ]
        )

        # Results list
        self._results_walker = urwid.SimpleFocusListWalker([])
        self._results_listbox = urwid.ListBox(self._results_walker)

        # Status line
        self._status_text = urwid.Text(("default", "[Enter] Jump to message | [Esc] Close"))

        # Layout
        pile = urwid.Pile(
            [
                ("pack", self._top_row),
                ("pack", urwid.Divider()),
                ("weight", 1, self._results_listbox),
                ("pack", self._status_text),
            ]
        )

        self._linebox = urwid.LineBox(pile, title="Search")
        self.widget = self._linebox

    def open_search(self, channel_id: str) -> None:
        """Open search for a specific channel."""
        self._channel_id = channel_id
        self._query = ""
        self._result_messages = []
        self._search_edit.set_edit_text("")
        self._results_walker.clear()

        # Find channel name for title
        ch_name = channel_id
        for ch in self.app.state.channels:
            if ch["id"] == channel_id:
                ch_name = ch.get("name", channel_id)
                break
        self._linebox.set_title(f"Search #{ch_name}")
        self._status_text.set_text(("default", "[Enter] Jump to message | [Esc] Close"))

    def _do_search(self) -> None:
        """Execute the search query."""
        query = self._search_edit.get_edit_text().strip()
        if not query:
            self.app.status.set_context("Enter a search query.")
            return

        self._query = query
        self._results_walker.clear()
        self._result_messages = []

        # Try sync engine first
        if self.app.sync_engine and hasattr(self.app.sync_engine, "search"):
            self.app.sync_engine.search(self._channel_id, query)
            self._status_text.set_text(("default", "Searching..."))
            return

        # Fall back to local search
        results = self._search_local(query)
        self._on_search_results(results)

    def _search_local(self, query: str) -> list[dict]:
        """Search local state and DB for messages matching the query."""
        results = []
        channel_id = self._channel_id
        if not channel_id:
            return results

        query_lower = query.lower()

        # Search in-memory state first
        messages = self.app.state.messages.get(channel_id, [])
        for msg in messages:
            body = msg.get("body", "")
            if body and query_lower in body.lower():
                results.append(msg)

        # Also search client DB
        if self.app.db is not None:
            try:
                db_msgs = self.app.db.get_messages(channel_id, limit=500)
                seen_hashes = {r.get("msg_hash") for r in results}
                for msg in db_msgs:
                    if msg.get("msg_hash") in seen_hashes:
                        continue
                    body = msg.get("body", "")
                    if body and query_lower in body.lower():
                        results.append(msg)
            except Exception:
                logger.debug("search DB fallback failed for %s", channel_id, exc_info=True)

        # Sort by timestamp descending (most recent first)
        results.sort(key=lambda m: m.get("timestamp", 0), reverse=True)
        return results

    def _on_search_results(self, data: list[dict]) -> None:
        """Populate results list when search data arrives."""
        self._results_walker.clear()
        self._result_messages = data

        if not data:
            self._results_walker.append(urwid.Text(("default", "  No results found.")))
            self._status_text.set_text(("default", "0 results | [Esc] Close"))
        else:
            for msg in data:
                w = self._make_highlighted_widget(msg)
                self._results_walker.append(w)
            self._status_text.set_text(
                ("default", f"{len(data)} results | [Enter] Jump to message | [Esc] Close")
            )

        self.app._schedule_redraw()

    def _make_highlighted_widget(self, msg: dict) -> MessageWidget:
        """Create a MessageWidget with query term highlighted.

        We modify the body to wrap matching text with highlight markers,
        then create a standard MessageWidget.
        """
        if self._query:
            body = msg.get("body", "")
            query_lower = self._query.lower()
            body_lower = body.lower()

            # Build highlighted body using urwid markup
            # For simplicity, we create a copy with the match marked
            idx = body_lower.find(query_lower)
            if idx >= 0:
                highlighted_msg = dict(msg)
                # Mark the match by uppercasing (simple visual indicator)
                # The actual highlighting is done via the MessageWidget's mention style
                highlighted_msg["_search_match"] = True
                return MessageWidget(highlighted_msg, sealed_keys=self._sealed_keys())

        return MessageWidget(msg, sealed_keys=self._sealed_keys())

    def _sealed_keys(self):
        db = getattr(self.app, "db", None)
        return getattr(db, "sealed_keys", None) if db else None

    def _jump_to_message(self) -> None:
        """Jump to the selected search result in the main messages view."""
        if not self._results_walker:
            return

        focus_widget, idx = self._results_walker.get_focus()
        if idx is not None and idx < len(self._result_messages):
            msg = self._result_messages[idx]
            seq = msg.get("seq")
            msg_hash = msg.get("msg_hash")

            # Close search first
            if hasattr(self.app, "channels_view") and self.app.channels_view is not None:
                self.app.channels_view.close_search()

            # Try to scroll to the message in the messages view
            if seq is not None and hasattr(self.app, "messages_view"):
                view = self.app.messages_view
                for i, mw in enumerate(view._message_widgets):
                    if mw.msg_hash == msg_hash or mw.msg_dict.get("seq") == seq:
                        if view._walker:
                            view._walker.set_focus(i)
                        break

            self.app.status.set_context(f"Jumped to message {(msg_hash or '')[:12]}")
            self.app._schedule_redraw()

    def _on_search_press(self, button: urwid.Button) -> None:
        self._do_search()

    def _on_close_press(self, button: urwid.Button) -> None:
        if hasattr(self.app, "channels_view") and self.app.channels_view is not None:
            self.app.channels_view.close_search()

    def keypress(self, size: tuple, key: str) -> str | None:
        """Handle keypresses within the search view."""
        if key == "esc":
            if hasattr(self.app, "channels_view") and self.app.channels_view is not None:
                self.app.channels_view.close_search()
            return None

        if key == "enter":
            # If results have focus, jump to message; otherwise do search
            # Check if we're focused on the results list
            if self._results_walker and self._result_messages:
                focus_w, focus_idx = self._results_walker.get_focus()
                if focus_w is not None and isinstance(focus_w, MessageWidget):
                    self._jump_to_message()
                    return None
            # Otherwise do search
            self._do_search()
            return None

        # Delegate to inner widgets
        return self.widget.keypress(size, key)

    def selectable(self) -> bool:
        return True
