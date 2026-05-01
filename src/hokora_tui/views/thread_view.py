# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Thread view — overlay within Channels tab for viewing/replying to threads."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import urwid

from hokora_tui.widgets.message_widget import MessageWidget

if TYPE_CHECKING:
    from hokora_tui.app import HokoraTUI

logger = logging.getLogger(__name__)


class _ThreadLineBox(urwid.WidgetWrap):
    """LineBox wrapper that intercepts Esc (close) and Enter (send reply)."""

    def __init__(self, inner: urwid.Widget, thread_view: ThreadView, **kwargs):
        self._linebox = urwid.LineBox(inner, **kwargs)
        self._thread_view = thread_view
        super().__init__(self._linebox)

    def set_title(self, title: str) -> None:
        self._linebox.set_title(title)

    def keypress(self, size: tuple, key: str) -> str | None:
        if key == "esc":
            app = self._thread_view.app
            if hasattr(app, "channels_view") and app.channels_view is not None:
                app.channels_view.close_thread()
            return None

        if key == "enter":
            text = self._thread_view._compose.get_edit_text().strip()
            if text:
                self._thread_view._send_reply(text)
                self._thread_view._compose.set_edit_text("")
                return None

        return self._linebox.keypress(size, key)

    def selectable(self) -> bool:
        return True


class ThreadView:
    """Overlay that shows a thread (root message + replies) within the Channels tab."""

    def __init__(self, app: HokoraTUI) -> None:
        self.app = app
        self._root_hash: str | None = None
        self._channel_id: str | None = None

        # Root message widget placeholder
        self._root_widget = urwid.Text(("default", ""))
        self._root_area = urwid.WidgetPlaceholder(self._root_widget)

        # Replies list
        self._replies_walker = urwid.SimpleFocusListWalker([])
        self._replies_listbox = urwid.ListBox(self._replies_walker)

        # Thread compose
        self._compose = urwid.Edit(("input_prompt", "\u21b3 "))
        self._compose_styled = urwid.AttrMap(self._compose, "input_text")

        # Layout
        pile = urwid.Pile(
            [
                ("pack", self._root_area),
                ("pack", urwid.Divider("\u2500")),
                ("weight", 1, self._replies_listbox),
                ("pack", urwid.Divider("\u2500")),
                ("pack", self._compose_styled),
            ]
        )

        self.widget = _ThreadLineBox(pile, self, title="Thread")

    def _sealed_keys(self):
        db = getattr(self.app, "db", None)
        return getattr(db, "sealed_keys", None) if db else None

    def open_thread(self, root_msg_hash: str) -> None:
        """Open a thread for the given root message hash."""
        self._root_hash = root_msg_hash
        self._channel_id = self.app.state.current_channel_id
        self._replies_walker.clear()

        # Find root message in state
        root_msg = self._find_message(root_msg_hash)
        if root_msg:
            preview = root_msg.get("body", "")[:60]
            self.widget.set_title(f"Thread: {preview}")
            root_widget = MessageWidget(root_msg, sealed_keys=self._sealed_keys())
            self._root_area.original_widget = root_widget
        else:
            self.widget.set_title(f"Thread: {root_msg_hash[:12]}...")
            self._root_area.original_widget = urwid.Text(
                ("default", f"Loading root message {root_msg_hash[:12]}...")
            )

        # Try sync engine first for thread data
        if self.app.sync_engine and hasattr(self.app.sync_engine, "get_thread"):
            self.app.sync_engine.get_thread(root_msg_hash)
            self.app.status.set_context(f"Loading thread for {root_msg_hash[:12]}...")
        else:
            # Search local DB for thread replies
            self._load_local_thread(root_msg_hash)

    def _find_message(self, msg_hash: str) -> dict | None:
        """Find a message by hash in the current channel's state."""
        channel_id = self._channel_id or self.app.state.current_channel_id
        if not channel_id:
            return None
        messages = self.app.state.messages.get(channel_id, [])
        for msg in messages:
            if msg.get("msg_hash") == msg_hash:
                return msg
        return None

    def _load_local_thread(self, root_hash: str) -> None:
        """Load thread replies from local DB or state."""
        channel_id = self._channel_id or self.app.state.current_channel_id
        if not channel_id:
            return

        # Search state messages for replies to this root
        replies = []
        messages = self.app.state.messages.get(channel_id, [])
        for msg in messages:
            if msg.get("reply_to") == root_hash:
                replies.append(msg)

        # Also check client DB
        if self.app.db is not None:
            try:
                db_msgs = self.app.db.get_messages(channel_id, limit=200)
                for msg in db_msgs:
                    if msg.get("reply_to") == root_hash:
                        # Avoid duplicates
                        if not any(r.get("msg_hash") == msg.get("msg_hash") for r in replies):
                            replies.append(msg)
            except Exception:
                logger.debug(
                    "thread reply DB lookup failed for %s/%s",
                    channel_id,
                    root_hash,
                    exc_info=True,
                )

        # Sort by thread_seq or timestamp
        replies.sort(key=lambda m: m.get("thread_seq", m.get("seq", m.get("timestamp", 0))))
        self._on_thread_data(replies)

    def _on_thread_data(self, messages: list[dict]) -> None:
        """Populate the replies list when thread data arrives."""
        self._replies_walker.clear()
        if not messages:
            self._replies_walker.append(
                urwid.Text(("default", "  No replies yet. Type below to start a thread."))
            )
        else:
            sealed_keys = self._sealed_keys()
            for msg in messages:
                w = MessageWidget(msg, sealed_keys=sealed_keys)
                self._replies_walker.append(w)
            # Scroll to bottom
            if self._replies_walker:
                self._replies_walker.set_focus(len(self._replies_walker) - 1)
        self.app._schedule_redraw()

    def _send_reply(self, body: str) -> None:
        """Send a thread reply."""
        if not body.strip():
            return

        channel_id = self._channel_id or self.app.state.current_channel_id
        if not channel_id or not self._root_hash:
            self.app.status.set_context("No thread context for reply.")
            return

        # Send via sync engine — daemon confirms and pushes back
        sent = False
        if self.app.sync_engine and hasattr(self.app.sync_engine, "send_thread_reply"):
            sent = self.app.sync_engine.send_thread_reply(channel_id, self._root_hash, body)

        if not sent:
            self.app.status.set_context("Thread reply queued locally (no remote connection)")

        self.app._schedule_redraw()

    def keypress(self, size: tuple, key: str) -> str | None:
        """Handle keypresses within the thread view."""
        return self.widget.keypress(size, key)

    def selectable(self) -> bool:
        return True
