# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Messages list view — scrollable message list with selection and pagination."""

from __future__ import annotations

from typing import TYPE_CHECKING

import urwid

from hokora_tui.widgets.confirm_dialog import ConfirmDialog
from hokora_tui.widgets.message_widget import MessageWidget

if TYPE_CHECKING:
    from hokora_tui.app import HokoraTUI


class _MessagesListBox(urwid.WidgetWrap):
    """ListBox wrapper that delegates action keys to MessagesView."""

    def __init__(self, listbox, view):
        self._view = view
        super().__init__(listbox)

    def keypress(self, size, key):
        result = self._view.keypress(size, key)
        if result is None:
            return None
        return super().keypress(size, key)


class MessagesView:
    """Scrollable list of messages for the current channel.

    Supports setting, appending, and prepending messages, plus
    keyboard navigation for message actions.
    """

    def __init__(self, app: HokoraTUI) -> None:
        self.app = app
        self._walker = urwid.SimpleFocusListWalker([])
        self._listbox = urwid.ListBox(self._walker)
        self._selected_index: int | None = None
        self._message_widgets: list[MessageWidget] = []
        self._reaction_target: str | None = None  # msg_hash awaiting emoji input
        self.widget = _MessagesListBox(self._listbox, self)

    @property
    def _sealed_keys(self):
        """Return the SealedKeyStore for render-time decrypt, or None."""
        db = getattr(self.app, "db", None)
        return getattr(db, "sealed_keys", None) if db else None

    def _resolve_reply_context(self, msg: dict, lookup: dict) -> None:
        """Add reply_context to msg if it has a reply_to that we can resolve."""
        reply_to = msg.get("reply_to")
        if reply_to and reply_to in lookup:
            parent = lookup[reply_to]
            name = parent.get("display_name") or parent.get("sender_hash", "")[:8]
            body = parent.get("body") or ""
            snippet = body[:40] + ("..." if len(body) > 40 else "")
            msg["reply_context"] = f"{name}: {snippet}"

    def set_messages(self, messages: list[dict]) -> None:
        """Clear and rebuild from a list of message dicts."""
        self._walker.clear()
        self._message_widgets.clear()
        self._selected_index = None
        # Build lookup for reply context resolution
        lookup = {m.get("msg_hash"): m for m in messages if m.get("msg_hash")}
        for msg in messages:
            self._resolve_reply_context(msg, lookup)
            w = MessageWidget(msg, sealed_keys=self._sealed_keys)
            self._message_widgets.append(w)
            self._walker.append(w)
        # Scroll to bottom
        if self._walker:
            self._walker.set_focus(len(self._walker) - 1)

    def append_message(self, msg_dict: dict) -> None:
        """Add a single message at the end and auto-scroll to bottom."""
        # Try to resolve reply context from existing messages in state
        if msg_dict.get("reply_to") and hasattr(self, "app") and self.app:
            ch_id = msg_dict.get("channel_id")
            if ch_id and ch_id in self.app.state.messages:
                lookup = {
                    m.get("msg_hash"): m
                    for m in self.app.state.messages[ch_id]
                    if m.get("msg_hash")
                }
                self._resolve_reply_context(msg_dict, lookup)
        w = MessageWidget(msg_dict, sealed_keys=self._sealed_keys)
        self._message_widgets.append(w)
        self._walker.append(w)
        if self._walker:
            self._walker.set_focus(len(self._walker) - 1)

    def prepend_messages(self, messages: list[dict]) -> None:
        """Add older messages at the top (for pagination)."""
        new_widgets = []
        for msg in messages:
            w = MessageWidget(msg, sealed_keys=self._sealed_keys)
            new_widgets.append(w)
        # Insert at the beginning
        for i, w in enumerate(new_widgets):
            self._message_widgets.insert(i, w)
            self._walker.insert(i, w)

    def get_selected_message(self) -> dict | None:
        """Return the msg_dict of the currently focused message, or None."""
        if not self._walker:
            return None
        focus_widget, idx = self._walker.get_focus()
        if focus_widget is not None and isinstance(focus_widget, MessageWidget):
            return focus_widget.msg_dict
        return None

    def keypress(self, size: tuple, key: str) -> str | None:
        """Handle message-area keys: actions + pagination."""
        # Page Up at top triggers older message load
        if key == "page up":
            focus_widget, idx = self._walker.get_focus()
            if idx == 0 or not self._walker:
                if hasattr(self.app, "load_older_messages"):
                    self.app.load_older_messages()
                return None

        # Message action keys
        msg = self.get_selected_message()
        if msg and hasattr(self.app, "commands") and self.app.commands is not None:
            channel_id = self.app.state.current_channel_id
            msg_hash = msg.get("msg_hash", "")

            if key == "r":
                # Prepare reply mode
                if hasattr(self.app, "compose_box") and self.app.compose_box is not None:
                    self.app.compose_box.set_reply_mode(msg_hash)
                return None
            elif key == "e":
                # Populate compose with message body for editing
                if hasattr(self.app, "compose_box") and self.app.compose_box is not None:
                    self.app.compose_box.set_edit_mode(msg_hash, msg.get("body", ""))
                return None
            elif key == "d":
                # Delete message — confirm-gated to prevent accidental loss.
                if channel_id and msg_hash:
                    self._confirm_delete(channel_id, msg_hash)
                return None
            elif key == "+":
                # Add reaction — enter reaction mode
                if msg_hash:
                    self._reaction_target = msg_hash
                    self.app.status.set_notice(
                        "Reaction mode: type emoji and press Enter (Esc cancel)",
                        level="info",
                        duration=6.0,
                    )
                    if hasattr(self.app, "compose_box") and self.app.compose_box:
                        self.app.compose_box.set_reaction_mode(msg_hash)
                return None
            elif key == "p":
                # Pin message
                if channel_id and msg_hash:
                    self.app.status.set_notice(
                        f"Pinning message {msg_hash[:12]}...",
                        level="info",
                    )
                    if hasattr(self.app, "sync_engine") and self.app.sync_engine:
                        self.app.sync_engine.send_pin(channel_id, msg_hash)
                return None
            elif key == "t":
                # Open thread via channels_view overlay
                if msg_hash and hasattr(self.app, "channels_view") and self.app.channels_view:
                    self.app.channels_view.open_thread(msg_hash)
                return None
            elif key == "f":
                # Download media attachment
                media_path = msg.get("media_path")
                if media_path and channel_id:
                    self.app.status.set_notice(f"Downloading {media_path}...", level="info")
                    if hasattr(self.app, "sync_engine") and self.app.sync_engine:
                        self.app.sync_engine.request_media_download(channel_id, media_path)
                else:
                    self.app.status.set_notice(
                        "No media attachment on this message",
                        level="warn",
                    )
                return None

        # Let the listbox handle the key
        return self._listbox.keypress(size, key)

    def clear(self) -> None:
        """Remove all messages."""
        self._walker.clear()
        self._message_widgets.clear()
        self._selected_index = None

    def _confirm_delete(self, channel_id: str, msg_hash: str) -> None:
        """Show confirm dialog before sending a delete to the daemon.

        Setting ``confirm_destructive_actions=false`` in client_db.settings
        bypasses the dialog for power users — opt-in only, default ON.
        """
        confirm_pref = "true"
        if hasattr(self.app, "db") and self.app.db is not None:
            confirm_pref = self.app.db.get_setting("confirm_destructive_actions") or "true"

        def _do_delete() -> None:
            self.app.status.set_notice(
                f"Deleting message {msg_hash[:12]}...",
                level="info",
            )
            if hasattr(self.app, "sync_engine") and self.app.sync_engine:
                self.app.sync_engine.send_delete(channel_id, msg_hash)

        if confirm_pref == "false":
            _do_delete()
            return

        ConfirmDialog.show(
            self.app,
            f"Delete message {msg_hash[:12]}? This cannot be undone.",
            on_confirm=_do_delete,
        )
