# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Compose box widget — message input with history and command dispatch."""

from __future__ import annotations

from typing import TYPE_CHECKING

import urwid

from hokora.constants import MAX_MESSAGE_BODY_SIZE, MSG_TEXT

if TYPE_CHECKING:
    from hokora_tui.app import HokoraTUI

_MAX_HISTORY = 100


class ComposeBox(urwid.WidgetWrap):
    """Message input box with /command dispatch and input history."""

    def __init__(self, app: HokoraTUI) -> None:
        self.app = app
        self._edit = urwid.Edit(("input_prompt", "> "))
        self._styled = urwid.AttrMap(self._edit, "input_text")
        super().__init__(self._styled)

        # Input history
        self._history: list[str] = []
        self._history_index: int = -1
        self._current_text: str = ""

        # Parent frame for focus switching (set by channels_view/conversations_view)
        self._parent_frame: object | None = None

        # Reply/edit/reaction mode
        self._reply_to: str | None = None
        self._edit_hash: str | None = None
        self._reaction_hash: str | None = None

    def keypress(self, size: tuple, key: str) -> str | None:
        if key == "enter":
            text = self._edit.get_edit_text().strip()
            if text:
                # Save to history
                self._history.append(text)
                if len(self._history) > _MAX_HISTORY:
                    self._history.pop(0)
                self._history_index = -1
                self._current_text = ""

                self._handle_input(text)
                self._edit.set_edit_text("")
            return None

        if key in ("page up", "page down"):
            # Switch focus to messages — next page up/down scrolls
            if self._parent_frame:
                self._parent_frame.focus_position = "body"
            return None

        if key == "up":
            # Navigate history backward
            if self._history:
                if self._history_index == -1:
                    self._current_text = self._edit.get_edit_text()
                    self._history_index = len(self._history) - 1
                elif self._history_index > 0:
                    self._history_index -= 1
                self._edit.set_edit_text(self._history[self._history_index])
                self._edit.set_edit_pos(len(self._edit.get_edit_text()))
                return None

        if key == "down":
            # Navigate history forward
            if self._history_index >= 0:
                if self._history_index < len(self._history) - 1:
                    self._history_index += 1
                    self._edit.set_edit_text(self._history[self._history_index])
                else:
                    self._history_index = -1
                    self._edit.set_edit_text(self._current_text)
                self._edit.set_edit_pos(len(self._edit.get_edit_text()))
                return None

        if key == "esc":
            # Cancel reply/edit/reaction mode
            if self._reply_to or self._edit_hash or self._reaction_hash:
                self.clear_reply_mode()
                return None

        return self._edit.keypress(size, key)

    def _handle_input(self, text: str) -> None:
        """Route input to command handler or message sender."""
        if text.startswith("/"):
            self.app.handle_command(text)
        elif self._reaction_hash:
            self._send_reaction(text)
        elif self._edit_hash:
            self._send_edit(text)
        else:
            self._send_message(text)

    def _send_message(self, body: str) -> None:
        """Send a text message to the current channel."""
        channel_id = self.app.state.current_channel_id
        if not channel_id:
            self.app.status.set_notice("Select a channel first.", level="warn")
            return

        # Check channel write access (from node_meta can_write flag)
        for ch in self.app.state.channels:
            if ch.get("id") == channel_id:
                if ch.get("can_write") is False:
                    access = ch.get("access_mode", "")
                    if access == "write_restricted":
                        self.app.status.set_notice(
                            "This channel is read-only",
                            level="warn",
                            duration=5.0,
                        )
                    else:
                        self.app.status.set_notice(
                            "Invite required to send in this channel",
                            level="warn",
                            duration=5.0,
                        )
                    return
                break

        # Client-side size check
        if len(body.encode("utf-8")) > MAX_MESSAGE_BODY_SIZE:
            self.app.status.set_notice(
                f"Message too long (max {MAX_MESSAGE_BODY_SIZE} bytes).",
                level="warn",
                duration=5.0,
            )
            return

        msg_data = {
            "type": MSG_TEXT,
            "body": body,
            "display_name": self.app.state.display_name or None,
            "channel_id": channel_id,
        }

        # If we have a reply target, include it
        if self._reply_to:
            msg_data["reply_to"] = self._reply_to

        # Send via sync engine — daemon confirms and pushes back via live event.
        # No optimistic display: the row appears only when the daemon echoes
        # back. Surface a transient "Sending..." notice so the user gets
        # feedback during the ~50ms TCP / 2-5s LoRa round-trip.
        sent = False
        if hasattr(self.app, "sync_engine") and self.app.sync_engine:
            sent = self.app.sync_engine.send_message(channel_id, msg_data)

        if sent:
            self.app.status.set_notice("Sending...", level="info", duration=3.0)
        else:
            self.app.status.set_notice(
                "Message queued locally (no remote connection)",
                level="warn",
            )

        # Clear reply mode
        if self._reply_to:
            self.clear_reply_mode()

        self.app._schedule_redraw()

    def _send_edit(self, new_body: str) -> None:
        """Send an edit for the currently targeted message."""
        channel_id = self.app.state.current_channel_id
        if not channel_id or not self._edit_hash:
            self.clear_reply_mode()
            return

        if hasattr(self.app, "sync_engine") and self.app.sync_engine:
            self.app.sync_engine.send_edit(channel_id, self._edit_hash, new_body)
            self.app.status.set_notice(f"Edit sent for {self._edit_hash[:12]}", level="info")
        else:
            self.app.status.set_notice("No remote connection for edit", level="warn")

        self.clear_reply_mode()

    def _send_reaction(self, emoji: str) -> None:
        """Send a reaction emoji to the target message."""
        channel_id = self.app.state.current_channel_id
        if not channel_id or not self._reaction_hash:
            self.clear_reply_mode()
            return

        # Trim to max 32 chars per spec
        emoji = emoji[:32]
        if hasattr(self.app, "sync_engine") and self.app.sync_engine:
            self.app.sync_engine.send_reaction(channel_id, self._reaction_hash, emoji)
            self.app.status.set_notice(
                f"Reacted {emoji} on {self._reaction_hash[:12]}",
                level="info",
            )
        else:
            self.app.status.set_notice("No remote connection for reaction", level="warn")

        self.clear_reply_mode()

    def set_reply_mode(self, msg_hash: str) -> None:
        """Enter reply mode targeting a specific message."""
        self._reply_to = msg_hash
        self._edit_hash = None
        self._edit.set_caption(("input_prompt", "\u21b3 replying > "))

    def set_edit_mode(self, msg_hash: str, original_body: str) -> None:
        """Enter edit mode, pre-filling the compose box with the original body."""
        self._edit_hash = msg_hash
        self._reply_to = None
        self._edit.set_caption(("input_prompt", "editing > "))
        self._edit.set_edit_text(original_body)
        self._edit.set_edit_pos(len(original_body))

    def set_reaction_mode(self, msg_hash: str) -> None:
        """Enter reaction mode — next Enter sends emoji as reaction."""
        self._reaction_hash = msg_hash
        self._reply_to = None
        self._edit_hash = None
        self._edit.set_caption(("input_prompt", "\u2795 react > "))
        self._edit.set_edit_text("")

    def clear_reply_mode(self) -> None:
        """Reset compose to normal mode."""
        self._reply_to = None
        self._edit_hash = None
        self._reaction_hash = None
        self._edit.set_caption(("input_prompt", "> "))

    def selectable(self) -> bool:
        return True
