# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Conversations tab — Direct Peer Messaging view."""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

import urwid

from hokora_tui.widgets.conversation_item import ConversationItem
from hokora_tui.widgets.message_widget import MessageWidget

if TYPE_CHECKING:
    from hokora_tui.app import HokoraTUI

logger = logging.getLogger(__name__)


class _DMComposeBox(urwid.WidgetWrap):
    """Minimal compose box for sending DMs, wired to the conversations view."""

    def __init__(self, conversations_view: ConversationsView) -> None:
        self._view = conversations_view
        self._edit = urwid.Edit(("input_prompt", "DM > "))
        self._styled = urwid.AttrMap(self._edit, "input_text")
        self._parent_frame = None  # Set by ConversationsView for focus switching
        super().__init__(self._styled)

    def keypress(self, size: tuple, key: str) -> str | None:
        if key == "enter":
            text = self._edit.get_edit_text().strip()
            if text:
                if text.startswith("/"):
                    self._view.app.handle_command(text)
                else:
                    self._view._send_dm(text)
                self._edit.set_edit_text("")
            return None
        if key in ("page up", "page down"):
            # Switch focus to DM messages — next page up/down scrolls
            if self._parent_frame:
                self._parent_frame.focus_position = "body"
            return None
        return self._edit.keypress(size, key)

    def selectable(self) -> bool:
        return True


class ConversationsView:
    """Two-pane DM layout: conversation list (left) and message area (right).

    Left panel: ListBox of ConversationItems, sorted by last_message_time DESC.
    Right panel: Pile [dm_messages (weight=1) | compose_box (pack)].
    """

    def __init__(self, app: HokoraTUI) -> None:
        self.app = app

        # --- Left panel: conversation list ---
        self._convo_walker = urwid.SimpleFocusListWalker([])
        self._convo_listbox = urwid.ListBox(self._convo_walker)
        self._convo_box = urwid.LineBox(self._convo_listbox, title="Conversations")

        # --- Right panel: DM messages + compose ---
        self._dm_walker = urwid.SimpleFocusListWalker([])
        self._dm_listbox = urwid.ListBox(self._dm_walker)

        self._placeholder = urwid.Filler(
            urwid.Text(
                ("bold", "Select a conversation or /dm <hash> <message>"),
                align="center",
            ),
            valign="middle",
        )

        self._compose_box = _DMComposeBox(self)
        self._compose_area = urwid.WidgetPlaceholder(self._compose_box)

        # Border the DM list directly (depth-1, mirrors `_convo_box`). A
        # layered chain (LineBox→WidgetPlaceholder→ListBox) breaks keypress
        # delegation under urwid 2.6.x. Empty-state swap moves to
        # `_right_area`, OUTSIDE the LineBox.
        self._dm_box = urwid.LineBox(self._dm_listbox, title="Direct Messages")

        self._right_pile = urwid.Frame(
            body=self._dm_box,
            footer=self._compose_area,
        )
        # Wire compose box for focus switching
        self._compose_box._parent_frame = self._right_pile

        # Right panel starts on the welcome placeholder; first conversation
        # select swaps it to the bordered Frame.
        self._right_area = urwid.WidgetPlaceholder(self._placeholder)

        # --- Two-column layout ---
        columns = urwid.Columns(
            [
                ("weight", 1, self._convo_box),
                ("weight", 3, self._right_area),
            ]
        )

        self.widget = columns

        # Subscribe to state events
        app.state.on("conversations_updated", lambda _=None: self._refresh_conversations())
        app.state.on("dm_received", self._on_dm_received)

        # Load conversations from DB on init
        self._load_persisted()

    def _load_persisted(self) -> None:
        """Load saved conversations from the client DB."""
        if self.app.db is None:
            return
        try:
            convos = self.app.db.get_conversations()
            self.app.state.conversations = convos
            self._refresh_conversations()
        except Exception:
            logger.debug("failed to load conversations from DB", exc_info=True)

    def _refresh_conversations(self) -> None:
        """Rebuild the conversation list from app state."""
        self._convo_walker.clear()

        convos = self.app.state.conversations
        if not convos:
            # Also check DB
            if self.app.db is not None:
                try:
                    convos = self.app.db.get_conversations()
                    self.app.state.conversations = convos
                except Exception:
                    logger.debug("failed to refresh conversations from DB", exc_info=True)

        if not convos:
            self._convo_walker.append(urwid.Text(("default", "  No conversations yet.")))
            return

        # Sort by last_message_time desc
        sorted_convos = sorted(
            convos,
            key=lambda c: c.get("last_message_time", 0),
            reverse=True,
        )

        for convo in sorted_convos:
            item = ConversationItem(convo, self._on_convo_selected)
            self._convo_walker.append(item)

        self.app._schedule_redraw()

    def _on_convo_selected(self, convo_dict: dict) -> None:
        """Handle selecting a conversation from the list."""
        peer_hash = convo_dict.get("peer_hash", "")
        if peer_hash:
            self.select_conversation(peer_hash)

    def select_conversation(self, peer_hash: str) -> None:
        """Select and display a DM conversation with a peer.

        Loads DMs from the DB, displays them, and marks the conversation read.
        """
        self.app.state.current_conversation_peer = peer_hash

        # Load DMs from DB
        dms = []
        if self.app.db is not None:
            try:
                dms = self.app.db.get_dms(peer_hash, limit=50)
            except Exception:
                logger.debug("failed to load DMs for %s", peer_hash, exc_info=True)

        # Store in state
        self.app.state.dm_messages[peer_hash] = dms

        # Display DMs
        self._dm_walker.clear()
        if dms:
            # DMs come in reverse chronological from get_dms, we want chrono order
            for dm in reversed(dms) if dms else []:
                widget = self._dm_to_message_widget(dm)
                self._dm_walker.append(widget)
            # Scroll to bottom
            if self._dm_walker:
                self._dm_walker.set_focus(len(self._dm_walker) - 1)
        else:
            self._dm_walker.append(
                urwid.Text(("default", "  No messages yet. Type below to start."))
            )

        # First conversation select: swap right pane from welcome placeholder
        # to the bordered DM Frame. The listbox is already wired into the
        # LineBox at __init__ time.
        if self._right_area.original_widget is not self._right_pile:
            self._right_area.original_widget = self._right_pile
        self._compose_area.original_widget = self._compose_box

        # Mark conversation as read
        if self.app.db is not None:
            try:
                self.app.db.mark_conversation_read(peer_hash)
            except Exception:
                logger.debug("failed to mark conversation read: %s", peer_hash, exc_info=True)

        # Reset unread count in state
        for convo in self.app.state.conversations:
            if convo.get("peer_hash") == peer_hash:
                convo["unread_count"] = 0
                break

        # Find peer name for status — format as "name (hash)"
        raw_name = self._get_peer_name(peer_hash)
        short = peer_hash[:8] if peer_hash else "?"
        if raw_name and raw_name != peer_hash[:12]:
            status_name = f"{raw_name} ({short})"
        else:
            status_name = short

        self._dm_box.set_title(f"DM @ {status_name}")
        self.app.status.set_context(f"DM with {status_name}")
        self.app._schedule_redraw()

    def _dm_to_message_widget(self, dm: dict) -> MessageWidget:
        """Convert a DM record dict to a MessageWidget for display."""
        # Determine if this is from us or the peer
        my_hash = ""
        identity = self.app.state.identity
        if identity and hasattr(identity, "hexhash"):
            my_hash = identity.hexhash

        sender_hash = dm.get("sender_hash", "")
        is_self = sender_hash == my_hash if my_hash else False

        # Build a message dict compatible with MessageWidget. Pass the raw
        # name only — MessageWidget appends "(short_hash)" itself, so
        # pre-formatting here would render "name (hash) (hash)".
        if is_self:
            display_name = "You"
        else:
            display_name = self._get_peer_name(sender_hash)
        msg_dict = {
            "msg_hash": str(dm.get("id", "")),
            "channel_id": "",
            "sender_hash": sender_hash,
            "seq": dm.get("id", 0),
            "timestamp": dm.get("timestamp", 0),
            "type": 0x01,  # MSG_TEXT
            "body": dm.get("body", ""),
            "display_name": display_name,
            "reply_to": None,
            "deleted": False,
            "pinned": False,
            "reactions": {},
            "verified": True,
        }
        return MessageWidget(msg_dict)

    def _get_peer_name(self, peer_hash: str) -> str:
        """Look up the raw display name for a peer hash.

        Returns just the name (no hash suffix) for storage. Display
        formatting with hash is done at widget rendering time.
        """
        # Check conversations state
        for convo in self.app.state.conversations:
            if convo.get("peer_hash") == peer_hash:
                n = convo.get("peer_name")
                if n and n != peer_hash[:12]:
                    return n

        # Check discovered peers
        peer_info = self.app.state.discovered_peers.get(peer_hash)
        if peer_info:
            name = peer_info.get("display_name")
            if name:
                return name

        return peer_hash[:12] if peer_hash else "Unknown"

    def _send_dm(self, body: str) -> None:
        """Send a DM to the currently selected conversation peer."""
        peer_hash = self.app.state.current_conversation_peer
        if not peer_hash:
            self.app.status.set_notice("Select a conversation first.", level="warn")
            return

        ts = time.time()

        # Get our identity hash
        my_hash = ""
        identity = self.app.state.identity
        if identity and hasattr(identity, "hexhash"):
            my_hash = identity.hexhash

        # Try to send via sync engine
        sent = False
        if self.app.sync_engine is not None:
            try:
                sent = self.app.sync_engine.send_dm(peer_hash, body)
            except Exception:
                logger.debug("DM send failed for peer %s", peer_hash, exc_info=True)

        # Store outbound DM in DB
        if self.app.db is not None:
            try:
                self.app.db.store_dm(
                    sender_hash=my_hash,
                    receiver_hash=peer_hash,
                    timestamp=ts,
                    body=body,
                )
            except Exception:
                logger.debug("failed to persist outbound DM to %s", peer_hash, exc_info=True)

        # Update conversation entry
        peer_name = self._get_peer_name(peer_hash)
        if self.app.db is not None:
            try:
                self.app.db.update_conversation(peer_hash, peer_name, ts)
            except Exception:
                logger.debug("failed to update conversation %s", peer_hash, exc_info=True)

        # Update state conversations
        self._update_conversation_state(peer_hash, peer_name, ts, body)

        # Optimistic display
        dm_display = {
            "msg_hash": f"local-{ts}",
            "channel_id": "",
            "sender_hash": my_hash,
            "seq": 0,
            "timestamp": ts,
            "type": 0x01,
            "body": body,
            "display_name": "You",
            "reply_to": None,
            "deleted": False,
            "pinned": False,
            "reactions": {},
            "verified": True,
        }
        widget = MessageWidget(dm_display)

        # Remove "no messages" placeholder if present
        if self._dm_walker and not isinstance(self._dm_walker[0], MessageWidget):
            self._dm_walker.clear()

        self._dm_walker.append(widget)
        if self._dm_walker:
            self._dm_walker.set_focus(len(self._dm_walker) - 1)

        if not sent:
            self.app.status.set_notice(
                "DM queued locally (no remote connection)",
                level="warn",
            )

        self.app._schedule_redraw()

    def _on_dm_received(self, data: dict | None = None) -> None:
        """Handle an incoming DM from the sync engine.

        Expected data keys: sender_hash, display_name, body, timestamp.
        """
        if data is None:
            return

        sender_hash = data.get("sender_hash", "")
        display_name = data.get("display_name") or sender_hash[:12]
        body = data.get("body", "")
        ts = data.get("timestamp", time.time())

        # Cache sender name in discovered_peers so _get_peer_name finds it
        if display_name and sender_hash and display_name != sender_hash[:12]:
            if sender_hash not in self.app.state.discovered_peers:
                self.app.state.discovered_peers[sender_hash] = {}
            self.app.state.discovered_peers[sender_hash]["display_name"] = display_name

        # Store in DB
        my_hash = ""
        identity = self.app.state.identity
        if identity and hasattr(identity, "hexhash"):
            my_hash = identity.hexhash

        if self.app.db is not None:
            try:
                self.app.db.store_dm(
                    sender_hash=sender_hash,
                    receiver_hash=my_hash,
                    timestamp=ts,
                    body=body,
                )
                self.app.db.update_conversation(sender_hash, display_name, ts)
            except Exception:
                logger.debug("failed to persist inbound DM from %s", sender_hash, exc_info=True)

        # Update state
        self._update_conversation_state(sender_hash, display_name, ts, body)

        # If we're currently viewing this conversation, display the message
        if self.app.state.current_conversation_peer == sender_hash:
            dm_display = {
                "msg_hash": f"recv-{ts}",
                "channel_id": "",
                "sender_hash": sender_hash,
                "seq": 0,
                "timestamp": ts,
                "type": 0x01,
                "body": body,
                "display_name": display_name,
                "reply_to": None,
                "deleted": False,
                "pinned": False,
                "reactions": {},
                "verified": True,
            }
            widget = MessageWidget(dm_display)

            # Remove placeholder if it's there
            if self._dm_walker and not isinstance(self._dm_walker[0], MessageWidget):
                self._dm_walker.clear()

            self._dm_walker.append(widget)
            if self._dm_walker:
                self._dm_walker.set_focus(len(self._dm_walker) - 1)

            # Mark read since we're viewing
            if self.app.db is not None:
                try:
                    self.app.db.mark_conversation_read(sender_hash)
                except Exception:
                    logger.debug("failed to mark conversation read: %s", sender_hash, exc_info=True)
        else:
            # Increment unread
            if self.app.db is not None:
                try:
                    self.app.db.increment_unread(sender_hash)
                except Exception:
                    logger.debug("failed to increment unread for %s", sender_hash, exc_info=True)

            for convo in self.app.state.conversations:
                if convo.get("peer_hash") == sender_hash:
                    convo["unread_count"] = convo.get("unread_count", 0) + 1
                    break

        self.app.state.emit("conversations_updated")
        self.app._schedule_redraw()

    def _update_conversation_state(
        self, peer_hash: str, peer_name: str, timestamp: float, body: str = ""
    ) -> None:
        """Update or create a conversation in app.state.conversations."""
        found = False
        for convo in self.app.state.conversations:
            if convo.get("peer_hash") == peer_hash:
                convo["last_message_time"] = timestamp
                convo["peer_name"] = peer_name
                convo["last_body"] = body
                found = True
                break

        if not found:
            self.app.state.conversations.append(
                {
                    "peer_hash": peer_hash,
                    "peer_name": peer_name,
                    "last_message_time": timestamp,
                    "unread_count": 0,
                    "last_body": body,
                }
            )

    def open_dm(self, peer_hash: str, initial_message: str | None = None) -> None:
        """Open a DM conversation, optionally sending an initial message.

        Called by the /dm command handler.
        """
        # Ensure conversation exists in state
        peer_name = self._get_peer_name(peer_hash)
        ts = time.time()

        # Check if conversation already exists
        exists = any(c.get("peer_hash") == peer_hash for c in self.app.state.conversations)
        if not exists:
            self.app.state.conversations.append(
                {
                    "peer_hash": peer_hash,
                    "peer_name": peer_name,
                    "last_message_time": ts,
                    "unread_count": 0,
                    "last_body": "",
                }
            )
            if self.app.db is not None:
                try:
                    self.app.db.update_conversation(peer_hash, peer_name, ts)
                except Exception:
                    logger.debug(
                        "failed to create conversation entry for %s", peer_hash, exc_info=True
                    )

        # Select the conversation
        self.select_conversation(peer_hash)

        # Send initial message if provided
        if initial_message:
            self._send_dm(initial_message)

        # Refresh conversation list
        self._refresh_conversations()

        # Set focus to compose box so user can type immediately.
        # Must be AFTER _refresh_conversations which rebuilds the left pane.
        try:
            self.widget.focus_position = 1  # Right pane (Columns)
            self._right_pile.focus_position = "footer"  # Compose box (Frame)
        except (IndexError, AttributeError):
            pass
