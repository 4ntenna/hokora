# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Single message display widget."""

from __future__ import annotations

import json
import time

import urwid

from hokora.constants import MSG_SYSTEM
from hokora_tui.palette import attrs_with_prefix


# Full-row highlight on focus: every per-segment ``msg_*`` attribute
# remaps to ``msg_selected`` so the highlight covers the whole row, not
# just the trailing fill. Derived from the palette — adding a new
# ``msg_*`` entry automatically participates, no synchronized hand list.
# ``None`` covers unattributed fill space (right-edge padding).
_MSG_FOCUS_MAP: dict[str | None, str] = {
    None: "msg_selected",
    **{a: "msg_selected" for a in attrs_with_prefix("msg_")},
}


class MessageWidget(urwid.WidgetWrap):
    """Renders a single message with styled attributes.

    Supports system messages, deleted, pinned, threaded, reactions,
    edited, media, and unverified states. Sealed-channel rows that
    arrive as ciphertext are decrypted at render-time when
    ``sealed_keys`` is provided.
    """

    def __init__(self, msg_dict: dict, sealed_keys=None) -> None:
        self.msg_dict = msg_dict
        self.msg_hash = msg_dict.get("msg_hash", "")
        self._sealed_keys = sealed_keys

        markup = self._build_markup(msg_dict)
        self._text = urwid.Text(markup)
        self._attr = urwid.AttrMap(self._text, None, focus_map=_MSG_FOCUS_MAP)
        super().__init__(self._attr)

    def _build_markup(self, msg: dict) -> list:
        """Build urwid text markup list from message dict."""
        msg_type = msg.get("type", 0x01)
        deleted = msg.get("deleted", False)
        body = msg.get("body") or ""
        # If the row carries ciphertext but no plaintext body, decrypt
        # at render-time via the SealedKeyStore.
        if not body and msg.get("encrypted_body") and self._sealed_keys is not None:
            from hokora_tui.security.sealed_render import body_for_render

            body = body_for_render(msg, self._sealed_keys)
        display_name = msg.get("display_name")
        sender_hash = msg.get("sender_hash", "")
        short_hash = sender_hash[:8] if sender_hash else "?"
        if display_name and display_name != sender_hash[:12]:
            sender = f"{display_name} ({short_hash})"
        else:
            sender = short_hash
        ts = msg.get("timestamp", 0)
        pinned = msg.get("pinned", False)
        reply_to = msg.get("reply_to")
        reactions = msg.get("reactions", {})
        verified = msg.get("verified", True)
        edited = msg.get("edited", False)
        media_path = msg.get("media_path")

        # Format timestamp
        try:
            time_str = time.strftime("%H:%M", time.localtime(ts))
        except (OSError, ValueError, OverflowError):
            time_str = "??:??"

        parts: list = []

        # System message
        if msg_type == MSG_SYSTEM:
            parts.append(("msg_time", f"[{time_str}] "))
            parts.append(("msg_system", f"--- {body} ---"))
            return parts

        # Deleted message
        if deleted:
            parts.append(("msg_time", f"[{time_str}] "))
            parts.append(("msg_deleted", "[deleted]"))
            return parts

        # Thread reply prefix with context
        if reply_to:
            reply_context = msg.get("reply_context")
            if reply_context:
                parts.append(("msg_thread", f"\u21b3 {reply_context}\n"))
            else:
                parts.append(("msg_thread", "\u21b3 "))

        # Pin prefix
        if pinned:
            parts.append(("msg_pinned", "\U0001f4cc "))

        # Timestamp
        parts.append(("msg_time", f"[{time_str}] "))

        # Unverified warning
        if not verified and verified is not None:
            parts.append(("msg_unverified", "[UNVERIFIED] "))

        # Sender
        parts.append(("msg_sender", f"{sender}: "))

        # Body
        parts.append(("msg_body", body))

        # Edited suffix
        if edited:
            parts.append(("msg_edited", " (edited)"))

        # Thread indicator
        if msg.get("has_thread"):
            parts.append(("msg_thread", " (thread)"))

        # Media suffix
        if media_path:
            filename = media_path.rsplit("/", 1)[-1] if "/" in str(media_path) else str(media_path)
            parts.append(("msg_body", f" [\U0001f4ce {filename}]"))

        # Reactions on a new line
        if reactions:
            if isinstance(reactions, str):
                try:
                    reactions = json.loads(reactions)
                except (json.JSONDecodeError, TypeError):
                    reactions = {}
            if reactions:
                reaction_parts = []
                for emoji, count in reactions.items():
                    if isinstance(count, (list, set)):
                        count = len(count)
                    reaction_parts.append(f"{emoji} ({count})")
                reaction_str = " | ".join(reaction_parts)
                parts.append("\n")
                parts.append(("msg_reaction", f"  [{reaction_str}]"))

        return parts

    def selectable(self) -> bool:
        return True

    def keypress(self, size: tuple, key: str) -> str | None:
        return key
