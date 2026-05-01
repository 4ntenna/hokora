# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Invite view — modal dialog for creating and redeeming invites."""

from __future__ import annotations

import logging
import secrets
import string
from typing import TYPE_CHECKING

import urwid

from hokora.security.invite_codes import INVITE_CODE_PREFIX
from hokora_tui.widgets.hokora_button import HokoraButton

if TYPE_CHECKING:
    from hokora_tui.app import HokoraTUI

logger = logging.getLogger(__name__)


def _generate_invite_code() -> str:
    """Generate a random short invite-code stub (placeholder display value).

    The real wire-format invite is produced by
    :func:`hokora.security.invite_codes.encode_invite`; this helper only
    populates the input field so the user can replace it.
    """
    chars = string.ascii_uppercase + string.digits
    suffix = "".join(secrets.choice(chars) for _ in range(5))
    return f"{INVITE_CODE_PREFIX}{suffix}"


class InviteView:
    """Modal dialog for creating and redeeming channel invites."""

    def __init__(self, app: HokoraTUI) -> None:
        self.app = app

        # --- Create Invite section ---
        self._create_header = urwid.Text(("bold", "Create Invite"))
        self._channel_label = urwid.Text(("default", ""))

        self._max_uses_edit = urwid.IntEdit(("setting_key", "Max uses: "), default=10)
        self._expires_edit = urwid.IntEdit(("setting_key", "Expires in (hours): "), default=24)

        create_btn = urwid.AttrMap(
            HokoraButton("Create", on_press=self._on_create), "button_normal", "button_focus"
        )

        create_section = urwid.Pile(
            [
                self._create_header,
                self._channel_label,
                urwid.Columns(
                    [
                        ("weight", 1, urwid.AttrMap(self._max_uses_edit, "input_text")),
                        ("weight", 1, urwid.AttrMap(self._expires_edit, "input_text")),
                    ]
                ),
                urwid.Padding(create_btn, left=0, width=14),
            ]
        )

        # --- Redeem Invite section ---
        self._redeem_header = urwid.Text(("bold", "Redeem Invite"))
        self._code_edit = urwid.Edit(("input_prompt", "Code: "))
        redeem_btn = urwid.AttrMap(
            HokoraButton("Redeem", on_press=self._on_redeem), "button_normal", "button_focus"
        )

        redeem_section = urwid.Pile(
            [
                self._redeem_header,
                urwid.Columns(
                    [
                        ("weight", 3, urwid.AttrMap(self._code_edit, "input_text")),
                        ("weight", 1, urwid.Padding(redeem_btn, left=1, width=14)),
                    ]
                ),
            ]
        )

        # --- Active Invites section ---
        self._invites_header = urwid.Text(("bold", "Active Invites"))
        self._invites_walker = urwid.SimpleFocusListWalker(
            [urwid.Text(("default", "  No active invites."))]
        )
        self._invites_listbox = urwid.ListBox(self._invites_walker)

        # --- Full layout ---
        pile = urwid.Pile(
            [
                ("pack", create_section),
                ("pack", urwid.Divider()),
                ("pack", redeem_section),
                ("pack", urwid.Divider()),
                ("pack", self._invites_header),
                ("weight", 1, self._invites_listbox),
            ]
        )

        self._linebox = urwid.LineBox(pile, title="Invites")
        self.widget = self._linebox

    def open_invite(self) -> None:
        """Open the invite dialog, refreshing state."""
        channel_id = self.app.state.current_channel_id
        if channel_id:
            ch_name = channel_id
            for ch in self.app.state.channels:
                if ch["id"] == channel_id:
                    ch_name = ch.get("name", channel_id)
                    break
            self._channel_label.set_text(("default", f"For channel: #{ch_name}"))
        else:
            self._channel_label.set_text(("default", "No channel selected"))

        self._code_edit.set_edit_text("")
        self._refresh_invites()

    def _refresh_invites(self) -> None:
        """Refresh the active invites list from DB/state."""
        self._invites_walker.clear()

        # Check client DB for stored invites
        invites = []
        if self.app.db is not None:
            try:
                raw = self.app.db.get_setting("active_invites")
                if raw:
                    import json

                    invites = json.loads(raw)
            except Exception:
                logger.debug("failed to load stored invites", exc_info=True)

        if not invites:
            self._invites_walker.append(urwid.Text(("default", "  No active invites.")))
        else:
            for inv in invites:
                code = inv.get("code", "???")
                uses = inv.get("uses", 0)
                max_uses = inv.get("max_uses", "?")
                self._invites_walker.append(
                    urwid.Text(("setting_value", f"  {code}  ({uses}/{max_uses} uses)"))
                )

    def _on_create(self, button: urwid.Button) -> None:
        """Handle create invite button press."""
        channel_id = self.app.state.current_channel_id
        if not channel_id:
            self.app.status.set_context("Select a channel first to create an invite.")
            return

        max_uses = self._max_uses_edit.value()
        expires_hours = self._expires_edit.value()
        code = _generate_invite_code()

        # Try sync engine
        if self.app.sync_engine and hasattr(self.app.sync_engine, "create_invite"):
            self.app.sync_engine.create_invite(channel_id, max_uses=max_uses, expires=expires_hours)
            self.app.status.set_context("Invite creation requested...")
        else:
            # Stub: store locally
            import json
            import time

            invites = []
            if self.app.db is not None:
                try:
                    raw = self.app.db.get_setting("active_invites")
                    if raw:
                        invites = json.loads(raw)
                except Exception:
                    logger.debug("failed to merge with stored invites", exc_info=True)

            invite_data = {
                "code": code,
                "channel_id": channel_id,
                "max_uses": max_uses,
                "expires_hours": expires_hours,
                "created_at": time.time(),
                "uses": 0,
            }
            invites.append(invite_data)

            if self.app.db is not None:
                self.app.db.set_setting("active_invites", json.dumps(invites))

            self.app.status.set_context(f"Invite created: {code}")
            self._refresh_invites()

        self.app._schedule_redraw()

    def _on_redeem(self, button: urwid.Button) -> None:
        """Handle redeem invite button press."""
        code = self._code_edit.get_edit_text().strip()
        if not code:
            self.app.status.set_context("Enter an invite code to redeem.")
            return

        # Try sync engine
        if self.app.sync_engine and hasattr(self.app.sync_engine, "redeem_invite"):
            self.app.sync_engine.redeem_invite(code)
            self.app.status.set_context(f"Redeeming invite {code}...")
        else:
            # Dispatch via command handler as fallback
            self.app.handle_command(f"/invite redeem {code}")

        self._code_edit.set_edit_text("")
        self.app._schedule_redraw()

    def keypress(self, size: tuple, key: str) -> str | None:
        """Handle keypresses within the invite view."""
        if key == "esc":
            # Close invite dialog
            if hasattr(self.app, "close_invite"):
                self.app.close_invite()
            return None

        return self.widget.keypress(size, key)

    def selectable(self) -> bool:
        return True
