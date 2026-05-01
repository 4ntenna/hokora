# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Identity tab — display and edit identity, announce settings."""

from __future__ import annotations

from typing import TYPE_CHECKING

import urwid

from hokora_tui.widgets.hokora_button import HokoraButton

if TYPE_CHECKING:
    from hokora_tui.app import HokoraTUI


# Debounce + display windows for the per-row "✓ saved" indicator.
# Show appears 0.4s after the last keystroke; clears 2.0s after that.
# Keeps the indicator stable instead of flickering per-keystroke while
# still confirming the save quickly enough to be useful.
_SAVED_INDICATOR_SHOW_DELAY_S = 0.4
_SAVED_INDICATOR_CLEAR_DELAY_S = 2.0


class IdentityView:
    """Identity management view: hash, fingerprint, display name, announce settings."""

    def __init__(self, app: HokoraTUI) -> None:
        self.app = app

        # --- Identity Hash (read-only) ---
        self._hash_label = urwid.Text(("id_label", "  Identity Hash:  "))
        id_hash = getattr(app.state, "identity", None)
        hash_str = id_hash.hexhash if id_hash and hasattr(id_hash, "hexhash") else "(none)"
        self._hash_value = urwid.Text(("id_hash", hash_str))
        hash_row = urwid.Columns(
            [
                ("pack", self._hash_label),
                self._hash_value,
            ]
        )

        # --- Fingerprint (read-only, AA:BB:CC format) ---
        self._fp_label = urwid.Text(("id_label", "  Fingerprint:    "))
        self._fp_value = urwid.Text(("id_fingerprint", self._format_fingerprint(hash_str)))
        fp_row = urwid.Columns(
            [
                ("pack", self._fp_label),
                self._fp_value,
            ]
        )

        # --- Display Name (editable) ---
        dn_label = urwid.Text(("id_label", "  Display Name:   "))
        self._name_edit = urwid.Edit(
            edit_text=app.state.display_name,
        )
        self._name_edit_styled = urwid.AttrMap(self._name_edit, "input_text")
        self._name_saved = urwid.Text(("info_dim", ""), align="right")
        name_row = urwid.Columns(
            [
                ("pack", dn_label),
                self._name_edit_styled,
                ("fixed", 12, self._name_saved),
            ]
        )

        # --- Status Text (editable) ---
        st_label = urwid.Text(("id_label", "  Status Text:    "))
        self._status_edit = urwid.Edit(
            edit_text=app.state.status_text,
        )
        self._status_edit_styled = urwid.AttrMap(self._status_edit, "input_text")
        self._status_saved = urwid.Text(("info_dim", ""), align="right")
        status_row = urwid.Columns(
            [
                ("pack", st_label),
                self._status_edit_styled,
                ("fixed", 12, self._status_saved),
            ]
        )

        # --- Announce Settings ---
        announce_header = urwid.Text(("category_header", "  -- Announce Settings --"))

        # Auto-announce toggle
        aa_label = urwid.Text(("id_label", "  Auto-announce:  "))
        self._announce_btn = HokoraButton(
            "ON" if app.state.auto_announce else "OFF",
            on_press=self._toggle_announce,
        )
        self._announce_btn_styled = urwid.AttrMap(
            self._announce_btn, "button_normal", "button_focus"
        )
        aa_row = urwid.Columns(
            [
                ("pack", aa_label),
                (12, self._announce_btn_styled),
            ]
        )

        # Interval
        interval_label = urwid.Text(("id_label", "  Interval:       "))
        self._interval_edit = urwid.IntEdit(
            default=app.state.announce_interval,
        )
        self._interval_styled = urwid.AttrMap(self._interval_edit, "input_text")
        interval_suffix = urwid.Text(("default", " seconds"))
        self._interval_saved = urwid.Text(("info_dim", ""), align="right")
        interval_row = urwid.Columns(
            [
                ("pack", interval_label),
                (10, self._interval_styled),
                ("pack", interval_suffix),
                ("fixed", 12, self._interval_saved),
            ]
        )

        # Announce Now button
        self._announce_now_btn = HokoraButton(
            "Announce Now",
            on_press=self._do_announce,
        )
        self._announce_now_styled = urwid.AttrMap(
            self._announce_now_btn, "button_normal", "button_focus"
        )
        announce_now_row = urwid.Columns(
            [
                ("pack", urwid.Text("  ")),
                (20, self._announce_now_styled),
            ]
        )

        # Connect change watchers
        urwid.connect_signal(self._name_edit, "postchange", self._on_name_change)
        urwid.connect_signal(self._status_edit, "postchange", self._on_status_change)
        urwid.connect_signal(self._interval_edit, "postchange", self._on_interval_change)

        # Cross-tab consistency: when auto-announce is toggled from the
        # Settings tab, refresh this tab's button label so the two stay
        # aligned. State-observer pattern via the existing emit/on hooks.
        app.state.on("auto_announce_changed", self._on_auto_announce_changed)
        app.state.on("announce_interval_changed", self._on_interval_changed_external)

        # Per-row "saved" indicator alarm handles for debounce.
        self._saved_alarms: dict[str, tuple] = {}

        # Build layout
        pile = urwid.Pile(
            [
                urwid.Divider(),
                hash_row,
                fp_row,
                urwid.Divider(),
                name_row,
                status_row,
                urwid.Divider(),
                announce_header,
                urwid.Divider(),
                aa_row,
                interval_row,
                urwid.Divider(),
                announce_now_row,
            ]
        )

        box = urwid.LineBox(pile, title="Your Identity")
        padded = urwid.Padding(box, left=2, right=2)
        self.widget = urwid.Filler(padded, valign="middle")

    def _format_fingerprint(self, hash_str: str) -> str:
        """Format a hex hash as AA:BB:CC:DD pairs."""
        if not hash_str or hash_str == "(none)":
            return "(none)"
        clean = hash_str.replace(":", "").upper()
        pairs = [clean[i : i + 2] for i in range(0, len(clean), 2)]
        return ":".join(pairs)

    # ── Save handlers ──────────────────────────────────────────────

    def _on_name_change(self, edit: urwid.Edit, old_text: str) -> None:
        """Persist display name change + show saved indicator."""
        new_name = edit.get_edit_text()
        self.app.state.display_name = new_name
        if hasattr(self.app, "sync_engine") and self.app.sync_engine:
            self.app.sync_engine.set_display_name(new_name)
        if hasattr(self.app, "db") and self.app.db is not None:
            self.app.db.set_setting("display_name", new_name)
        self._show_saved("name", self._name_saved)

    def _on_status_change(self, edit: urwid.Edit, old_text: str) -> None:
        """Persist status text change + show saved indicator."""
        new_status = edit.get_edit_text()
        self.app.state.status_text = new_status
        if hasattr(self.app, "db") and self.app.db is not None:
            self.app.db.set_setting("status_text", new_status)
        self._show_saved("status", self._status_saved)

    def _on_interval_change(self, edit: urwid.IntEdit, old_text: str) -> None:
        """Update + clamp + persist announce interval."""
        try:
            val = int(edit.get_edit_text() or "0")
        except (ValueError, TypeError):
            val = 300
        # Routes through the AppState chokepoint so the value is clamped,
        # persisted to DB, and broadcast to any other subscribed tab.
        self.app.state.set_announce_interval(val)
        self._show_saved("interval", self._interval_saved)

    # ── Toggle / action handlers ───────────────────────────────────

    def _toggle_announce(self, button: urwid.Button) -> None:
        """Toggle the auto-announce setting via the AppState chokepoint."""
        new_value = not self.app.state.auto_announce
        # set_auto_announce persists, wakes the announcer thread, and
        # emits ``auto_announce_changed`` so the Settings-tab checkbox
        # picks up the change too.
        self.app.state.set_auto_announce(new_value)
        # Local widget update is handled by the observer below; no need
        # to set_label here. Calling set_label directly would race with
        # the observer's update.

    def _do_announce(self, button: urwid.Button) -> None:
        """Trigger an immediate announce."""
        if hasattr(self.app, "trigger_announce"):
            self.app.trigger_announce()
        self.app.status.set_context("Announce triggered")
        self.app._schedule_redraw()

    # ── Observers (cross-tab sync) ─────────────────────────────────

    def _on_auto_announce_changed(self, value: bool | None = None) -> None:
        """Refresh the toggle button when state changes from any source."""
        if value is None:
            value = self.app.state.auto_announce
        try:
            self._announce_btn.set_label("ON" if value else "OFF")
        except Exception:
            pass
        self.app._schedule_redraw()

    def _on_interval_changed_external(self, value: int | None = None) -> None:
        """Refresh the interval edit when state changes from any source.

        The Settings tab clamps via ``set_announce_interval`` too, so this
        keeps the two views aligned. Skips the update if the user is
        currently editing this widget (avoids snapping the cursor away
        mid-keystroke when the edit itself is what triggered the event).
        """
        if value is None:
            value = self.app.state.announce_interval
        try:
            current_text = self._interval_edit.get_edit_text() or "0"
            if int(current_text) != value:
                self._interval_edit.set_edit_text(str(value))
        except (ValueError, TypeError):
            self._interval_edit.set_edit_text(str(value))
        self.app._schedule_redraw()

    # ── Saved-indicator state machine ──────────────────────────────

    def _show_saved(self, key: str, widget: urwid.Text) -> None:
        """Schedule the per-row "✓ saved" indicator with debounce.

        Cancels any prior alarm for the same key before scheduling,
        producing a single stable indicator after the user stops typing
        rather than a flicker per keystroke.
        """
        loop = getattr(self.app, "loop", None)
        if loop is None:
            return
        # Cancel prior alarms for this key.
        prior = self._saved_alarms.pop(key, None)
        if prior:
            for handle in prior:
                if handle is not None:
                    try:
                        loop.remove_alarm(handle)
                    except Exception:
                        pass

        def _show(_loop=None, _data=None):
            try:
                widget.set_text(("info_dim", "  ✓ saved"))
            except Exception:
                pass
            self.app._schedule_redraw()

        def _clear(_loop=None, _data=None):
            try:
                widget.set_text(("info_dim", ""))
            except Exception:
                pass
            self.app._schedule_redraw()

        show_handle = loop.set_alarm_in(_SAVED_INDICATOR_SHOW_DELAY_S, _show)
        clear_handle = loop.set_alarm_in(
            _SAVED_INDICATOR_SHOW_DELAY_S + _SAVED_INDICATOR_CLEAR_DELAY_S, _clear
        )
        self._saved_alarms[key] = (show_handle, clear_handle)

    def refresh_identity(self) -> None:
        """Update displayed identity info from current state."""
        identity = self.app.state.identity
        if identity and hasattr(identity, "hexhash"):
            hash_str = identity.hexhash
        else:
            hash_str = "(none)"
        self._hash_value.set_text(("id_hash", hash_str))
        self._fp_value.set_text(("id_fingerprint", self._format_fingerprint(hash_str)))
