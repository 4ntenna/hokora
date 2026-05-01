# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Settings tab — sync profile, display preferences, announce settings, data management."""

from __future__ import annotations

from typing import TYPE_CHECKING

import urwid

from hokora.constants import (
    CDSP_PROFILE_FULL,
    CDSP_PROFILE_PRIORITIZED,
    CDSP_PROFILE_MINIMAL,
    CDSP_PROFILE_BATCHED,
)
from hokora_tui.widgets.confirm_dialog import ConfirmDialog
from hokora_tui.widgets.hokora_button import HokoraButton
from hokora_tui.widgets.hokora_radio import HokoraRadioButton

if TYPE_CHECKING:
    from hokora_tui.app import HokoraTUI

_PROFILE_NAME_TO_CONST = {
    "FULL": CDSP_PROFILE_FULL,
    "PRIORITIZED": CDSP_PROFILE_PRIORITIZED,
    "MINIMAL": CDSP_PROFILE_MINIMAL,
    "BATCHED": CDSP_PROFILE_BATCHED,
}

# Sync profile definitions
_SYNC_PROFILES = {
    "FULL": "Desktop/rich client, all features enabled",
    "PRIORITIZED": "Prioritize recent channels, defer old history",
    "MINIMAL": "Minimal sync, headers only until requested",
    "BATCHED": "Batch sync at intervals, low bandwidth",
}

# Timestamp format options
_TS_FORMATS = ["HH:MM", "HH:MM:SS", "Relative"]


class SettingsView:
    """Full settings panel with sync profile, display prefs, announce, and data."""

    def __init__(self, app: HokoraTUI | None = None) -> None:
        self.app = app

        # If no app, build a simple placeholder (backwards compat with no-arg init)
        if app is None:
            text = urwid.Text(("bold", "Settings"), align="center")
            self.widget = urwid.Filler(text, valign="middle")
            return

        # --- Sync Profile ---
        self._sync_radios: list[HokoraRadioButton] = []
        sync_group: list[HokoraRadioButton] = []
        current_profile = self._get_setting("sync_profile", "FULL")

        # Push saved profile to sync engine on init (convert name → int)
        if app.sync_engine and current_profile != "FULL":
            profile_int = _PROFILE_NAME_TO_CONST.get(current_profile, CDSP_PROFILE_FULL)
            app.sync_engine.set_sync_profile(profile_int)

        for name, desc in _SYNC_PROFILES.items():
            rb = HokoraRadioButton(
                sync_group,
                name,
                state=(name == current_profile),
                on_state_change=self._on_sync_profile_change,
                user_data=name,
            )
            self._sync_radios.append(rb)

        self._sync_desc = urwid.Text(
            ("default", f"Current: {current_profile} -- {_SYNC_PROFILES.get(current_profile, '')}")
        )

        sync_pile = urwid.Pile(
            [urwid.AttrMap(rb, "setting_value") for rb in self._sync_radios] + [self._sync_desc]
        )
        sync_box = urwid.LineBox(sync_pile, title="Sync Profile")

        # --- Display Preferences ---
        self._ts_radios: list[HokoraRadioButton] = []
        ts_group: list[HokoraRadioButton] = []
        current_ts = self._get_setting("timestamp_format", "HH:MM")

        for fmt in _TS_FORMATS:
            rb = HokoraRadioButton(
                ts_group,
                fmt,
                state=(fmt == current_ts),
                on_state_change=self._on_ts_format_change,
                user_data=fmt,
            )
            self._ts_radios.append(rb)

        ts_row = urwid.Columns(
            [
                ("pack", urwid.Text(("setting_key", "Timestamp format: "))),
            ]
            + [("pack", urwid.AttrMap(rb, "setting_value")) for rb in self._ts_radios]
        )

        show_sigs = self._get_setting("show_signatures", "true") == "true"
        self._sig_checkbox = urwid.CheckBox(
            "Show signatures",
            state=show_sigs,
            on_state_change=self._on_checkbox_change,
            user_data="show_signatures",
        )

        show_reactions = self._get_setting("show_reactions", "true") == "true"
        self._react_checkbox = urwid.CheckBox(
            "Show reactions",
            state=show_reactions,
            on_state_change=self._on_checkbox_change,
            user_data="show_reactions",
        )

        confirm_destructive = self._get_setting("confirm_destructive_actions", "true") == "true"
        self._confirm_destructive_cb = urwid.CheckBox(
            "Confirm destructive actions (delete, clear cache, restart)",
            state=confirm_destructive,
            on_state_change=self._on_checkbox_change,
            user_data="confirm_destructive_actions",
        )

        display_pile = urwid.Pile(
            [
                ts_row,
                urwid.AttrMap(self._sig_checkbox, "setting_value"),
                urwid.AttrMap(self._react_checkbox, "setting_value"),
                urwid.AttrMap(self._confirm_destructive_cb, "setting_value"),
            ]
        )
        display_box = urwid.LineBox(display_pile, title="Display Preferences")

        # --- Announce Settings ---
        # Read the live state value (already reconciled with DB at startup
        # by ``HokoraTUI._load_settings``) so this tab and the Identity
        # tab agree from the moment they construct.
        self._auto_announce_cb = urwid.CheckBox(
            "Auto-announce",
            state=app.state.auto_announce,
            on_state_change=self._on_auto_announce_toggle,
        )

        self._announce_int_edit = urwid.IntEdit(
            ("setting_key", "Announce interval (seconds): "),
            default=app.state.announce_interval,
        )
        urwid.connect_signal(
            self._announce_int_edit, "postchange", self._on_announce_interval_change
        )

        announce_pile = urwid.Pile(
            [
                urwid.AttrMap(self._auto_announce_cb, "setting_value"),
                urwid.AttrMap(self._announce_int_edit, "input_text"),
            ]
        )
        announce_box = urwid.LineBox(announce_pile, title="Announce Settings")

        # Cross-tab consistency: Identity tab and any other future
        # surface that mutates auto_announce / announce_interval will
        # emit these events; refresh our widgets to match.
        app.state.on("auto_announce_changed", self._on_auto_announce_changed_external)
        app.state.on("announce_interval_changed", self._on_interval_changed_external)

        # --- Data ---
        data_path = "~/.hokora-client/"
        self._data_label = urwid.Text(("setting_key", f"Client data: {data_path}"))

        clear_btn = urwid.AttrMap(
            HokoraButton("Clear client cache", on_press=self._on_clear_cache),
            "button_normal",
            "button_focus",
        )
        export_btn = urwid.AttrMap(
            HokoraButton("Export identity", on_press=self._on_export_identity),
            "button_normal",
            "button_focus",
        )

        data_pile = urwid.Pile(
            [
                self._data_label,
                urwid.Columns(
                    [
                        ("weight", 1, clear_btn),
                        ("weight", 1, export_btn),
                    ]
                ),
            ]
        )
        data_box = urwid.LineBox(data_pile, title="Data")

        # --- Full layout ---
        main_pile = urwid.Pile(
            [
                ("pack", sync_box),
                ("pack", display_box),
                ("pack", announce_box),
                ("pack", data_box),
            ]
        )

        self.widget = urwid.Filler(main_pile, valign="top")

    def _get_setting(self, key: str, default: str = "") -> str:
        """Read a setting from client DB or return default."""
        if self.app is not None and self.app.db is not None:
            val = self.app.db.get_setting(key)
            if val is not None:
                return val
        return default

    def _save_setting(self, key: str, value: str) -> None:
        """Persist a setting to client DB."""
        if self.app is not None and self.app.db is not None:
            self.app.db.set_setting(key, value)

    def _on_sync_profile_change(
        self, radio: urwid.RadioButton, new_state: bool, user_data: str = ""
    ) -> None:
        """Handle sync profile radio button change."""
        if not new_state:
            return
        profile = user_data
        self._save_setting("sync_profile", profile)
        self._sync_desc.set_text(
            ("default", f"Current: {profile} -- {_SYNC_PROFILES.get(profile, '')}")
        )

        # Update app state
        if self.app is not None:
            self.app.state.sync_profile = {"name": profile}
            # Notify sync engine if connected (convert name → int constant)
            if self.app.sync_engine and hasattr(self.app.sync_engine, "update_sync_profile"):
                profile_int = _PROFILE_NAME_TO_CONST.get(profile, CDSP_PROFILE_FULL)
                self.app.sync_engine.update_sync_profile(profile_int)
            if self.app.status:
                self.app.status.set_context(f"Sync profile changed to: {profile}")
            self.app._schedule_redraw()

    def _on_ts_format_change(
        self, radio: urwid.RadioButton, new_state: bool, user_data: str = ""
    ) -> None:
        """Handle timestamp format radio button change."""
        if not new_state:
            return
        self._save_setting("timestamp_format", user_data)
        if self.app is not None and self.app.status:
            self.app.status.set_context(f"Timestamp format: {user_data}")
            self.app._schedule_redraw()

    def _on_checkbox_change(
        self, checkbox: urwid.CheckBox, new_state: bool, user_data: str = ""
    ) -> None:
        """Handle generic checkbox change (display prefs only).

        Auto-announce has its own dedicated handler below that routes
        through the AppState chokepoint so the Identity tab stays in
        sync. This method handles the remaining checkboxes
        (show_signatures, show_reactions, confirm_destructive_actions).
        """
        key = user_data
        value = "true" if new_state else "false"
        self._save_setting(key, value)

    def _on_auto_announce_toggle(self, checkbox: urwid.CheckBox, new_state: bool) -> None:
        """Route through the AppState chokepoint.

        ``set_auto_announce`` persists, wakes the announcer thread for
        immediate effect on toggle-ON, and emits ``auto_announce_changed``
        so the Identity tab's button picks up the change.
        """
        if self.app is not None:
            self.app.state.set_auto_announce(new_state)

    def _on_announce_interval_change(self, edit: urwid.IntEdit, old_text: str) -> None:
        """Route through the AppState chokepoint (clamps + persists)."""
        if self.app is None:
            return
        try:
            val = int(edit.get_edit_text() or "0")
        except (ValueError, TypeError):
            val = 300
        self.app.state.set_announce_interval(val)

    def _on_auto_announce_changed_external(self, value: bool | None = None) -> None:
        """Refresh the checkbox when state changes from any source."""
        if value is None:
            value = self.app.state.auto_announce if self.app is not None else False
        try:
            # Avoid re-firing our own handler.
            if self._auto_announce_cb.get_state() != value:
                self._auto_announce_cb.set_state(value, do_callback=False)
        except Exception:
            pass
        if self.app is not None:
            self.app._schedule_redraw()

    def _on_interval_changed_external(self, value: int | None = None) -> None:
        """Refresh the interval edit when state changes from any source."""
        if self.app is None:
            return
        if value is None:
            value = self.app.state.announce_interval
        try:
            current = int(self._announce_int_edit.get_edit_text() or "0")
            if current != value:
                self._announce_int_edit.set_edit_text(str(value))
        except (ValueError, TypeError):
            self._announce_int_edit.set_edit_text(str(value))
        self.app._schedule_redraw()

    def _on_clear_cache(self, button: urwid.Button) -> None:
        """Handle clear cache button — confirm before destroying client state."""
        if self.app is None:
            return

        confirm_pref = self._get_setting("confirm_destructive_actions", "true")
        if confirm_pref == "false":
            self._do_clear_cache()
            return

        ConfirmDialog.show(
            self.app,
            "Clear all client cache?\n\nThis deletes the message DB, LXMF "
            "store, and all cursors. Identity is preserved.",
            on_confirm=self._do_clear_cache,
        )

    def _do_clear_cache(self) -> None:
        """Actually delete client DB and LXMF storage. Routed through confirm."""
        if self.app is None:
            return

        import shutil
        from pathlib import Path

        client_dir = Path.home() / ".hokora-client"

        try:
            if self.app.db is not None:
                self.app.db.close()
                self.app.db = None

            for suffix in ("", "-shm", "-wal"):
                db_file = client_dir / f"tui.db{suffix}"
                if db_file.exists():
                    db_file.unlink()

            lxmf_dir = client_dir / "lxmf"
            if lxmf_dir.exists():
                shutil.rmtree(lxmf_dir)

            self.app.state.messages.clear()
            if self.app.sync_engine:
                self.app.sync_engine.clear_cursors()

            if hasattr(self.app, "_init_client_db"):
                self.app._init_client_db()

            self.app.status.set_notice(
                "Cache cleared. Reconnect to sync fresh data.",
                level="info",
                duration=6.0,
            )
        except Exception as e:
            self.app.status.set_notice(
                f"Cache clear failed: {e}",
                level="error",
                duration=6.0,
            )

        self.app._schedule_redraw()

    def _on_export_identity(self, button: urwid.Button) -> None:
        """Confirm before writing the unencrypted identity file to disk."""
        if self.app is None:
            return

        confirm_pref = self._get_setting("confirm_destructive_actions", "true")
        if confirm_pref == "false":
            self._do_export_identity()
            return

        ConfirmDialog.show(
            self.app,
            "Export identity to ~/?\n\nThe exported file is your private "
            "key in plaintext (0o600). Keep it safe.",
            on_confirm=self._do_export_identity,
        )

    def _do_export_identity(self) -> None:
        """Copy identity file to ~/hokora_identity_<short>.key. Confirm-gated."""
        if self.app is None:
            return

        import os
        import shutil
        from pathlib import Path

        try:
            src = Path.home() / ".hokora-client" / "client_identity"
            if not src.exists():
                self.app.status.set_notice("No identity file found.", level="error")
                self.app._schedule_redraw()
                return

            identity = self.app.state.identity
            short_hash = identity.hexhash[:8] if identity else "unknown"
            dest = Path.home() / f"hokora_identity_{short_hash}.key"

            shutil.copy2(str(src), str(dest))
            os.chmod(str(dest), 0o600)

            self.app.status.set_notice(
                f"Identity exported to ~/{dest.name} (hash: {short_hash})",
                level="info",
                duration=6.0,
            )
        except Exception as e:
            self.app.status.set_notice(f"Export failed: {e}", level="error", duration=6.0)

        self.app._schedule_redraw()
