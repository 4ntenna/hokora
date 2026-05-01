# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for the MessagesView delete-confirm gate (T1a).

The single-key ``d`` shortcut on the focused message used to fire
``send_delete`` immediately. T1a routes through ConfirmDialog with an
opt-out (``confirm_destructive_actions=false`` setting) for power users.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from hokora_tui.views.messages_view import MessagesView


def _make_view(confirm_pref: str = "true"):
    """Construct a MessagesView with a mock app that records confirm + send."""
    app = MagicMock()
    app.db = MagicMock()
    app.db.get_setting = MagicMock(return_value=confirm_pref)
    app.sync_engine = MagicMock()
    app.status = MagicMock()
    app.frame = MagicMock()
    app._schedule_redraw = MagicMock()
    return MessagesView(app), app


def test_confirm_pref_default_opens_dialog(monkeypatch):
    """Default behaviour: pref unset → confirm dialog opens, send NOT called."""
    view, app = _make_view(confirm_pref="true")

    shown: list = []
    monkeypatch.setattr(
        "hokora_tui.views.messages_view.ConfirmDialog.show",
        lambda app, msg, on_confirm: shown.append((msg, on_confirm)),
    )

    view._confirm_delete("ch1", "abc123def456789")
    assert len(shown) == 1
    assert "abc123def456" in shown[0][0]
    # Send NOT triggered yet — waiting on confirm.
    app.sync_engine.send_delete.assert_not_called()


def test_confirm_pref_false_bypasses_dialog(monkeypatch):
    """Power-user opt-out: pref=false → send fires immediately, no dialog."""
    view, app = _make_view(confirm_pref="false")

    shown: list = []
    monkeypatch.setattr(
        "hokora_tui.views.messages_view.ConfirmDialog.show",
        lambda app, msg, on_confirm: shown.append((msg, on_confirm)),
    )

    view._confirm_delete("ch1", "abc123def456789")
    assert shown == []  # No dialog.
    app.sync_engine.send_delete.assert_called_once_with("ch1", "abc123def456789")


def test_confirm_callback_actually_sends(monkeypatch):
    """When user clicks Yes, the on_confirm callback fires send_delete."""
    view, app = _make_view(confirm_pref="true")

    captured: dict = {}
    monkeypatch.setattr(
        "hokora_tui.views.messages_view.ConfirmDialog.show",
        lambda a, m, on_confirm: captured.update(cb=on_confirm),
    )

    view._confirm_delete("ch1", "deadbeefcafe1234")
    captured["cb"]()  # Simulate Yes click.
    app.sync_engine.send_delete.assert_called_once_with("ch1", "deadbeefcafe1234")


def test_no_db_defaults_to_confirm(monkeypatch):
    """If db is None (test/early-init), default to safe — confirm on."""
    view, app = _make_view(confirm_pref="true")
    app.db = None

    shown: list = []
    monkeypatch.setattr(
        "hokora_tui.views.messages_view.ConfirmDialog.show",
        lambda a, m, on_confirm: shown.append(on_confirm),
    )

    view._confirm_delete("ch1", "deadbeefcafe1234")
    assert len(shown) == 1
