# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the small commands: /disconnect, /sync, /name, /status."""

import logging
from unittest.mock import MagicMock

import pytest

from hokora_tui.commands._base import CommandContext, UIGate
from hokora_tui.commands.disconnect_command import DisconnectCommand
from hokora_tui.commands.name_command import NameCommand
from hokora_tui.commands.status_command import StatusCommand
from hokora_tui.commands.sync_command import SyncCommand


@pytest.fixture
def ctx():
    return CommandContext(
        app=MagicMock(),
        state=MagicMock(),
        db=MagicMock(),
        engine=MagicMock(),
        gate=UIGate(loop=None),
        log=logging.getLogger("test"),
        status=MagicMock(),
        emit=MagicMock(),
    )


class TestDisconnectCommand:
    def test_calls_engine_disconnect_all(self, ctx):
        DisconnectCommand().execute(ctx, "")
        ctx.engine.disconnect_all.assert_called_once()

    def test_clears_state(self, ctx):
        DisconnectCommand().execute(ctx, "")
        assert ctx.state.channels == []
        assert ctx.state.messages == {}
        assert ctx.state.current_channel_id is None
        assert ctx.state.connection_status == "disconnected"

    def test_emits_channels_updated(self, ctx):
        DisconnectCommand().execute(ctx, "")
        ctx.state.emit.assert_called_with("channels_updated")

    def test_tolerates_no_engine(self, ctx):
        ctx.engine = None
        # Need to rebuild because engine is positional in dataclass
        ctx2 = CommandContext(
            app=ctx.app,
            state=ctx.state,
            db=ctx.db,
            engine=None,
            gate=ctx.gate,
            log=ctx.log,
            status=ctx.status,
            emit=ctx.emit,
        )
        # Should not raise
        DisconnectCommand().execute(ctx2, "")
        assert ctx2.state.connection_status == "disconnected"


class TestSyncCommand:
    def test_no_channel_selected(self, ctx):
        ctx.state.current_channel_id = None
        SyncCommand().execute(ctx, "")
        ctx.status.set_context.assert_called_with("No channel selected.")
        ctx.engine.sync_history.assert_not_called()

    def test_no_engine(self, ctx):
        ctx2 = CommandContext(
            app=ctx.app,
            state=ctx.state,
            db=ctx.db,
            engine=None,
            gate=ctx.gate,
            log=ctx.log,
            status=ctx.status,
            emit=ctx.emit,
        )
        ctx2.state.current_channel_id = "ch1"
        SyncCommand().execute(ctx2, "")
        ctx2.status.set_context.assert_called_with("No sync engine connected.")

    def test_dispatches_to_engine(self, ctx):
        ctx.state.current_channel_id = "ch1"
        SyncCommand().execute(ctx, "")
        ctx.engine.sync_history.assert_called_once_with("ch1")
        ctx.status.set_context.assert_called_with("Syncing...")


class TestNameCommand:
    def test_empty_args_shows_usage(self, ctx):
        NameCommand().execute(ctx, "")
        ctx.status.set_context.assert_called_with("Usage: /name <display_name>")
        ctx.engine.set_display_name.assert_not_called()

    def test_sets_display_name(self, ctx):
        NameCommand().execute(ctx, "alice")
        assert ctx.state.display_name == "alice"
        ctx.engine.set_display_name.assert_called_once_with("alice")
        ctx.db.set_setting.assert_called_once_with("display_name", "alice")

    def test_strips_whitespace(self, ctx):
        NameCommand().execute(ctx, "  bob  ")
        assert ctx.state.display_name == "bob"

    def test_tolerates_no_engine_no_db(self, ctx):
        ctx2 = CommandContext(
            app=ctx.app,
            state=ctx.state,
            db=None,
            engine=None,
            gate=ctx.gate,
            log=ctx.log,
            status=ctx.status,
            emit=ctx.emit,
        )
        NameCommand().execute(ctx2, "carol")
        assert ctx2.state.display_name == "carol"


class TestStatusCommand:
    def test_empty_args_shows_usage(self, ctx):
        StatusCommand().execute(ctx, "")
        ctx.status.set_context.assert_called_with("Usage: /status <text>")

    def test_sets_status_text(self, ctx):
        StatusCommand().execute(ctx, "afk")
        assert ctx.state.status_text == "afk"
        ctx.db.set_setting.assert_called_once_with("status_text", "afk")

    def test_strips_whitespace(self, ctx):
        StatusCommand().execute(ctx, "  available  ")
        assert ctx.state.status_text == "available"
