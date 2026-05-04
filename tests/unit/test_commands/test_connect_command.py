# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for ``ConnectCommand``."""

import logging
from unittest.mock import MagicMock, patch

import pytest

from hokora_tui.commands._base import CommandContext, UIGate
from hokora_tui.commands.connect_command import ConnectCommand


@pytest.fixture
def ctx():
    app = MagicMock()
    app.loop = None
    return CommandContext(
        app=app,
        state=MagicMock(),
        db=MagicMock(),
        engine=MagicMock(),
        gate=UIGate(loop=None),
        log=logging.getLogger("test"),
        status=MagicMock(),
        emit=MagicMock(),
    )


class TestArgValidation:
    def test_no_args_shows_usage(self, ctx):
        ConnectCommand().execute(ctx, "")
        # Usage is now a sticky notice (T1c) so the user can read it before
        # the next event clobbers the status line.
        last = ctx.status.set_notice.call_args.args[0]
        assert "Usage: /connect" in last
        assert ctx.status.set_notice.call_args.kwargs.get("level") == "warn"

    def test_invalid_hex_rejected(self, ctx):
        ConnectCommand().execute(ctx, "not-hex-at-all")
        last = ctx.status.set_notice.call_args.args[0]
        assert "Invalid destination hash" in last
        assert ctx.status.set_notice.call_args.kwargs.get("level") == "error"

    def test_valid_args_spawns_thread(self, ctx):
        with patch("hokora_tui.commands.connect_command.threading.Thread") as Thread:
            ConnectCommand().execute(ctx, "aa" * 16)
            ctx.status.set_connection.assert_called_with("connecting")
            Thread.assert_called_once()


class TestOnConnecting:
    def test_sets_connecting_state(self, ctx):
        ctx.state.connected_node_hash = ""
        ConnectCommand._on_connecting(ctx, "abcd" * 8)
        assert ctx.state.connection_status == "connecting"
        assert ctx.state.connected_node_hash == "abcd" * 8
        ctx.status.set_connection.assert_called_with("connecting", "abcdabcdabcdabcd")


class TestOnConnected:
    def test_with_channel_id(self, ctx):
        ctx.state.connected_node_name = ""
        ConnectCommand._on_connected(ctx, "aa" * 16, "ch1")
        assert ctx.state.connection_status == "connected"
        assert ctx.state.connected_node_hash == "aa" * 16
        last = ctx.status.set_context.call_args.args[0]
        assert "channel ch1" in last

    def test_without_channel_id_says_meta(self, ctx):
        ctx.state.connected_node_name = ""
        ConnectCommand._on_connected(ctx, "aa" * 16, None)
        last = ctx.status.set_context.call_args.args[0]
        assert "channel meta" in last

    def test_preserves_existing_node_name(self, ctx):
        ctx.state.connected_node_name = "MyNode"
        ConnectCommand._on_connected(ctx, "aa" * 16, "ch1")
        assert ctx.state.connected_node_name == "MyNode"


class TestOnEngineFail:
    def test_sets_disconnected(self, ctx):
        ConnectCommand._on_engine_fail(ctx)
        ctx.status.set_connection.assert_called_with("disconnected")
        # Engine-fail is a sticky error notice (T1c).
        last = ctx.status.set_notice.call_args.args[0]
        assert "Failed to initialize sync engine" in last
        assert ctx.status.set_notice.call_args.kwargs.get("level") == "error"


class TestOnTimeout:
    def test_sets_disconnected_with_i2p_hint(self, ctx):
        ConnectCommand._on_timeout(ctx)
        assert ctx.state.connection_status == "disconnected"
        last = ctx.status.set_notice.call_args.args[0]
        assert "I2P" in last
        assert ctx.status.set_notice.call_args.kwargs.get("level") == "error"
