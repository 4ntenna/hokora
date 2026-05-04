# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for ``LocalCommand``."""

import logging
from unittest.mock import MagicMock, patch

import pytest

from hokora_tui.commands._base import CommandContext, UIGate
from hokora_tui.commands.local_command import LocalCommand


@pytest.fixture
def ctx():
    app = MagicMock()
    app.loop = None  # so _schedule_main_thread runs fn immediately
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


class TestLocalCommandEntry:
    def test_sets_connecting_status_and_spawns_thread(self, ctx):
        with patch("hokora_tui.commands.local_command.threading.Thread") as Thread:
            LocalCommand().execute(ctx, "")
            ctx.status.set_connection.assert_called_with("connecting")
            ctx.status.set_context.assert_called_with("Connecting to local node...")
            ctx.app._schedule_redraw.assert_called_once()
            Thread.assert_called_once()
            assert Thread.call_args.kwargs["daemon"] is True


class TestOnSuccess:
    def test_populates_state(self, ctx):
        channels = [
            {"id": "c1", "name": "general", "destination_hash": "aa" * 16},
            {"id": "c2", "name": "off-topic", "destination_hash": "bb" * 16},
        ]
        all_messages = {"c1": [], "c2": []}
        local_node = {"hash": "local", "node_name": "local", "channel_count": 2}

        ctx.state.unread_counts = {}
        ctx.state.discovered_nodes = {}
        ctx.state.connected_node_name = ""

        ctx.app.sync_engine = MagicMock()
        ctx.app.nav = MagicMock()
        ctx.app.channels_view = MagicMock()

        # Stub helpers.ensure_sync_engine where local_command imports it
        with patch("hokora_tui.commands.helpers.ensure_sync_engine") as ensure:
            LocalCommand._on_success(ctx, channels, all_messages, "local", local_node)
            ensure.assert_called_once_with(ctx.app)

        assert ctx.state.channels == channels
        assert ctx.state.messages == all_messages
        assert ctx.state.connection_status == "connected"
        assert ctx.state.connected_node_name == "local"
        assert ctx.state.unread_counts == {"c1": 0, "c2": 0}
        assert ctx.state.discovered_nodes["local"] is local_node
        ctx.state.emit.assert_any_call("channels_updated")
        ctx.state.emit.assert_any_call("nodes_updated")
        ctx.app.nav.switch_to.assert_called_once_with(3)
        ctx.app.channels_view.select_channel.assert_called_once_with("c1")

    def test_connects_each_channel_with_dest_hash(self, ctx):
        channels = [
            {"id": "c1", "destination_hash": "aa" * 16},
        ]
        ctx.state.unread_counts = {}
        ctx.state.discovered_nodes = {}
        ctx.state.connected_node_name = ""
        ctx.app.sync_engine = MagicMock()
        ctx.app.nav = MagicMock()

        with patch("hokora_tui.commands.helpers.ensure_sync_engine"):
            LocalCommand._on_success(ctx, channels, {"c1": []}, "local", {})

        ctx.app.sync_engine.connect_channel.assert_called_once()
        called_dh, called_id = ctx.app.sync_engine.connect_channel.call_args.args
        assert called_dh == bytes.fromhex("aa" * 16)
        assert called_id == "c1"


class TestOnEmpty:
    def test_sets_disconnected_status(self, ctx):
        LocalCommand._on_empty(ctx)
        ctx.status.set_connection.assert_called_with("disconnected")
        ctx.status.set_context.assert_called_with("No channels found on local node.")
        ctx.app._schedule_redraw.assert_called_once()


class TestOnError:
    def test_includes_error_message(self, ctx):
        LocalCommand._on_error(ctx, "DB locked")
        ctx.status.set_context.assert_called_with("Connect failed: DB locked")
