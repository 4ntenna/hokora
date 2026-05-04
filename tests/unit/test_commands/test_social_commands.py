# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for social commands: /invite, /search, /thread, /members."""

import logging
from unittest.mock import MagicMock

import pytest

from hokora_tui.commands._base import CommandContext, UIGate
from hokora_tui.commands.invite_command import InviteCommand
from hokora_tui.commands.members_command import MembersCommand
from hokora_tui.commands.search_command import SearchCommand
from hokora_tui.commands.thread_command import ThreadCommand


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


class TestInviteCommand:
    def test_no_subcmd_opens_dialog(self, ctx):
        InviteCommand().execute(ctx, "")
        ctx.app.open_invite.assert_called_once()

    def test_create_no_channel_warns(self, ctx):
        ctx.state.current_channel_id = None
        InviteCommand().execute(ctx, "create")
        ctx.status.set_context.assert_called_with("Select a channel first.")

    def test_create_no_engine_warns(self, ctx):
        ctx.state.current_channel_id = "ch1"
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
        InviteCommand().execute(ctx2, "create")
        ctx2.status.set_context.assert_called_with("Not connected.")

    def test_create_default_max_uses(self, ctx):
        ctx.state.current_channel_id = "ch1"
        InviteCommand().execute(ctx, "create")
        ctx.engine.create_invite.assert_called_once_with("ch1", max_uses=1)

    def test_create_custom_max_uses(self, ctx):
        ctx.state.current_channel_id = "ch1"
        InviteCommand().execute(ctx, "create 5")
        ctx.engine.create_invite.assert_called_once_with("ch1", max_uses=5)

    def test_redeem_no_code_warns(self, ctx):
        InviteCommand().execute(ctx, "redeem")
        ctx.status.set_context.assert_called_with("Usage: /invite redeem <code>")

    def test_redeem_uses_current_channel(self, ctx):
        ctx.state.current_channel_id = "ch1"
        InviteCommand().execute(ctx, "redeem CODE-XYZ")
        ctx.engine.redeem_invite.assert_called_once_with("ch1", "CODE-XYZ")

    def test_redeem_falls_back_to_first_connected_channel(self, ctx):
        ctx.state.current_channel_id = None
        ctx.engine.first_connected_channel_id.return_value = "ch_other"
        InviteCommand().execute(ctx, "redeem CODE-XYZ")
        ctx.engine.redeem_invite.assert_called_once_with("ch_other", "CODE-XYZ")

    def test_redeem_no_connection_warns(self, ctx):
        ctx.state.current_channel_id = None
        ctx.engine.first_connected_channel_id.return_value = None
        InviteCommand().execute(ctx, "redeem CODE-XYZ")
        ctx.status.set_context.assert_called_with("Connect to a node first.")

    def test_list_dispatches(self, ctx):
        ctx.state.current_channel_id = "ch1"
        InviteCommand().execute(ctx, "list")
        ctx.engine.list_invites.assert_called_once_with("ch1")

    def test_unknown_subcommand_warns(self, ctx):
        InviteCommand().execute(ctx, "frobnicate")
        last = ctx.status.set_context.call_args.args[0]
        assert "Unknown invite subcommand" in last


class TestSearchCommand:
    def test_switches_to_channels_tab_then_opens_search(self, ctx):
        ctx.app.nav.active_tab = 0  # not channels
        SearchCommand().execute(ctx, "")
        ctx.app.nav.switch_to.assert_called_once_with(3)
        ctx.app.open_search.assert_called_once()

    def test_does_not_switch_if_already_on_channels_tab(self, ctx):
        ctx.app.nav.active_tab = 3
        SearchCommand().execute(ctx, "")
        ctx.app.nav.switch_to.assert_not_called()
        ctx.app.open_search.assert_called_once()


class TestThreadCommand:
    def test_no_args_shows_usage(self, ctx):
        ThreadCommand().execute(ctx, "")
        ctx.status.set_context.assert_called_with("Usage: /thread <msg_hash>")

    def test_opens_thread(self, ctx):
        ThreadCommand().execute(ctx, "msg_hash_123")
        ctx.app.open_thread.assert_called_once_with("msg_hash_123")


class TestMembersCommand:
    def test_no_channel_selected(self, ctx):
        ctx.state.current_channel_id = None
        MembersCommand().execute(ctx, "")
        text = ctx.status.set_notice.call_args.args[0]
        assert "Select a channel first" in text

    def test_no_engine(self, ctx):
        ctx.state.current_channel_id = "ch1"
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
        MembersCommand().execute(ctx2, "")
        text = ctx2.status.set_notice.call_args.args[0]
        assert text == "Not connected."

    def test_dispatches_to_engine(self, ctx):
        ctx.state.current_channel_id = "ch1"
        MembersCommand().execute(ctx, "")
        ctx.engine.get_member_list.assert_called_once_with("ch1")
