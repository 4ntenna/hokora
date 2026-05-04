# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for messaging commands: /dm and /dms."""

import logging
from unittest.mock import MagicMock

import pytest

from hokora_tui.commands._base import CommandContext, UIGate
from hokora_tui.commands.dm_command import DmCommand
from hokora_tui.commands.dms_command import DmsCommand


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


_VALID_HASH = "ab" * 16  # 32 hex chars / 16 bytes — RNS Identity hash


class TestDmCommand:
    def test_no_args_shows_usage(self, ctx):
        DmCommand().execute(ctx, "")
        last = ctx.status.set_notice.call_args.args[0]
        assert "Usage: /dm" in last
        assert ctx.status.set_notice.call_args.kwargs.get("level") == "warn"

    def test_invalid_hex_rejected(self, ctx):
        DmCommand().execute(ctx, "not-hex")
        last = ctx.status.set_notice.call_args.args[0]
        assert "Invalid peer hash" in last
        assert ctx.status.set_notice.call_args.kwargs.get("level") == "error"

    def test_short_hex_rejected(self, ctx):
        DmCommand().execute(ctx, "abcd1234")
        last = ctx.status.set_notice.call_args.args[0]
        assert "Invalid peer hash" in last

    def test_opens_conversation_view(self, ctx):
        ctx.app.conversations_view = MagicMock()
        DmCommand().execute(ctx, _VALID_HASH)
        ctx.app.nav.switch_to.assert_called_once_with(4)
        ctx.app.conversations_view.open_dm.assert_called_once_with(
            _VALID_HASH, initial_message=None
        )

    def test_passes_initial_message(self, ctx):
        ctx.app.conversations_view = MagicMock()
        DmCommand().execute(ctx, f"{_VALID_HASH} hello there")
        ctx.app.conversations_view.open_dm.assert_called_once_with(
            _VALID_HASH, initial_message="hello there"
        )

    def test_no_conversations_view_shows_error(self, ctx):
        ctx.app.conversations_view = None
        DmCommand().execute(ctx, _VALID_HASH)
        last = ctx.status.set_notice.call_args.args[0]
        assert "Conversations view not available" in last
        assert ctx.status.set_notice.call_args.kwargs.get("level") == "error"


class TestDmsCommand:
    def test_switches_to_conversations_tab(self, ctx):
        DmsCommand().execute(ctx, "")
        ctx.app.nav.switch_to.assert_called_once_with(4)
        ctx.status.set_context.assert_called_with("Conversations")
