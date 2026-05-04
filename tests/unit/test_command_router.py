# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for ``CommandRouter``."""

import logging
from unittest.mock import MagicMock

import pytest

from hokora_tui.commands._base import CommandContext, UIGate
from hokora_tui.commands.router import CommandRouter


@pytest.fixture
def ctx():
    """Build a CommandContext with everything mocked."""
    return CommandContext(
        app=MagicMock(),
        state=MagicMock(),
        db=MagicMock(),
        engine=MagicMock(),
        gate=UIGate(loop=None),  # no loop in tests
        log=logging.getLogger("test"),
        status=MagicMock(),
        emit=MagicMock(),
    )


@pytest.fixture
def router(ctx):
    return CommandRouter(ctx)


def _make_command(name: str, aliases: tuple = (), summary: str = "") -> MagicMock:
    """Build a Command-shape MagicMock with attributes the router expects."""
    cmd = MagicMock()
    cmd.name = name
    cmd.aliases = aliases
    cmd.summary = summary
    return cmd


class TestParse:
    def test_parses_simple_cmd(self, router):
        assert router._parse("/help") == ("help", "")

    def test_parses_cmd_with_args(self, router):
        assert router._parse("/dm peer-hash hello world") == (
            "dm",
            "peer-hash hello world",
        )

    def test_lowercases_command_name(self, router):
        assert router._parse("/HELP") == ("help", "")

    def test_strips_whitespace(self, router):
        assert router._parse("   /sync  channel1  ") == ("sync", "channel1")

    def test_empty_returns_none(self, router):
        assert router._parse("") is None
        assert router._parse("   ") is None

    def test_non_slash_returns_none(self, router):
        assert router._parse("hello") is None
        assert router._parse("not a command") is None

    def test_bare_slash_returns_none(self, router):
        assert router._parse("/") is None


class TestRegister:
    def test_register_indexes_by_name(self, router):
        cmd = _make_command("foo")
        router.register(cmd)
        assert router._commands["foo"] is cmd

    def test_register_indexes_by_alias(self, router):
        cmd = _make_command("quit", aliases=("q", "exit"))
        router.register(cmd)
        assert router._commands["quit"] is cmd
        assert router._commands["q"] is cmd
        assert router._commands["exit"] is cmd

    def test_known_commands_dedupes_by_alias(self, router):
        cmd_a = _make_command("a")
        cmd_b = _make_command("b", aliases=("c",))
        router.register(cmd_a)
        router.register(cmd_b)
        known = router.known_commands()
        assert len(known) == 2
        assert cmd_a in known
        assert cmd_b in known


class TestDispatch:
    def test_dispatch_unknown_returns_false(self, router):
        assert router.dispatch("/nonexistent") is False

    def test_dispatch_non_slash_returns_false(self, router):
        assert router.dispatch("not a command") is False

    def test_dispatch_calls_execute(self, router, ctx):
        cmd = _make_command("foo")
        router.register(cmd)
        result = router.dispatch("/foo arg1 arg2")
        assert result is True
        cmd.execute.assert_called_once_with(ctx, "arg1 arg2")

    def test_dispatch_resolves_alias(self, router, ctx):
        cmd = _make_command("quit", aliases=("q",))
        router.register(cmd)
        assert router.dispatch("/q") is True
        cmd.execute.assert_called_once_with(ctx, "")

    def test_dispatch_swallows_command_exception(self, router):
        cmd = _make_command("boom")
        cmd.execute.side_effect = RuntimeError("crashy")
        router.register(cmd)
        # Should NOT raise — router logs.exception and returns True.
        assert router.dispatch("/boom") is True


class TestRegisterBuiltins:
    def test_registers_all_17_commands(self, router):
        """Every /command is routed via CommandRouter."""
        router.register_builtins()
        names = {cmd.name for cmd in router.known_commands()}
        assert names == {
            "help",
            "quit",
            "clear",
            "disconnect",
            "sync",
            "name",
            "status",
            "local",
            "connect",
            "dm",
            "dms",
            "invite",
            "search",
            "thread",
            "members",
            "upload",
            "download",
        }

    def test_quit_alias_q_registered(self, router):
        router.register_builtins()
        assert router._commands["q"] is router._commands["quit"]

    def test_help_dispatches(self, router, ctx):
        router.register_builtins()
        assert router.dispatch("/help") is True
        ctx.status.set_context.assert_called_once()
        # Confirm the help text contains all registered command names
        call_text = ctx.status.set_context.call_args.args[0]
        assert "/help" in call_text
        assert "/quit" in call_text
        assert "/clear" in call_text

    def test_quit_calls_app_quit(self, router, ctx):
        router.register_builtins()
        assert router.dispatch("/quit") is True
        ctx.app.quit.assert_called_once()

    def test_q_alias_calls_app_quit(self, router, ctx):
        router.register_builtins()
        assert router.dispatch("/q") is True
        ctx.app.quit.assert_called_once()

    def test_clear_calls_messages_view_clear(self, router, ctx):
        # Mock messages_view on the app
        mv = MagicMock()
        ctx.app.messages_view = mv
        router.register_builtins()
        assert router.dispatch("/clear") is True
        mv.clear.assert_called_once()
        ctx.status.set_context.assert_called_once_with("Messages cleared.")
        ctx.app._schedule_redraw.assert_called_once()

    def test_clear_tolerates_no_messages_view(self, router, ctx):
        # No messages_view attr on app — clear should still set status
        delattr(ctx.app, "messages_view") if hasattr(ctx.app, "messages_view") else None
        ctx.app.messages_view = None
        router.register_builtins()
        assert router.dispatch("/clear") is True
        ctx.status.set_context.assert_called_once_with("Messages cleared.")


class TestUIGate:
    def test_no_loop_is_noop(self):
        gate = UIGate(loop=None)
        # Should not raise
        gate.schedule(lambda: None)

    def test_schedules_with_loop(self):
        loop = MagicMock()
        gate = UIGate(loop=loop)
        called = []
        gate.schedule(lambda x: called.append(x), 42)
        loop.set_alarm_in.assert_called_once()
        # The callback wraps fn; invoke it manually to verify it forwards
        delay_arg, cb = loop.set_alarm_in.call_args.args
        assert delay_arg == 0.0
        cb(loop, None)
        assert called == [42]

    def test_custom_delay(self):
        loop = MagicMock()
        gate = UIGate(loop=loop)
        gate.schedule(lambda: None, delay=2.5)
        delay_arg, _ = loop.set_alarm_in.call_args.args
        assert delay_arg == 2.5
