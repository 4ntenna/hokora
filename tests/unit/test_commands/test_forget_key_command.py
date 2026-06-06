# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for ``ForgetKeyCommand`` (TOFU pin reset)."""

import logging
from unittest.mock import MagicMock, call

import pytest

from hokora_tui.commands._base import CommandContext, UIGate
from hokora_tui.commands.forget_key_command import ForgetKeyCommand

# Sender hashes are RNS identity.hexhash values — 32 hex chars (truncated
# hash), NOT the 64-hex SHA-256 width used for message hashes.
SENDER = "ab" * 16


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
        ForgetKeyCommand().execute(ctx, "")
        last = ctx.status.set_context.call_args.args[0]
        assert "Usage: /forget-key" in last
        ctx.db.tofu_keys.delete.assert_not_called()
        ctx.engine.forget_identity_key.assert_not_called()

    def test_non_hex_rejected(self, ctx):
        ForgetKeyCommand().execute(ctx, "not-a-hash")
        assert "Usage: /forget-key" in ctx.status.set_context.call_args.args[0]
        ctx.db.tofu_keys.delete.assert_not_called()

    def test_short_hash_rejected(self, ctx):
        """Full sender hash only — no prefix matching on a security delete."""
        ForgetKeyCommand().execute(ctx, SENDER[:16])
        assert "Usage: /forget-key" in ctx.status.set_context.call_args.args[0]
        ctx.db.tofu_keys.delete.assert_not_called()

    def test_64_hex_rejected(self, ctx):
        """Message-hash width (64 hex) is NOT a sender hash — reject it."""
        ForgetKeyCommand().execute(ctx, "ab" * 32)
        assert "Usage: /forget-key" in ctx.status.set_context.call_args.args[0]
        ctx.db.tofu_keys.delete.assert_not_called()

    def test_uppercase_hash_normalized(self, ctx):
        ctx.engine.forget_identity_key.return_value = True
        ForgetKeyCommand().execute(ctx, SENDER.upper())
        ctx.engine.forget_identity_key.assert_called_once_with(SENDER)
        ctx.db.tofu_keys.delete.assert_called_once_with(SENDER)


class TestExecution:
    def test_valid_hash_deletes_from_store_and_engine(self, ctx):
        ctx.engine.forget_identity_key.return_value = True
        ForgetKeyCommand().execute(ctx, SENDER)
        ctx.db.tofu_keys.delete.assert_called_once_with(SENDER)
        ctx.engine.forget_identity_key.assert_called_once_with(SENDER)
        assert "Forgot pinned key" in ctx.status.set_context.call_args.args[0]

    def test_store_delete_runs_before_memory_pop(self, ctx):
        """DB row goes first so an interleaved in-flight verify re-persists
        rather than leaving memory and store divergent."""
        order = MagicMock()
        order.attach_mock(ctx.db.tofu_keys.delete, "store_delete")
        order.attach_mock(ctx.engine.forget_identity_key, "memory_pop")
        ForgetKeyCommand().execute(ctx, SENDER)
        assert order.mock_calls.index(call.store_delete(SENDER)) < order.mock_calls.index(
            call.memory_pop(SENDER)
        )

    def test_no_engine_still_deletes_from_store(self, ctx):
        ctx.engine = None
        ForgetKeyCommand().execute(ctx, SENDER)
        ctx.db.tofu_keys.delete.assert_called_once_with(SENDER)

    def test_no_db_reports_degraded_outcome(self, ctx):
        """In-memory pin dropped but DB unavailable — the user must NOT be
        told the reset fully succeeded (a persisted pin would re-hydrate)."""
        ctx.db = None
        ctx.engine.forget_identity_key.return_value = True
        ForgetKeyCommand().execute(ctx, SENDER)
        last = ctx.status.set_context.call_args.args[0]
        assert "client DB unavailable" in last
        assert "not cleared" in last

    def test_no_db_no_pin_reports_no_pin(self, ctx):
        ctx.db = None
        ctx.engine.forget_identity_key.return_value = False
        ForgetKeyCommand().execute(ctx, SENDER)
        assert "No pinned key" in ctx.status.set_context.call_args.args[0]

    def test_store_failure_reported_not_swallowed(self, ctx):
        """A failing store (e.g. closed connection after a cache clear)
        must surface as an error, not a silent no-op or a false success."""
        ctx.db.tofu_keys.get.side_effect = RuntimeError("closed")
        ctx.engine.forget_identity_key.return_value = True
        ForgetKeyCommand().execute(ctx, SENDER)
        last = ctx.status.set_context.call_args.args[0]
        assert "Client DB error" in last
        assert "not cleared" in last

    def test_unknown_sender_reports_no_pin(self, ctx):
        ctx.engine.forget_identity_key.return_value = False
        ctx.db.tofu_keys.get.return_value = None
        ForgetKeyCommand().execute(ctx, SENDER)
        ctx.db.tofu_keys.delete.assert_called_once_with(SENDER)
        assert "No pinned key" in ctx.status.set_context.call_args.args[0]

    def test_store_only_pin_still_reports_forgotten(self, ctx):
        """Pin present on disk but not in the (fresh) in-memory cache."""
        ctx.engine.forget_identity_key.return_value = False
        ctx.db.tofu_keys.get.return_value = b"\x01" * 32
        ForgetKeyCommand().execute(ctx, SENDER)
        assert "Forgot pinned key" in ctx.status.set_context.call_args.args[0]
