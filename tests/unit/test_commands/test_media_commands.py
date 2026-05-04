# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for media commands: /upload and /download."""

import logging
from unittest.mock import MagicMock

import pytest

from hokora_tui.commands._base import CommandContext, UIGate
from hokora_tui.commands.download_command import DownloadCommand
from hokora_tui.commands.upload_command import UploadCommand


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


def _last_notice(ctx):
    """Most recent set_notice text + level for assertion."""
    return ctx.status.set_notice.call_args.args[0], ctx.status.set_notice.call_args.kwargs.get(
        "level"
    )


class TestUploadCommand:
    def test_no_args(self, ctx):
        UploadCommand().execute(ctx, "")
        text, level = _last_notice(ctx)
        assert "Usage: /upload" in text
        assert level == "warn"

    def test_no_channel(self, ctx):
        ctx.state.current_channel_id = None
        UploadCommand().execute(ctx, "/tmp/foo.bin")
        text, level = _last_notice(ctx)
        assert "Select a channel first" in text
        assert level == "warn"

    def test_missing_file(self, ctx):
        ctx.state.current_channel_id = "ch1"
        UploadCommand().execute(ctx, "/nonexistent/file.bin")
        text, level = _last_notice(ctx)
        assert "File not found" in text
        assert level == "error"

    def test_too_large(self, ctx, tmp_path):
        ctx.state.current_channel_id = "ch1"
        big = tmp_path / "big.bin"
        big.write_bytes(b"x" * (5 * 1024 * 1024 + 1))
        UploadCommand().execute(ctx, str(big))
        text, level = _last_notice(ctx)
        assert "too large" in text
        assert level == "error"
        ctx.engine.send_media.assert_not_called()

    def test_no_engine(self, ctx, tmp_path):
        ctx.state.current_channel_id = "ch1"
        f = tmp_path / "f.bin"
        f.write_bytes(b"data")
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
        UploadCommand().execute(ctx2, str(f))
        text, level = _last_notice(ctx2)
        assert text == "Not connected."
        assert level == "warn"

    def test_happy_path(self, ctx, tmp_path):
        ctx.state.current_channel_id = "ch1"
        f = tmp_path / "img.png"
        f.write_bytes(b"PNG-data")
        ctx.engine.send_media.return_value = True
        UploadCommand().execute(ctx, str(f))
        ctx.engine.send_media.assert_called_once_with("ch1", str(f))
        text, _ = _last_notice(ctx)
        assert "Uploading img.png" in text

    def test_engine_returns_false(self, ctx, tmp_path):
        ctx.state.current_channel_id = "ch1"
        f = tmp_path / "img.png"
        f.write_bytes(b"PNG-data")
        ctx.engine.send_media.return_value = False
        UploadCommand().execute(ctx, str(f))
        text, level = _last_notice(ctx)
        assert "Upload failed" in text
        assert level == "error"


class TestDownloadCommand:
    def test_no_args(self, ctx):
        DownloadCommand().execute(ctx, "")
        text, level = _last_notice(ctx)
        assert "Usage: /download" in text
        assert level == "warn"

    def test_no_channel(self, ctx):
        ctx.state.current_channel_id = None
        DownloadCommand().execute(ctx, "foo.bin")
        text, level = _last_notice(ctx)
        assert "Select a channel first" in text
        assert level == "warn"

    def test_no_matching_media(self, ctx):
        ctx.state.current_channel_id = "ch1"
        ctx.state.messages = {"ch1": [{"media_path": "other.bin"}]}
        DownloadCommand().execute(ctx, "missing.bin")
        text, _ = _last_notice(ctx)
        assert "No media 'missing.bin'" in text

    def test_exact_match(self, ctx):
        ctx.state.current_channel_id = "ch1"
        ctx.state.messages = {"ch1": [{"media_path": "foo.bin"}]}
        DownloadCommand().execute(ctx, "foo.bin")
        ctx.engine.request_media_download.assert_called_once_with("ch1", "foo.bin", save_path=None)

    def test_basename_suffix_match(self, ctx):
        ctx.state.current_channel_id = "ch1"
        ctx.state.messages = {"ch1": [{"media_path": "media/uploads/foo.bin"}]}
        DownloadCommand().execute(ctx, "foo.bin")
        ctx.engine.request_media_download.assert_called_once_with(
            "ch1", "media/uploads/foo.bin", save_path=None
        )

    def test_with_save_path(self, ctx):
        ctx.state.current_channel_id = "ch1"
        ctx.state.messages = {"ch1": [{"media_path": "foo.bin"}]}
        DownloadCommand().execute(ctx, "foo.bin /tmp/saved")
        ctx.engine.request_media_download.assert_called_once_with(
            "ch1", "foo.bin", save_path="/tmp/saved"
        )

    def test_no_engine(self, ctx):
        ctx.state.current_channel_id = "ch1"
        ctx.state.messages = {"ch1": [{"media_path": "foo.bin"}]}
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
        DownloadCommand().execute(ctx2, "foo.bin")
        text, level = _last_notice(ctx2)
        assert text == "Not connected."
        assert level == "warn"
