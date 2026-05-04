# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for ``logging_config``."""

import json
import logging

import pytest

from hokora.core.logging_config import JsonFormatter, configure_logging
from hokora.security.log_sanitizer import TransportLogSanitizer


@pytest.fixture(autouse=True)
def _reset_root_logger():
    """Save/restore root logger state so each test starts clean."""
    root = logging.getLogger()
    saved_handlers = list(root.handlers)
    saved_level = root.level
    root.handlers = []
    yield
    root.handlers = saved_handlers
    root.setLevel(saved_level)


class TestJsonFormatter:
    def test_emits_valid_json_line(self):
        fmt = JsonFormatter()
        rec = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="x.py",
            lineno=10,
            msg="hello",
            args=(),
            exc_info=None,
        )
        out = fmt.format(rec)
        payload = json.loads(out)
        assert payload["level"] == "INFO"
        assert payload["logger"] == "test"
        assert payload["msg"] == "hello"
        assert "ts" in payload
        assert payload["line"] == 10

    def test_ts_is_iso_like(self):
        fmt = JsonFormatter()
        rec = logging.LogRecord(
            name="t",
            level=logging.INFO,
            pathname="x.py",
            lineno=1,
            msg="m",
            args=(),
            exc_info=None,
        )
        payload = json.loads(fmt.format(rec))
        # ISO 8601 with the T separator and Z trailing (UTC).
        assert "T" in payload["ts"] and payload["ts"].endswith("Z")

    def test_extra_dict_merged(self):
        fmt = JsonFormatter()
        rec = logging.LogRecord(
            name="t",
            level=logging.INFO,
            pathname="x.py",
            lineno=1,
            msg="m",
            args=(),
            exc_info=None,
        )
        rec.channel_id = "ch-42"
        rec.request_id = 7
        payload = json.loads(fmt.format(rec))
        assert payload["channel_id"] == "ch-42"
        assert payload["request_id"] == 7

    def test_extra_with_unserializable_value_repr_fallback(self):
        fmt = JsonFormatter()
        rec = logging.LogRecord(
            name="t",
            level=logging.INFO,
            pathname="x.py",
            lineno=1,
            msg="m",
            args=(),
            exc_info=None,
        )
        rec.weird = object()  # not JSON-serialisable
        payload = json.loads(fmt.format(rec))
        assert "weird" in payload
        assert payload["weird"].startswith("<object")

    def test_exc_info_serialised(self):
        fmt = JsonFormatter()
        try:
            raise RuntimeError("boom")
        except RuntimeError:
            import sys

            rec = logging.LogRecord(
                name="t",
                level=logging.ERROR,
                pathname="x.py",
                lineno=1,
                msg="fail",
                args=(),
                exc_info=sys.exc_info(),
            )
        payload = json.loads(fmt.format(rec))
        assert "exc_info" in payload
        assert "RuntimeError" in payload["exc_info"]
        assert "boom" in payload["exc_info"]

    def test_unicode_message_survives(self):
        fmt = JsonFormatter()
        rec = logging.LogRecord(
            name="t",
            level=logging.INFO,
            pathname="x.py",
            lineno=1,
            msg="héllo 🌍",
            args=(),
            exc_info=None,
        )
        payload = json.loads(fmt.format(rec))
        assert payload["msg"] == "héllo 🌍"


class TestConfigureLogging:
    def test_creates_log_dir_if_missing(self, tmp_dir):
        target = tmp_dir / "deep" / "nested"
        assert not target.exists()
        configure_logging(log_dir=target, log_filename="t.log")
        assert target.is_dir()

    def test_plaintext_output_by_default(self, tmp_dir):
        configure_logging(log_dir=tmp_dir, log_filename="t.log")
        logging.getLogger("unit").info("hello")
        for h in logging.getLogger().handlers:
            h.flush()
        text = (tmp_dir / "t.log").read_text()
        assert "hello" in text
        # Plaintext format, not JSON
        with pytest.raises(json.JSONDecodeError):
            json.loads(text.splitlines()[0])

    def test_json_output_when_enabled(self, tmp_dir):
        configure_logging(log_dir=tmp_dir, log_filename="t.log", json_logging=True)
        logging.getLogger("unit").info("hello")
        for h in logging.getLogger().handlers:
            h.flush()
        line = (tmp_dir / "t.log").read_text().splitlines()[0]
        payload = json.loads(line)
        assert payload["msg"] == "hello"
        assert payload["logger"] == "unit"

    def test_log_to_stdout_adds_stream_handler(self, tmp_dir):
        configure_logging(log_dir=tmp_dir, log_filename="t.log", log_to_stdout=True)
        handlers = logging.getLogger().handlers
        # one file + one stream
        assert len(handlers) == 2
        assert any(
            isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler)
            for h in handlers
        )

    def test_log_to_stdout_omitted_by_default(self, tmp_dir):
        configure_logging(log_dir=tmp_dir, log_filename="t.log")
        handlers = logging.getLogger().handlers
        assert len(handlers) == 1  # file only

    def test_idempotent_no_duplicate_handlers(self, tmp_dir):
        configure_logging(log_dir=tmp_dir, log_filename="t.log")
        configure_logging(log_dir=tmp_dir, log_filename="t.log")
        configure_logging(log_dir=tmp_dir, log_filename="t.log")
        assert len(logging.getLogger().handlers) == 1

    def test_transport_log_sanitizer_attached(self, tmp_dir):
        configure_logging(log_dir=tmp_dir, log_filename="t.log")
        handler = logging.getLogger().handlers[0]
        assert any(isinstance(f, TransportLogSanitizer) for f in handler.filters)

    def test_level_honoured(self, tmp_dir):
        configure_logging(log_dir=tmp_dir, log_filename="t.log", log_level="WARNING")
        root = logging.getLogger()
        assert root.level == logging.WARNING

    def test_rotation_honours_max_bytes(self, tmp_dir):
        # Tiny max_bytes forces rotation quickly.
        configure_logging(
            log_dir=tmp_dir,
            log_filename="t.log",
            max_bytes=200,
            backup_count=2,
        )
        log = logging.getLogger("rot")
        for i in range(50):
            log.info("padding line number %d with enough bytes to force rollover", i)
        for h in logging.getLogger().handlers:
            h.flush()
        # At least one backup file should exist
        assert (tmp_dir / "t.log.1").exists()
