# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Centralised logging configuration: plaintext or JSON, rotating file + optional stdout."""

from __future__ import annotations

import json
import logging
import sys
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

_DEFAULT_FORMAT = "%(asctime)s [%(name)s] %(levelname)s: %(message)s"
_ROTATE_MAX_BYTES = 10 * 1024 * 1024
_ROTATE_BACKUP_COUNT = 5

# Standard LogRecord attributes; anything else came from ``extra={...}``.
_STANDARD_LOGRECORD_KEYS = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "message",
        "module",
        "msecs",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "taskName",
        "thread",
        "threadName",
    }
)


class JsonFormatter(logging.Formatter):
    """Emit one JSON object per log line; ``extra={...}`` keys are merged in."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "module": record.module,
            "line": record.lineno,
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        for key, value in record.__dict__.items():
            if key in _STANDARD_LOGRECORD_KEYS or key in payload:
                continue
            try:
                json.dumps(value)
                payload[key] = value
            except (TypeError, ValueError):
                payload[key] = repr(value)
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(
    log_dir: Path,
    log_level: str = "INFO",
    json_logging: bool = False,
    log_to_stdout: bool = False,
    log_filename: str = "hokorad.log",
    max_bytes: int = _ROTATE_MAX_BYTES,
    backup_count: int = _ROTATE_BACKUP_COUNT,
) -> None:
    """Configure the root logger with a rotating file handler.

    Idempotent across reloads. Attaches TransportLogSanitizer to every
    handler so transport secrets can't leak via the log surface.
    """
    from hokora.security.log_sanitizer import TransportLogSanitizer

    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    level = getattr(logging, log_level.upper(), logging.INFO)
    formatter: logging.Formatter = (
        JsonFormatter() if json_logging else logging.Formatter(_DEFAULT_FORMAT)
    )

    file_handler = RotatingFileHandler(
        str(log_dir / log_filename),
        maxBytes=max_bytes,
        backupCount=backup_count,
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)

    handlers: list[logging.Handler] = [file_handler]
    if log_to_stdout:
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setLevel(level)
        stream_handler.setFormatter(formatter)
        handlers.append(stream_handler)

    sanitizer = TransportLogSanitizer()
    for handler in handlers:
        handler.addFilter(sanitizer)

    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.setLevel(level)
    for handler in handlers:
        root.addHandler(handler)
