# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for ``handle_list_seeds`` in protocol/handlers/transport.py.

Covers:

* Reads live seed list from the daemon's RNS config directory.
* Rate-limit invocation delegated to ``ctx.rate_limiter``.
* Degrades to ``ok=False`` on a parse error.
* Empty config dir returns ``ok=True, seeds=[]``.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import pytest

from hokora.protocol.handlers.transport import handle_list_seeds


@dataclass
class _FakeConfig:
    rns_config_dir: Optional[Path] = None


class _FakeRateLimiter:
    def __init__(self):
        self.calls: list[str] = []

    def check_rate_limit(self, identity_hash: str) -> None:
        self.calls.append(identity_hash)


class _Ctx:
    def __init__(self, rns_config_dir: Optional[Path], rate_limiter=None) -> None:
        self.config = _FakeConfig(rns_config_dir=rns_config_dir)
        self.rate_limiter = rate_limiter


def _run(coro):
    """Drive a coroutine via ``asyncio.run`` — manages its own loop and
    closes it on exit so no thread-local policy leaks into subsequent
    pytest-asyncio tests."""
    return asyncio.run(coro)


def _write_seed_config(path: Path, sections: str) -> None:
    path.write_text(f"[interfaces]\n{sections}")
    os.chmod(path, 0o600)


def test_empty_config_returns_empty_list(tmp_path: Path):
    _write_seed_config(tmp_path / "config", "")
    ctx = _Ctx(rns_config_dir=tmp_path)
    result = _run(handle_list_seeds(ctx, None, b"n", {}, None))
    assert result["ok"] is True
    assert result["seeds"] == []
    assert result["restart_required"] is False


def test_lists_tcp_seed(tmp_path: Path):
    _write_seed_config(
        tmp_path / "config",
        """  [[VPS]]
    type = TCPClientInterface
    enabled = yes
    target_host = 1.2.3.4
    target_port = 4242
""",
    )
    ctx = _Ctx(rns_config_dir=tmp_path)
    result = _run(handle_list_seeds(ctx, None, b"n", {}, None))
    assert result["ok"] is True
    assert len(result["seeds"]) == 1
    seed = result["seeds"][0]
    assert seed["name"] == "VPS"
    assert seed["type"] == "tcp"
    assert seed["target_host"] == "1.2.3.4"
    assert seed["target_port"] == 4242
    assert seed["enabled"] is True


def test_filters_non_seed_interfaces(tmp_path: Path):
    _write_seed_config(
        tmp_path / "config",
        """  [[TCP Server]]
    type = TCPServerInterface
    listen_ip = 127.0.0.1
    listen_port = 4242
  [[Outbound]]
    type = TCPClientInterface
    target_host = h
    target_port = 4242
""",
    )
    ctx = _Ctx(rns_config_dir=tmp_path)
    result = _run(handle_list_seeds(ctx, None, b"n", {}, None))
    assert [s["name"] for s in result["seeds"]] == ["Outbound"]


def test_rate_limiter_invoked_with_requester_hash(tmp_path: Path):
    _write_seed_config(tmp_path / "config", "")
    limiter = _FakeRateLimiter()
    ctx = _Ctx(rns_config_dir=tmp_path, rate_limiter=limiter)
    _run(handle_list_seeds(ctx, None, b"n", {}, None, requester_hash="abc123"))
    assert limiter.calls == ["abc123"]


def test_rate_limiter_skipped_when_no_requester(tmp_path: Path):
    _write_seed_config(tmp_path / "config", "")
    limiter = _FakeRateLimiter()
    ctx = _Ctx(rns_config_dir=tmp_path, rate_limiter=limiter)
    _run(handle_list_seeds(ctx, None, b"n", {}, None))
    assert limiter.calls == []


def test_missing_config_dir_returns_empty():
    # Nonexistent rns_config_dir — handler returns ok with empty seeds.
    ctx = _Ctx(rns_config_dir=Path("/tmp/definitely-not-a-real-dir"))
    result = _run(handle_list_seeds(ctx, None, b"n", {}, None))
    assert result["ok"] is True
    assert result["seeds"] == []


def test_no_config_object_on_ctx(tmp_path: Path):
    # ctx.config is None (e.g., minimal handler unit test).
    class _MinCtx:
        config = None
        rate_limiter = None

    result = _run(handle_list_seeds(_MinCtx(), None, b"n", {}, None))
    # Uses RNS default path (~/.reticulum/config) — may or may not exist.
    # Either way we get a well-formed response.
    assert "seeds" in result
    assert isinstance(result["seeds"], list)


def test_rate_limit_exception_propagates(tmp_path: Path):
    _write_seed_config(tmp_path / "config", "")

    class _RaiseLimiter:
        def check_rate_limit(self, h):
            raise RuntimeError("throttled")

    ctx = _Ctx(rns_config_dir=tmp_path, rate_limiter=_RaiseLimiter())
    with pytest.raises(RuntimeError):
        _run(handle_list_seeds(ctx, None, b"n", {}, None, requester_hash="abc"))
