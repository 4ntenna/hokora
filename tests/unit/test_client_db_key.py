# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for the TUI-side client_db_key resolver wrapper."""

from __future__ import annotations

from pathlib import Path

import pytest

from hokora.security.db_key import DB_KEY_PATTERN
from hokora_tui.security.client_db_key import (
    CLIENT_DB_KEYFILE_NAME,
    client_db_keyfile_path,
    resolve_client_db_key,
)


def test_keyfile_path_is_inside_client_dir(tmp_path: Path):
    assert client_db_keyfile_path(tmp_path) == tmp_path / CLIENT_DB_KEYFILE_NAME


def test_first_call_creates_keyfile(tmp_path: Path):
    key = resolve_client_db_key(tmp_path)
    assert DB_KEY_PATTERN.match(key)
    assert (tmp_path / "db_key").is_file()


def test_first_call_writes_0o600(tmp_path: Path):
    resolve_client_db_key(tmp_path)
    mode = (tmp_path / "db_key").stat().st_mode & 0o777
    assert mode == 0o600


def test_idempotent(tmp_path: Path):
    first = resolve_client_db_key(tmp_path)
    second = resolve_client_db_key(tmp_path)
    assert first == second


def test_corrupted_keyfile_raises(tmp_path: Path):
    (tmp_path / "db_key").write_text("garbage\n")
    (tmp_path / "db_key").chmod(0o600)
    with pytest.raises(ValueError, match="64 hex characters"):
        resolve_client_db_key(tmp_path)
