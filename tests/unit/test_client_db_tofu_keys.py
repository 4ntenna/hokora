# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for the TUI TofuKeyStore (persisted sender-key TOFU pins)."""

from __future__ import annotations

from pathlib import Path

import pytest

from hokora_tui.client_db import ClientDB

SENDER = "a" * 64
KEY_A = b"\x01" * 32
KEY_B = b"\x02" * 32


@pytest.fixture
def db(tmp_path: Path):
    client = ClientDB(tmp_path / "tui.db", encrypt=False)
    yield client
    client.close()


def test_insert_and_get(db):
    db.tofu_keys.insert_if_absent(SENDER, KEY_A)
    assert db.tofu_keys.get(SENDER) == KEY_A


def test_get_missing_returns_none(db):
    assert db.tofu_keys.get("absent" + "0" * 58) is None


def test_first_write_wins(db):
    """A second insert for the same sender must NOT overwrite the pin."""
    db.tofu_keys.insert_if_absent(SENDER, KEY_A)
    db.tofu_keys.insert_if_absent(SENDER, KEY_B)
    assert db.tofu_keys.get(SENDER) == KEY_A


def test_insert_is_idempotent(db):
    db.tofu_keys.insert_if_absent(SENDER, KEY_A)
    db.tofu_keys.insert_if_absent(SENDER, KEY_A)
    assert db.tofu_keys.get(SENDER) == KEY_A


def test_all_keys_returns_dict(db):
    other = "b" * 64
    db.tofu_keys.insert_if_absent(SENDER, KEY_A)
    db.tofu_keys.insert_if_absent(other, KEY_B)
    all_ = db.tofu_keys.all_keys()
    assert all_ == {SENDER: KEY_A, other: KEY_B}


def test_delete(db):
    db.tofu_keys.insert_if_absent(SENDER, KEY_A)
    db.tofu_keys.delete(SENDER)
    assert db.tofu_keys.get(SENDER) is None


def test_delete_absent_is_noop(db):
    db.tofu_keys.delete(SENDER)  # must not raise
    assert db.tofu_keys.get(SENDER) is None


def test_delete_then_repin_takes_new_key(db):
    """The explicit reset path: delete allows a different key to pin."""
    db.tofu_keys.insert_if_absent(SENDER, KEY_A)
    db.tofu_keys.delete(SENDER)
    db.tofu_keys.insert_if_absent(SENDER, KEY_B)
    assert db.tofu_keys.get(SENDER) == KEY_B


def test_persists_across_reopen(tmp_path: Path):
    p = tmp_path / "tui.db"
    db = ClientDB(p, encrypt=False)
    try:
        db.tofu_keys.insert_if_absent(SENDER, KEY_A)
    finally:
        db.close()
    db2 = ClientDB(p, encrypt=False)
    try:
        assert db2.tofu_keys.get(SENDER) == KEY_A
    finally:
        db2.close()


def test_schema_v9_table_exists(db):
    rows = db.conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='tofu_keys'"
    ).fetchall()
    assert len(rows) == 1
