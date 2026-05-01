# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for the TUI SealedKeyStore (sealed-channel symmetric keys)."""

from __future__ import annotations

from pathlib import Path

import pytest

from hokora_tui.client_db import ClientDB


@pytest.fixture
def db(tmp_path: Path):
    client = ClientDB(tmp_path / "tui.db", encrypt=False)
    yield client
    client.close()


def test_upsert_and_get(db):
    key = b"\xaa" * 32
    db.sealed_keys.upsert("ch1", key, 1)
    got = db.sealed_keys.get("ch1")
    assert got is not None
    assert got[0] == key
    assert got[1] == 1


def test_get_missing_returns_none(db):
    assert db.sealed_keys.get("absent") is None


def test_upsert_replaces_on_epoch_bump(db):
    db.sealed_keys.upsert("ch1", b"\x01" * 32, 1)
    db.sealed_keys.upsert("ch1", b"\x02" * 32, 2)
    got = db.sealed_keys.get("ch1")
    assert got == (b"\x02" * 32, 2)


def test_all_keys_returns_dict(db):
    db.sealed_keys.upsert("ch1", b"\x01" * 32, 1)
    db.sealed_keys.upsert("ch2", b"\x02" * 32, 1)
    all_ = db.sealed_keys.all_keys()
    assert set(all_.keys()) == {"ch1", "ch2"}
    assert all_["ch1"] == (b"\x01" * 32, 1)


def test_delete(db):
    db.sealed_keys.upsert("ch1", b"\x01" * 32, 1)
    db.sealed_keys.delete("ch1")
    assert db.sealed_keys.get("ch1") is None


def test_persists_across_reopen(tmp_path: Path):
    p = tmp_path / "tui.db"
    db = ClientDB(p, encrypt=False)
    try:
        db.sealed_keys.upsert("ch1", b"\xff" * 32, 7)
    finally:
        db.close()
    db2 = ClientDB(p, encrypt=False)
    try:
        assert db2.sealed_keys.get("ch1") == (b"\xff" * 32, 7)
    finally:
        db2.close()


def test_schema_v8_columns_exist(db):
    cols = {row[1] for row in db.conn.execute("PRAGMA table_info(messages)").fetchall()}
    assert "encrypted_body" in cols
    assert "encryption_nonce" in cols
    assert "encryption_epoch" in cols


def test_schema_v8_table_exists(db):
    rows = db.conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='sealed_keys'"
    ).fetchall()
    assert len(rows) == 1
