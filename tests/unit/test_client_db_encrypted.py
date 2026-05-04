# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for SQLCipher-backed ClientDB construction."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
import sqlcipher3

from hokora_tui.client_db import ClientDB
from hokora_tui.client_db._engine import is_plaintext_sqlite, open_encrypted

KEY_A = "a" * 64
KEY_B = "b" * 64


class TestOpenEncrypted:
    def test_round_trip(self, tmp_path: Path):
        p = tmp_path / "x.db"
        conn = open_encrypted(str(p), KEY_A)
        try:
            conn.execute("CREATE TABLE t (x INTEGER)")
            conn.execute("INSERT INTO t VALUES (?)", (1,))
            conn.commit()
            assert conn.execute("SELECT x FROM t").fetchone()[0] == 1
        finally:
            conn.close()

        # Reopen with same key works.
        conn2 = open_encrypted(str(p), KEY_A)
        try:
            assert conn2.execute("SELECT x FROM t").fetchone()[0] == 1
        finally:
            conn2.close()

    def test_wrong_key_fails(self, tmp_path: Path):
        p = tmp_path / "y.db"
        conn = open_encrypted(str(p), KEY_A)
        try:
            conn.execute("CREATE TABLE t (x INTEGER)")
            conn.commit()
        finally:
            conn.close()

        # Reopen with wrong key — fails during PRAGMA-driven key check
        # (sqlcipher fails fast on the journal-mode pragma when the key
        # is wrong, before the SELECT is ever issued). The error class
        # is sqlcipher3.dbapi2.DatabaseError which is a sqlite3.DatabaseError
        # subclass; match either form.
        with pytest.raises((sqlite3.DatabaseError, sqlcipher3.dbapi2.DatabaseError)):
            open_encrypted(str(p), KEY_B)

    def test_invalid_key_rejected(self, tmp_path: Path):
        with pytest.raises(ValueError, match="64 hexadecimal"):
            open_encrypted(str(tmp_path / "z.db"), "not-hex")


class TestIsPlaintextSqlite:
    def test_plaintext_db_returns_true(self, tmp_path: Path):
        p = tmp_path / "plain.db"
        conn = sqlite3.connect(str(p))
        conn.execute("CREATE TABLE t (x INTEGER)")
        conn.commit()
        conn.close()
        assert is_plaintext_sqlite(str(p)) is True

    def test_encrypted_db_returns_false(self, tmp_path: Path):
        p = tmp_path / "enc.db"
        conn = open_encrypted(str(p), KEY_A)
        conn.execute("CREATE TABLE t (x INTEGER)")
        conn.commit()
        conn.close()
        assert is_plaintext_sqlite(str(p)) is False

    def test_missing_returns_false(self, tmp_path: Path):
        assert is_plaintext_sqlite(str(tmp_path / "absent.db")) is False


class TestClientDBEncrypted:
    def test_encrypt_true_requires_key(self, tmp_path: Path):
        with pytest.raises(ValueError, match="requires key_hex"):
            ClientDB(tmp_path / "tui.db", encrypt=True)

    def test_encrypt_true_round_trip(self, tmp_path: Path):
        db = ClientDB(tmp_path / "tui.db", KEY_A)
        try:
            db.set_setting("display_name", "Alice")
            assert db.get_setting("display_name") == "Alice"
        finally:
            db.close()

        # Reopen with same key — data persists.
        db2 = ClientDB(tmp_path / "tui.db", KEY_A)
        try:
            assert db2.get_setting("display_name") == "Alice"
        finally:
            db2.close()

    def test_encrypt_false_test_path(self, tmp_path: Path):
        db = ClientDB(tmp_path / "tui.db", encrypt=False)
        try:
            db.set_setting("k", "v")
            assert db.get_setting("k") == "v"
        finally:
            db.close()

    def test_raw_sqlite_open_fails_on_encrypted(self, tmp_path: Path):
        p = tmp_path / "tui.db"
        db = ClientDB(p, KEY_A)
        try:
            db.set_setting("display_name", "Alice")
        finally:
            db.close()
        # Raw stdlib sqlite3 cannot read SQLCipher-encrypted data.
        raw = sqlite3.connect(str(p))
        try:
            with pytest.raises(sqlite3.DatabaseError):
                raw.execute("SELECT * FROM settings").fetchone()
        finally:
            raw.close()
