# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for the plaintext→encrypted ClientDB one-time migration."""

from __future__ import annotations

from pathlib import Path

import pytest

from hokora_tui.client_db import ClientDB
from hokora_tui.client_db._engine import is_plaintext_sqlite, open_encrypted
from hokora_tui.client_db._migration import (
    ClientDBMigrationError,
    migrate_to_encrypted,
)

KEY = "c" * 64


def _seed_plaintext(db_path: Path) -> None:
    """Create a plaintext ClientDB with sample rows in every table."""
    db = ClientDB(db_path, encrypt=False)
    try:
        db.set_setting("display_name", "Alice")
        db.set_setting("status_text", "online")
        db.update_conversation("a" * 32, "Bob", 1234.5)
        db.store_dm(
            sender_hash="a" * 32,
            receiver_hash="b" * 32,
            timestamp=1234.5,
            body="hello",
        )
    finally:
        db.close()


class TestMigrateToEncrypted:
    def test_round_trip(self, tmp_path: Path):
        p = tmp_path / "tui.db"
        _seed_plaintext(p)
        assert is_plaintext_sqlite(str(p))

        bak = migrate_to_encrypted(p, KEY)

        assert bak == p.with_suffix(p.suffix + ".pre-encryption.bak")
        assert bak.is_file()
        # Original path is now encrypted.
        assert not is_plaintext_sqlite(str(p))
        # Re-open via SQLCipher and verify rows survived.
        conn = open_encrypted(str(p), KEY)
        try:
            row = conn.execute("SELECT value FROM settings WHERE key='display_name'").fetchone()
            assert row[0] == "Alice"
            row = conn.execute("SELECT body FROM direct_messages").fetchone()
            assert row[0] == "hello"
        finally:
            conn.close()

    def test_backup_is_plaintext_copy(self, tmp_path: Path):
        p = tmp_path / "tui.db"
        _seed_plaintext(p)
        original_size = p.stat().st_size
        migrate_to_encrypted(p, KEY)
        bak = p.with_suffix(p.suffix + ".pre-encryption.bak")
        # Backup is byte-identical to the pre-migration plaintext file.
        assert bak.stat().st_size == original_size
        assert is_plaintext_sqlite(str(bak))

    def test_post_migration_mode_0o600(self, tmp_path: Path):
        p = tmp_path / "tui.db"
        _seed_plaintext(p)
        migrate_to_encrypted(p, KEY)
        assert (p.stat().st_mode & 0o777) == 0o600

    def test_invalid_key_rejected(self, tmp_path: Path):
        p = tmp_path / "tui.db"
        _seed_plaintext(p)
        with pytest.raises(ValueError, match="64 hexadecimal"):
            migrate_to_encrypted(p, "short")

    def test_missing_source_raises(self, tmp_path: Path):
        with pytest.raises(ClientDBMigrationError, match="does not exist"):
            migrate_to_encrypted(tmp_path / "absent.db", KEY)

    def test_notice_callback_invoked(self, tmp_path: Path):
        p = tmp_path / "tui.db"
        _seed_plaintext(p)
        notices = []
        migrate_to_encrypted(p, KEY, notice=notices.append)
        assert any("Encrypting" in n for n in notices)
        assert any("backup" in n.lower() for n in notices)


class TestClientDBMigrationIntegration:
    def test_clientdb_runs_migration_on_plaintext(self, tmp_path: Path):
        p = tmp_path / "tui.db"
        _seed_plaintext(p)

        notices = []
        db = ClientDB(p, KEY, notice=notices.append)
        try:
            # Data preserved across migration.
            assert db.get_setting("display_name") == "Alice"
        finally:
            db.close()

        # Backup retained.
        assert p.with_suffix(p.suffix + ".pre-encryption.bak").is_file()
        assert any("Encrypting" in n for n in notices)

    def test_clientdb_no_migration_on_encrypted(self, tmp_path: Path):
        p = tmp_path / "tui.db"
        # First open with key → encrypted from scratch.
        db = ClientDB(p, KEY)
        try:
            db.set_setting("k", "v")
        finally:
            db.close()

        # Reopen — should NOT trigger migration (no .bak created).
        notices = []
        db2 = ClientDB(p, KEY, notice=notices.append)
        try:
            assert db2.get_setting("k") == "v"
        finally:
            db2.close()
        assert not p.with_suffix(p.suffix + ".pre-encryption.bak").is_file()
