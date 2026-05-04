# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for the shared SQLCipher key resolver at hokora.security.db_key."""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from hokora.security.db_key import (
    DB_KEY_BYTES,
    DB_KEY_PATTERN,
    ensure_db_key,
    resolve_db_key_from_path,
    validate_db_key_hex,
)


class TestValidateDbKeyHex:
    def test_accepts_64_lowercase_hex(self):
        key = "a" * 64
        assert validate_db_key_hex(key) == key

    def test_accepts_mixed_case_hex(self):
        key = "AbCdEf01" * 8
        assert validate_db_key_hex(key) == key

    def test_rejects_short(self):
        with pytest.raises(ValueError, match="64 hexadecimal"):
            validate_db_key_hex("a" * 63)

    def test_rejects_long(self):
        with pytest.raises(ValueError, match="64 hexadecimal"):
            validate_db_key_hex("a" * 65)

    def test_rejects_non_hex(self):
        with pytest.raises(ValueError, match="64 hexadecimal"):
            validate_db_key_hex("g" * 64)

    def test_source_appears_in_error(self):
        with pytest.raises(ValueError, match="custom_source"):
            validate_db_key_hex("zzz", source="custom_source")


class TestResolveFromPath:
    def test_reads_clean_file(self, tmp_path: Path):
        p = tmp_path / "db_key"
        key = "f" * 64
        p.write_text(key + "\n")
        os.chmod(str(p), 0o600)
        assert resolve_db_key_from_path(p) == key

    def test_strips_trailing_whitespace(self, tmp_path: Path):
        p = tmp_path / "db_key"
        key = "1" * 64
        p.write_text(f"  {key}  \n\n")
        os.chmod(str(p), 0o600)
        assert resolve_db_key_from_path(p) == key

    def test_missing_file_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError, match="db_keyfile points at"):
            resolve_db_key_from_path(tmp_path / "absent")

    def test_malformed_contents_raises(self, tmp_path: Path):
        p = tmp_path / "db_key"
        p.write_text("not-hex-at-all\n")
        os.chmod(str(p), 0o600)
        with pytest.raises(ValueError, match="64 hex characters"):
            resolve_db_key_from_path(p)

    def test_loose_perms_warn(self, tmp_path: Path, caplog):
        p = tmp_path / "db_key"
        p.write_text("a" * 64 + "\n")
        os.chmod(str(p), 0o644)
        with caplog.at_level("WARNING"):
            resolve_db_key_from_path(p)
        assert any("loose permissions" in rec.message for rec in caplog.records)


class TestEnsureDbKey:
    def test_first_run_generates_64_hex(self, tmp_path: Path):
        p = tmp_path / "db_key"
        key = ensure_db_key(p)
        assert DB_KEY_PATTERN.match(key)
        assert p.is_file()

    def test_first_run_writes_0o600(self, tmp_path: Path):
        p = tmp_path / "db_key"
        ensure_db_key(p)
        assert (p.stat().st_mode & 0o777) == 0o600

    def test_idempotent_returns_existing_key(self, tmp_path: Path):
        p = tmp_path / "db_key"
        first = ensure_db_key(p)
        second = ensure_db_key(p)
        assert first == second

    def test_second_call_does_not_overwrite(self, tmp_path: Path):
        p = tmp_path / "db_key"
        ensure_db_key(p)
        mtime_first = p.stat().st_mtime_ns
        # Second call must short-circuit through resolve, no rewrite.
        ensure_db_key(p)
        assert p.stat().st_mtime_ns == mtime_first


class TestConstants:
    def test_db_key_bytes_is_32(self):
        assert DB_KEY_BYTES == 32

    def test_pattern_is_64_hex(self):
        assert isinstance(DB_KEY_PATTERN, re.Pattern)
        assert DB_KEY_PATTERN.match("a" * 64)
        assert not DB_KEY_PATTERN.match("a" * 63)
