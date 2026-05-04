# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""``hokora db migrate-key`` CLI behaviour.

Covers the happy path, idempotency, refusal cases, and the .prev backup
contract used by every filesystem-gated mutation in the project.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from hokora.cli.db import db_group

VALID_KEY = "a" * 64


@pytest.fixture
def hokora_env(tmp_path, monkeypatch):
    """Point HOKORA_CONFIG at a tmp toml so the CLI doesn't touch ~/.hokora/."""
    toml = tmp_path / "hokora.toml"
    monkeypatch.setenv("HOKORA_CONFIG", str(toml))
    return tmp_path, toml


def _write_inline_toml(toml: Path, data_dir: Path, key: str = VALID_KEY) -> None:
    toml.write_text(
        f'node_name = "Test"\ndata_dir = "{data_dir}"\ndb_encrypt = true\ndb_key = "{key}"\n'
    )


def _write_relay_toml(toml: Path, data_dir: Path) -> None:
    toml.write_text(
        f'node_name = "Relay"\ndata_dir = "{data_dir}"\ndb_encrypt = false\nrelay_only = true\n'
    )


class TestMigrateKeyHappyPath:
    def test_writes_keyfile_at_default_path_with_0600(self, hokora_env):
        data_dir, toml = hokora_env
        _write_inline_toml(toml, data_dir)
        runner = CliRunner()
        result = runner.invoke(db_group, ["migrate-key"])
        assert result.exit_code == 0, result.output
        keyfile = data_dir / "db_key"
        assert keyfile.is_file()
        assert keyfile.read_text().strip() == VALID_KEY
        assert (keyfile.stat().st_mode & 0o777) == 0o600

    def test_writes_prev_backup(self, hokora_env):
        data_dir, toml = hokora_env
        _write_inline_toml(toml, data_dir)
        original = toml.read_text()
        runner = CliRunner()
        runner.invoke(db_group, ["migrate-key"])
        backup = toml.with_suffix(toml.suffix + ".prev")
        assert backup.is_file()
        assert backup.read_text() == original

    def test_replaces_inline_db_key_with_db_keyfile_line(self, hokora_env):
        data_dir, toml = hokora_env
        _write_inline_toml(toml, data_dir)
        runner = CliRunner()
        runner.invoke(db_group, ["migrate-key"])
        rewritten = toml.read_text()
        assert "db_key =" not in rewritten
        assert f'db_keyfile = "{data_dir / "db_key"}"' in rewritten

    def test_resolver_returns_same_key_after_migration(self, hokora_env):
        from hokora.config import load_config

        data_dir, toml = hokora_env
        _write_inline_toml(toml, data_dir)
        runner = CliRunner()
        runner.invoke(db_group, ["migrate-key"])
        cfg = load_config(toml)
        assert cfg.resolve_db_key() == VALID_KEY

    def test_explicit_to_file_path(self, hokora_env, tmp_path):
        data_dir, toml = hokora_env
        _write_inline_toml(toml, data_dir)
        custom = tmp_path / "custom_keys" / "the_key"
        # Parent directory does not exist — write_secure creates it.
        runner = CliRunner()
        result = runner.invoke(db_group, ["migrate-key", "--to-file", str(custom)])
        assert result.exit_code == 0, result.output
        assert custom.is_file()
        assert (custom.stat().st_mode & 0o777) == 0o600


class TestMigrateKeyRefusalCases:
    def test_already_migrated_is_noop(self, hokora_env):
        data_dir, toml = hokora_env
        _write_inline_toml(toml, data_dir)
        runner = CliRunner()
        runner.invoke(db_group, ["migrate-key"])
        result = runner.invoke(db_group, ["migrate-key"])
        assert result.exit_code == 0
        assert "Already migrated" in result.output

    def test_refuses_when_db_encrypt_disabled(self, hokora_env):
        data_dir, toml = hokora_env
        _write_relay_toml(toml, data_dir)
        runner = CliRunner()
        result = runner.invoke(db_group, ["migrate-key"])
        assert result.exit_code == 0
        assert "Refusing to migrate" in result.output
        assert "db_encrypt is false" in result.output
        assert not (data_dir / "db_key").exists()

    def test_refuses_when_target_keyfile_already_exists(self, hokora_env):
        data_dir, toml = hokora_env
        _write_inline_toml(toml, data_dir)
        existing = data_dir / "db_key"
        existing.write_text("pre-existing\n")
        os.chmod(existing, 0o600)
        runner = CliRunner()
        result = runner.invoke(db_group, ["migrate-key"])
        assert result.exit_code == 0
        assert "Refusing to overwrite" in result.output
        # Inline key untouched
        assert "db_key =" in toml.read_text()

    def test_refuses_when_no_inline_key_present(self, hokora_env, tmp_path):
        """If the operator already wrote a db_keyfile and no db_key line,
        migrate-key should be a no-op (already-migrated message)."""
        data_dir, toml = hokora_env
        keyfile = data_dir / "db_key"
        keyfile.parent.mkdir(parents=True, exist_ok=True)
        keyfile.write_text(VALID_KEY + "\n")
        os.chmod(keyfile, 0o600)
        toml.write_text(
            f'node_name = "Test"\n'
            f'data_dir = "{data_dir}"\n'
            f"db_encrypt = true\n"
            f'db_keyfile = "{keyfile}"\n'
        )
        runner = CliRunner()
        result = runner.invoke(db_group, ["migrate-key"])
        assert result.exit_code == 0
        assert "Already migrated" in result.output

    def test_missing_config_file(self, tmp_path, monkeypatch):
        nonexistent = tmp_path / "nope" / "hokora.toml"
        monkeypatch.setenv("HOKORA_CONFIG", str(nonexistent))
        runner = CliRunner()
        result = runner.invoke(db_group, ["migrate-key"])
        assert result.exit_code == 0
        assert "config not found" in result.output
