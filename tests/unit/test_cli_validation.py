# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for CLI input validation and display fixes."""

import asyncio

try:
    import tomllib
except ImportError:
    import tomli as tomllib

import pytest
from click.testing import CliRunner

from hokora.cli.channel import channel_group
from hokora.cli.role import role_group
from hokora.config import NodeConfig
from hokora.db.engine import create_db_engine, create_session_factory, init_db
from hokora.security.roles import RoleManager


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def cli_config(tmp_dir, monkeypatch):
    """Set up a temporary config and DB for CLI tests."""
    db_path = tmp_dir / "hokora.db"
    (tmp_dir / "identities").mkdir(parents=True, exist_ok=True)
    (tmp_dir / "media").mkdir(parents=True, exist_ok=True)

    config_path = tmp_dir / "hokora.toml"
    config_path.write_text(
        f'node_name = "CLI Test Node"\ndata_dir = "{tmp_dir}"\ndb_encrypt = false\n'
    )
    monkeypatch.setenv("HOKORA_CONFIG", str(config_path))

    config = NodeConfig(
        node_name="CLI Test Node",
        data_dir=tmp_dir,
        db_encrypt=False,
    )

    async def _init():
        engine = create_db_engine(db_path)
        await init_db(engine)
        sf = create_session_factory(engine)
        async with sf() as session:
            async with session.begin():
                mgr = RoleManager()
                await mgr.ensure_builtin_roles(session)
        await engine.dispose()

    asyncio.run(_init())
    return config


# --- Fix 1: TOML injection via node name ---


class TestWriteConfigEscaping:
    def test_write_config_escapes_quotes(self, tmp_dir):
        from hokora.cli.init import _write_config

        config = NodeConfig(
            node_name='Test "Quoted" Node',
            data_dir=tmp_dir,
            db_encrypt=False,
        )
        config_path = tmp_dir / "test_config.toml"
        _write_config(config_path, config)

        # Should produce valid TOML
        with open(config_path, "rb") as f:
            parsed = tomllib.load(f)
        assert parsed["node_name"] == 'Test "Quoted" Node'

    def test_write_config_escapes_backslash(self, tmp_dir):
        from hokora.cli.init import _write_config

        config = NodeConfig(
            node_name="Test\\Backslash\\Node",
            data_dir=tmp_dir,
            db_encrypt=False,
        )
        config_path = tmp_dir / "test_config.toml"
        _write_config(config_path, config)

        with open(config_path, "rb") as f:
            parsed = tomllib.load(f)
        assert parsed["node_name"] == "Test\\Backslash\\Node"


# --- Fix 2: Empty / too-long channel name ---


class TestChannelNameValidation:
    def test_channel_create_rejects_empty_name(self, runner, cli_config):
        result = runner.invoke(channel_group, ["create", ""])
        assert result.exit_code == 0
        assert "empty" in result.output.lower()

    def test_channel_create_rejects_long_name(self, runner, cli_config):
        long_name = "a" * 100
        result = runner.invoke(channel_group, ["create", long_name])
        assert result.exit_code == 0
        assert "exceeds" in result.output.lower() or "64" in result.output


# --- Fix 3: channel info shows sealed and slowmode ---


class TestChannelInfoDisplay:
    def test_channel_info_shows_sealed(self, runner, cli_config):
        result = runner.invoke(channel_group, ["create", "sealed-ch", "--sealed"])
        assert result.exit_code == 0
        ch_id = result.output.split("(")[1].split(")")[0]

        result = runner.invoke(channel_group, ["info", ch_id])
        assert result.exit_code == 0
        assert "Sealed:" in result.output
        assert "yes" in result.output

    def test_channel_info_shows_slowmode(self, runner, cli_config):
        result = runner.invoke(channel_group, ["create", "slow-ch"])
        assert result.exit_code == 0
        ch_id = result.output.split("(")[1].split(")")[0]

        # Set slowmode via edit
        runner.invoke(channel_group, ["edit", ch_id, "--slowmode", "30"])

        result = runner.invoke(channel_group, ["info", ch_id])
        assert result.exit_code == 0
        assert "Slowmode:" in result.output
        assert "30s" in result.output


# --- Fix 4: Duplicate role name ---


class TestRoleDuplicate:
    def test_role_create_duplicate_name_friendly_error(self, runner, cli_config):
        result = runner.invoke(role_group, ["create", "moderator", "-p", "255"])
        assert result.exit_code == 0
        assert "moderator" in result.output

        result = runner.invoke(role_group, ["create", "moderator", "-p", "1"])
        assert result.exit_code == 0
        assert "already exists" in result.output


# --- Fix 5: Negative permissions ---


class TestNegativePermissions:
    def test_role_create_rejects_negative_permissions(self, runner, cli_config):
        result = runner.invoke(role_group, ["create", "bad", "-p", "-1"])
        assert result.exit_code == 0
        assert "non-negative" in result.output
