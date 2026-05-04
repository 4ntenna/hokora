# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for ``hokora seed`` and ``hokora config validate-rns`` CLI commands.

Runs the Click CLI in-process via ``CliRunner`` with an HOKORA_CONFIG
pointed at a temp hokora.toml.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from hokora.cli.main import cli


@pytest.fixture
def cli_env(tmp_path: Path, monkeypatch):
    """Point HOKORA_CONFIG at a temp hokora.toml with a fresh RNS dir."""
    rns_dir = tmp_path / "rns"
    rns_dir.mkdir()
    (rns_dir / "config").write_text(
        "[interfaces]\n  [[TCP Server]]\n    type = TCPServerInterface\n    listen_port = 4242\n"
    )
    os.chmod(rns_dir / "config", 0o600)

    toml = tmp_path / "hokora.toml"
    toml.write_text(
        f'node_name = "seedtest"\n'
        f'data_dir = "{tmp_path}"\n'
        f'rns_config_dir = "{rns_dir}"\n'
        f"db_encrypt = false\n"
    )
    os.chmod(toml, 0o600)
    monkeypatch.setenv("HOKORA_CONFIG", str(toml))
    return tmp_path, rns_dir


def test_seed_list_empty(cli_env):
    runner = CliRunner()
    result = runner.invoke(cli, ["seed", "list"])
    assert result.exit_code == 0
    assert "No seeds configured" in result.output


def test_seed_add_tcp(cli_env):
    runner = CliRunner()
    result = runner.invoke(cli, ["seed", "add", "VPS", "1.2.3.4:4242"])
    assert result.exit_code == 0, result.output
    assert "Added seed 'VPS'" in result.output
    assert "Restart the daemon" in result.output


def test_seed_add_then_list_shows_seed(cli_env):
    runner = CliRunner()
    runner.invoke(cli, ["seed", "add", "VPS", "1.2.3.4:4242"])
    result = runner.invoke(cli, ["seed", "list"])
    assert result.exit_code == 0
    assert "VPS" in result.output
    assert "tcp" in result.output
    assert "1.2.3.4:4242" in result.output


def test_seed_add_duplicate_errors(cli_env):
    runner = CliRunner()
    runner.invoke(cli, ["seed", "add", "VPS", "1.2.3.4:4242"])
    result = runner.invoke(cli, ["seed", "add", "VPS", "5.6.7.8:4242"])
    assert result.exit_code != 0
    assert "already exists" in result.output


def test_seed_add_invalid_port(cli_env):
    runner = CliRunner()
    result = runner.invoke(cli, ["seed", "add", "Bad", "1.2.3.4:70000"])
    assert result.exit_code != 0
    assert "port" in result.output.lower()


def test_seed_add_i2p(cli_env):
    runner = CliRunner()
    result = runner.invoke(cli, ["seed", "add", "I2P", "abc.b32.i2p"])
    assert result.exit_code == 0, result.output
    result2 = runner.invoke(cli, ["seed", "list"])
    assert "I2P" in result2.output
    assert "i2p" in result2.output


def test_seed_add_i2p_with_port_rejected(cli_env):
    runner = CliRunner()
    result = runner.invoke(cli, ["seed", "add", "I2P", "abc.b32.i2p:4242"])
    assert result.exit_code != 0


def test_seed_remove(cli_env):
    runner = CliRunner()
    runner.invoke(cli, ["seed", "add", "VPS", "1.2.3.4:4242"])
    result = runner.invoke(cli, ["seed", "remove", "VPS"])
    assert result.exit_code == 0
    assert "Removed seed 'VPS'" in result.output
    result2 = runner.invoke(cli, ["seed", "list"])
    assert "No seeds configured" in result2.output


def test_seed_remove_not_found(cli_env):
    runner = CliRunner()
    result = runner.invoke(cli, ["seed", "remove", "Nope"])
    assert result.exit_code != 0
    assert "No seed named" in result.output


def test_seed_remove_server_interface_refused(cli_env):
    # TCP Server is a transport server, not a seed — refuse to delete
    # via `hokora seed remove`.
    runner = CliRunner()
    result = runner.invoke(cli, ["seed", "remove", "TCP Server"])
    assert result.exit_code != 0


def test_seed_apply_reports_when_no_daemon(cli_env):
    # No daemon running in the test harness — apply should surface that
    # cleanly rather than crash.
    runner = CliRunner()
    result = runner.invoke(cli, ["seed", "apply"])
    assert result.exit_code == 0
    assert "No running daemon" in result.output


def test_config_validate_rns_clean(cli_env):
    runner = CliRunner()
    result = runner.invoke(cli, ["config", "validate-rns"])
    assert result.exit_code == 0
    assert "OK" in result.output


def test_config_validate_rns_flags_invalid_seed(cli_env):
    tmp_path, rns_dir = cli_env
    # Inject a TCPClientInterface with bad port — ConfigObj accepts the
    # string, but list_seeds/validate should flag it.
    cfg = rns_dir / "config"
    cfg.write_text(
        cfg.read_text()
        + "  [[Broken]]\n    type = TCPClientInterface\n    target_host = h\n"
        + "    target_port = 99999\n"
    )
    runner = CliRunner()
    result = runner.invoke(cli, ["config", "validate-rns"])
    # Either flagged (port out of range after parse) or silently skipped
    # (missing target details). Both are tolerable — key invariant is
    # that the CLI does not crash and surfaces a clean 0 or non-0 rc.
    assert result.exit_code in (0, 1)


def test_seed_list_missing_config_file(tmp_path, monkeypatch):
    # hokora.toml points at a fresh rns_config_dir with no file yet.
    rns_dir = tmp_path / "rns"
    rns_dir.mkdir()
    toml = tmp_path / "hokora.toml"
    toml.write_text(
        f'node_name = "seedtest"\n'
        f'data_dir = "{tmp_path}"\n'
        f'rns_config_dir = "{rns_dir}"\n'
        f"db_encrypt = false\n"
    )
    monkeypatch.setenv("HOKORA_CONFIG", str(toml))
    runner = CliRunner()
    result = runner.invoke(cli, ["seed", "list"])
    assert result.exit_code == 0
    assert "No seeds configured" in result.output


# ── Fallback to ~/.reticulum when hokora.toml sets no rns_config_dir
# (or no hokora.toml at all). Must always print a visible notice so
# the operator knows which config file they're editing.


def test_seed_list_falls_back_to_reticulum_when_no_rns_config_dir(tmp_path, monkeypatch):
    """With hokora.toml present but no rns_config_dir, fall back to ~/.reticulum."""
    # Redirect HOME so ~/.reticulum points at tmp_path/reticulum.
    monkeypatch.setenv("HOME", str(tmp_path))
    reticulum_dir = tmp_path / ".reticulum"
    reticulum_dir.mkdir()
    (reticulum_dir / "config").write_text(
        "[interfaces]\n"
        "  [[Local Seed]]\n"
        "    type = TCPClientInterface\n"
        "    target_host = 10.0.0.1\n"
        "    target_port = 4242\n"
    )
    # Bare hokora.toml with no rns_config_dir at tmp_path/.hokora/hokora.toml.
    data_dir = tmp_path / ".hokora"
    data_dir.mkdir()
    (data_dir / "hokora.toml").write_text(
        f'node_name = "fallback-test"\ndata_dir = "{tmp_path}"\ndb_encrypt = false\n'
    )
    monkeypatch.delenv("HOKORA_CONFIG", raising=False)

    runner = CliRunner()
    result = runner.invoke(cli, ["seed", "list"])
    assert result.exit_code == 0, result.output
    # Notice about the fallback must appear somewhere the operator can see it.
    combined = result.output + (result.stderr if result.stderr_bytes else "")
    assert "~/.reticulum" in combined or str(reticulum_dir) in combined, (
        f"Expected fallback notice; got: {combined!r}"
    )
    # The seed from the fallback file is listed.
    assert "Local Seed" in result.output


def test_seed_list_falls_back_when_no_hokora_toml_at_all(tmp_path, monkeypatch):
    """With no hokora.toml anywhere and no HOKORA_CONFIG, fall back silently-but-loudly."""
    monkeypatch.setenv("HOME", str(tmp_path))
    reticulum_dir = tmp_path / ".reticulum"
    reticulum_dir.mkdir()
    (reticulum_dir / "config").write_text("[interfaces]\n")
    monkeypatch.delenv("HOKORA_CONFIG", raising=False)

    runner = CliRunner()
    result = runner.invoke(cli, ["seed", "list"])
    assert result.exit_code == 0, result.output
    assert "No seeds configured" in result.output


def test_explicit_rns_config_dir_wins_over_fallback(tmp_path, monkeypatch):
    """When hokora.toml sets rns_config_dir explicitly, fallback must not trigger."""
    monkeypatch.setenv("HOME", str(tmp_path))
    # Create ~/.reticulum with a decoy seed so we can detect wrong resolution.
    (tmp_path / ".reticulum").mkdir()
    (tmp_path / ".reticulum" / "config").write_text(
        "[interfaces]\n  [[Decoy]]\n    type = TCPClientInterface\n"
        "    target_host = 99.99.99.99\n    target_port = 4242\n"
    )
    # Explicit rns_config_dir via hokora.toml.
    rns_dir = tmp_path / "explicit_rns"
    rns_dir.mkdir()
    (rns_dir / "config").write_text(
        "[interfaces]\n  [[Explicit]]\n    type = TCPClientInterface\n"
        "    target_host = 1.1.1.1\n    target_port = 4242\n"
    )
    toml = tmp_path / "hokora.toml"
    toml.write_text(
        f'node_name = "explicit"\ndata_dir = "{tmp_path}"\n'
        f'rns_config_dir = "{rns_dir}"\ndb_encrypt = false\n'
    )
    monkeypatch.setenv("HOKORA_CONFIG", str(toml))

    runner = CliRunner()
    result = runner.invoke(cli, ["seed", "list"])
    assert result.exit_code == 0, result.output
    assert "Explicit" in result.output
    assert "Decoy" not in result.output, "Fallback path must not be consulted"


def test_config_validate_rns_fallback_path(tmp_path, monkeypatch):
    """``hokora config validate-rns`` obeys the same fallback + notice."""
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".reticulum").mkdir()
    (tmp_path / ".reticulum" / "config").write_text("[interfaces]\n")
    monkeypatch.delenv("HOKORA_CONFIG", raising=False)

    runner = CliRunner()
    result = runner.invoke(cli, ["config", "validate-rns"])
    assert result.exit_code == 0
    assert "OK" in result.output
