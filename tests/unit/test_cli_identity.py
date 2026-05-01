# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Smoke tests for ``hokora identity`` (create / list / export / import).

Pin the security-sensitive contract: identity files written by the CLI
land at ``0o600`` mode + are valid RNS identities. Round-tripping
``create`` → ``export`` → ``import`` must produce the same hexhash.
"""

import os
import stat

import pytest
import RNS
from click.testing import CliRunner

from hokora.cli.identity import identity_group
from hokora.config import NodeConfig


@pytest.fixture
def runner():
    return CliRunner()


def _make_config(tmp_path):
    return NodeConfig(
        node_name="ident-test",
        data_dir=tmp_path,
        db_path=tmp_path / "test.db",
        identity_dir=tmp_path / "identities",
        db_encrypt=False,
    )


def test_create_writes_identity_at_0o600(runner, tmp_path, monkeypatch):
    cfg = _make_config(tmp_path)
    monkeypatch.setattr("hokora.cli.identity.load_config", lambda: cfg)

    result = runner.invoke(identity_group, ["create", "alice"])
    assert result.exit_code == 0
    assert "Created identity 'alice'" in result.output

    path = cfg.identity_dir / "custom_alice"
    assert path.is_file()
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600, f"identity file mode should be 0o600, got {oct(mode)}"


def test_create_refuses_duplicate(runner, tmp_path, monkeypatch):
    cfg = _make_config(tmp_path)
    monkeypatch.setattr("hokora.cli.identity.load_config", lambda: cfg)

    runner.invoke(identity_group, ["create", "bob"])
    result2 = runner.invoke(identity_group, ["create", "bob"])
    assert result2.exit_code == 0
    assert "already exists" in result2.output


def test_list_empty_directory(runner, tmp_path, monkeypatch):
    cfg = _make_config(tmp_path)
    monkeypatch.setattr("hokora.cli.identity.load_config", lambda: cfg)

    result = runner.invoke(identity_group, ["list"])
    assert result.exit_code == 0
    assert "No identities found" in result.output


def test_list_shows_created_identities(runner, tmp_path, monkeypatch):
    cfg = _make_config(tmp_path)
    monkeypatch.setattr("hokora.cli.identity.load_config", lambda: cfg)

    runner.invoke(identity_group, ["create", "carol"])
    result = runner.invoke(identity_group, ["list"])
    assert result.exit_code == 0
    assert "custom_carol" in result.output


def test_list_handles_invalid_identity_file(runner, tmp_path, monkeypatch):
    """A non-RNS file in the identity dir is reported as ``(invalid)``,
    not crashed-on."""
    cfg = _make_config(tmp_path)
    cfg.identity_dir.mkdir(parents=True, exist_ok=True)
    (cfg.identity_dir / "garbage").write_text("not an identity")
    monkeypatch.setattr("hokora.cli.identity.load_config", lambda: cfg)

    result = runner.invoke(identity_group, ["list"])
    assert result.exit_code == 0
    assert "garbage" in result.output
    assert "(invalid)" in result.output


def test_export_roundtrip_preserves_hexhash(runner, tmp_path, monkeypatch):
    """create → export → import yields the same identity hexhash."""
    cfg = _make_config(tmp_path)
    monkeypatch.setattr("hokora.cli.identity.load_config", lambda: cfg)

    create_result = runner.invoke(identity_group, ["create", "dave"])
    # Output: "Created identity 'dave': <hexhash>"
    original_hash = create_result.output.strip().rsplit(": ", 1)[-1]

    export_path = tmp_path / "dave.bin"
    export_result = runner.invoke(identity_group, ["export", "dave", str(export_path)])
    assert export_result.exit_code == 0
    assert export_path.exists()

    import_result = runner.invoke(identity_group, ["import", str(export_path), "dave_clone"])
    assert import_result.exit_code == 0
    assert original_hash in import_result.output


def test_export_missing_identity(runner, tmp_path, monkeypatch):
    cfg = _make_config(tmp_path)
    cfg.identity_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("hokora.cli.identity.load_config", lambda: cfg)

    result = runner.invoke(identity_group, ["export", "ghost", str(tmp_path / "out.bin")])
    assert result.exit_code == 0
    assert "not found" in result.output


def test_import_invalid_file_is_rolled_back(runner, tmp_path, monkeypatch):
    """A malformed identity file is detected post-copy and unlinked."""
    cfg = _make_config(tmp_path)
    monkeypatch.setattr("hokora.cli.identity.load_config", lambda: cfg)

    bad = tmp_path / "bad.bin"
    bad.write_text("definitely not an RNS identity")

    result = runner.invoke(identity_group, ["import", str(bad), "evil"])
    assert result.exit_code == 0
    assert "Failed to import" in result.output

    target = cfg.identity_dir / "custom_evil"
    assert not target.exists(), "invalid imported identity should have been removed"


def test_import_refuses_duplicate(runner, tmp_path, monkeypatch):
    cfg = _make_config(tmp_path)
    monkeypatch.setattr("hokora.cli.identity.load_config", lambda: cfg)

    runner.invoke(identity_group, ["create", "frank"])
    # Build a real identity file to import.
    src = tmp_path / "src_ident"
    RNS.Identity().to_file(str(src))

    result = runner.invoke(identity_group, ["import", str(src), "frank"])
    assert result.exit_code == 0
    assert "already exists" in result.output
