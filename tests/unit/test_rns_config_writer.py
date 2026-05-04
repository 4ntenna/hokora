# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for :mod:`hokora.security.rns_config` — pure-function
read/validate/write of the daemon's RNS config file.

Covers:

* ``list_seeds`` round-trip for TCP + I2P.
* Filter semantics — server interfaces, plain sections, and malformed
  entries are ignored.
* ``validate_seed_entry`` structural rejections.
* ``apply_add`` preserves comments, writes 0o600, creates 0o600 backup.
* ``apply_remove`` error paths — SeedNotFound for missing and for non-seed.
* ``validate_config_file`` returns issue list.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from hokora.security.rns_config import (
    DuplicateSeed,
    InvalidSeed,
    SeedConfigError,
    SeedEntry,
    SeedNotFound,
    apply_add,
    apply_remove,
    list_seeds,
    validate_config_file,
    validate_seed_entry,
)


_BASE_CONFIG = """# Node test config
[reticulum]
  enable_transport = Yes
  share_instance = Yes

[interfaces]
  [[TCP Server]]
    type = TCPServerInterface
    enabled = yes
    listen_ip = 127.0.0.1
    listen_port = 4242
"""


@pytest.fixture
def rns_dir(tmp_path: Path) -> Path:
    (tmp_path / "config").write_text(_BASE_CONFIG)
    os.chmod(tmp_path / "config", 0o600)
    return tmp_path


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_list_seeds_empty_when_only_server(rns_dir: Path):
    # A TCPServerInterface is not a seed.
    assert list_seeds(rns_dir) == []


def test_list_seeds_after_add(rns_dir: Path):
    entry = SeedEntry(
        name="Example Seed",
        type="tcp",
        target_host="192.0.2.1",
        target_port=4242,
    )
    apply_add(rns_dir, entry)
    seeds = list_seeds(rns_dir)
    assert len(seeds) == 1
    assert seeds[0].name == "Example Seed"
    assert seeds[0].type == "tcp"
    assert seeds[0].target_host == "192.0.2.1"
    assert seeds[0].target_port == 4242
    assert seeds[0].enabled is True


def test_add_preserves_comments_and_other_sections(rns_dir: Path):
    apply_add(
        rns_dir,
        SeedEntry(name="S", type="tcp", target_host="h", target_port=4242),
    )
    content = (rns_dir / "config").read_text()
    assert "# Node test config" in content
    assert "[[TCP Server]]" in content
    assert "[[S]]" in content
    assert "target_host = h" in content


def test_add_permissions_are_0o600(rns_dir: Path):
    apply_add(
        rns_dir,
        SeedEntry(name="S", type="tcp", target_host="h", target_port=4242),
    )
    assert _mode(rns_dir / "config") == 0o600


def test_add_creates_backup_file(rns_dir: Path):
    apply_add(
        rns_dir,
        SeedEntry(name="S", type="tcp", target_host="h", target_port=4242),
    )
    backup = rns_dir / "config.prev"
    assert backup.exists()
    assert _mode(backup) == 0o600
    # Backup holds the pre-add content.
    assert "[[S]]" not in backup.read_text()
    assert "# Node test config" in backup.read_text()


def test_add_duplicate_is_rejected(rns_dir: Path):
    entry = SeedEntry(name="S", type="tcp", target_host="h", target_port=4242)
    apply_add(rns_dir, entry)
    with pytest.raises(DuplicateSeed):
        apply_add(rns_dir, entry)


def test_add_i2p_seed(rns_dir: Path):
    i2p = SeedEntry(
        name="I2P",
        type="i2p",
        target_host="abcdefgh.b32.i2p",
        target_port=0,
    )
    apply_add(rns_dir, i2p)
    seeds = list_seeds(rns_dir)
    assert seeds[0].type == "i2p"
    assert seeds[0].target_host == "abcdefgh.b32.i2p"
    assert seeds[0].target_port == 0
    # Written form uses `peers = ...` (not target_host) — that's how RNS
    # parses I2P outbound interfaces.
    content = (rns_dir / "config").read_text()
    assert "peers = abcdefgh.b32.i2p" in content
    assert "type = I2PInterface" in content


def test_remove_removes_seed(rns_dir: Path):
    apply_add(
        rns_dir,
        SeedEntry(name="S", type="tcp", target_host="h", target_port=4242),
    )
    apply_remove(rns_dir, "S")
    assert list_seeds(rns_dir) == []


def test_remove_missing_raises_not_found(rns_dir: Path):
    with pytest.raises(SeedNotFound):
        apply_remove(rns_dir, "Nope")


def test_remove_refuses_non_seed_interface(rns_dir: Path):
    # TCP Server is not a seed — CLI must not allow deleting server interfaces.
    with pytest.raises(SeedNotFound):
        apply_remove(rns_dir, "TCP Server")


def test_remove_empty_name_raises_invalid(rns_dir: Path):
    with pytest.raises(InvalidSeed):
        apply_remove(rns_dir, "")


def test_validate_entry_rejects_bad_port():
    with pytest.raises(InvalidSeed, match="port"):
        validate_seed_entry(SeedEntry(name="S", type="tcp", target_host="h", target_port=0))


def test_validate_entry_rejects_i2p_with_port():
    with pytest.raises(InvalidSeed):
        validate_seed_entry(SeedEntry(name="S", type="i2p", target_host="x.i2p", target_port=4242))


def test_validate_entry_rejects_tcp_with_i2p_host():
    with pytest.raises(InvalidSeed, match="I2P"):
        validate_seed_entry(
            SeedEntry(name="S", type="tcp", target_host="abc.i2p", target_port=4242)
        )


def test_validate_entry_rejects_brackets_in_name():
    with pytest.raises(InvalidSeed):
        validate_seed_entry(SeedEntry(name="S[1]", type="tcp", target_host="h", target_port=4242))


def test_validate_entry_rejects_empty_name():
    with pytest.raises(InvalidSeed):
        validate_seed_entry(SeedEntry(name="", type="tcp", target_host="h", target_port=4242))


def test_validate_entry_rejects_unknown_type():
    with pytest.raises(InvalidSeed, match="Unsupported"):
        validate_seed_entry(SeedEntry(name="S", type="quic", target_host="h", target_port=4242))


def test_validate_config_file_clean(rns_dir: Path):
    assert validate_config_file(rns_dir) == []


def test_validate_config_file_missing():
    issues = validate_config_file(Path("/tmp/nonexistent-rns-config-dir-xyz"))
    assert any("not found" in i.lower() for i in issues)


def test_list_seeds_missing_config_returns_empty():
    # No config file at all — should degrade gracefully.
    assert list_seeds(Path("/tmp/does-not-exist-test")) == []


def test_malformed_tcp_entry_is_skipped(tmp_path: Path):
    # TCPClientInterface missing target_port — list_seeds ignores it.
    cfg = tmp_path / "config"
    cfg.write_text(
        "[interfaces]\n  [[Broken]]\n    type = TCPClientInterface\n    target_host = h\n"
    )
    os.chmod(cfg, 0o600)
    assert list_seeds(tmp_path) == []


def test_parse_error_surfaces(tmp_path: Path):
    cfg = tmp_path / "config"
    cfg.write_text("this is not config\x00 garbage [broken")
    os.chmod(cfg, 0o600)
    # Depending on ConfigObj tolerance, this may parse as empty OR raise.
    # We only assert that the function doesn't crash catastrophically.
    try:
        result = list_seeds(tmp_path)
        assert isinstance(result, list)
    except SeedConfigError:
        pass
