# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for hokora.security.fs.secure_client_dir."""

from __future__ import annotations

import os
from pathlib import Path

from hokora.security.fs import secure_client_dir


def _mode(p: Path) -> int:
    return p.stat().st_mode & 0o777


def test_creates_dir_at_0o700(tmp_path: Path):
    target = tmp_path / "client"
    secure_client_dir(target)
    assert target.is_dir()
    assert _mode(target) == 0o700


def test_tightens_existing_dir(tmp_path: Path):
    target = tmp_path / "client"
    target.mkdir(mode=0o755)
    os.chmod(str(target), 0o755)
    secure_client_dir(target)
    assert _mode(target) == 0o700


def test_non_recursive_tightens_immediate_files(tmp_path: Path):
    target = tmp_path / "client"
    target.mkdir()
    f = target / "tui.db"
    f.write_text("data")
    os.chmod(str(f), 0o644)
    secure_client_dir(target)
    assert _mode(f) == 0o600


def test_non_recursive_does_not_descend(tmp_path: Path):
    target = tmp_path / "client"
    sub = target / "lxmf"
    sub.mkdir(parents=True)
    leaf = sub / "spool.dat"
    leaf.write_text("data")
    os.chmod(str(leaf), 0o644)
    os.chmod(str(sub), 0o755)
    secure_client_dir(target)
    # Direct child dir gets its mode set; deeper file untouched.
    assert _mode(sub) == 0o700
    assert _mode(leaf) == 0o644


def test_recursive_descends_into_subtree(tmp_path: Path):
    target = tmp_path / "client"
    sub = target / "lxmf" / "deep"
    sub.mkdir(parents=True)
    leaf = sub / "spool.dat"
    leaf.write_text("data")
    os.chmod(str(leaf), 0o644)
    os.chmod(str(sub), 0o755)
    secure_client_dir(target, recursive=True)
    assert _mode(sub) == 0o700
    assert _mode(leaf) == 0o600


def test_idempotent(tmp_path: Path):
    target = tmp_path / "client"
    secure_client_dir(target)
    f = target / "x"
    f.write_text("a")
    secure_client_dir(target)
    mode_first = _mode(target)
    secure_client_dir(target)
    assert _mode(target) == mode_first


def test_skips_symlinks(tmp_path: Path):
    target = tmp_path / "client"
    target.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("a")
    os.chmod(str(outside), 0o644)
    (target / "link").symlink_to(outside)
    secure_client_dir(target, recursive=True)
    # Outside file untouched — symlink not followed.
    assert _mode(outside) == 0o644
