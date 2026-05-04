# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Identity-file permission tests.

Covers src/hokora/security/fs.py helpers and the 0o600 guarantee on
every path that writes an RNS.Identity to disk.
"""

import os
import stat
from unittest.mock import MagicMock

import pytest

from hokora.security.fs import (
    secure_existing_file,
    secure_identity_dir,
    write_identity_secure,
)


@pytest.fixture
def fake_identity():
    """Fake RNS.Identity that writes 80 bytes of deterministic data via to_file."""
    ident = MagicMock()

    def _to_file(path):
        with open(path, "wb") as f:
            f.write(b"\x00" * 80)

    ident.to_file.side_effect = _to_file
    ident.hexhash = "a" * 32
    return ident


class TestWriteIdentitySecure:
    def test_fresh_write_is_0o600(self, tmp_path, fake_identity):
        path = tmp_path / "ids" / "node_identity"
        write_identity_secure(fake_identity, path)
        assert path.exists()
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    def test_creates_parent_dir(self, tmp_path, fake_identity):
        path = tmp_path / "missing" / "ids" / "node_identity"
        write_identity_secure(fake_identity, path)
        assert path.exists()

    def test_atomic_rename_leaves_no_tmp(self, tmp_path, fake_identity):
        path = tmp_path / "node_identity"
        write_identity_secure(fake_identity, path)
        leftovers = [p for p in tmp_path.iterdir() if p.name.endswith(".tmp")]
        assert leftovers == []

    def test_overwrites_existing_with_0o600(self, tmp_path, fake_identity):
        path = tmp_path / "node_identity"
        path.write_bytes(b"old")
        os.chmod(path, 0o644)
        write_identity_secure(fake_identity, path)
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        # Content has been replaced (to_file wrote 80 null bytes)
        assert path.read_bytes() == b"\x00" * 80

    def test_stale_tmp_is_cleaned(self, tmp_path, fake_identity):
        """If a crash left a .tmp file, write_identity_secure removes it first."""
        path = tmp_path / "node_identity"
        stale = path.with_suffix(path.suffix + ".tmp")
        stale.write_bytes(b"stale")
        write_identity_secure(fake_identity, path)
        assert not stale.exists()
        assert path.exists()
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


class TestSecureIdentityDir:
    def test_dir_becomes_0o700(self, tmp_path):
        d = tmp_path / "identities"
        secure_identity_dir(d)
        assert stat.S_IMODE(d.stat().st_mode) == 0o700

    def test_migrates_0o644_file_to_0o600(self, tmp_path):
        d = tmp_path / "identities"
        d.mkdir()
        file = d / "node_identity"
        file.write_bytes(b"key")
        os.chmod(file, 0o644)
        secure_identity_dir(d)
        assert stat.S_IMODE(file.stat().st_mode) == 0o600

    def test_idempotent(self, tmp_path):
        d = tmp_path / "identities"
        d.mkdir()
        file = d / "channel_abc"
        file.write_bytes(b"key")
        secure_identity_dir(d)
        first = stat.S_IMODE(file.stat().st_mode)
        secure_identity_dir(d)
        second = stat.S_IMODE(file.stat().st_mode)
        assert first == second == 0o600

    def test_skips_symlinks(self, tmp_path):
        """Symlinks should be skipped to avoid chmodding targets outside the dir."""
        target = tmp_path / "outside_target"
        target.write_bytes(b"data")
        os.chmod(target, 0o644)
        d = tmp_path / "identities"
        d.mkdir()
        (d / "evil_symlink").symlink_to(target)
        secure_identity_dir(d)
        # The real file outside identity_dir must NOT have been chmodded
        assert stat.S_IMODE(target.stat().st_mode) == 0o644

    def test_creates_missing_dir(self, tmp_path):
        d = tmp_path / "does_not_exist_yet"
        secure_identity_dir(d)
        assert d.exists()
        assert stat.S_IMODE(d.stat().st_mode) == 0o700

    def test_leaves_already_correct_files_untouched(self, tmp_path):
        """Files already at 0o600 should be idempotently left alone."""
        d = tmp_path / "identities"
        d.mkdir()
        file = d / "node_identity"
        file.write_bytes(b"key")
        os.chmod(file, 0o600)
        before_mtime = file.stat().st_mtime
        secure_identity_dir(d)
        assert stat.S_IMODE(file.stat().st_mode) == 0o600
        # mtime shouldn't change since we don't rewrite
        assert file.stat().st_mtime == before_mtime


class TestSecureExistingFile:
    def test_chmods_to_0o600(self, tmp_path):
        f = tmp_path / "file"
        f.write_bytes(b"x")
        os.chmod(f, 0o644)
        secure_existing_file(f, 0o600)
        assert stat.S_IMODE(f.stat().st_mode) == 0o600

    def test_missing_file_tolerated(self, tmp_path):
        # Should not raise
        secure_existing_file(tmp_path / "nope")

    def test_symlink_skipped(self, tmp_path):
        target = tmp_path / "real"
        target.write_bytes(b"x")
        os.chmod(target, 0o644)
        link = tmp_path / "link"
        link.symlink_to(target)
        secure_existing_file(link, 0o600)
        # Real target's perms stay at 0o644
        assert stat.S_IMODE(target.stat().st_mode) == 0o644


class TestIdentityManagerIntegration:
    """Verify IdentityManager routes writes through the secure helper."""

    def test_new_node_identity_is_0o600(self, tmp_path, monkeypatch):
        from hokora.core import identity as identity_mod

        fake_ident = MagicMock()

        def _to_file(path):
            with open(path, "wb") as f:
                f.write(b"\x00" * 80)

        fake_ident.to_file.side_effect = _to_file
        fake_ident.hexhash = "b" * 32

        mock_rns = MagicMock()
        mock_rns.Identity.return_value = fake_ident
        mock_rns.Identity.from_file.return_value = fake_ident
        monkeypatch.setattr(identity_mod, "RNS", mock_rns)

        ident_dir = tmp_path / "identities"
        mgr = identity_mod.IdentityManager(ident_dir, MagicMock())
        mgr.get_or_create_node_identity()

        path = ident_dir / "node_identity"
        assert path.exists()
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(ident_dir.stat().st_mode) == 0o700

    def test_existing_loose_file_migrated_on_init(self, tmp_path, monkeypatch):
        """Simulate a legacy deployment: existing identity file is 0o644 on disk.
        IdentityManager.__init__ should chmod it to 0o600 via secure_identity_dir."""
        from hokora.core import identity as identity_mod

        ident_dir = tmp_path / "identities"
        ident_dir.mkdir()
        legacy = ident_dir / "node_identity"
        legacy.write_bytes(b"legacy-key")
        os.chmod(legacy, 0o644)

        mock_rns = MagicMock()
        monkeypatch.setattr(identity_mod, "RNS", mock_rns)

        identity_mod.IdentityManager(ident_dir, MagicMock())

        assert stat.S_IMODE(legacy.stat().st_mode) == 0o600
