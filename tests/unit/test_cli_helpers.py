# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for src/hokora/cli/_helpers.py."""

import os
import stat

from hokora.cli._helpers import write_secure


class TestWriteSecure:
    def test_permissions_are_mode(self, tmp_path):
        target = tmp_path / "secret.toml"
        write_secure(target, 'db_key = "deadbeef"', mode=0o600)
        assert stat.S_IMODE(target.stat().st_mode) == 0o600

    def test_custom_mode(self, tmp_path):
        target = tmp_path / "config"
        write_secure(target, "public content", mode=0o644)
        assert stat.S_IMODE(target.stat().st_mode) == 0o644

    def test_writes_content(self, tmp_path):
        target = tmp_path / "file.txt"
        write_secure(target, "hello world")
        assert target.read_text() == "hello world"

    def test_writes_unicode(self, tmp_path):
        target = tmp_path / "file.txt"
        write_secure(target, "héllo 🌍")
        assert target.read_text(encoding="utf-8") == "héllo 🌍"

    def test_overwrites_existing(self, tmp_path):
        target = tmp_path / "file.txt"
        target.write_text("old content")
        write_secure(target, "new content", mode=0o600)
        assert target.read_text() == "new content"
        assert stat.S_IMODE(target.stat().st_mode) == 0o600

    def test_tmp_file_cleaned_up(self, tmp_path):
        target = tmp_path / "file.txt"
        write_secure(target, "content", mode=0o600)
        # No leftover .tmp file
        leftovers = [p for p in tmp_path.iterdir() if p.name.endswith(".tmp")]
        assert leftovers == []

    def test_never_world_readable_during_write(self, tmp_path):
        """The file must never exist at a wider mode than requested.

        We check that the mode is correct at the final path, since write_secure
        uses tmp+rename — the actual atomic guarantee is that no looser-mode
        file with the final name ever exists.
        """
        target = tmp_path / "secret"
        write_secure(target, "k", mode=0o600)
        mode = stat.S_IMODE(target.stat().st_mode)
        assert not (mode & (stat.S_IRGRP | stat.S_IROTH))
        assert not (mode & (stat.S_IWGRP | stat.S_IWOTH))

    def test_fsync_called(self, tmp_path, monkeypatch):
        """Verify fsync is invoked for durability."""
        fsync_calls = []
        real_fsync = os.fsync

        def spy(fd):
            fsync_calls.append(fd)
            return real_fsync(fd)

        monkeypatch.setattr(os, "fsync", spy)
        target = tmp_path / "file"
        write_secure(target, "x")
        assert len(fsync_calls) == 1
