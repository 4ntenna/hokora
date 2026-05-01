# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for ``PidFile``."""

import os

import pytest

from hokora.core.pid_file import PidFile


@pytest.fixture
def pid_path(tmp_dir):
    return tmp_dir / "hokorad.pid"


class TestWrite:
    def test_write_creates_file(self, pid_path):
        pf = PidFile(pid_path)
        pf.write(12345)
        assert pid_path.exists()
        assert pid_path.read_text().strip() == "12345"

    def test_write_defaults_to_current_pid(self, pid_path):
        pf = PidFile(pid_path)
        pf.write()
        assert int(pid_path.read_text().strip()) == os.getpid()

    def test_write_sets_0o600_perms(self, pid_path):
        pf = PidFile(pid_path)
        pf.write(42)
        mode = pid_path.stat().st_mode & 0o777
        assert mode == 0o600

    def test_write_is_atomic_via_tmp_rename(self, pid_path, monkeypatch):
        captured = {}

        real_replace = os.replace

        def spy_replace(src, dst):
            captured["src"] = src
            captured["dst"] = dst
            return real_replace(src, dst)

        monkeypatch.setattr("hokora.core.pid_file.os.replace", spy_replace)

        pf = PidFile(pid_path)
        pf.write(7)

        assert captured["src"].endswith(".tmp")
        assert captured["dst"] == str(pid_path)

    def test_write_tolerates_oserror(self, pid_path, monkeypatch):
        def boom(*_a, **_kw):
            raise OSError("disk full")

        monkeypatch.setattr("hokora.core.pid_file.os.open", boom)
        pf = PidFile(pid_path)
        pf.write(99)  # should not raise


class TestRemove:
    def test_remove_deletes_file(self, pid_path):
        pid_path.write_text("12345")
        pf = PidFile(pid_path)
        pf.remove()
        assert not pid_path.exists()

    def test_remove_is_idempotent_when_missing(self, pid_path):
        pf = PidFile(pid_path)
        pf.remove()  # no-op, no raise
        pf.remove()


class TestRead:
    def test_read_returns_pid(self, pid_path):
        pid_path.write_text("4242\n")
        pf = PidFile(pid_path)
        assert pf.read() == 4242

    def test_read_returns_none_when_missing(self, pid_path):
        pf = PidFile(pid_path)
        assert pf.read() is None

    def test_read_returns_none_when_invalid(self, pid_path):
        pid_path.write_text("not-a-number")
        pf = PidFile(pid_path)
        assert pf.read() is None


class TestIsStale:
    def test_is_stale_when_missing(self, pid_path):
        pf = PidFile(pid_path)
        assert pf.is_stale() is True

    def test_is_stale_when_pid_nonexistent(self, pid_path):
        pid_path.write_text("999999")  # Linux pid_max default is 32768
        pf = PidFile(pid_path)
        assert pf.is_stale() is True

    def test_is_not_stale_for_current_process(self, pid_path):
        pid_path.write_text(str(os.getpid()))
        pf = PidFile(pid_path)
        assert pf.is_stale() is False
