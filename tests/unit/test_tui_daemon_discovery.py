# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for the TUI's daemon-discovery helper in hokora_tui.app.

Pure-function tests — no urwid, no RNS, no network.
"""

import os

from hokora_tui.app import _discover_daemon_rns_config


def _write_toml(data_dir, rns_config_dir: str, db_encrypt: bool = False) -> None:
    """Write a minimal hokora.toml under data_dir pointing at the given rns dir."""
    data_dir.mkdir(parents=True, exist_ok=True)
    toml = data_dir / "hokora.toml"
    toml.write_text(
        f'node_name = "t"\n'
        f'data_dir = "{data_dir}"\n'
        f"db_encrypt = {'true' if db_encrypt else 'false'}\n"
        f'rns_config_dir = "{rns_config_dir}"\n'
    )


def _make_rns_dir(tmp_path, name: str = "rns") -> str:
    """Create a placeholder RNS config dir so load_config's path check passes."""
    rns_dir = tmp_path / name
    rns_dir.mkdir(parents=True, exist_ok=True)
    return str(rns_dir)


class TestDaemonDiscovery:
    def test_explicit_hokora_config_takes_precedence(self, tmp_path, monkeypatch):
        """Explicit HOKORA_CONFIG wins over PID-file discovery."""
        # Create a fake "running" daemon — it should be ignored.
        home = tmp_path / "home"
        home.mkdir()
        daemon_dir = home / ".hokora-community-new"
        rns_a = _make_rns_dir(tmp_path, "rns_a")
        _write_toml(daemon_dir, rns_a)
        (daemon_dir / "hokorad.pid").write_text("99999")  # treat as alive

        # Explicit config points elsewhere
        other_data = tmp_path / "explicit"
        rns_b = _make_rns_dir(tmp_path, "rns_b")
        _write_toml(other_data, rns_b)

        monkeypatch.setattr("pathlib.Path.home", lambda: home)
        result = _discover_daemon_rns_config(str(other_data / "hokora.toml"))
        assert result == rns_b

    def test_single_alive_daemon_returns_its_rns_dir(self, tmp_path, monkeypatch):
        home = tmp_path / "home"
        home.mkdir()
        daemon_dir = home / ".hokora-community-new"
        rns = _make_rns_dir(tmp_path)
        _write_toml(daemon_dir, rns)
        (daemon_dir / "hokorad.pid").write_text("12345")

        monkeypatch.setattr("pathlib.Path.home", lambda: home)
        result = _discover_daemon_rns_config(None, pid_alive=lambda pid: True)
        assert result == rns

    def test_stale_pid_is_skipped(self, tmp_path, monkeypatch):
        """Dead PID → not used, falls through to legacy/None."""
        home = tmp_path / "home"
        home.mkdir()
        daemon_dir = home / ".hokora-community-new"
        rns = _make_rns_dir(tmp_path)
        _write_toml(daemon_dir, rns)
        (daemon_dir / "hokorad.pid").write_text("1")

        monkeypatch.setattr("pathlib.Path.home", lambda: home)
        # pid_alive returns False for all PIDs
        result = _discover_daemon_rns_config(None, pid_alive=lambda pid: False)
        assert result is None

    def test_multiple_alive_daemons_picks_first_and_warns(self, tmp_path, monkeypatch, caplog):
        home = tmp_path / "home"
        home.mkdir()
        rns_a = _make_rns_dir(tmp_path, "rns_a")
        rns_b = _make_rns_dir(tmp_path, "rns_b")
        dir_a = home / ".hokora-a"
        dir_b = home / ".hokora-b"
        _write_toml(dir_a, rns_a)
        _write_toml(dir_b, rns_b)
        (dir_a / "hokorad.pid").write_text("1111")
        (dir_b / "hokorad.pid").write_text("2222")

        monkeypatch.setattr("pathlib.Path.home", lambda: home)
        import logging

        with caplog.at_level(logging.WARNING, logger="hokora_tui.app"):
            result = _discover_daemon_rns_config(None, pid_alive=lambda pid: True)
        # Glob is sorted alphabetically; .hokora-a wins.
        assert result == rns_a
        assert any("Multiple running daemons" in rec.message for rec in caplog.records)

    def test_no_daemon_no_legacy_returns_none(self, tmp_path, monkeypatch):
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setattr("pathlib.Path.home", lambda: home)
        assert _discover_daemon_rns_config(None, pid_alive=lambda pid: True) is None

    def test_no_pid_file_returns_none_even_if_hokora_toml_exists(self, tmp_path, monkeypatch):
        """Without a PID file, an orphan hokora.toml is NOT a discovery target.

        Previously a legacy scan list picked up old configs; that fallback was
        removed because the daemon itself now writes a PID file at startup,
        making PID-based discovery the single source of truth.
        """
        home = tmp_path / "home"
        home.mkdir()
        legacy_dir = home / ".hokora"
        rns = _make_rns_dir(tmp_path)
        _write_toml(legacy_dir, rns)
        # No hokorad.pid written — daemon not running.

        monkeypatch.setattr("pathlib.Path.home", lambda: home)
        assert _discover_daemon_rns_config(None, pid_alive=lambda pid: True) is None

    def test_corrupt_pid_file_skipped(self, tmp_path, monkeypatch):
        home = tmp_path / "home"
        home.mkdir()
        daemon_dir = home / ".hokora-community-new"
        rns = _make_rns_dir(tmp_path)
        _write_toml(daemon_dir, rns)
        (daemon_dir / "hokorad.pid").write_text("not-a-number")

        monkeypatch.setattr("pathlib.Path.home", lambda: home)
        result = _discover_daemon_rns_config(None, pid_alive=lambda pid: True)
        assert result is None

    def test_default_pid_alive_uses_os_kill(self, tmp_path, monkeypatch):
        """Without a custom pid_alive, the helper uses os.kill(pid, 0)."""
        home = tmp_path / "home"
        home.mkdir()
        daemon_dir = home / ".hokora-community-new"
        rns = _make_rns_dir(tmp_path)
        _write_toml(daemon_dir, rns)
        # Use our own PID — guaranteed alive.
        (daemon_dir / "hokorad.pid").write_text(str(os.getpid()))

        monkeypatch.setattr("pathlib.Path.home", lambda: home)
        result = _discover_daemon_rns_config(None)  # no pid_alive seam
        assert result == rns
