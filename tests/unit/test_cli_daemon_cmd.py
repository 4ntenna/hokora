# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Smoke tests for ``hokora daemon`` (start / stop / status).

Operator-facing commands; the daemon-lifecycle integration suite covers
the actual subprocess fork. Here we pin:

* ``status``: no PID file → "not running"; corrupt PID file → cleanup;
  stale PID (process gone) → cleanup; live PID → "running".
* ``stop``: same PID-file path with SIGTERM via mocked ``os.kill``.
* ``start --foreground``: short-circuits into the in-process daemon
  entry, but we don't actually start one — patch the entry to a no-op
  and assert it was invoked.
"""

import signal
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from hokora.cli.daemon_cmd import daemon_group
from hokora.config import NodeConfig


@pytest.fixture
def runner():
    return CliRunner()


def _make_config(tmp_path):
    return NodeConfig(
        node_name="cmd-test",
        data_dir=tmp_path,
        db_path=tmp_path / "test.db",
        db_encrypt=False,
        relay_only=False,
    )


def test_status_no_pid_file(runner, tmp_path):
    cfg = _make_config(tmp_path)
    with patch("hokora.cli.daemon_cmd.load_config", return_value=cfg):
        result = runner.invoke(daemon_group, ["status"])
    assert result.exit_code == 0
    assert "not running" in result.output


def test_status_corrupt_pid_file(runner, tmp_path):
    """Non-numeric PID-file content → CLI removes file + reports."""
    cfg = _make_config(tmp_path)
    pid_file = tmp_path / "hokorad.pid"
    pid_file.write_text("not-a-pid\n")
    with patch("hokora.cli.daemon_cmd.load_config", return_value=cfg):
        result = runner.invoke(daemon_group, ["status"])
    assert result.exit_code == 0
    assert "corrupt PID" in result.output
    assert not pid_file.exists()


def test_status_stale_pid_cleans_up(runner, tmp_path):
    """PID exists but the process is gone → CLI removes the PID file."""
    cfg = _make_config(tmp_path)
    pid_file = tmp_path / "hokorad.pid"
    pid_file.write_text("999999\n")
    with patch("hokora.cli.daemon_cmd.load_config", return_value=cfg):
        with patch("hokora.cli.daemon_cmd.os.kill", side_effect=ProcessLookupError()):
            result = runner.invoke(daemon_group, ["status"])
    assert result.exit_code == 0
    assert "stale PID" in result.output
    assert not pid_file.exists()


def test_status_live_pid_reports_running(runner, tmp_path):
    """Live PID (os.kill(pid, 0) succeeds) → CLI reports running."""
    cfg = _make_config(tmp_path)
    pid_file = tmp_path / "hokorad.pid"
    pid_file.write_text("12345\n")
    with patch("hokora.cli.daemon_cmd.load_config", return_value=cfg):
        with patch("hokora.cli.daemon_cmd.os.kill"):
            result = runner.invoke(daemon_group, ["status"])
    assert result.exit_code == 0
    assert "running (PID: 12345)" in result.output
    # Live PID is preserved.
    assert pid_file.exists()


def test_stop_no_pid_file(runner, tmp_path):
    cfg = _make_config(tmp_path)
    with patch("hokora.cli.daemon_cmd.load_config", return_value=cfg):
        result = runner.invoke(daemon_group, ["stop"])
    assert result.exit_code == 0
    assert "No PID file found" in result.output


def test_stop_sigterm_then_unlink(runner, tmp_path):
    """Live PID → SIGTERM via os.kill + remove the PID file."""
    cfg = _make_config(tmp_path)
    pid_file = tmp_path / "hokorad.pid"
    pid_file.write_text("12345\n")
    with patch("hokora.cli.daemon_cmd.load_config", return_value=cfg):
        with patch("hokora.cli.daemon_cmd.os.kill") as mock_kill:
            result = runner.invoke(daemon_group, ["stop"])
    assert result.exit_code == 0
    mock_kill.assert_called_once_with(12345, signal.SIGTERM)
    assert "Sent SIGTERM" in result.output
    assert not pid_file.exists()


def test_stop_process_already_gone(runner, tmp_path):
    """ProcessLookupError on SIGTERM → CLI reports + cleans PID file."""
    cfg = _make_config(tmp_path)
    pid_file = tmp_path / "hokorad.pid"
    pid_file.write_text("999999\n")
    with patch("hokora.cli.daemon_cmd.load_config", return_value=cfg):
        with patch("hokora.cli.daemon_cmd.os.kill", side_effect=ProcessLookupError()):
            result = runner.invoke(daemon_group, ["stop"])
    assert result.exit_code == 0
    assert "not found" in result.output
    assert not pid_file.exists()


def test_start_foreground_invokes_in_process_entry(runner, tmp_path):
    """``--foreground`` short-circuits into ``hokora.__main__.main``."""
    cfg = _make_config(tmp_path)
    with patch("hokora.cli.daemon_cmd.load_config", return_value=cfg):
        with patch("hokora.__main__.main") as mock_main:
            result = runner.invoke(daemon_group, ["start", "--foreground"])
    assert result.exit_code == 0
    mock_main.assert_called_once()
    assert "foreground" in result.output


def test_start_aborts_when_existing_daemon_alive(runner, tmp_path):
    """``start`` (background) + live PID file → no fork, just report."""
    cfg = _make_config(tmp_path)
    pid_file = tmp_path / "hokorad.pid"
    pid_file.write_text("12345\n")
    with patch("hokora.cli.daemon_cmd.load_config", return_value=cfg):
        with patch("hokora.cli.daemon_cmd.os.kill"):
            with patch("hokora.cli.daemon_cmd.subprocess.Popen") as mock_popen:
                result = runner.invoke(daemon_group, ["start"])
    assert result.exit_code == 0
    assert "already running" in result.output
    mock_popen.assert_not_called()
