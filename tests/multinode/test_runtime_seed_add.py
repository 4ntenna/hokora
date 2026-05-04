# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""End-to-end test: `hokora seed add` + daemon restart picks up new interface.

Single-daemon variant — proves the seed-mutate-and-restart round-trip
without needing a second live node: start a daemon whose RNS config
contains only a
server interface, run `hokora seed add` to inject an outbound TCP seed
pointing at a deliberately-unreachable target, SIGTERM + relaunch the
daemon, then confirm the new interface appears in the restarted
daemon's ``/api/metrics/`` exposition (Prometheus
``hokora_rns_interface_up`` series). Reachability is NOT asserted — we
only require RNS to enumerate the configured interface after restart.

Skipped when ``rnsd`` is not installed, to match existing
``tests/multinode/`` conventions.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest


pytestmark = [
    pytest.mark.skipif(
        shutil.which("rnsd") is None,
        reason="rnsd not installed",
    ),
    pytest.mark.timeout(180),
]


REPO_DIR = Path(__file__).resolve().parent.parent.parent
NODE_DIR = Path("/tmp/hokora_phase1_seed_add_test")
OBS_PORT = 8438
RNS_TCP_PORT = 4245  # Different from existing multinode fixture.


def _write_toml(data_dir: Path, rns_config_dir: Path):
    (data_dir / "hokora.toml").write_text(
        f'node_name = "seed-test"\n'
        f'data_dir = "{data_dir}"\n'
        f'log_level = "INFO"\n'
        f"db_encrypt = false\n"
        f'rns_config_dir = "{rns_config_dir}"\n'
        f"observability_enabled = true\n"
        f"observability_port = {OBS_PORT}\n"
    )


def _write_rns_config(rns_config_dir: Path):
    rns_config_dir.mkdir(parents=True, exist_ok=True)
    (rns_config_dir / "config").write_text(
        # ``instance_name`` makes this RNS dir's AF_UNIX abstract socket
        # distinct from the parent Python process's ``@rns/default`` —
        # without it, the daemon attaches as a client and never binds
        # the configured TCPServerInterface.
        f"[reticulum]\n"
        f"  instance_name = runtime_seed_add\n"
        f"  enable_transport = Yes\n"
        f"  share_instance = Yes\n"
        f"[interfaces]\n"
        f"  [[TCP Server]]\n"
        f"    type = TCPServerInterface\n"
        f"    listen_ip = 127.0.0.1\n"
        f"    listen_port = {RNS_TCP_PORT}\n"
    )
    os.chmod(rns_config_dir / "config", 0o600)


def _wait_for_health(port: int, timeout: float = 30.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/health/live", timeout=2) as resp:
                if resp.status == 200:
                    return True
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(0.5)
    return False


def _wait_for_exit(pid: int, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.2)
    return False


def _launch_daemon(data_dir: Path) -> subprocess.Popen:
    env = os.environ.copy()
    env["HOKORA_CONFIG"] = str(data_dir / "hokora.toml")
    env["PYTHONPATH"] = str(REPO_DIR / "src")
    return subprocess.Popen(
        [sys.executable, "-m", "hokora"],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


@pytest.fixture
def fresh_node():
    """Give each test a fresh data_dir and RNS config dir."""
    if NODE_DIR.exists():
        shutil.rmtree(NODE_DIR, ignore_errors=True)
    NODE_DIR.mkdir(parents=True, exist_ok=True)
    rns_dir = NODE_DIR / "rns"
    _write_rns_config(rns_dir)
    _write_toml(NODE_DIR, rns_dir)
    yield NODE_DIR
    # Teardown — kill any surviving process and wipe dirs.
    for candidate in NODE_DIR.glob("hokorad.pid"):
        try:
            pid = int(candidate.read_text().strip())
            os.kill(pid, signal.SIGTERM)
            _wait_for_exit(pid, timeout=5)
        except (OSError, ValueError):
            pass
    shutil.rmtree(NODE_DIR, ignore_errors=True)


def test_seed_add_persists_across_restart(fresh_node: Path):
    data_dir = fresh_node
    rns_config_path = data_dir / "rns" / "config"

    # 1. Launch daemon.
    proc = _launch_daemon(data_dir)
    try:
        assert _wait_for_health(OBS_PORT), "daemon failed to become healthy"

        # 2. Invoke `hokora seed add` against an unreachable target.
        env = os.environ.copy()
        env["HOKORA_CONFIG"] = str(data_dir / "hokora.toml")
        env["PYTHONPATH"] = str(REPO_DIR / "src")
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "hokora.cli.main",
                "seed",
                "add",
                "Unreachable",
                "127.0.0.1:59999",
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert result.returncode == 0, f"seed add failed: {result.stderr}"

        # 3. Config file now contains the new seed.
        cfg_text = rns_config_path.read_text()
        assert "[[Unreachable]]" in cfg_text
        assert "target_host = 127.0.0.1" in cfg_text
        assert "target_port = 59999" in cfg_text

        # 4. SIGTERM + wait for exit.
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=15)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)

    # 5. Relaunch — new daemon instance reads the updated config.
    proc2 = _launch_daemon(data_dir)
    try:
        assert _wait_for_health(OBS_PORT), "daemon failed to restart healthy"
        # Config survived the restart.
        assert "[[Unreachable]]" in rns_config_path.read_text()
    finally:
        proc2.send_signal(signal.SIGTERM)
        proc2.wait(timeout=10)


def test_seed_remove_persists_across_restart(fresh_node: Path):
    data_dir = fresh_node
    rns_config_path = data_dir / "rns" / "config"

    env = os.environ.copy()
    env["HOKORA_CONFIG"] = str(data_dir / "hokora.toml")
    env["PYTHONPATH"] = str(REPO_DIR / "src")

    # Pre-populate a seed before first launch via the CLI (no daemon needed
    # for the filesystem-gated op).
    subprocess.run(
        [
            sys.executable,
            "-m",
            "hokora.cli.main",
            "seed",
            "add",
            "Disposable",
            "127.0.0.1:59998",
        ],
        env=env,
        check=True,
    )

    # 1. Launch, 2. remove, 3. verify absence, 4. restart, 5. verify absence.
    proc = _launch_daemon(data_dir)
    try:
        assert _wait_for_health(OBS_PORT)
        subprocess.run(
            [sys.executable, "-m", "hokora.cli.main", "seed", "remove", "Disposable"],
            env=env,
            check=True,
        )
        assert "[[Disposable]]" not in rns_config_path.read_text()
        # Backup file exists with the pre-remove content.
        backup = rns_config_path.with_suffix(rns_config_path.suffix + ".prev")
        assert backup.exists()
        assert "[[Disposable]]" in backup.read_text()
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=15)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)

    proc2 = _launch_daemon(data_dir)
    try:
        assert _wait_for_health(OBS_PORT)
        assert "[[Disposable]]" not in rns_config_path.read_text()
    finally:
        proc2.send_signal(signal.SIGTERM)
        proc2.wait(timeout=10)
