# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Subprocess-based two-node fixture for multinode integration tests.

Each node runs in its own subprocess with isolated RNS config to avoid
the ``RNS.Reticulum`` singleton problem. Nodes communicate via TCP
transport on localhost.

Tests assert against the daemon's loopback ObservabilityListener
(``/health/live``, ``/api/metrics/``) and query the unencrypted SQLite
DB directly for channel/status data — there is no web dashboard.

Hardening notes:

* RNS state isolation. Each session copies the committed ``tests/live/rns_*``
  templates into a scratch directory under ``tmp_path_factory`` so the
  committed config dirs never accumulate persisted storage. Earlier
  versions wrote ``storage/`` into the committed dirs, leaking path-table
  state into ``test_cold_start_mirror`` via its template-copy path.

* Fixture scope. ``scope="module"`` so the heavy two-daemon spin-up runs
  once per test file, not once per ``Test*`` class.

* rnsd readiness. Polls the TCP listen port instead of a fixed
  ``time.sleep(2)`` so slow CI workers do not flake.

* Subprocess output capture. Uses ``proc.communicate(timeout=...)``
  instead of ``proc.stdout.read()``: the latter only returns output
  from already-exited processes, so a hung daemon would yield an
  empty diagnostic.
"""

import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import urllib.error
import urllib.request

import pytest

REPO_DIR = Path(__file__).resolve().parent.parent.parent
RNS_A_TEMPLATE = REPO_DIR / "tests" / "live" / "rns_a"
RNS_B_TEMPLATE = REPO_DIR / "tests" / "live" / "rns_b"

# Daemon observability ports. Each daemon owns its own loopback
# listener; tests probe these for /health/live and /api/metrics/.
OBS_PORT_A = 8430
OBS_PORT_B = 8431
RNS_TCP_PORT = 4242


def _write_toml(data_dir: Path, node_name: str, rns_config_dir: Path, observability_port: int):
    """Write a minimal TOML config for a test node."""
    content = f'''node_name = "{node_name}"
data_dir = "{data_dir}"
log_level = "DEBUG"
db_encrypt = false
rns_config_dir = "{rns_config_dir}"
announce_interval = 10
rate_limit_tokens = 10
rate_limit_refill = 1.0
max_upload_bytes = 5242880
max_storage_bytes = 1073741824
retention_days = 0
enable_fts = true
observability_enabled = true
observability_port = {observability_port}
'''
    (data_dir / "hokora.toml").write_text(content)


def _wait_for_http(port: int, timeout: float = 30.0) -> bool:
    """Wait for the daemon's loopback /health/live endpoint to respond."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            req = urllib.request.Request(f"http://127.0.0.1:{port}/health/live")
            with urllib.request.urlopen(req, timeout=2) as resp:
                if resp.status in (200, 503):
                    return True
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(0.5)
    return False


def _wait_for_tcp(host: str, port: int, timeout: float = 10.0) -> bool:
    """Poll a TCP port until something is listening or the deadline passes.

    Used for rnsd readiness: rnsd doesn't expose a health endpoint, but
    its TCPServerInterface starts accepting connections almost
    immediately after launch.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            try:
                s.connect((host, port))
                return True
            except (OSError, socket.timeout):
                pass
        time.sleep(0.2)
    return False


def _kill_proc(proc: subprocess.Popen, timeout: float = 5.0):
    """Send SIGTERM, wait, then SIGKILL if needed."""
    if proc.poll() is not None:
        return
    try:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=timeout)
    except (subprocess.TimeoutExpired, ProcessLookupError):
        try:
            proc.kill()
            proc.wait(timeout=3)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            pass


def _capture_diagnostic(procs: list) -> str:
    """Collect any output from a subprocess. Uses ``communicate`` so a
    still-running process is not waited on indefinitely; on TimeoutExpired
    we kill and re-collect."""
    chunks = []
    for p in procs:
        try:
            out, _ = p.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            p.kill()
            try:
                out, _ = p.communicate(timeout=1)
            except subprocess.TimeoutExpired:
                continue
        if out:
            chunks.append(out.decode(errors="replace"))
    return "\n---\n".join(chunks)


def _prepare_rns_dir(template: Path, dest: Path, instance_name: str):
    """Copy an RNS config template to a scratch dir with empty storage.

    Rewrites ``instance_name`` to a unique value per scratch dir so the
    AF_UNIX abstract socket ``@rns/<instance_name>`` does not collide
    with any other RNS instance in the same pytest process.
    """
    import re

    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    cfg = (template / "config").read_text()
    if re.search(r"^\s*instance_name\s*=", cfg, re.MULTILINE):
        cfg = re.sub(
            r"^\s*instance_name\s*=.*$",
            f"  instance_name = {instance_name}",
            cfg,
            count=1,
            flags=re.MULTILINE,
        )
    else:
        cfg = cfg.replace(
            "[reticulum]\n",
            f"[reticulum]\n  instance_name = {instance_name}\n",
            1,
        )
    (dest / "config").write_text(cfg)
    (dest / "storage").mkdir(exist_ok=True)


@pytest.fixture(scope="module")
def two_nodes(tmp_path_factory):
    """Start two Hokora nodes connected via RNS TCP transport.

    Yields a dict with connection details for both nodes.
    Tears down all processes on exit.
    """
    procs: list[subprocess.Popen] = []

    # Per-session scratch dirs, never overlapping the committed templates.
    session_root = tmp_path_factory.mktemp("multinode")
    node_a_dir = session_root / "node_a"
    node_b_dir = session_root / "node_b"
    rns_a_dir = session_root / "rns_a"
    rns_b_dir = session_root / "rns_b"

    # --- Init both nodes via subprocess ---
    for node_dir, node_name in ((node_a_dir, "TestNodeA"), (node_b_dir, "TestNodeB")):
        env = os.environ.copy()
        env["HOKORA_DATA_DIR"] = str(node_dir)
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "hokora.cli.main",
                "init",
                "--node-name",
                node_name,
                "--node-type",
                "community",
                "--data-dir",
                str(node_dir),
                "--no-db-encrypt",
                "--skip-luks-check",
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(REPO_DIR),
        )
        if result.returncode != 0:
            pytest.fail(f"hokora init failed for {node_name}: {result.stderr}\n{result.stdout}")

    # Per-node RNS dirs copied from the committed templates (so the
    # committed dirs stay clean; storage/ stays empty per session).
    _prepare_rns_dir(RNS_A_TEMPLATE, rns_a_dir, instance_name="multinode_a")
    _prepare_rns_dir(RNS_B_TEMPLATE, rns_b_dir, instance_name="multinode_b")

    # Overwrite TOML configs with our custom ones.
    _write_toml(node_a_dir, "TestNodeA", rns_a_dir, OBS_PORT_A)
    _write_toml(node_b_dir, "TestNodeB", rns_b_dir, OBS_PORT_B)

    # --- Start RNS instances ---
    env_base = os.environ.copy()
    env_base["PYTHONPATH"] = str(REPO_DIR / "src")

    rnsd_log_a = session_root / "rnsd_a.log"
    rnsd_log_b = session_root / "rnsd_b.log"
    # Hold file handles open for the lifetime of the fixture so they
    # don't GC before Popen's child has finished writing.
    log_handles = [rnsd_log_a.open("wb"), rnsd_log_b.open("wb")]
    for (rns_dir, _log_path), handle in zip(
        ((rns_a_dir, rnsd_log_a), (rns_b_dir, rnsd_log_b)), log_handles
    ):
        proc = subprocess.Popen(
            ["rnsd", "--config", str(rns_dir)],
            env=env_base,
            stdout=handle,
            stderr=subprocess.STDOUT,
        )
        procs.append(proc)

    # rnsd readiness: poll the TCP listen port instead of a fixed sleep.
    # 30s budget is generous — rnsd typically binds in <2s, but a busy
    # CI worker that just finished the integration suite can be slower.
    if not _wait_for_tcp("127.0.0.1", RNS_TCP_PORT, timeout=30):
        for p in procs:
            _kill_proc(p)
        for h in log_handles:
            h.close()
        rnsd_a_tail = rnsd_log_a.read_text(errors="replace")[-2000:] if rnsd_log_a.exists() else ""
        rnsd_b_tail = rnsd_log_b.read_text(errors="replace")[-2000:] if rnsd_log_b.exists() else ""
        pytest.fail(
            f"rnsd did not bind 127.0.0.1:{RNS_TCP_PORT} within 30s.\n"
            f"--- rnsd_a ---\n{rnsd_a_tail}\n--- rnsd_b ---\n{rnsd_b_tail}"
        )

    # --- Start daemons ---
    for node_dir in (node_a_dir, node_b_dir):
        env = env_base.copy()
        env["HOKORA_CONFIG"] = str(node_dir / "hokora.toml")
        proc = subprocess.Popen(
            [sys.executable, "-m", "hokora"],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=str(REPO_DIR),
        )
        procs.append(proc)

    # Wait for both daemons' observability listeners to come up.
    for port in (OBS_PORT_A, OBS_PORT_B):
        if not _wait_for_http(port, timeout=30):
            diagnostic = _capture_diagnostic(procs)
            for p in procs:
                _kill_proc(p)
            pytest.fail(
                f"Daemon observability listener on port {port} did not start within 30s.\n"
                + diagnostic
            )

    # API key for /api/metrics/. ``hokora init`` writes one at 0o600.
    api_key_a = (node_a_dir / "api_key").read_text().strip()
    api_key_b = (node_b_dir / "api_key").read_text().strip()

    yield {
        "dir_a": node_a_dir,
        "dir_b": node_b_dir,
        "db_a": node_a_dir / "hokora.db",
        "db_b": node_b_dir / "hokora.db",
        "obs_port_a": OBS_PORT_A,
        "obs_port_b": OBS_PORT_B,
        "api_key_a": api_key_a,
        "api_key_b": api_key_b,
    }

    # --- Teardown ---
    for proc in procs:
        _kill_proc(proc)
    for h in log_handles:
        h.close()
    # tmp_path_factory cleans the session dir automatically.
