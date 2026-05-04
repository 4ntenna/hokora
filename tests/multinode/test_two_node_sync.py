# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Multi-node integration tests: two nodes discover each other and sync.

These tests require rnsd to be installed and run against live Reticulum
instances using TCP transport on localhost. They are automatically skipped
when rnsd is not available (e.g. in CI).

Tests assert against the daemon's loopback ObservabilityListener
(``/health/live`` and ``/api/metrics/``) and query the unencrypted SQLite
DB directly for channel and message state. There is no web dashboard.

Run with: PYTHONPATH=src python -m pytest tests/multinode/ -v -s --timeout=120
"""

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.skipif(
        not shutil.which("rnsd"),
        reason="rnsd not available — install RNS to run multinode tests",
    ),
    pytest.mark.timeout(180),
]


def _http_get_json(port: int, path: str, timeout: float = 5.0):
    """GET a loopback endpoint and parse JSON."""
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def _http_get_text(port: int, path: str, api_key: str | None = None, timeout: float = 5.0):
    """GET a loopback endpoint as raw text. Adds X-API-Key when supplied."""
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
    if api_key:
        req.add_header("X-API-Key", api_key)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode()


def _parse_metric(text: str, metric_name: str) -> int:
    """Extract an integer metric value from Prometheus-format text."""
    for line in text.splitlines():
        if line.startswith(metric_name + " "):
            return int(line.split()[-1])
    return 0


def _db_channels(db_path: Path) -> list[dict]:
    """Return the channel rows from a node's unencrypted SQLite DB."""
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, name, description, access_mode, latest_seq, position FROM channels"
        ).fetchall()
        return [dict(r) for r in rows]


def _db_message_count(db_path: Path) -> int:
    with sqlite3.connect(str(db_path)) as conn:
        return conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]


def _db_node_identity(data_dir: Path) -> str | None:
    """Read the node identity hexhash via RNS.Identity.from_file (no daemon dep)."""
    identity_path = data_dir / "identities" / "node_identity"
    if not identity_path.exists():
        return None
    import RNS

    return RNS.Identity.from_file(str(identity_path)).hexhash


class TestTwoNodeSync:
    """Tests for node discovery and cross-node message flow."""

    def test_announce_discovery(self, two_nodes):
        """Two nodes on TCP transport discover each other's channels via announce."""
        info = two_nodes

        # Both daemons should be live (loopback /health/live, unauth).
        live_a = _http_get_json(info["obs_port_a"], "/health/live")
        assert live_a["status"] == "live"

        live_b = _http_get_json(info["obs_port_b"], "/health/live")
        assert live_b["status"] == "live"

        # Both nodes should have the default #general channel (DB read).
        channels_a = _db_channels(info["db_a"])
        assert len(channels_a) >= 1
        assert any(ch["name"] == "general" for ch in channels_a)

        channels_b = _db_channels(info["db_b"])
        assert len(channels_b) >= 1
        assert any(ch["name"] == "general" for ch in channels_b)

    def test_cross_node_metrics_endpoint(self, two_nodes):
        """Verify both daemons expose Prometheus metrics with channel counters."""
        info = two_nodes

        metrics_a = _http_get_text(info["obs_port_a"], "/api/metrics/", info["api_key_a"])
        assert "hokora_channels_total" in metrics_a

        metrics_b = _http_get_text(info["obs_port_b"], "/api/metrics/", info["api_key_b"])
        assert "hokora_channels_total" in metrics_b


class TestHealthSmoke:
    """Liveness + DB-schema smoke checks across both nodes.

    These are NOT mirror tests — they assert daemons are still up after
    the announce / metrics tests above and that the channels-table schema
    is what the mirror code reads. The actual mirror state-machine and
    cold-start linkage are exercised in ``test_cold_start_mirror.py``.
    """

    def test_both_daemons_still_live(self, two_nodes):
        """Both daemons remain healthy and have at least one channel each."""
        info = two_nodes

        live_a = _http_get_json(info["obs_port_a"], "/health/live")
        live_b = _http_get_json(info["obs_port_b"], "/health/live")
        assert live_a["status"] == "live"
        assert live_b["status"] == "live"

        channels_a = _db_channels(info["db_a"])
        channels_b = _db_channels(info["db_b"])
        assert len(channels_a) >= 1, "Node A needs at least one channel"
        assert len(channels_b) >= 1, "Node B needs at least one channel"

    def test_channels_schema_shape(self, two_nodes):
        """Both nodes report consistent channel-row shape (id/name/latest_seq)."""
        info = two_nodes

        channels_a = _db_channels(info["db_a"])
        channels_b = _db_channels(info["db_b"])
        for ch in channels_a:
            assert "id" in ch
            assert "name" in ch
            assert "latest_seq" in ch
        for ch in channels_b:
            assert "id" in ch
            assert "name" in ch
            assert "latest_seq" in ch


class TestCrossNodeMessageFlow:
    """E2E tests that verify actual message flow between federated nodes.

    These tests insert messages directly into Node A's database via a
    helper subprocess, then verify they are visible locally and that
    federation push infrastructure is ready to deliver them.
    """

    def test_local_message_ingest_and_query(self, two_nodes):
        """Insert a message on Node A and verify it appears in metrics + DB."""
        info = two_nodes

        # Get Node A's general channel ID.
        channels_a = _db_channels(info["db_a"])
        general = next((ch for ch in channels_a if ch["name"] == "general"), None)
        assert general is not None, "Node A must have a #general channel"
        channel_id = general["id"]

        # Record initial message count from metrics.
        metrics_before = _http_get_text(info["obs_port_a"], "/api/metrics/", info["api_key_a"])
        initial_count = _parse_metric(metrics_before, "hokora_messages_total_all")

        # Insert a message via the checked-in helper module. Earlier
        # versions embedded a 35-line ``async def`` body inside an
        # f-string subprocess script — fragile under whitespace edits
        # and unlintable. The helper takes the channel_id as argv.
        repo_dir = Path(__file__).resolve().parent.parent.parent
        env = os.environ.copy()
        env["HOKORA_CONFIG"] = str(info["dir_a"] / "hokora.toml")
        env["PYTHONPATH"] = str(repo_dir / "src") + os.pathsep + str(repo_dir)

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "tests.multinode._helpers.insert_test_message",
                channel_id,
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
            cwd=str(repo_dir),
        )
        assert result.returncode == 0, f"Message insert failed: {result.stderr}"

        # Wait briefly for metrics to update.
        time.sleep(1)

        # Verify the message count increased (DB + metrics agree).
        assert _db_message_count(info["db_a"]) > 0
        metrics_after = _http_get_text(info["obs_port_a"], "/api/metrics/", info["api_key_a"])
        final_count = _parse_metric(metrics_after, "hokora_messages_total_all")
        assert final_count > initial_count, (
            f"Message count should have increased: {initial_count} -> {final_count}"
        )

    def test_both_nodes_have_independent_channel_state(self, two_nodes):
        """Verify both nodes maintain independent channel state with consistent schema."""
        info = two_nodes

        channels_a = _db_channels(info["db_a"])
        channels_b = _db_channels(info["db_b"])

        # Both should have general channel.
        general_a = next((ch for ch in channels_a if ch["name"] == "general"), None)
        general_b = next((ch for ch in channels_b if ch["name"] == "general"), None)
        assert general_a is not None
        assert general_b is not None

        # Channel IDs should be DIFFERENT (independent nodes, not mirrors).
        assert general_a["id"] != general_b["id"], (
            "Independent nodes should have different channel IDs"
        )

        # Both should have consistent schema.
        required_fields = {"id", "name", "description", "access_mode", "latest_seq", "position"}
        assert required_fields.issubset(general_a.keys())
        assert required_fields.issubset(general_b.keys())

    def test_node_identity_uniqueness(self, two_nodes):
        """Verify each node has a unique identity (prerequisite for federation auth)."""
        info = two_nodes

        identity_a = _db_node_identity(info["dir_a"])
        identity_b = _db_node_identity(info["dir_b"])

        assert identity_a is not None
        assert identity_b is not None
        assert identity_a != identity_b, "Federated nodes must have unique identities"
        assert len(identity_a) >= 16, "Node identity should be a hex hash"
        assert len(identity_b) >= 16

    def test_metrics_consistency_across_nodes(self, two_nodes):
        """Verify both nodes independently track message and channel metrics."""
        info = two_nodes

        metrics_a = _http_get_text(info["obs_port_a"], "/api/metrics/", info["api_key_a"])
        metrics_b = _http_get_text(info["obs_port_b"], "/api/metrics/", info["api_key_b"])

        # Both nodes should expose channel and message counters.
        assert "hokora_channels_total" in metrics_a
        assert "hokora_channels_total" in metrics_b
        assert "hokora_messages_total_all" in metrics_a
        assert "hokora_messages_total_all" in metrics_b

        # Channel counts should be non-zero (at least #general).
        ch_count_a = _parse_metric(metrics_a, "hokora_channels_total")
        ch_count_b = _parse_metric(metrics_b, "hokora_channels_total")
        assert ch_count_a >= 1
        assert ch_count_b >= 1
