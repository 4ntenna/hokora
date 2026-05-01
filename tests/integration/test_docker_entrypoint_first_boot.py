# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Pin secure defaults across the container's first-boot flow.

The container entrypoint runs ``hokora init`` and then trusts
``config.load_config``'s env-var overlay for runtime tuning. These tests
mirror the entrypoint's CLI invocation and assert that the resulting
``hokora.toml`` carries the secure defaults — a future flip of any of
these values in ``NodeConfig`` must surface here, not in production.

Each test spawns ``hokora init`` in a subprocess (matching the
container flow and dodging the ``RNS.Reticulum`` singleton).
"""

from __future__ import annotations

import subprocess
import sys

from hokora.config import load_config


def _run_init(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "hokora.cli.main", "init", *args],
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_community_first_boot_carries_secure_defaults(tmp_path):
    """Mirrors the entrypoint's community-mode invocation."""
    result = _run_init(
        "--node-name",
        "TestNode",
        "--node-type",
        "community",
        "--data-dir",
        str(tmp_path),
        "--skip-luks-check",
        "--no-db-encrypt",
    )
    assert result.returncode == 0, result.stdout + result.stderr

    config = load_config(tmp_path / "hokora.toml")
    assert config.require_signed_federation is True
    assert config.federation_auto_trust is False
    assert config.fs_enabled is True
    assert config.cdsp_enabled is True


def test_relay_first_boot_carries_secure_defaults(tmp_path):
    """Mirrors the entrypoint's relay-mode invocation."""
    result = _run_init(
        "--node-name",
        "TestRelay",
        "--node-type",
        "relay",
        "--data-dir",
        str(tmp_path),
        "--skip-luks-check",
    )
    assert result.returncode == 0, result.stdout + result.stderr

    config = load_config(tmp_path / "hokora.toml")
    assert config.relay_only is True
    assert config.propagation_enabled is True
    assert config.require_signed_federation is True
    assert config.federation_auto_trust is False
