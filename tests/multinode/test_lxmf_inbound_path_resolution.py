# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Multi-node regression coverage for the LXMF inbound binding gate.

These tests assert that B's chokepoint is wired into a live daemon
without breaking startup or the metrics surface, and that the new
counter family is exposed alongside the existing federation binding
counters. The full SOURCE_UNKNOWN attack flow is exercised in the
unit + integration suites where RNS state can be mocked
deterministically.
"""

from __future__ import annotations

import json
import shutil
import urllib.request

import pytest

pytestmark = [
    pytest.mark.skipif(
        not shutil.which("rnsd"),
        reason="rnsd not available — install RNS to run multinode tests",
    ),
    pytest.mark.timeout(180),
]


def _http_get_text(port: int, path: str, api_key: str | None = None, timeout: float = 5.0):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
    if api_key:
        req.add_header("X-API-Key", api_key)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode()


def _http_get_json(port: int, path: str, timeout: float = 5.0):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


class TestLxmfInboundCountersExposed:
    def test_action_family_present_on_both_nodes(self, two_nodes):
        info = two_nodes
        for port_key, key_key in (("obs_port_a", "api_key_a"), ("obs_port_b", "api_key_b")):
            metrics = _http_get_text(info[port_key], "/api/metrics/", info[key_key])
            assert "hokora_lxmf_inbound_actions_total" in metrics
            for action in (
                "rejected",
                "recovered",
                "signature_failed",
                "opt_out_passthrough",
            ):
                assert f'action="{action}"' in metrics

    def test_rejection_family_present_on_both_nodes(self, two_nodes):
        info = two_nodes
        for port_key, key_key in (("obs_port_a", "api_key_a"), ("obs_port_b", "api_key_b")):
            metrics = _http_get_text(info[port_key], "/api/metrics/", info[key_key])
            assert "hokora_lxmf_inbound_rejections_total" in metrics

    def test_health_remains_green_with_new_chokepoint_wired(self, two_nodes):
        info = two_nodes
        for port_key in ("obs_port_a", "obs_port_b"):
            live = _http_get_json(info[port_key], "/health/live")
            assert live.get("status") == "live"
            ready = _http_get_json(info[port_key], "/health/ready")
            assert ready.get("status") == "ready"
