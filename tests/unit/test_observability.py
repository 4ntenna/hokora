# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for ObservabilityListener — loopback HTTP liveness surface."""

from __future__ import annotations

import http.client
import socket
import time
from pathlib import Path

import pytest

from hokora.core.observability import ObservabilityListener


def _free_port() -> int:
    """Grab an unused high port (loopback only)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _get(port: int, path: str, headers: dict | None = None) -> tuple[int, str]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("GET", path, headers=headers or {})
        resp = conn.getresponse()
        return resp.status, resp.read().decode("utf-8")
    finally:
        conn.close()


def _write_fresh_heartbeat(path: Path) -> None:
    """Ensure the heartbeat file exists with a recent mtime."""
    path.write_bytes(b"x")


@pytest.fixture
def listener(tmp_path):
    """Construct a listener; caller calls ``.start()``."""
    port = _free_port()
    hb = tmp_path / "heartbeat"

    class _Holder:
        pass

    h = _Holder()
    h.port = port
    h.heartbeat = hb
    h.listener = ObservabilityListener(
        heartbeat_path=hb,
        port=port,
        api_key=None,
        session_factory=None,
        asyncio_loop=None,
        stale_threshold_s=5.0,
    )
    yield h
    h.listener.stop()


def test_health_live_returns_503_when_heartbeat_missing(listener):
    # No heartbeat file yet → stale.
    listener.listener.start()
    status, _body = _get(listener.port, "/health/live")
    assert status == 503


def test_health_live_returns_200_when_heartbeat_fresh(listener):
    _write_fresh_heartbeat(listener.heartbeat)
    listener.listener.start()
    status, body = _get(listener.port, "/health/live")
    assert status == 200
    assert '"live"' in body


def test_health_live_503_when_stale(listener, tmp_path):
    _write_fresh_heartbeat(listener.heartbeat)
    # Backdate the file past the threshold.
    past = time.time() - 100
    import os

    os.utime(listener.heartbeat, (past, past))
    listener.listener.start()
    status, body = _get(listener.port, "/health/live")
    assert status == 503
    assert "stale" in body


def test_health_ready_includes_rns_and_maintenance(tmp_path):
    port = _free_port()
    hb = tmp_path / "heartbeat"
    hb.write_bytes(b"x")

    state = {"rns": True, "maint": True}
    lst = ObservabilityListener(
        heartbeat_path=hb,
        port=port,
        rns_alive=lambda: state["rns"],
        maintenance_fresh=lambda: state["maint"],
        stale_threshold_s=5.0,
    )
    try:
        lst.start()
        # All good → 200.
        status, body = _get(port, "/health/ready")
        assert status == 200
        assert "ready" in body

        # RNS down → 503.
        state["rns"] = False
        status, body = _get(port, "/health/ready")
        assert status == 503
        assert "rns_down" in body

        # RNS back, maintenance stale → 503.
        state["rns"] = True
        state["maint"] = False
        status, body = _get(port, "/health/ready")
        assert status == 503
        assert "maintenance_stale" in body
    finally:
        lst.stop()


def test_health_ready_503_when_heartbeat_stale(tmp_path):
    """A stale heartbeat short-circuits ready → 503 before checking other invariants."""
    port = _free_port()
    hb = tmp_path / "heartbeat"  # never written

    lst = ObservabilityListener(
        heartbeat_path=hb,
        port=port,
        rns_alive=lambda: True,
        maintenance_fresh=lambda: True,
        stale_threshold_s=5.0,
    )
    try:
        lst.start()
        status, _ = _get(port, "/health/ready")
        assert status == 503
    finally:
        lst.stop()


def test_metrics_returns_404_when_disabled(tmp_path):
    """Without an api_key + session_factory, /api/metrics/ is invisible."""
    port = _free_port()
    hb = tmp_path / "heartbeat"
    hb.write_bytes(b"x")

    lst = ObservabilityListener(heartbeat_path=hb, port=port, api_key=None)
    try:
        lst.start()
        status, _ = _get(port, "/api/metrics/")
        assert status == 404
    finally:
        lst.stop()


def test_metrics_requires_api_key(tmp_path):
    import asyncio

    port = _free_port()
    hb = tmp_path / "heartbeat"
    hb.write_bytes(b"x")

    loop = asyncio.new_event_loop()

    class _FakeSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def execute(self, *a, **k):
            class _R:
                def __iter__(self):
                    return iter([])

                def scalar(self):
                    return 0

            return _R()

    def _sf():
        """Mimics ``async_sessionmaker`` semantics: synchronous call
        returning an async context manager — not a coroutine."""
        return _FakeSession()

    lst = ObservabilityListener(
        heartbeat_path=hb,
        port=port,
        api_key="secret-key-1234",
        session_factory=_sf,
        asyncio_loop=loop,
    )

    import threading

    t = threading.Thread(target=loop.run_forever, daemon=True)
    t.start()
    try:
        lst.start()
        # No key → 401.
        status, _ = _get(port, "/api/metrics/")
        assert status == 401
        # Wrong key → 401.
        status, _ = _get(port, "/api/metrics/", headers={"X-API-Key": "wrong"})
        assert status == 401
        # Correct key → 200 (and the body is Prometheus text).
        status, body = _get(port, "/api/metrics/", headers={"X-API-Key": "secret-key-1234"})
        assert status == 200
        assert "hokora_daemon_uptime_seconds" in body
    finally:
        lst.stop()
        loop.call_soon_threadsafe(loop.stop)
        t.join(timeout=2)
        loop.close()
        asyncio.set_event_loop(None)


def test_unknown_path_returns_404(listener):
    listener.listener.start()
    status, _ = _get(listener.port, "/etc/passwd")
    assert status == 404
    status, _ = _get(listener.port, "/health")  # partial match
    assert status == 404


def test_listener_binds_loopback_only(listener):
    """The bind address must be 127.0.0.1 — not 0.0.0.0, not a hostname."""
    listener.listener.start()
    # The server_address should reflect the hard-coded loopback constant.
    assert listener.listener._server is not None
    bound_host, _ = listener.listener._server.server_address[:2]
    assert bound_host == "127.0.0.1"


def test_start_is_idempotent(listener):
    listener.listener.start()
    # Second start must be a no-op — no second thread, no rebind attempt.
    listener.listener.start()
    assert listener.listener._server is not None


def test_stop_is_idempotent(listener):
    listener.listener.start()
    listener.listener.stop()
    # No raise on double stop.
    listener.listener.stop()


class TestAccessLogScrubsApiKey:
    """``?key=…`` must never reach the access log verbatim."""

    def test_scrubs_single_key_param(self):
        from hokora.core.observability import _scrub_query_secrets

        line = "GET /api/metrics/?key=topsecret HTTP/1.1"
        assert _scrub_query_secrets(line) == "GET /api/metrics/?key=REDACTED HTTP/1.1"

    def test_scrubs_key_with_neighbour_params(self):
        from hokora.core.observability import _scrub_query_secrets

        line = "GET /api/metrics/?foo=1&key=topsecret&bar=2 HTTP/1.1"
        assert _scrub_query_secrets(line) == "GET /api/metrics/?foo=1&key=REDACTED&bar=2 HTTP/1.1"

    def test_passthrough_when_no_key(self):
        from hokora.core.observability import _scrub_query_secrets

        line = "GET /api/metrics/ HTTP/1.1"
        assert _scrub_query_secrets(line) == line

    def test_live_request_does_not_log_secret(self, tmp_path, caplog):
        """End-to-end: a real request through the listener never persists the key."""
        import logging

        api_key = "topsecret_must_not_leak"
        port = _free_port()
        hb = tmp_path / "heartbeat"
        hb.write_bytes(b"x")
        listener_obj = ObservabilityListener(
            heartbeat_path=hb,
            port=port,
            api_key=api_key,
            session_factory=lambda: None,
            asyncio_loop=None,
            stale_threshold_s=5.0,
        )
        try:
            listener_obj.start()
            with caplog.at_level(logging.DEBUG, logger="hokora.core.observability"):
                # Hit the metrics route with the key in the query string.
                # The 500 response (no real loop) is fine — we're checking
                # the access log, not the metrics body.
                _get(port, f"/api/metrics/?key={api_key}")
        finally:
            listener_obj.stop()

        full = "\n".join(r.getMessage() for r in caplog.records)
        assert api_key not in full, "raw API key reached the access log"
        assert "key=REDACTED" in full, "scrubbed marker missing"
