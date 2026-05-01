# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""ObservabilityListener: loopback-only HTTP surface for liveness + metrics.

Three routes served from a stdlib ``ThreadingHTTPServer``:

  * ``GET /health/live`` — 200 if the heartbeat file is fresh
    (mtime within ``stale_threshold_s``), 503 otherwise. No auth.
    Consumers: Docker healthcheck, host cron, future kubelet probe.

  * ``GET /health/ready`` — 200 if live AND the daemon believes its
    subsystems are ready. No auth. Consumers: fleet dashboards that
    need to distinguish "dead" from "degraded".

  * ``GET /api/metrics/`` — Prometheus text format.
    **API-key gated** (X-API-Key header or ``?key=`` query param for
    curl-from-loopback convenience). The api_key file is created by
    ``hokora init``; if absent, the route returns 404.

Binding is **loopback-only, hard-coded in source**. A misconfigured TOML
must not be able to expose health endpoints on a public interface. The
config surface exposes only ``port`` and ``enabled``.

Threading model: stdlib ThreadingHTTPServer spins a thread per request.
That's a deviation from the asyncio-everywhere rule, but the handlers
only touch:
  * the heartbeat file (already atomic via the writer's ``os.replace``),
  * a process-local API-key string (read-only after config load),
  * ``asyncio.run_coroutine_threadsafe`` to run the metrics coroutine
    on the daemon's event loop (thread-safe by asyncio contract).

No daemon-managed subsystem state is mutated from handler threads.
"""

from __future__ import annotations

import asyncio
import http.server
import json
import logging
import re
import secrets
import socketserver
import threading
import time
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlparse

logger = logging.getLogger(__name__)

# Hard-coded loopback bind. Not configurable by design: the health
# surface reveals node identity + metrics fingerprint. If a future
# deployment needs non-loopback access, it MUST route through a
# reverse proxy with its own auth — not a TOML flag.
_BIND_ADDRESS = "127.0.0.1"

# Default stale threshold: 3× a 30s heartbeat interval, matching the
# systemd WatchdogSec convention.
_DEFAULT_STALE_THRESHOLD_S = 90.0

_ACCESS_LOG_KEY_RE = re.compile(r"([?&])key=[^ &]*")


def _scrub_query_secrets(line: str) -> str:
    """Redact ``?key=…`` / ``&key=…`` query values from an access-log line.

    The metrics endpoint accepts the API key as a query param for
    curl-from-loopback convenience; without scrubbing, a tech-support
    ``--log-level=DEBUG`` capture would persist the secret to
    ``hokorad.log``.
    """
    return _ACCESS_LOG_KEY_RE.sub(r"\1key=REDACTED", line)


class ObservabilityListener:
    """Stdlib HTTP server exposing liveness + metrics on loopback."""

    def __init__(
        self,
        heartbeat_path: Path,
        *,
        port: int = 8421,
        api_key: Optional[str] = None,
        session_factory=None,
        asyncio_loop: Optional[asyncio.AbstractEventLoop] = None,
        rns_alive: Optional[callable] = None,
        maintenance_fresh: Optional[callable] = None,
        stale_threshold_s: float = _DEFAULT_STALE_THRESHOLD_S,
        rns_transport=None,
        daemon_start_time: Optional[float] = None,
        mirror_manager=None,
    ) -> None:
        """Construct the listener.

        Args:
            heartbeat_path: Path to the heartbeat file; mtime drives /health/live.
            port: TCP port to bind on 127.0.0.1.
            api_key: Shared secret for /api/metrics/ auth. None disables
                metrics (returns 404) — acceptable for air-gapped nodes.
            session_factory: AsyncSession-producing callable for the
                Prometheus exporter. None disables /api/metrics/.
            asyncio_loop: Daemon's event loop; used to marshal async
                work (DB queries for metrics) from the HTTP thread.
            rns_alive: Zero-arg callable, True iff RNS transport is up.
                Feeds /health/ready.
            maintenance_fresh: Zero-arg callable, True iff the
                maintenance scheduler ran within its expected window.
                Feeds /health/ready; None for relay mode.
            stale_threshold_s: Max age (seconds) of the heartbeat file
                before /health/live returns 503.
            rns_transport: The ``RNS.Transport`` module (or a stand-in
                exposing ``.interfaces``). When provided, the Prometheus
                exporter emits per-interface rx/tx counters + up gauge.
                None omits those metrics — appropriate for contexts
                with no RNS attached (tests, isolated metrics fixtures).
        """
        self._heartbeat_path = heartbeat_path
        self._port = port
        self._api_key = api_key
        self._session_factory = session_factory
        self._loop = asyncio_loop
        self._rns_alive = rns_alive
        self._maintenance_fresh = maintenance_fresh
        self._stale_threshold_s = stale_threshold_s
        self._rns_transport = rns_transport
        self._daemon_start_time = daemon_start_time
        self._mirror_manager = mirror_manager
        self._server: Optional[socketserver.TCPServer] = None
        self._thread: Optional[threading.Thread] = None

    # ── Lifecycle ───────────────────────────────────────────────────

    def start(self) -> None:
        """Bind the server and serve forever on a daemon thread."""
        if self._server is not None:
            return

        listener = self

        class _Handler(http.server.BaseHTTPRequestHandler):
            # Silence stdlib's default-to-stderr access log; we route
            # through our logger instead.
            def log_message(self, format, *args):  # noqa: A002 — stdlib sig
                logger.debug(
                    "obs %s - %s",
                    self.address_string(),
                    _scrub_query_secrets(format % args),
                )

            def do_GET(self):  # noqa: N802 — stdlib sig
                parsed = urlparse(self.path)
                route = parsed.path.rstrip("/")
                if route == "/health/live" or route == "/health/live/":
                    listener._handle_live(self)
                elif route == "/health/ready" or route == "/health/ready/":
                    listener._handle_ready(self)
                elif route == "/api/metrics" or route == "/api/metrics/":
                    listener._handle_metrics(self, parsed.query)
                else:
                    self.send_error(404, "not found")

        class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
            daemon_threads = True
            allow_reuse_address = True

        try:
            self._server = _Server((_BIND_ADDRESS, self._port), _Handler)
        except OSError as exc:
            logger.error(
                "ObservabilityListener failed to bind %s:%s (%s); health endpoint unavailable",
                _BIND_ADDRESS,
                self._port,
                exc,
            )
            self._server = None
            return

        # Enforce loopback: double-check the bind actually landed on
        # loopback. Any other result is a misconfigured interface and
        # must tear down the listener to avoid exposing the surface.
        bound_host, _bound_port = self._server.server_address[:2]
        if bound_host not in ("127.0.0.1", "::1"):
            logger.error(
                "ObservabilityListener bound to %s which is not loopback; "
                "closing to preserve the loopback-only invariant",
                bound_host,
            )
            self._server.server_close()
            self._server = None
            return

        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="observability-listener",
            daemon=True,
        )
        self._thread.start()
        logger.info("ObservabilityListener listening on %s:%s", _BIND_ADDRESS, self._port)

    def stop(self) -> None:
        """Shut down the HTTP server and join its serving thread."""
        if self._server is not None:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:
                logger.debug("server shutdown raised", exc_info=True)
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    # ── Handlers ────────────────────────────────────────────────────

    def _heartbeat_fresh(self) -> bool:
        try:
            mtime = self._heartbeat_path.stat().st_mtime
        except FileNotFoundError:
            return False
        except OSError:
            return False
        return (time.time() - mtime) <= self._stale_threshold_s

    def _handle_live(self, handler: http.server.BaseHTTPRequestHandler) -> None:
        ok = self._heartbeat_fresh()
        _write_json(handler, 200 if ok else 503, {"status": "live" if ok else "stale"})

    def _handle_ready(self, handler: http.server.BaseHTTPRequestHandler) -> None:
        if not self._heartbeat_fresh():
            _write_json(handler, 503, {"status": "stale"})
            return
        if self._rns_alive is not None:
            try:
                if not self._rns_alive():
                    _write_json(handler, 503, {"status": "rns_down"})
                    return
            except Exception:
                _write_json(handler, 503, {"status": "rns_check_error"})
                return
        if self._maintenance_fresh is not None:
            try:
                if not self._maintenance_fresh():
                    _write_json(handler, 503, {"status": "maintenance_stale"})
                    return
            except Exception:
                _write_json(handler, 503, {"status": "maintenance_check_error"})
                return
        _write_json(handler, 200, {"status": "ready"})

    def _handle_metrics(self, handler: http.server.BaseHTTPRequestHandler, query: str) -> None:
        if self._api_key is None or self._session_factory is None or self._loop is None:
            # Metrics disabled — hide the route entirely so probers can't
            # distinguish "not configured" from "wrong auth".
            handler.send_error(404, "not found")
            return

        provided = handler.headers.get("X-API-Key")
        if not provided:
            q = parse_qs(query)
            if "key" in q and q["key"]:
                provided = q["key"][0]
        if not provided or not secrets.compare_digest(provided, self._api_key):
            handler.send_error(401, "unauthorized")
            return

        try:
            from hokora.core.prometheus_exporter import render_metrics

            future = asyncio.run_coroutine_threadsafe(
                render_metrics(
                    self._session_factory,
                    rns_transport=self._rns_transport,
                    daemon_start_time=self._daemon_start_time,
                    mirror_manager=self._mirror_manager,
                ),
                self._loop,
            )
            # 10s matches the Docker healthcheck timeout; metrics
            # rendering is a handful of COUNT queries, should be fast.
            body = future.result(timeout=10)
        except Exception:
            logger.warning("metrics render failed", exc_info=True)
            handler.send_error(500, "metrics unavailable")
            return

        handler.send_response(200)
        handler.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        handler.send_header("Content-Length", str(len(body.encode("utf-8"))))
        handler.end_headers()
        handler.wfile.write(body.encode("utf-8"))


def _write_json(handler, status: int, payload: dict) -> None:
    """Write a minimal JSON response body with common headers."""
    blob = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(blob)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(blob)
