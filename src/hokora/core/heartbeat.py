# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""HeartbeatWriter: transport-independent daemon-liveness signal.

Writes a small msgpack heartbeat file every ``interval_s`` seconds — but
**only when the daemon's key invariants pass**. A heartbeat represents
"this node is functional," not "this task is alive." If the announce
loop or maintenance loop wedges while the heartbeat task keeps ticking,
external probes would see a stale-but-lying green light; gating the
write on inline invariant checks prevents that silent-degradation mode.

Consumers:
  * ``ObservabilityListener`` reads the file's mtime to answer
    ``/health/live`` on the loopback HTTP endpoint.
  * ``systemd`` watchdog units can consume the file via a sidecar
    script — no HTTP required.
  * Air-gapped LoRa operators read it during ops-visits.

Security notes:
  * File permissions 0o644 — heartbeat contains only the node identity
    hash (already announced publicly) and a timestamp. No secrets.
  * Atomic rename via ``os.replace`` — a racing reader sees either the
    prior write or the new one, never a partial file.
  * No subsystem internals exposed to external callers; only the mtime
    and a stable JSON shape.

Architecture:
  * One asyncio task per daemon, owned by ``HokoraDaemon``.
  * Checks are inline conditionals — no plugin framework (YAGNI).
  * Reading invariant state must not touch the event loop (e.g. never
    await inside a check) to keep the tick cadence predictable.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from pathlib import Path
from typing import Optional

import msgpack

logger = logging.getLogger(__name__)

# File format version. Bump if the field set changes incompatibly.
_HEARTBEAT_VERSION = 1


class HeartbeatWriter:
    """Background task that writes a heartbeat file guarded by invariants."""

    def __init__(
        self,
        path: Path,
        role: str,
        node_identity_hash: str,
        interval_s: float = 30.0,
        *,
        rns_alive: Optional[callable] = None,
        maintenance_fresh: Optional[callable] = None,
    ) -> None:
        """Construct a heartbeat writer.

        Args:
            path: Target file path. Parent directory must exist.
            role: Node role identifier (``"relay"`` | ``"community"``).
                Included in the heartbeat payload for fleet ops.
            node_identity_hash: Daemon's RNS identity hex hash.
            interval_s: Seconds between tick attempts. 30s matches the
                systemd WatchdogSec convention; external readers should
                treat the file as stale after 3× this value.
            rns_alive: Optional zero-arg callable returning True iff the
                RNS transport has at least one online interface. None
                disables the check.
            maintenance_fresh: Optional zero-arg callable returning True
                iff the maintenance scheduler ran within its expected
                window. None disables the check (e.g. relay mode has no
                maintenance loop).
        """
        self._path = path
        self._role = role
        self._node_identity_hash = node_identity_hash
        self._interval_s = interval_s
        self._rns_alive = rns_alive
        self._maintenance_fresh = maintenance_fresh
        self._task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()

    # ── Lifecycle ───────────────────────────────────────────────────

    def start(self) -> None:
        """Schedule the heartbeat tick on the current event loop."""
        if self._task is not None and not self._task.done():
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run(), name="heartbeat-writer")

    async def stop(self) -> None:
        """Signal the task to exit and await its completion."""
        self._stop.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=self._interval_s + 5)
            except asyncio.TimeoutError:
                logger.warning("heartbeat task did not stop in time; cancelling")
                self._task.cancel()
                try:
                    await self._task
                except (asyncio.CancelledError, Exception):
                    pass
            self._task = None

    # ── Tick loop ───────────────────────────────────────────────────

    async def _run(self) -> None:
        """Periodic tick. Never raises — a failed tick is logged and skipped."""
        # First write as early as possible so readers don't see "stale"
        # during the grace period between daemon.start() completing and
        # the first scheduled tick.
        self._try_tick()
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self._interval_s)
            except asyncio.TimeoutError:
                self._try_tick()

    def _try_tick(self) -> None:
        """Evaluate invariants; write heartbeat if all pass."""
        failure = self._invariant_failure()
        if failure is not None:
            # Skip the write so the file goes stale and external probes
            # see the degraded state. Log at WARNING so ops tooling
            # picks it up immediately — without this signal a wedged
            # subsystem can fail silently while the heartbeat keeps
            # ticking.
            logger.warning("heartbeat skipped: invariant failed (%s)", failure)
            return
        try:
            self._write_atomic()
        except Exception:
            # Write failures are not fatal — next tick will retry. We
            # deliberately don't re-raise: the heartbeat task must
            # never bring the daemon down, even if the filesystem goes
            # read-only transiently.
            logger.warning("heartbeat write failed", exc_info=True)

    def _invariant_failure(self) -> Optional[str]:
        """Return a short name for the first failing invariant, or None."""
        if self._rns_alive is not None:
            try:
                if not self._rns_alive():
                    return "rns_transport"
            except Exception:
                logger.debug("rns_alive check raised", exc_info=True)
                return "rns_transport_check_error"
        if self._maintenance_fresh is not None:
            try:
                if not self._maintenance_fresh():
                    return "maintenance_stale"
            except Exception:
                logger.debug("maintenance_fresh check raised", exc_info=True)
                return "maintenance_check_error"
        return None

    def _write_atomic(self) -> None:
        """Write heartbeat via tmp-then-rename. POSIX-atomic."""
        payload = {
            "v": _HEARTBEAT_VERSION,
            "ts": time.time(),
            "role": self._role,
            "node_identity_hash": self._node_identity_hash,
            "pid": os.getpid(),
        }
        blob = msgpack.packb(payload, use_bin_type=True)
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        tmp.write_bytes(blob)
        # 0o644 — public readable by design. Heartbeat contains only the
        # already-announced identity hash; consumers on other UIDs (cron
        # as root, systemd as hokora) need read access.
        os.chmod(tmp, 0o644)
        os.replace(tmp, self._path)


def read_heartbeat(path: Path) -> Optional[dict]:
    """Best-effort read of a heartbeat file. Returns None on any error.

    Readers (ObservabilityListener, systemd watchdog script) use this to
    get a structured view. They should additionally check the file's
    mtime for staleness via ``os.stat`` — the ``ts`` inside the payload
    is informational (daemon's wall clock) while mtime is what external
    supervision should trust.
    """
    try:
        raw = path.read_bytes()
        return msgpack.unpackb(raw, raw=False)
    except Exception:
        return None
