# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for HeartbeatWriter."""

from __future__ import annotations

import asyncio
import time  # noqa: F401 — used by os.utime + utc tick assertions in some tests

import msgpack

from hokora.core.heartbeat import HeartbeatWriter, read_heartbeat


def _fast_writer(tmp_path, **overrides):
    """Construct a writer with tiny interval for test speed."""
    defaults = dict(
        path=tmp_path / "heartbeat",
        role="test",
        node_identity_hash="a" * 32,
        interval_s=0.05,
    )
    defaults.update(overrides)
    return HeartbeatWriter(**defaults)


async def test_first_tick_happens_before_sleep(tmp_path):
    """The writer must attempt a tick immediately on start so the file
    exists by the time ``/health/live`` is first probed."""
    w = _fast_writer(tmp_path)
    w.start()
    # Give the first tick a moment — shorter than interval_s so this
    # only passes if the first write is out-of-band.
    await asyncio.sleep(0.01)
    assert (tmp_path / "heartbeat").exists(), (
        "first heartbeat write must happen before the first interval sleep"
    )
    await w.stop()


async def test_payload_shape_and_fields(tmp_path):
    w = _fast_writer(tmp_path)
    w.start()
    await asyncio.sleep(0.01)
    await w.stop()

    data = read_heartbeat(tmp_path / "heartbeat")
    assert isinstance(data, dict)
    assert data["v"] == 1
    assert data["role"] == "test"
    assert data["node_identity_hash"] == "a" * 32
    assert isinstance(data["ts"], float)
    assert data["pid"] > 0


async def test_atomic_rename_leaves_no_partial_file(tmp_path):
    """No ``.tmp`` sibling survives a successful tick."""
    w = _fast_writer(tmp_path)
    w.start()
    await asyncio.sleep(0.2)
    await w.stop()

    survivors = {p.name for p in tmp_path.iterdir()}
    assert "heartbeat" in survivors
    assert not any(name.endswith(".tmp") for name in survivors)


async def test_invariant_failure_skips_write(tmp_path):
    """When an invariant fails, the heartbeat file is NOT updated — so
    external probes see the daemon as degraded."""
    w = _fast_writer(tmp_path, rns_alive=lambda: False)
    w.start()
    await asyncio.sleep(0.2)
    await w.stop()
    assert not (tmp_path / "heartbeat").exists(), (
        "invariant-failed ticks must not write the heartbeat file"
    )


async def test_invariant_failure_after_success_leaves_stale_file(tmp_path):
    """Once the invariant fails mid-run, subsequent ticks stop updating
    mtime so the file becomes stale (/health/live → 503)."""
    state = {"alive": True}
    w = _fast_writer(tmp_path, rns_alive=lambda: state["alive"])
    w.start()
    await asyncio.sleep(0.05)
    await w.stop()  # Stop the writer while the invariant still passed.

    initial_mtime = (tmp_path / "heartbeat").stat().st_mtime

    # Restart with invariant broken. No further ticks should update mtime.
    state["alive"] = False
    w2 = _fast_writer(tmp_path, rns_alive=lambda: state["alive"])
    w2.start()
    await asyncio.sleep(0.2)
    await w2.stop()

    assert (tmp_path / "heartbeat").stat().st_mtime == initial_mtime, (
        "failing invariant must not rewrite mtime"
    )


async def test_invariant_check_raising_is_treated_as_failure(tmp_path):
    def _bad_check():
        raise RuntimeError("boom")

    w = _fast_writer(tmp_path, rns_alive=_bad_check)
    w.start()
    await asyncio.sleep(0.2)
    await w.stop()
    assert not (tmp_path / "heartbeat").exists()


async def test_maintenance_fresh_check(tmp_path):
    """Relay mode omits this; community mode must enforce it."""
    fresh = {"val": True}
    w = _fast_writer(tmp_path, maintenance_fresh=lambda: fresh["val"])
    w.start()
    await asyncio.sleep(0.05)
    await w.stop()
    assert (tmp_path / "heartbeat").exists()

    # Flip the invariant and remove the old heartbeat; next writer
    # shouldn't recreate it.
    (tmp_path / "heartbeat").unlink()
    fresh["val"] = False
    w2 = _fast_writer(tmp_path, maintenance_fresh=lambda: fresh["val"])
    w2.start()
    await asyncio.sleep(0.1)
    await w2.stop()
    assert not (tmp_path / "heartbeat").exists()


async def test_stop_is_idempotent(tmp_path):
    w = _fast_writer(tmp_path)
    w.start()
    await asyncio.sleep(0.05)
    await w.stop()
    # Should not raise on repeated stop.
    await w.stop()


async def test_read_heartbeat_handles_missing_file(tmp_path):
    assert read_heartbeat(tmp_path / "no_such_file") is None


async def test_read_heartbeat_handles_garbage(tmp_path):
    p = tmp_path / "heartbeat"
    p.write_bytes(b"\x00\xff not msgpack")
    assert read_heartbeat(p) is None


async def test_file_mode_0o644(tmp_path):
    """Heartbeat must be world-readable by design — consumers on other
    UIDs (cron as root, systemd as hokora) need read access. The
    file contains no secrets."""
    w = _fast_writer(tmp_path)
    w.start()
    await asyncio.sleep(0.05)
    await w.stop()

    mode = (tmp_path / "heartbeat").stat().st_mode & 0o777
    assert mode == 0o644, f"heartbeat perms must be 0o644, got 0o{mode:o}"


async def test_payload_is_msgpack_not_json(tmp_path):
    w = _fast_writer(tmp_path)
    w.start()
    await asyncio.sleep(0.05)
    await w.stop()
    raw = (tmp_path / "heartbeat").read_bytes()
    # msgpack starts with specific byte sequences, never ASCII `{`.
    assert raw[0] != ord("{"), "heartbeat must be msgpack, not JSON"
    # Round-trips cleanly via msgpack.
    data = msgpack.unpackb(raw, raw=False)
    assert data["role"] == "test"


async def test_write_failure_does_not_crash(tmp_path, monkeypatch):
    """If the fs rejects the write, the tick logs and continues — the
    heartbeat task must never bring the daemon down."""
    import os as _os

    w = _fast_writer(tmp_path)

    orig_replace = _os.replace
    calls = {"n": 0}

    def _flaky_replace(src, dst):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("disk full")
        return orig_replace(src, dst)

    monkeypatch.setattr(_os, "replace", _flaky_replace)
    w.start()
    await asyncio.sleep(0.2)
    await w.stop()
    # Second tick should have succeeded — file must exist.
    assert (tmp_path / "heartbeat").exists()
