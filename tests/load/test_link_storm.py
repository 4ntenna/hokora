# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Load test: ReconnectScheduler with 100 targets doesn't thunder-herd
and shuts down promptly."""

import threading
import time
from unittest.mock import MagicMock

import pytest

from hokora_tui.sync.reconnect_scheduler import ReconnectScheduler

pytestmark = pytest.mark.load


def _make_link_manager():
    """Link manager that reports nothing connected (drives the reconnect loop)."""
    lm = MagicMock()
    lm.is_connected = MagicMock(return_value=False)
    lm.any_active = MagicMock(return_value=False)
    lm.connect_channel = MagicMock()
    return lm


def test_100_targets_single_reconnect_thread():
    """Adding 100 targets and triggering should spawn exactly one backoff
    thread, not 100 (which would be a thundering herd)."""
    lm = _make_link_manager()
    scheduler = ReconnectScheduler(link_manager=lm)

    for i in range(100):
        scheduler.add_target(f"chan-{i}", bytes([i & 0xFF]) * 16)

    threads_before = {t.name for t in threading.enumerate()}
    scheduler.trigger()
    # Also verify trigger() is idempotent — a second call doesn't spawn a second loop.
    scheduler.trigger()
    scheduler.trigger()

    time.sleep(0.2)  # let the thread start up
    threads_after = {t.name for t in threading.enumerate()}
    new_threads = threads_after - threads_before
    reconnect_threads = [n for n in new_threads if "reconnect" in n]
    assert len(reconnect_threads) == 1, (
        f"Expected 1 reconnect thread, got {len(reconnect_threads)}: {reconnect_threads}"
    )

    scheduler.mark_user_disconnected()


def test_stop_terminates_thread_within_5_seconds():
    """After mark_user_disconnected(), the reconnect loop should exit
    within 5s even if it's inside a backoff sleep."""
    lm = _make_link_manager()
    scheduler = ReconnectScheduler(link_manager=lm)
    scheduler.add_target("chan-1", b"\x01" * 16)
    scheduler.trigger()
    time.sleep(0.2)

    assert scheduler._reconnect_thread is not None
    assert scheduler._reconnect_thread.is_alive()

    t0 = time.monotonic()
    scheduler.mark_user_disconnected()
    scheduler._reconnect_thread.join(timeout=5.0)
    elapsed = time.monotonic() - t0

    assert not scheduler._reconnect_thread.is_alive(), (
        f"reconnect thread still alive {elapsed:.2f}s after stop signal"
    )
    assert elapsed < 5.0


def test_backoff_honoured_no_immediate_flood():
    """First reconnect attempt must wait at least ~0.8s (base=1s − 20%
    jitter). If this fails we've regressed to immediate retry on every
    target at once."""
    lm = _make_link_manager()
    scheduler = ReconnectScheduler(link_manager=lm)
    for i in range(50):
        scheduler.add_target(f"chan-{i}", bytes([i & 0xFF]) * 16)

    t0 = time.monotonic()
    scheduler.trigger()
    # Wait for the first round of connect_channel calls to happen.
    deadline = t0 + 3.0
    while time.monotonic() < deadline and lm.connect_channel.call_count < 50:
        time.sleep(0.05)

    elapsed_to_first_burst = time.monotonic() - t0
    scheduler.mark_user_disconnected()
    if scheduler._reconnect_thread:
        scheduler._reconnect_thread.join(timeout=5.0)

    # With BACKOFF_SCHEDULE[0]=1s and ±20% jitter, the minimum is 0.8s.
    assert elapsed_to_first_burst >= 0.6, (
        f"reconnect burst fired too fast ({elapsed_to_first_burst:.2f}s) — "
        "backoff schedule may be ignored"
    )
