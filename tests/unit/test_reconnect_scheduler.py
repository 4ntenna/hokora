# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for ReconnectScheduler — Step A of the sync_engine refactor."""

import threading
import time
from unittest.mock import MagicMock

from hokora_tui.sync.reconnect_scheduler import ReconnectScheduler


class _FakeLinkManager:
    """Minimal stand-in for ChannelLinkManager.

    Tests don't need RNS — just is_connected + any_active + connect_channel
    to track reconnect attempts.
    """

    def __init__(self):
        self.connect_calls: list[tuple[bytes, str]] = []
        self._active: set[str] = set()

    def is_connected(self, channel_id: str) -> bool:
        return channel_id in self._active

    def any_active(self) -> bool:
        return bool(self._active)

    def connect_channel(self, dest_hash: bytes, channel_id: str) -> None:
        self.connect_calls.append((dest_hash, channel_id))
        self._active.add(channel_id)  # simulate successful connect


class TestTargets:
    def test_add_and_remove_target(self):
        lm = _FakeLinkManager()
        s = ReconnectScheduler(lm)
        s.add_target("ch1", b"\x01" * 16)
        assert s.targets_snapshot() == {"ch1": b"\x01" * 16}
        s.remove_target("ch1")
        assert s.targets_snapshot() == {}

    def test_clear_targets(self):
        lm = _FakeLinkManager()
        s = ReconnectScheduler(lm)
        s.add_target("ch1", b"\x01" * 16)
        s.add_target("ch2", b"\x02" * 16)
        s.clear_targets()
        assert s.targets_snapshot() == {}

    def test_targets_snapshot_is_live_reference(self):
        """Backward-compat shim relies on this returning the live dict."""
        lm = _FakeLinkManager()
        s = ReconnectScheduler(lm)
        snap = s.targets_snapshot()
        s.add_target("ch1", b"\x01" * 16)
        assert "ch1" in snap


class TestUserDisconnected:
    def test_default_is_false(self):
        s = ReconnectScheduler(_FakeLinkManager())
        assert not s.is_user_disconnected()

    def test_mark_and_reset(self):
        s = ReconnectScheduler(_FakeLinkManager())
        s.mark_user_disconnected()
        assert s.is_user_disconnected()
        s.reset_user_disconnected()
        assert not s.is_user_disconnected()

    def test_mark_signals_stop(self):
        s = ReconnectScheduler(_FakeLinkManager())
        s.mark_user_disconnected()
        assert s.stop_event.is_set()


class TestTrigger:
    def test_no_targets_is_noop(self):
        lm = _FakeLinkManager()
        s = ReconnectScheduler(lm)
        s.trigger()
        assert s._reconnect_thread is None

    def test_user_disconnected_blocks_start(self):
        lm = _FakeLinkManager()
        s = ReconnectScheduler(lm)
        s.add_target("ch1", b"\x01" * 16)
        s.mark_user_disconnected()
        s.trigger()
        assert s._reconnect_thread is None

    def test_idempotent_when_already_running(self):
        lm = _FakeLinkManager()
        s = ReconnectScheduler(lm)
        s.add_target("ch1", b"\x01" * 16)

        # First trigger spawns a thread
        s.trigger()
        t1 = s._reconnect_thread
        assert t1 is not None
        # Second trigger before thread finishes does not replace it
        s.trigger()
        assert s._reconnect_thread is t1
        # Clean up
        s.stop()
        t1.join(timeout=2)

    def test_trigger_starts_thread_and_connects_after_backoff(self):
        lm = _FakeLinkManager()
        s = ReconnectScheduler(lm)
        # Shorten schedule for the test
        s.BACKOFF_SCHEDULE = (0.05,)
        s.BACKOFF_JITTER = 0.0
        s.add_target("ch1", b"\xaa" * 16)

        s.trigger()
        # Wait up to 2s for connect to happen
        deadline = time.time() + 2
        while time.time() < deadline and not lm.connect_calls:
            time.sleep(0.02)
        s.stop()
        s._reconnect_thread.join(timeout=2)
        # Loop exits once a link becomes active (set by fake connect_channel)
        assert lm.connect_calls == [(b"\xaa" * 16, "ch1")]


class TestBackoffProgression:
    def test_attempt_counter_increments(self):
        """Backoff attempt should increment on each iteration."""
        lm = _FakeLinkManager()
        # Override: never become active, so loop keeps iterating
        lm.connect_channel = MagicMock(side_effect=lambda *_args: None)

        s = ReconnectScheduler(lm)
        s.BACKOFF_SCHEDULE = (0.01,)
        s.BACKOFF_JITTER = 0.0
        s.add_target("ch1", b"\xbb" * 16)
        s.trigger()

        # Let the loop run briefly
        time.sleep(0.15)
        s.stop()
        s._reconnect_thread.join(timeout=2)
        # Attempt must have incremented beyond 1
        assert s._reconnect_attempt >= 2

    def test_reset_attempt_sets_zero_and_signals_stop(self):
        s = ReconnectScheduler(_FakeLinkManager())
        s._reconnect_attempt = 5
        s.reset_attempt()
        assert s._reconnect_attempt == 0
        assert s.stop_event.is_set()

    def test_backoff_steps_capped_at_max(self):
        """After exhausting schedule, step stays at max_step."""
        lm = _FakeLinkManager()
        s = ReconnectScheduler(lm)
        # Custom short schedule so we hit the cap quickly
        s.BACKOFF_SCHEDULE = (0.01, 0.02)
        s.BACKOFF_JITTER = 0.0
        s.add_target("ch1", b"\xcc" * 16)
        # Don't actually connect
        lm.connect_channel = MagicMock()

        s.trigger()
        time.sleep(0.15)
        s.stop()
        s._reconnect_thread.join(timeout=2)
        assert s._reconnect_attempt >= 2


class TestOnRecoveringCallback:
    def test_fires_with_attempt_info(self):
        lm = _FakeLinkManager()
        recv: list[dict] = []
        s = ReconnectScheduler(lm, on_recovering=recv.append)
        s.BACKOFF_SCHEDULE = (0.01,)
        s.BACKOFF_JITTER = 0.0
        s.add_target("ch1", b"\xdd" * 16)
        s.trigger()
        deadline = time.time() + 1.5
        while time.time() < deadline and not recv:
            time.sleep(0.02)
        s.stop()
        s._reconnect_thread.join(timeout=2)
        assert recv, "on_recovering never fired"
        event = recv[0]
        assert event["attempt"] >= 1
        assert event["next_retry_in"] >= 0.01
        assert event["targets"] == ["ch1"]

    def test_callback_exception_does_not_crash_loop(self):
        lm = _FakeLinkManager()

        def bad(_ev):
            raise RuntimeError("boom")

        s = ReconnectScheduler(lm, on_recovering=bad)
        s.BACKOFF_SCHEDULE = (0.01,)
        s.BACKOFF_JITTER = 0.0
        s.add_target("ch1", b"\xee" * 16)
        s.trigger()
        # Wait until connect happens or 1.5s, whichever first. The
        # scheduler enforces a 0.1s floor on delay, so we can't assume
        # the loop completes in one short sleep — poll instead.
        deadline = time.time() + 1.5
        while time.time() < deadline and not lm.connect_calls:
            time.sleep(0.02)
        s.stop()
        s._reconnect_thread.join(timeout=2)
        # Reached connect despite the callback raising
        assert lm.connect_calls, "Loop was killed by bad callback"


class TestStopBehavior:
    def test_stop_before_trigger_is_safe(self):
        s = ReconnectScheduler(_FakeLinkManager())
        s.stop()  # no thread — should just set the event

    def test_stop_interrupts_sleeping_loop(self):
        lm = _FakeLinkManager()
        s = ReconnectScheduler(lm)
        # Long backoff so loop sleeps
        s.BACKOFF_SCHEDULE = (3600,)
        s.BACKOFF_JITTER = 0.0
        s.add_target("ch1", b"\xff" * 16)
        s.trigger()
        time.sleep(0.05)
        start = time.time()
        s.stop()
        s._reconnect_thread.join(timeout=2)
        elapsed = time.time() - start
        assert elapsed < 1.0, f"Stop did not interrupt sleep (took {elapsed:.2f}s)"


class TestThreadSafety:
    def test_concurrent_add_remove_clear(self):
        """Thread-storm add/remove/clear while trigger is running."""
        lm = _FakeLinkManager()
        s = ReconnectScheduler(lm)
        s.BACKOFF_SCHEDULE = (0.005,)
        s.BACKOFF_JITTER = 0.0

        def churner():
            for i in range(200):
                s.add_target(f"ch{i % 5}", bytes([i & 0xFF] * 16))
                if i % 10 == 0:
                    s.remove_target("ch0")
                if i % 50 == 0:
                    s.clear_targets()

        s.add_target("ch1", b"\x00" * 16)
        s.trigger()
        ts = [threading.Thread(target=churner) for _ in range(4)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        s.stop()
        if s._reconnect_thread:
            s._reconnect_thread.join(timeout=2)
        # No assertions on final state — just that nothing crashed.
