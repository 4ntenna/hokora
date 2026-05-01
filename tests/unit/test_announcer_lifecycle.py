# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for the announcer's auto-announce lifecycle.

The pre-fix bug was: ``Announcer.start`` only spawned the auto-announce
loop if ``state.auto_announce`` was True at startup. Combined with
``app._load_settings`` not reading the setting from DB, this meant the
loop never started on a fresh launch — toggling later did nothing.
The fix unconditionally starts the loop and adds a wake event so a
toggle-ON gets immediate effect.
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

from hokora_tui.announcer import Announcer
from hokora_tui.state import AppState


def _make_announcer(auto_announce_initial: bool = False) -> Announcer:
    """Build an Announcer with a minimal fake app for thread tests."""
    app = MagicMock()
    app.state = AppState()
    app.state.auto_announce = auto_announce_initial
    app.state.announce_interval = 60
    app.state.identity = MagicMock()
    return Announcer(app)


class TestAnnouncerStart:
    def test_start_unconditionally_spawns_thread(self):
        """The thread must spawn even when auto_announce is False at start —
        so a later toggle-ON takes effect without a TUI restart.
        """
        ann = _make_announcer(auto_announce_initial=False)
        # Patch RNS register to a no-op so start() doesn't blow up.
        with patch("hokora_tui.announcer.RNS", create=True) as fake_rns:
            fake_rns.Transport.register_announce_handler = MagicMock()
            ann.start()
        try:
            assert ann._auto_thread is not None
            assert ann._auto_thread.is_alive()
        finally:
            ann.stop()

    def test_start_with_auto_announce_true_also_spawns(self):
        ann = _make_announcer(auto_announce_initial=True)
        with patch("hokora_tui.announcer.RNS", create=True) as fake_rns:
            fake_rns.Transport.register_announce_handler = MagicMock()
            with patch.object(ann, "announce_profile"):
                ann.start()
                # Give the loop one cycle to run announce_profile.
                time.sleep(0.05)
        try:
            assert ann._auto_thread is not None
            assert ann._auto_thread.is_alive()
        finally:
            ann.stop()


class TestAnnouncerWake:
    def test_wake_sets_signal(self):
        ann = _make_announcer()
        assert not ann._signal.is_set()
        ann.wake()
        assert ann._signal.is_set()

    def test_wake_interrupts_long_interval(self):
        """Toggle-ON path: a freshly-enabled auto-announce announces
        within milliseconds, not after ``announce_interval`` seconds.
        """
        ann = _make_announcer(auto_announce_initial=False)
        # Long interval — the test must finish in well under that.
        ann.app.state.announce_interval = 60
        ann.app.state.auto_announce = False

        with patch.object(ann, "announce_profile") as mock_announce:
            with patch("hokora_tui.announcer.RNS", create=True) as fake_rns:
                fake_rns.Transport.register_announce_handler = MagicMock()
                ann.start()

            # Loop runs but skips announce because auto_announce is False.
            time.sleep(0.05)
            assert mock_announce.call_count == 0

            # Toggle ON + wake.
            ann.app.state.auto_announce = True
            ann.wake()

            # The wake should interrupt the wait. Allow a generous slack
            # for thread scheduling but well under the 60s interval.
            deadline = time.monotonic() + 1.0
            while mock_announce.call_count == 0 and time.monotonic() < deadline:
                time.sleep(0.02)

            assert mock_announce.call_count >= 1, (
                "wake() did not interrupt the loop within 1 second; "
                "the announcer would have waited the full announce_interval"
            )

        ann.stop()


class TestAnnouncerStop:
    def test_stop_terminates_loop(self):
        ann = _make_announcer()
        with patch("hokora_tui.announcer.RNS", create=True) as fake_rns:
            fake_rns.Transport.register_announce_handler = MagicMock()
            ann.start()
        ann.stop()
        deadline = time.monotonic() + 1.0
        while ann._auto_thread is not None and ann._auto_thread.is_alive():
            if time.monotonic() > deadline:
                raise AssertionError("auto-announce loop did not stop within 1 second")
            time.sleep(0.02)


class TestStateAnnouncerWiring:
    """The integration point: AppState.set_auto_announce(True) calls
    Announcer.wake. Already covered in test_appstate_setting_chokepoints
    via the MagicMock — this class exercises the real Announcer.wake.
    """

    def test_state_set_auto_announce_wakes_real_announcer(self):
        ann = _make_announcer()
        ann.app.state.set_announcer(ann)
        assert not ann._signal.is_set()
        ann.app.state.set_auto_announce(True)
        assert ann._signal.is_set()
