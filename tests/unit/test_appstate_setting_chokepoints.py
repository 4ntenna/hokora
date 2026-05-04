# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for the ``AppState.set_auto_announce`` / ``set_announce_interval``
chokepoints. They centralise the persistence + observer broadcast so any
tab that mutates a setting routes through one helper instead of doing
state += persist + emit by hand.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from hokora_tui.state import AppState


def _wire_state() -> tuple[AppState, dict, list]:
    """Build an AppState with a recording persister + observer."""
    state = AppState()
    persisted: dict[str, str] = {}
    state.set_setting_persister(lambda k, v: persisted.update({k: v}))

    aa_events: list[bool] = []
    interval_events: list[int] = []
    state.on("auto_announce_changed", lambda v: aa_events.append(v))
    state.on("announce_interval_changed", lambda v: interval_events.append(v))

    return state, persisted, [aa_events, interval_events]


class TestSetAutoAnnounce:
    def test_writes_field(self):
        state, _, _ = _wire_state()
        state.set_auto_announce(True)
        assert state.auto_announce is True

    def test_persists_via_injected_setter(self):
        state, persisted, _ = _wire_state()
        state.set_auto_announce(True)
        assert persisted == {"auto_announce": "true"}
        state.set_auto_announce(False)
        assert persisted == {"auto_announce": "false"}

    def test_emits_observer_event(self):
        state, _, (aa_events, _) = _wire_state()
        state.set_auto_announce(True)
        state.set_auto_announce(False)
        assert aa_events == [True, False]

    def test_wakes_announcer_on_enable(self):
        state, _, _ = _wire_state()
        announcer = MagicMock()
        state.set_announcer(announcer)
        state.set_auto_announce(True)
        announcer.wake.assert_called_once()

    def test_does_not_wake_announcer_on_disable(self):
        state, _, _ = _wire_state()
        announcer = MagicMock()
        state.set_announcer(announcer)
        state.set_auto_announce(False)
        announcer.wake.assert_not_called()

    def test_no_announcer_does_not_crash(self):
        state, _, _ = _wire_state()
        # No set_announcer call → toggle should not raise.
        state.set_auto_announce(True)
        assert state.auto_announce is True

    def test_no_persister_does_not_crash(self):
        """Pre-DB-init phase or test environments may have no persister."""
        state = AppState()
        state.set_auto_announce(True)
        assert state.auto_announce is True

    def test_coerces_truthy_to_bool(self):
        state, _, _ = _wire_state()
        state.set_auto_announce(1)  # type: ignore[arg-type]
        assert state.auto_announce is True
        state.set_auto_announce("")  # type: ignore[arg-type]
        assert state.auto_announce is False

    def test_persister_exception_does_not_crash(self):
        """Any DB write failure must not raise out of the chokepoint —
        the in-memory state is still updated.
        """
        state = AppState()
        state.set_setting_persister(lambda k, v: (_ for _ in ()).throw(RuntimeError("boom")))
        state.set_auto_announce(True)
        assert state.auto_announce is True


class TestSetAnnounceInterval:
    def test_writes_clamped_field(self):
        state, _, _ = _wire_state()
        state.set_announce_interval(120)
        assert state.announce_interval == 120

    def test_clamps_below_floor(self):
        state, _, _ = _wire_state()
        result = state.set_announce_interval(5)
        assert state.announce_interval == 30
        assert result == 30

    def test_clamps_above_ceiling(self):
        state, _, _ = _wire_state()
        result = state.set_announce_interval(999999)
        assert state.announce_interval == 86400
        assert result == 86400

    def test_clamps_negative(self):
        state, _, _ = _wire_state()
        state.set_announce_interval(-1)
        assert state.announce_interval == 30

    def test_persists_clamped_value(self):
        state, persisted, _ = _wire_state()
        state.set_announce_interval(5)
        assert persisted == {"announce_interval": "30"}

    def test_emits_observer_event_with_clamped_value(self):
        state, _, (_, interval_events) = _wire_state()
        state.set_announce_interval(5)
        state.set_announce_interval(120)
        assert interval_events == [30, 120]

    def test_invalid_input_falls_back_to_default(self):
        state, _, _ = _wire_state()
        state.set_announce_interval("not-a-number")  # type: ignore[arg-type]
        assert state.announce_interval == 300

    def test_returns_clamped_value(self):
        state, _, _ = _wire_state()
        assert state.set_announce_interval(5) == 30
        assert state.set_announce_interval(120) == 120
