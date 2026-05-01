# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""N3 cold-start fix: ChannelMirror state machine + MirrorLifecycleManager wake-up.

Covers the four invariants that turn the regression into a build failure:

1. ``recall()=None`` parks the mirror in WAITING_FOR_PATH instead of
   silently returning, with a backoff timer scheduled.
2. ``wake()`` is no-op while the mirror is already CONNECTING/LINKED
   (idempotent under timer + announce race).
3. ``MirrorLifecycleManager.wake_for_hash`` matches by identity hash
   and only wakes parked mirrors.
4. The attempt callback fires with the right result strings so the
   Prometheus counter is meaningful.
"""

from __future__ import annotations

import importlib
import threading
from unittest.mock import MagicMock, patch


def _load_mirror_module(rns_mock):
    """Load (or reload) the mirror module with a controllable RNS stand-in."""
    with patch.dict("sys.modules", {"RNS": rns_mock}):
        import hokora.federation.mirror as mod

        importlib.reload(mod)
        return mod


def _make_rns_mock(*, recall_returns=None, link_raises=False):
    """Build an RNS stand-in for one mirror's lifetime.

    recall_returns: a deque-like list of values for successive calls;
        each call pops the front. Falsy values simulate the cold path.
    link_raises: when True, RNS.Link() raises — exercises the
        link_failed branch of _connect.
    """
    rns = MagicMock(name="RNS")
    queue = list(recall_returns or [])

    def recall(_h):
        if not queue:
            return None
        return queue.pop(0)

    rns.Identity.recall.side_effect = recall

    if link_raises:
        rns.Link.side_effect = RuntimeError("boom")
    else:
        rns.Link.return_value = MagicMock(name="Link")

    rns.Destination.OUT = "OUT"
    rns.Destination.SINGLE = "SINGLE"
    rns.Destination.return_value = MagicMock(name="Destination")
    return rns


class TestStateMachineColdStart:
    def test_recall_none_parks_in_waiting_for_path(self):
        rns = _make_rns_mock(recall_returns=[None])
        mod = _load_mirror_module(rns)

        attempts = []
        mirror = mod.ChannelMirror(
            remote_destination_hash=b"\xaa" * 16,
            channel_id="ch01",
            attempt_callback=attempts.append,
        )
        # Replace the threading.Timer so the test is deterministic
        mirror._reconnect_timer = None
        with patch.object(threading, "Timer") as MockTimer:
            MockTimer.return_value = MagicMock()
            mirror.start(MagicMock(name="Reticulum"))

        assert mirror.state == mod.MirrorState.WAITING_FOR_PATH
        assert mirror._link is None
        # Timer scheduled — recovery path exists
        assert MockTimer.called, "Expected a backoff timer to be scheduled"
        # Attempt counter wired through
        assert "recall_none" in attempts

    def test_first_few_recall_failures_log_at_info(self):
        rns = _make_rns_mock(recall_returns=[None])
        mod = _load_mirror_module(rns)

        mirror = mod.ChannelMirror(
            remote_destination_hash=b"\xbb" * 16,
            channel_id="ch02",
        )
        with patch.object(threading, "Timer") as MockTimer:
            MockTimer.return_value = MagicMock()
            with (
                patch.object(mod.logger, "info") as mock_info,
                patch.object(mod.logger, "warning") as mock_warning,
            ):
                mirror.start(MagicMock())

                # First failure → INFO, never WARNING.
                assert mock_info.called
                assert not any(
                    "Cannot recall identity" in str(call.args[0])
                    for call in mock_warning.call_args_list
                )

    def test_persistent_recall_failures_promote_to_warning(self):
        # Need to walk through enough attempts to cross the threshold
        rns = _make_rns_mock(recall_returns=[])  # always None
        mod = _load_mirror_module(rns)

        mirror = mod.ChannelMirror(
            remote_destination_hash=b"\xcc" * 16,
            channel_id="ch03",
        )
        # Force state out of CONNECTING/LINKED so _handle_recall_none
        # can be exercised repeatedly without resetting.
        with (
            patch.object(mod.logger, "warning") as mock_warning,
            patch.object(threading, "Timer") as MockTimer,
        ):
            MockTimer.return_value = MagicMock()
            mirror._running = True
            for _ in range(6):  # > _RECALL_WARN_AFTER_ATTEMPTS
                # Reset state so _connect's idempotency guard doesn't
                # short-circuit our deliberately-repeated probe.
                mirror._state = mod.MirrorState.IDLE
                mirror._connect()

            # At least one WARNING entry once we crossed the threshold.
            assert any(
                "Cannot recall identity" in str(call.args[0])
                for call in mock_warning.call_args_list
            ), "Expected WARNING after threshold"


class TestStateMachineSuccess:
    def test_recall_success_creates_link_and_records_attempt(self):
        rns = _make_rns_mock(recall_returns=[MagicMock(name="DestIdentity")])
        mod = _load_mirror_module(rns)

        attempts = []
        mirror = mod.ChannelMirror(
            remote_destination_hash=b"\xdd" * 16,
            channel_id="ch04",
            attempt_callback=attempts.append,
        )
        mirror.start(MagicMock())

        # State stays at CONNECTING until _on_linked fires (we don't
        # actually have a Link callback here, just verifying the path).
        assert mirror.state == mod.MirrorState.CONNECTING
        assert mirror._link is not None
        # Now simulate the link-established callback
        mirror._on_linked(mirror._link)
        assert mirror.state == mod.MirrorState.LINKED
        assert "success" in attempts


class TestWakeIdempotency:
    def test_wake_no_op_while_connecting(self):
        rns = _make_rns_mock(recall_returns=[None])
        mod = _load_mirror_module(rns)

        mirror = mod.ChannelMirror(
            remote_destination_hash=b"\xee" * 16,
            channel_id="ch05",
        )
        # Pretend we're mid-connect
        mirror._running = True
        mirror._state = mod.MirrorState.CONNECTING

        # wake() should NOT trigger a new connect attempt
        with patch.object(mirror, "_connect") as mock_connect:
            assert mirror.wake() is False
            assert not mock_connect.called

    def test_wake_no_op_while_linked(self):
        rns = _make_rns_mock(recall_returns=[None])
        mod = _load_mirror_module(rns)

        mirror = mod.ChannelMirror(
            remote_destination_hash=b"\xff" * 16,
            channel_id="ch06",
        )
        mirror._running = True
        mirror._state = mod.MirrorState.LINKED

        with patch.object(mirror, "_connect") as mock_connect:
            assert mirror.wake() is False
            assert not mock_connect.called

    def test_wake_from_waiting_for_path_invokes_connect(self):
        rns = _make_rns_mock(recall_returns=[None])
        mod = _load_mirror_module(rns)

        mirror = mod.ChannelMirror(
            remote_destination_hash=b"\x11" * 16,
            channel_id="ch07",
        )
        mirror._running = True
        mirror._state = mod.MirrorState.WAITING_FOR_PATH

        with patch.object(mirror, "_connect") as mock_connect:
            assert mirror.wake() is True
            mock_connect.assert_called_once()

    def test_wake_cancels_pending_timer(self):
        rns = _make_rns_mock(recall_returns=[None])
        mod = _load_mirror_module(rns)

        mirror = mod.ChannelMirror(
            remote_destination_hash=b"\x22" * 16,
            channel_id="ch08",
        )
        mirror._running = True
        mirror._state = mod.MirrorState.WAITING_FOR_PATH
        timer = MagicMock(spec=threading.Timer)
        mirror._reconnect_timer = timer

        with patch.object(mirror, "_connect"):
            mirror.wake()
            timer.cancel.assert_called_once()


class TestLinkConstructionFailure:
    def test_link_raise_records_link_failed_and_schedules_retry(self):
        rns = _make_rns_mock(recall_returns=[MagicMock()], link_raises=True)
        mod = _load_mirror_module(rns)

        attempts = []
        mirror = mod.ChannelMirror(
            remote_destination_hash=b"\x33" * 16,
            channel_id="ch09",
            attempt_callback=attempts.append,
        )
        with patch.object(threading, "Timer") as MockTimer:
            MockTimer.return_value = MagicMock()
            mirror.start(MagicMock())

            assert mirror.state == mod.MirrorState.CLOSED
            assert "link_failed" in attempts
            assert MockTimer.called


class TestMirrorLifecycleManagerWakeUp:
    def _make_manager_with_mirrors(self, hashes):
        from hokora.core.mirror_manager import MirrorLifecycleManager

        mgr = MirrorLifecycleManager(session_factory=MagicMock())
        for h in hashes:
            m = MagicMock()
            m.remote_hash = h
            m.channel_id = "x"
            m.state = MagicMock()
            m.state.value = "waiting_for_path"
            m.wake.return_value = True
            mgr._mirrors[f"{h.hex()}:x"] = m
        return mgr

    def test_wake_for_hash_matches_only_keyed_mirrors(self):
        a, b = b"\xaa" * 16, b"\xbb" * 16
        mgr = self._make_manager_with_mirrors([a, b])

        woken = mgr.wake_for_hash(a)
        assert woken == 1
        mgr._mirrors[f"{a.hex()}:x"].wake.assert_called_once()
        mgr._mirrors[f"{b.hex()}:x"].wake.assert_not_called()

    def test_wake_for_hash_returns_zero_when_none_match(self):
        a = b"\xaa" * 16
        mgr = self._make_manager_with_mirrors([a])
        assert mgr.wake_for_hash(b"\xff" * 16) == 0
        mgr._mirrors[f"{a.hex()}:x"].wake.assert_not_called()

    def test_attempt_callback_increments_counter(self):
        from hokora.core.mirror_manager import MirrorLifecycleManager

        mgr = MirrorLifecycleManager(session_factory=MagicMock())
        cb = mgr.make_attempt_callback()
        cb("recall_none")
        cb("recall_none")
        cb("success")
        assert mgr.connect_attempts == {"recall_none": 2, "success": 1}

    def test_state_summary_counts_by_state(self):
        from hokora.core.mirror_manager import MirrorLifecycleManager
        from hokora.federation.mirror import MirrorState

        mgr = MirrorLifecycleManager(session_factory=MagicMock())
        for i, st in enumerate(
            [MirrorState.LINKED, MirrorState.LINKED, MirrorState.WAITING_FOR_PATH]
        ):
            m = MagicMock()
            m.remote_hash = bytes([i]) * 16
            m.state = st
            mgr._mirrors[f"k{i}"] = m
        assert mgr.state_summary() == {"linked": 2, "waiting_for_path": 1}


class TestPeerDiscoveryWakeWiring:
    def test_announce_wakes_mirror_keyed_on_destination_hash(self):
        """Mirrors are keyed on destination_hash (per cli/mirror.py — the
        operator-facing arg is ``<remote_dest_hash>`` even though the
        persisted column is misleadingly named Peer.identity_hash).
        Wake-up must therefore use destination_hash, NOT
        announced_identity.hash, so the wake's recall() can succeed.
        """
        from hokora.federation.peering import PeerDiscovery

        wake_calls: list[bytes] = []

        class _Mgr:
            def wake_for_hash(self, h):
                wake_calls.append(h)
                return 1

        pd = PeerDiscovery(mirror_manager=_Mgr())
        dest_hash = b"\xde" * 16
        ident = MagicMock()
        ident.hash = b"\x42" * 16  # different from dest_hash on purpose
        pd.handle_announce(dest_hash, ident, app_data=None)

        assert wake_calls == [dest_hash], f"Wake must use destination_hash; got {wake_calls!r}"

    def test_announce_with_no_destination_does_not_wake(self):
        from hokora.federation.peering import PeerDiscovery

        wake_calls: list[bytes] = []

        class _Mgr:
            def wake_for_hash(self, h):
                wake_calls.append(h)
                return 0

        pd = PeerDiscovery(mirror_manager=_Mgr())
        # Non-bytes destination_hash → skipped
        pd.handle_announce(None, None, app_data=None)
        assert wake_calls == []
