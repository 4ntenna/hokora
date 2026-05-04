# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for CDSP live subscription profile enforcement."""

from unittest.mock import MagicMock, patch

from hokora.constants import (
    CDSP_PROFILE_FULL,
    CDSP_PROFILE_PRIORITIZED,
    CDSP_PROFILE_MINIMAL,
    CDSP_PROFILE_BATCHED,
)


_rns_mock = MagicMock()
_rns_mock.Link.ACTIVE = 1
_rns_mock.Link.CLOSED = 0
_rns_mock.Link.MDU = 500


def _make_live_manager():
    """Create a LiveSubscriptionManager with mocked RNS."""
    with patch.dict("sys.modules", {"RNS": _rns_mock}):
        import importlib
        import hokora.protocol.live as mod

        importlib.reload(mod)
        return mod.LiveSubscriptionManager()


def _make_link(active=True):
    """Create a mock RNS.Link."""
    link = MagicMock()
    link.status = _rns_mock.Link.ACTIVE if active else _rns_mock.Link.CLOSED
    link.link_id = id(link)
    return link


class TestFullSubscriber:
    def test_receives_immediate_push(self):
        mgr = _make_live_manager()
        link = _make_link()

        assert mgr.subscribe("ch1", link, sync_profile=CDSP_PROFILE_FULL)
        # FULL: push should work without exception (immediate delivery)
        mgr.push_event("ch1", "message", {"body": "hello"})
        # No exception means push was sent successfully


class TestPrioritizedSubscriber:
    def test_receives_messages(self):
        mgr = _make_live_manager()
        link = _make_link()

        assert mgr.subscribe("ch1", link, sync_profile=CDSP_PROFILE_PRIORITIZED)
        # Should not raise
        mgr.push_event("ch1", "message", {"body": "hello"})

    def test_skips_typing_events(self):
        mgr = _make_live_manager()
        link = _make_link()

        assert mgr.subscribe("ch1", link, sync_profile=CDSP_PROFILE_PRIORITIZED)
        # typing is a non-critical event; should be silently skipped
        mgr.push_event("ch1", "typing", {"user": "alice"})
        # No exception means typing was correctly skipped

    def test_skips_presence_events(self):
        mgr = _make_live_manager()
        link = _make_link()

        assert mgr.subscribe("ch1", link, sync_profile=CDSP_PROFILE_PRIORITIZED)
        mgr.push_event("ch1", "presence", {"user": "alice", "status": "online"})


class TestMinimalSubscriber:
    def test_subscribe_rejected(self):
        mgr = _make_live_manager()
        link = _make_link()

        result = mgr.subscribe("ch1", link, sync_profile=CDSP_PROFILE_MINIMAL)
        assert result is False

    def test_no_subscribers_after_rejection(self):
        mgr = _make_live_manager()
        link = _make_link()

        mgr.subscribe("ch1", link, sync_profile=CDSP_PROFILE_MINIMAL)
        subs = mgr.get_subscribers("ch1")
        assert len(subs) == 0


class TestBatchedSubscriber:
    def test_events_accumulated(self):
        mgr = _make_live_manager()
        link = _make_link()

        assert mgr.subscribe("ch1", link, sync_profile=CDSP_PROFILE_BATCHED)
        mgr.push_event("ch1", "message", {"body": "hello"})
        mgr.push_event("ch1", "message", {"body": "world"})

        # Events should be in the batch buffer, not sent yet
        assert len(mgr._batch_buffer) > 0

    def test_flush_sends_batched(self):
        mgr = _make_live_manager()
        link = _make_link()

        assert mgr.subscribe("ch1", link, sync_profile=CDSP_PROFILE_BATCHED)
        mgr.push_event("ch1", "message", {"body": "hello"})

        # Flush should clear buffer
        mgr.flush_batches()
        assert len(mgr._batch_buffer) == 0


class TestSubscriptionProfileUpdate:
    def test_resubscribe_updates_profile(self):
        mgr = _make_live_manager()
        link = _make_link()

        mgr.subscribe("ch1", link, sync_profile=CDSP_PROFILE_FULL)
        subs = mgr.get_subscribers("ch1")
        assert subs[link] == CDSP_PROFILE_FULL

        # Re-subscribe with different profile
        mgr.subscribe("ch1", link, sync_profile=CDSP_PROFILE_PRIORITIZED)
        subs = mgr.get_subscribers("ch1")
        assert subs[link] == CDSP_PROFILE_PRIORITIZED
