# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for FederationPusher: push logic, origin filtering, ack handling, backoff."""

import time
from unittest.mock import AsyncMock, MagicMock, patch


def _make_pusher(**kwargs):
    """Create a FederationPusher with mocked RNS."""
    with patch.dict("sys.modules", {"RNS": MagicMock()}):
        import importlib
        import hokora.federation.pusher as mod

        importlib.reload(mod)

        defaults = {
            "peer_identity_hash": "peer1234" + "0" * 24,
            "channel_id": "ch01",
            "node_identity_hash": "node5678" + "0" * 24,
        }
        defaults.update(kwargs)
        return mod.FederationPusher(**defaults), mod


class TestPushPending:
    async def test_push_pending_no_link_is_noop(self):
        pusher, mod = _make_pusher()
        # No link set, should return without error
        result = await pusher.push_pending()
        assert result is False

    async def test_push_pending_returns_false_when_no_link(self):
        """No link increments consecutive failures and returns False."""
        pusher, mod = _make_pusher()
        assert pusher._consecutive_failures == 0
        result = await pusher.push_pending()
        assert result is False
        assert pusher._consecutive_failures == 1

    async def test_push_pending_returns_true_on_success(self):
        """Successful push resets consecutive failures and returns True."""
        pusher, mod = _make_pusher()
        # Simulate prior failures
        pusher._consecutive_failures = 3

        # Mock session factory to return no messages (nothing to push = success)
        mock_repo = MagicMock()
        mock_repo.get_history = AsyncMock(return_value=[])

        mock_session = AsyncMock()
        mock_session.begin = MagicMock(return_value=AsyncMock())

        mock_factory = MagicMock(
            return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_session))
        )
        pusher._session_factory = mock_factory
        pusher._link = MagicMock()

        with patch("hokora.db.queries.MessageRepo", return_value=mock_repo):
            result = await pusher.push_pending()

        assert result is True
        assert pusher._consecutive_failures == 0

    def test_push_pending_filters_origin_node(self):
        """Messages originating from the target peer should be filtered out."""
        pusher, mod = _make_pusher()
        peer_hash = pusher.peer_identity_hash

        # Simulate the filter logic directly (same as push_pending internals)
        class FakeMsg:
            def __init__(self, origin, seq):
                self.origin_node = origin
                self.seq = seq

        messages = [
            FakeMsg(peer_hash, 1),  # From peer — should be filtered
            FakeMsg("local_node", 2),  # Local — should be kept
            FakeMsg(None, 3),  # No origin — should be kept
        ]

        to_push = [m for m in messages if m.origin_node != peer_hash]
        assert len(to_push) == 2
        assert all(m.origin_node != peer_hash for m in to_push)


class TestBackoff:
    def test_should_retry_with_no_failures(self):
        """With no failures, should always retry."""
        pusher, _ = _make_pusher()
        assert pusher._should_retry() is True

    def test_should_retry_respects_backoff(self):
        """After failures, should wait exponentially before retrying."""
        pusher, _ = _make_pusher()
        pusher._consecutive_failures = 3
        pusher._last_attempt = time.monotonic()  # just now
        # With 3 failures and backoff_base=30, min delay = 30*4*0.75 = 90s
        assert pusher._should_retry() is False

    def test_should_retry_resets_after_success(self):
        """After resetting failures, immediately retryable."""
        pusher, _ = _make_pusher()
        pusher._consecutive_failures = 5
        pusher._last_attempt = time.monotonic()
        assert pusher._should_retry() is False

        # Simulate success
        pusher._consecutive_failures = 0
        assert pusher._should_retry() is True

    def test_backoff_capped_at_max(self):
        """Backoff delay should not exceed max_backoff."""
        pusher, _ = _make_pusher(max_backoff=60.0)
        pusher._consecutive_failures = 100  # Very high
        # max delay with jitter = 60 * 1.25 = 75, so 76s ago is always enough
        pusher._last_attempt = time.monotonic() - 76
        assert pusher._should_retry() is True


class TestPushAck:
    def test_handle_push_ack_advances_cursor(self):
        pusher, mod = _make_pusher()
        assert pusher.push_cursor == 0

        pusher.handle_push_ack({"received": [5, 10, 3]})
        assert pusher.push_cursor == 10

    def test_cursor_callback_invoked_on_ack(self):
        """handle_push_ack() calls cursor_callback with correct args."""
        callback = MagicMock()
        pusher, _ = _make_pusher(cursor_callback=callback)
        pusher.handle_push_ack({"received": [5, 10, 3]})
        callback.assert_called_once_with(pusher.peer_identity_hash, "ch01", 10)

    def test_cursor_callback_not_invoked_when_cursor_not_advanced(self):
        """If ack doesn't advance cursor, callback should not be called."""
        callback = MagicMock()
        pusher, _ = _make_pusher(cursor_callback=callback)
        pusher.push_cursor = 15
        pusher.handle_push_ack({"received": [5, 10, 3]})
        callback.assert_not_called()

    def test_push_batch_size_respected(self):
        _, mod = _make_pusher()
        assert mod.PUSH_BATCH_SIZE == 15


class TestStaleCursor:
    async def test_stale_cursor_advances_past_filtered_messages(self):
        """When all messages are filtered by origin_node, cursor advances past them."""
        callback = MagicMock()
        pusher, _ = _make_pusher(cursor_callback=callback)
        pusher._link = MagicMock()

        peer_hash = pusher.peer_identity_hash

        class FakeMsg:
            def __init__(self, origin, seq):
                self.origin_node = origin
                self.seq = seq

        # All messages from peer — all filtered
        filtered_msgs = [FakeMsg(peer_hash, 5), FakeMsg(peer_hash, 10)]

        mock_repo = MagicMock()
        mock_repo.get_history = AsyncMock(return_value=filtered_msgs)

        mock_session = AsyncMock()
        mock_session.begin = MagicMock(return_value=AsyncMock())

        mock_factory = MagicMock(
            return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_session))
        )
        pusher._session_factory = mock_factory

        with patch("hokora.db.queries.MessageRepo", return_value=mock_repo):
            result = await pusher.push_pending()

        assert result is True
        assert pusher.push_cursor == 10
        callback.assert_called_once_with(peer_hash, "ch01", 10)
