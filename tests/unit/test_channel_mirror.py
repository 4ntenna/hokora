# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for ChannelMirror: backoff, response routing, lifecycle."""

import threading
from unittest.mock import MagicMock, patch


def _make_mirror(**kwargs):
    """Create a ChannelMirror with mocked RNS."""
    with patch.dict("sys.modules", {"RNS": MagicMock()}):
        import importlib
        import hokora.federation.mirror as mod

        importlib.reload(mod)

        defaults = {
            "remote_destination_hash": b"\xaa" * 16,
            "channel_id": "ch01",
        }
        defaults.update(kwargs)
        return mod.ChannelMirror(**defaults), mod


class TestBackoff:
    def test_backoff_calculation_capped_at_max(self):
        mirror, mod = _make_mirror()
        mirror._attempt = 100  # Very high attempt count
        delay = mirror._get_backoff_delay()
        # max_backoff is 300, jitter adds ±25%
        assert delay <= 300 * 1.25
        assert delay >= 300 * 0.75


class TestHandleResponse:
    def test_handle_response_history_ingests_messages(self):
        ingested = []
        mirror, mod = _make_mirror(ingest_callback=lambda m: ingested.append(m))

        # Build a valid sync response
        from hokora.protocol.wire import encode_sync_response

        resp_bytes = encode_sync_response(
            b"\x00" * 16,
            {
                "action": "history",
                "messages": [
                    {"seq": 5, "body": "hello", "msg_hash": "abc"},
                    {"seq": 10, "body": "world", "msg_hash": "def"},
                ],
                "has_more": False,
            },
        )

        mirror.handle_response(resp_bytes)
        assert len(ingested) == 2
        assert mirror._cursor == 10

    def test_handle_response_routes_handshake(self):
        mirror, mod = _make_mirror()
        handshake_data = []
        mirror._handshake_response_callback = lambda m, d: handshake_data.append(d)

        from hokora.protocol.wire import encode_sync_response

        resp_bytes = encode_sync_response(
            b"\x00" * 16,
            {"action": "federation_handshake", "step": 2, "accepted": True},
        )

        mirror.handle_response(resp_bytes)
        assert len(handshake_data) == 1
        assert handshake_data[0]["step"] == 2

    def test_handle_response_routes_push_ack(self):
        mirror, mod = _make_mirror()
        ack_data = []
        mirror._push_ack_callback = lambda m, d: ack_data.append(d)

        from hokora.protocol.wire import encode_sync_response

        resp_bytes = encode_sync_response(
            b"\x00" * 16,
            {"action": "push_ack", "received": [1, 2, 3]},
        )

        mirror.handle_response(resp_bytes)
        assert len(ack_data) == 1
        assert ack_data[0]["received"] == [1, 2, 3]


class TestStop:
    def test_stop_cancels_reconnect_timer(self):
        mirror, mod = _make_mirror()
        mirror._running = True

        # Set up a mock timer
        timer = MagicMock(spec=threading.Timer)
        mirror._reconnect_timer = timer

        mirror.stop()
        assert mirror._running is False
        timer.cancel.assert_called_once()
        assert mirror._reconnect_timer is None
