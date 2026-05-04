# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Thread safety tests: LinkManager, LiveSubscriptionManager, RateLimiter, response size guard."""

import asyncio
import threading
from unittest.mock import MagicMock, patch


from hokora.exceptions import SyncError


class TestLinkManagerThreadSafety:
    """LinkManager _links dict is protected by a lock — exercised by
    concurrent establish/close from multiple threads."""

    def test_concurrent_link_operations(self):
        """Simulate concurrent link establish/close from multiple threads."""
        with patch("hokora.protocol.link_manager.RNS"):
            from hokora.protocol.link_manager import LinkManager

            loop = asyncio.new_event_loop()
            try:
                lm = LinkManager(loop)
            finally:
                # ``lm`` retains the reference but never schedules against
                # this loop — the test exercises only the threading lock.
                loop.close()
                asyncio.set_event_loop(None)

            errors = []

            def establish_links(start_id, count):
                try:
                    for i in range(count):
                        link = MagicMock()
                        link.link_id = (start_id + i).to_bytes(16, "big")
                        link.get_remote_identity.return_value = None
                        lm.on_link_established(link, f"ch{start_id}")
                except Exception as e:
                    errors.append(e)

            def close_links():
                try:
                    for ctx in lm.get_all_links():
                        lm._on_link_closed(ctx.link)
                except Exception as e:
                    errors.append(e)

            threads = []
            for i in range(5):
                t = threading.Thread(target=establish_links, args=(i * 100, 20))
                threads.append(t)
            for i in range(3):
                t = threading.Thread(target=close_links)
                threads.append(t)

            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=5)

            assert not errors, f"Thread safety errors: {errors}"


class TestLiveSubscriptionThreadSafety:
    """LiveSubscriptionManager is thread-safe under concurrent
    subscribe/unsubscribe and returns defensive copies on read."""

    def test_get_subscribers_returns_copy(self):
        """get_subscribers should return a copy so iteration is safe."""
        with patch("hokora.protocol.live.RNS"):
            from hokora.protocol.live import LiveSubscriptionManager

            lsm = LiveSubscriptionManager()
            link = MagicMock()
            lsm.subscribe("ch1", link)
            subs = lsm.get_subscribers("ch1")
            # Modifying returned set shouldn't affect internal state
            subs.clear()
            assert len(lsm.get_subscribers("ch1")) == 1

    def test_concurrent_subscribe_unsubscribe(self):
        with patch("hokora.protocol.live.RNS"):
            from hokora.protocol.live import LiveSubscriptionManager

            lsm = LiveSubscriptionManager()
            errors = []

            def subscribe_many():
                try:
                    for i in range(50):
                        link = MagicMock()
                        link.status = 0x01
                        lsm.subscribe(f"ch{i % 5}", link)
                except Exception as e:
                    errors.append(e)

            def unsubscribe_many():
                try:
                    for ch_id in [f"ch{i}" for i in range(5)]:
                        for link in lsm.get_subscribers(ch_id):
                            lsm.unsubscribe(ch_id, link)
                except Exception as e:
                    errors.append(e)

            threads = [
                threading.Thread(target=subscribe_many),
                threading.Thread(target=subscribe_many),
                threading.Thread(target=unsubscribe_many),
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=5)

            assert not errors


class TestResponseSizeGuard:
    """4A: Response size guard in LinkManager."""

    def test_link_manager_handles_sync_error_on_encode(self):
        """If encode_sync_response raises SyncError, should truncate and retry."""
        from hokora.protocol.link_manager import LinkManager, LinkContext

        loop = asyncio.new_event_loop()

        # Run the loop in a background thread so run_coroutine_threadsafe works
        loop_thread = threading.Thread(target=loop.run_forever, daemon=True)
        loop_thread.start()

        try:
            with patch("hokora.protocol.link_manager.RNS") as mock_rns:
                mock_rns.Link.MDU = 500
                lm = LinkManager(loop)

                call_count = 0

                def mock_encode(nonce, data, **kwargs):
                    nonlocal call_count
                    call_count += 1
                    if call_count == 1:
                        raise SyncError("Frame too large")
                    return b"\x00" * 10

                with patch(
                    "hokora.protocol.link_manager.encode_sync_response",
                    side_effect=mock_encode,
                ):

                    async def handler(action, nonce, payload, ch_id, requester_hash, **kw):
                        return {"messages": [{"body": "x"}] * 100}

                    lm.set_sync_handler(handler)

                    mock_link = MagicMock()
                    mock_link.link_id = b"\x01" * 16
                    mock_packet = MagicMock()
                    mock_packet.link = mock_link

                    ctx = LinkContext(mock_link, "ch1")
                    with lm._links_lock:
                        lm._links[mock_link.link_id] = ctx

                    from hokora.protocol.wire import encode_sync_request
                    from hokora.constants import SYNC_HISTORY

                    nonce = b"\x00" * 16
                    request_bytes = encode_sync_request(SYNC_HISTORY, nonce, {"channel_id": "ch1"})

                    lm._on_packet(request_bytes, mock_packet)

                    # Should have called encode twice (first fails, truncated retry)
                    assert call_count == 2
        finally:
            loop.call_soon_threadsafe(loop.stop)
            loop_thread.join(timeout=5)
            loop.close()
            asyncio.set_event_loop(None)
