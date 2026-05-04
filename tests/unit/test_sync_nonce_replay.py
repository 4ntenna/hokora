# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for server-side nonce replay protection in SyncHandler."""

import os
import threading
import pytest
from unittest.mock import MagicMock

from hokora.constants import SYNC_NODE_META
from hokora.core.channel import ChannelManager
from hokora.core.sequencer import SequenceManager
from hokora.exceptions import VerificationError
from hokora.protocol.sync import SyncHandler
from hokora.protocol.wire import generate_nonce
from hokora.security.verification import NonceTracker


def _make_handler():
    """Create a minimal SyncHandler for nonce replay tests."""
    config = MagicMock()
    config.channels = {}
    identity_mgr = MagicMock()
    ch_mgr = ChannelManager(config, identity_mgr)
    sequencer = SequenceManager()
    return SyncHandler(
        ch_mgr,
        sequencer,
        node_name="TestNode",
        node_description="Test",
        node_identity="testhash",
    )


class TestSyncHandlerNonceReplay:
    """Verify nonce replay protection is enforced in SyncHandler.handle()."""

    async def test_fresh_nonce_accepted(self, session):
        """A fresh nonce should be accepted and the handler dispatches normally."""
        handler = _make_handler()
        nonce = generate_nonce()
        result = await handler.handle(
            session,
            SYNC_NODE_META,
            nonce,
            payload={},
        )
        assert result["node_name"] == "TestNode"

    async def test_replayed_nonce_rejected(self, session):
        """A replayed nonce should raise VerificationError."""
        handler = _make_handler()
        nonce = generate_nonce()

        # First call succeeds
        await handler.handle(session, SYNC_NODE_META, nonce, payload={})

        # Second call with same nonce raises
        with pytest.raises(VerificationError, match="replay"):
            await handler.handle(session, SYNC_NODE_META, nonce, payload={})

    async def test_different_nonces_all_accepted(self, session):
        """Multiple calls with different nonces should all succeed."""
        handler = _make_handler()
        for _ in range(5):
            nonce = generate_nonce()
            result = await handler.handle(
                session,
                SYNC_NODE_META,
                nonce,
                payload={},
            )
            assert result["node_name"] == "TestNode"


class TestNonceTrackerThreadSafety:
    """Verify NonceTracker threading.Lock prevents concurrent duplicate acceptance."""

    def test_concurrent_check_and_record_same_nonce(self):
        """Two threads submitting the same nonce: exactly one should succeed."""
        tracker = NonceTracker()
        nonce = os.urandom(16)
        results = []
        barrier = threading.Barrier(2)

        def worker():
            barrier.wait()
            results.append(tracker.check_and_record(nonce))

        t1 = threading.Thread(target=worker)
        t2 = threading.Thread(target=worker)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert results.count(True) == 1
        assert results.count(False) == 1

    def test_concurrent_different_nonces_all_succeed(self):
        """Different nonces from different threads should all succeed."""
        tracker = NonceTracker()
        nonces = [os.urandom(16) for _ in range(10)]
        results = []
        barrier = threading.Barrier(len(nonces))

        def worker(n):
            barrier.wait()
            results.append(tracker.check_and_record(n))

        threads = [threading.Thread(target=worker, args=(n,)) for n in nonces]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert all(results)
        assert len(tracker) == 10

    def test_nonce_tracker_has_threading_lock(self):
        """NonceTracker must have a threading.Lock instance."""
        tracker = NonceTracker()
        assert isinstance(tracker._lock, type(threading.Lock()))
