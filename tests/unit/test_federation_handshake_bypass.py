# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Test federation handshake auth bypass is prevented.

Verifies that step 3 of the federation handshake cannot skip signature
verification by omitting counter_response or peer_public_key fields.
"""

import os
import time

import pytest

from hokora.core.channel import ChannelManager
from hokora.core.sequencer import SequenceManager
from hokora.exceptions import SyncError
from hokora.protocol.sync import SyncHandler


def _make_handler(**kwargs):
    """Create a minimal SyncHandler for handshake testing."""
    defaults = dict(
        channel_manager=ChannelManager.__new__(ChannelManager),
        sequencer=SequenceManager.__new__(SequenceManager),
        node_name="test-node",
        node_identity="ab" * 16,
        config=type("C", (), {"federation_auto_trust": True})(),
    )
    defaults.update(kwargs)
    return SyncHandler(**defaults)


class _FakePeer:
    """Minimal stand-in for Peer ORM model."""

    def __init__(self):
        self.identity_hash = "cd" * 16
        self.node_name = "attacker"
        self.federation_trusted = False
        self.last_handshake = None
        self.public_key = None


class _FakeSession:
    """Minimal async session stub that returns a fake peer."""

    def __init__(self, peer=None):
        self._peer = peer

    async def execute(self, stmt):
        return _FakeResult(self._peer)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass


class _FakeResult:
    def __init__(self, peer):
        self._peer = peer

    def scalar_one_or_none(self):
        return self._peer


class TestHandshakeBypass:
    """Ensure step 3 rejects incomplete payloads instead of granting trust."""

    async def test_step3_missing_counter_response_raises(self):
        handler = _make_handler()
        peer = _FakePeer()
        session = _FakeSession(peer)

        # Simulate a pending counter-challenge (as if step 1 already happened)
        peer_hash = "cd" * 16
        handler._pending_counter_challenges[peer_hash] = (os.urandom(32), time.time())

        payload = {
            "step": 3,
            "identity_hash": peer_hash,
            "node_name": "attacker",
            # counter_response deliberately omitted
            "peer_public_key": os.urandom(32),
        }

        with pytest.raises(SyncError, match="step 3 incomplete"):
            await handler._handle_federation_handshake(
                session,
                os.urandom(16),
                payload,
                None,
            )

        assert not peer.federation_trusted

    async def test_step3_missing_peer_public_key_raises(self):
        handler = _make_handler()
        peer = _FakePeer()
        session = _FakeSession(peer)

        peer_hash = "cd" * 16
        handler._pending_counter_challenges[peer_hash] = (os.urandom(32), time.time())

        payload = {
            "step": 3,
            "identity_hash": peer_hash,
            "node_name": "attacker",
            "counter_response": os.urandom(64),
            # peer_public_key deliberately omitted
        }

        with pytest.raises(SyncError, match="step 3 incomplete"):
            await handler._handle_federation_handshake(
                session,
                os.urandom(16),
                payload,
                None,
            )

        assert not peer.federation_trusted

    async def test_step3_no_stored_challenge_raises(self):
        handler = _make_handler()
        peer = _FakePeer()
        session = _FakeSession(peer)

        peer_hash = "cd" * 16
        # No pending counter-challenge stored (step 1 never happened)

        payload = {
            "step": 3,
            "identity_hash": peer_hash,
            "node_name": "attacker",
            "counter_response": os.urandom(64),
            "peer_public_key": os.urandom(32),
        }

        with pytest.raises(SyncError, match="step 3 incomplete"):
            await handler._handle_federation_handshake(
                session,
                os.urandom(16),
                payload,
                None,
            )

        assert not peer.federation_trusted

    async def test_step3_all_empty_raises(self):
        handler = _make_handler()
        peer = _FakePeer()
        session = _FakeSession(peer)

        payload = {
            "step": 3,
            "identity_hash": "cd" * 16,
            "node_name": "attacker",
            # All verification fields missing
        }

        with pytest.raises(SyncError, match="step 3 incomplete"):
            await handler._handle_federation_handshake(
                session,
                os.urandom(16),
                payload,
                None,
            )

        assert not peer.federation_trusted
