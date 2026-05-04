# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Step-5 (FS epoch handshake) dispatch contract on the receiver side.

Pinning that step 5 frames are accepted when ``identity_hash`` is present
(used by ``RNS.Identity.recall`` for FS-frame signature verification),
and rejected with a clear per-step error when it isn't.
"""

import os
import time

import pytest

from hokora.core.channel import ChannelManager
from hokora.core.sequencer import SequenceManager
from hokora.exceptions import SyncError
from hokora.protocol.sync import SyncHandler


def _make_handler(**kwargs):
    defaults = dict(
        channel_manager=ChannelManager.__new__(ChannelManager),
        sequencer=SequenceManager.__new__(SequenceManager),
        node_name="receiver-node",
        node_identity="ab" * 16,
        config=type(
            "C",
            (),
            {"federation_auto_trust": True, "fs_enabled": False, "fs_epoch_duration": 3600},
        )(),
    )
    defaults.update(kwargs)
    return SyncHandler(**defaults)


class _FakePeer:
    def __init__(self):
        self.identity_hash = "cd" * 16
        self.node_name = "peer-node"
        self.federation_trusted = True
        self.last_handshake = None
        self.public_key = None


class _FakeResult:
    def __init__(self, peer):
        self._peer = peer

    def scalar_one_or_none(self):
        return self._peer


class _FakeSession:
    def __init__(self, peer=None):
        self._peer = peer

    async def execute(self, stmt):
        return _FakeResult(self._peer)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass


class TestStep5Dispatch:
    async def test_step5_missing_identity_hash_raises_with_step_named(self):
        handler = _make_handler()
        session = _FakeSession(_FakePeer())
        payload = {
            "step": 5,
            "epoch_rotate_frame": b"\x00" * 8,
            # identity_hash deliberately omitted — sender is expected to include
            # it on every step. A handler that forgets to require it on step 5
            # would silently break FS rotations.
        }
        with pytest.raises(SyncError, match="step 5"):
            await handler._handle_federation_handshake(
                session,
                os.urandom(16),
                payload,
                channel_id=None,
                requester_hash=None,
                link=None,
            )

    async def test_step5_missing_epoch_rotate_frame_raises(self):
        handler = _make_handler()
        peer = _FakePeer()
        session = _FakeSession(peer)
        payload = {
            "step": 5,
            "identity_hash": peer.identity_hash,
            # epoch_rotate_frame deliberately omitted
        }
        with pytest.raises(SyncError, match="epoch_rotate_frame"):
            await handler._handle_federation_handshake(
                session,
                os.urandom(16),
                payload,
                channel_id=None,
                requester_hash=None,
                link=None,
            )

    async def test_step1_missing_identity_hash_raises_with_step_named(self):
        handler = _make_handler()
        session = _FakeSession(_FakePeer())
        payload = {
            "step": 1,
            "challenge": os.urandom(32),
        }
        with pytest.raises(SyncError, match="step 1"):
            await handler._handle_federation_handshake(
                session,
                os.urandom(16),
                payload,
                channel_id=None,
                requester_hash=None,
                link=None,
            )

    async def test_step3_missing_identity_hash_raises_with_step_named(self):
        handler = _make_handler()
        session = _FakeSession(_FakePeer())
        peer_hash = "cd" * 16
        handler._pending_counter_challenges[peer_hash] = (os.urandom(32), time.time())
        payload = {
            "step": 3,
            "counter_response": os.urandom(64),
            "peer_public_key": os.urandom(32),
        }
        with pytest.raises(SyncError, match="step 3"):
            await handler._handle_federation_handshake(
                session,
                os.urandom(16),
                payload,
                channel_id=None,
                requester_hash=None,
                link=None,
            )
