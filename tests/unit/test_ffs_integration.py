# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Integration tests for Forward Secrecy across components."""

import pytest
import pytest_asyncio

from hokora.federation.epoch_manager import EpochManager
from hokora.federation.epoch_wire import is_epoch_frame
from tests._factories import make_mock_rns_identity as _make_mock_identity


def _handshake_pair():
    """Create and complete handshake for a pair of EpochManagers."""
    id_a = _make_mock_identity()
    id_b = _make_mock_identity()

    em_a = EpochManager("bb" * 16, True, id_a, epoch_duration=3600, peer_rns_identity=id_b)
    em_b = EpochManager("aa" * 16, False, id_b, epoch_duration=3600, peer_rns_identity=id_a)

    rotate = em_a.create_epoch_rotate()
    ack = em_b.handle_epoch_rotate(rotate)
    em_a.handle_epoch_rotate_ack(ack)

    return em_a, em_b


class TestTwoPeerScenario:
    def test_full_message_exchange(self):
        """Two peers exchange multiple messages after epoch establishment."""
        em_a, em_b = _handshake_pair()

        for i in range(10):
            msg = f"message {i}".encode()
            encrypted = em_a.encrypt(msg)
            assert is_epoch_frame(encrypted)
            decrypted = em_b.decrypt(encrypted)
            assert decrypted == msg

        for i in range(10):
            msg = f"reply {i}".encode()
            encrypted = em_b.encrypt(msg)
            decrypted = em_a.decrypt(encrypted)
            assert decrypted == msg

    def test_rotation_mid_conversation(self):
        """Messages work across a mid-conversation key rotation."""
        em_a, em_b = _handshake_pair()

        # Send under epoch 1
        enc1 = em_a.encrypt(b"before rotation")
        dec1 = em_b.decrypt(enc1)
        assert dec1 == b"before rotation"

        # Rotate to epoch 2
        rotate2 = em_a.create_epoch_rotate()
        ack2 = em_b.handle_epoch_rotate(rotate2)
        em_a.handle_epoch_rotate_ack(ack2)

        # Send under epoch 2
        enc2 = em_a.encrypt(b"after rotation")
        dec2 = em_b.decrypt(enc2)
        assert dec2 == b"after rotation"

    def test_multiple_rotations(self):
        """5 rotations with messages between each."""
        em_a, em_b = _handshake_pair()

        for epoch in range(5):
            msg = f"epoch {epoch + 1} msg".encode()
            enc = em_a.encrypt(msg)
            dec = em_b.decrypt(enc)
            assert dec == msg

            if epoch < 4:
                rotate = em_a.create_epoch_rotate()
                ack = em_b.handle_epoch_rotate(rotate)
                em_a.handle_epoch_rotate_ack(ack)

        assert em_a._current_epoch_id == 5  # 1 initial + 4 rotations


class TestLegacyFallback:
    def test_non_epoch_frame_passthrough(self):
        """Non-epoch frames are not detected as epoch frames."""
        # Typical msgpack data
        msgpack_data = b"\x83\xa6action\xa7history"
        assert not is_epoch_frame(msgpack_data)

    def test_epoch_manager_inactive_by_default(self):
        """EpochManager is not active before handshake."""
        em = EpochManager("xx" * 16, True, _make_mock_identity())
        assert not em.is_active


class TestRestartRecovery:
    @pytest_asyncio.fixture
    async def session_factory(self, engine):
        from hokora.db.engine import create_session_factory

        return create_session_factory(engine)

    async def test_persist_and_load_state(self, session_factory):
        """Epoch state survives persist/load cycle."""
        em_a, em_b = _handshake_pair()
        em_a._session_factory = session_factory

        await em_a.persist_state()

        # Create a new manager and load state
        em_restored = EpochManager(
            "bb" * 16, True, _make_mock_identity(), session_factory=session_factory
        )
        await em_restored.load_state()

        assert em_restored._current_epoch_id == em_a._current_epoch_id
        assert em_restored._message_counter == em_a._message_counter
        assert em_restored._last_chain_hash == em_a._last_chain_hash


class TestCDSPCoexistence:
    def test_epoch_frame_detection_does_not_affect_cdsp(self):
        """CDSP session init frames (0x0E) are not epoch frames."""
        cdsp_frame = bytes([0x0E]) + b"\x00" * 50
        assert not is_epoch_frame(cdsp_frame)

    def test_all_sync_actions_not_epoch(self):
        """All existing sync action codes (0x01-0x11) are not epoch frames."""
        for action_code in range(0x01, 0x12):
            data = bytes([action_code]) + b"\x00" * 50
            assert not is_epoch_frame(data)


class TestTeardownCleanup:
    def test_double_teardown_safe(self):
        """Calling teardown twice doesn't crash."""
        em_a, _ = _handshake_pair()
        em_a.teardown()
        em_a.teardown()  # should not raise

    def test_teardown_then_encrypt_raises(self):
        """Cannot encrypt after teardown."""
        em_a, em_b = _handshake_pair()
        em_a.teardown()
        from hokora.exceptions import EpochError

        with pytest.raises(EpochError):
            em_a.encrypt(b"nope")
