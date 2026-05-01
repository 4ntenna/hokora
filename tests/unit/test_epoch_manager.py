# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for EpochManager state machine."""

from unittest.mock import MagicMock

import pytest

from hokora.exceptions import EpochError
from hokora.federation.epoch_manager import EpochManager
from tests._factories import make_mock_rns_identity as _make_mock_identity


def _make_pair():
    """Create a matched initiator/responder EpochManager pair."""
    id_init = _make_mock_identity()
    id_resp = _make_mock_identity()

    initiator = EpochManager(
        peer_identity_hash="bb" * 16,
        is_initiator=True,
        local_rns_identity=id_init,
        epoch_duration=3600,
        peer_rns_identity=id_resp,
    )
    responder = EpochManager(
        peer_identity_hash="aa" * 16,
        is_initiator=False,
        local_rns_identity=id_resp,
        epoch_duration=3600,
        peer_rns_identity=id_init,
    )
    return initiator, responder


class TestHandshake:
    def test_full_handshake(self):
        """Initiator creates EpochRotate -> responder handles -> initiator handles Ack."""
        initiator, responder = _make_pair()

        # Step 5: initiator creates rotate frame
        rotate_frame = initiator.create_epoch_rotate()
        assert not initiator.is_active  # not yet, waiting for ack

        # Step 5: responder processes and returns ack
        ack_frame = responder.handle_epoch_rotate(rotate_frame)
        assert responder.is_active
        assert responder._current_epoch_id == 1

        # Step 6: initiator processes ack
        initiator.handle_epoch_rotate_ack(ack_frame)
        assert initiator.is_active
        assert initiator._current_epoch_id == 1

    def test_bidirectional_encrypt_decrypt(self):
        """After handshake, both sides can encrypt/decrypt in both directions."""
        initiator, responder = _make_pair()

        rotate = initiator.create_epoch_rotate()
        ack = responder.handle_epoch_rotate(rotate)
        initiator.handle_epoch_rotate_ack(ack)

        # Initiator -> Responder
        msg1 = b"hello from initiator"
        encrypted1 = initiator.encrypt(msg1)
        decrypted1 = responder.decrypt(encrypted1)
        assert decrypted1 == msg1

        # Responder -> Initiator
        msg2 = b"hello from responder"
        encrypted2 = responder.encrypt(msg2)
        decrypted2 = initiator.decrypt(encrypted2)
        assert decrypted2 == msg2


class TestRotation:
    def test_chain_hash_continuity(self):
        """Chain hash updates across 3 rotations."""
        initiator, responder = _make_pair()

        hashes = []
        for i in range(3):
            rotate = initiator.create_epoch_rotate()
            ack = responder.handle_epoch_rotate(rotate)
            initiator.handle_epoch_rotate_ack(ack)
            hashes.append(initiator._last_chain_hash)

        # All hashes should be unique
        assert len(set(hashes)) == 3
        assert initiator._current_epoch_id == 3

    def test_chain_hash_mismatch_rejected(self):
        """Responder rejects EpochRotate with wrong chain hash."""
        initiator, responder = _make_pair()

        # Complete first epoch
        rotate = initiator.create_epoch_rotate()
        ack = responder.handle_epoch_rotate(rotate)
        initiator.handle_epoch_rotate_ack(ack)

        # Tamper with initiator's chain hash
        initiator._last_chain_hash = b"\xff" * 32

        rotate2 = initiator.create_epoch_rotate()
        with pytest.raises(EpochError, match="Chain hash mismatch"):
            responder.handle_epoch_rotate(rotate2)

    def test_epoch_id_regression_rejected(self):
        """Responder rejects EpochRotate with non-increasing epoch ID."""
        initiator, responder = _make_pair()

        rotate = initiator.create_epoch_rotate()
        ack = responder.handle_epoch_rotate(rotate)
        initiator.handle_epoch_rotate_ack(ack)

        # Manually craft a rotate with old epoch_id
        initiator._current_epoch_id = 0  # regress
        rotate_bad = initiator.create_epoch_rotate()
        with pytest.raises(EpochError, match="Epoch ID regression"):
            responder.handle_epoch_rotate(rotate_bad)


class TestTransitionWindow:
    def test_old_key_works_during_transition(self):
        """Previous epoch key works until first successful decrypt under new key."""
        initiator, responder = _make_pair()

        # Epoch 1
        rotate1 = initiator.create_epoch_rotate()
        ack1 = responder.handle_epoch_rotate(rotate1)
        initiator.handle_epoch_rotate_ack(ack1)

        # Encrypt under epoch 1
        msg_epoch1 = initiator.encrypt(b"epoch1 message")

        # Rotate to epoch 2
        rotate2 = initiator.create_epoch_rotate()
        ack2 = responder.handle_epoch_rotate(rotate2)
        initiator.handle_epoch_rotate_ack(ack2)

        # Responder should still be able to decrypt epoch 1 message
        # (prev key retained during transition)
        decrypted = responder.decrypt(msg_epoch1)
        assert decrypted == b"epoch1 message"

    def test_old_key_erased_after_new_key_decrypt(self):
        """After first successful decrypt under new key, prev key is erased."""
        initiator, responder = _make_pair()

        # Epoch 1
        rotate1 = initiator.create_epoch_rotate()
        ack1 = responder.handle_epoch_rotate(rotate1)
        initiator.handle_epoch_rotate_ack(ack1)

        msg_epoch1 = initiator.encrypt(b"epoch1")

        # Epoch 2
        rotate2 = initiator.create_epoch_rotate()
        ack2 = responder.handle_epoch_rotate(rotate2)
        initiator.handle_epoch_rotate_ack(ack2)

        # Decrypt under new key first
        msg_epoch2 = initiator.encrypt(b"epoch2")
        responder.decrypt(msg_epoch2)

        # Now old key should be erased
        assert responder._prev_recv_key is None

        # Decrypting old epoch message should fail
        with pytest.raises(EpochError, match="No key for epoch"):
            responder.decrypt(msg_epoch1)


class TestCounterAndNonce:
    def test_counter_increments(self):
        initiator, responder = _make_pair()
        rotate = initiator.create_epoch_rotate()
        ack = responder.handle_epoch_rotate(rotate)
        initiator.handle_epoch_rotate_ack(ack)

        assert initiator._message_counter == 0
        initiator.encrypt(b"msg1")
        assert initiator._message_counter == 1
        initiator.encrypt(b"msg2")
        assert initiator._message_counter == 2

    def test_nonce_overflow_raises(self):
        initiator, responder = _make_pair()
        rotate = initiator.create_epoch_rotate()
        ack = responder.handle_epoch_rotate(rotate)
        initiator.handle_epoch_rotate_ack(ack)

        initiator._message_counter = 2**63
        with pytest.raises(EpochError, match="Nonce counter overflow"):
            initiator.encrypt(b"overflow")


class TestEncryptWithoutActiveEpoch:
    def test_encrypt_before_handshake_raises(self):
        em = EpochManager(
            peer_identity_hash="cc" * 16,
            is_initiator=True,
            local_rns_identity=_make_mock_identity(),
        )
        with pytest.raises(EpochError, match="no active epoch"):
            em.encrypt(b"test")


class TestTeardown:
    def test_teardown_erases_keys(self):
        initiator, responder = _make_pair()
        rotate = initiator.create_epoch_rotate()
        ack = responder.handle_epoch_rotate(rotate)
        initiator.handle_epoch_rotate_ack(ack)

        send_key_ref = initiator._send_key
        recv_key_ref = initiator._recv_key

        initiator.teardown()

        assert initiator._send_key is None
        assert initiator._recv_key is None
        assert not initiator.is_active
        # Original bytearrays should be zeroed
        assert send_key_ref == bytearray(32)
        assert recv_key_ref == bytearray(32)

    def test_teardown_cancels_rotation(self):
        initiator, _ = _make_pair()
        mock_task = MagicMock()
        initiator._rotation_task = mock_task
        initiator.teardown()
        mock_task.cancel.assert_called_once()
        assert initiator._rotation_task is None


class TestSignatureVerification:
    def test_epoch_rotate_rejected_on_bad_signature(self):
        """Responder rejects EpochRotate with invalid signature."""
        initiator, responder = _make_pair()

        # Make the responder's peer identity (initiator's identity) reject signatures
        responder._peer_identity.validate = MagicMock(return_value=False)

        rotate_frame = initiator.create_epoch_rotate()
        with pytest.raises(EpochError, match="signature verification failed"):
            responder.handle_epoch_rotate(rotate_frame)

    def test_epoch_rotate_ack_rejected_on_bad_signature(self):
        """Initiator rejects EpochRotateAck with invalid signature."""
        initiator, responder = _make_pair()

        rotate_frame = initiator.create_epoch_rotate()
        ack_frame = responder.handle_epoch_rotate(rotate_frame)

        # Make the initiator's peer identity (responder's identity) reject signatures
        initiator._peer_identity.validate = MagicMock(return_value=False)

        with pytest.raises(EpochError, match="signature verification failed"):
            initiator.handle_epoch_rotate_ack(ack_frame)

    def test_no_peer_identity_raises(self):
        """EpochManager without peer identity cannot verify frames."""
        id_init = _make_mock_identity()
        id_resp = _make_mock_identity()

        initiator = EpochManager(
            peer_identity_hash="bb" * 16,
            is_initiator=True,
            local_rns_identity=id_init,
            peer_rns_identity=id_resp,
        )
        responder = EpochManager(
            peer_identity_hash="aa" * 16,
            is_initiator=False,
            local_rns_identity=id_resp,
            # No peer_rns_identity — simulates missing peer recall
        )

        rotate_frame = initiator.create_epoch_rotate()
        with pytest.raises(EpochError, match="no peer identity"):
            responder.handle_epoch_rotate(rotate_frame)


class TestRetryLogic:
    def test_no_pending_key_raises(self):
        """handle_epoch_rotate_ack without create_epoch_rotate raises."""
        peer_id = _make_mock_identity()
        em = EpochManager(
            peer_identity_hash="dd" * 16,
            is_initiator=True,
            local_rns_identity=_make_mock_identity(),
            peer_rns_identity=peer_id,
        )
        # Craft a minimal ack frame
        from hokora.federation.epoch_wire import encode_epoch_rotate_ack

        ack = encode_epoch_rotate_ack(1, b"\x00" * 32, b"\x00" * 32, b"\x00" * 64)
        with pytest.raises(EpochError, match="No pending key exchange"):
            em.handle_epoch_rotate_ack(ack)
