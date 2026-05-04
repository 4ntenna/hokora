# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Test sealed channel encryption."""

import pytest

from hokora.security.sealed import SealedChannelManager
from hokora.exceptions import SealedChannelError


class TestSealedChannelManager:
    def test_generate_and_encrypt_decrypt(self):
        mgr = SealedChannelManager()
        key, epoch = mgr.generate_key("ch1")
        assert epoch == 1
        assert len(key) == 32

        plaintext = b"Secret message content"
        nonce, ciphertext, ep = mgr.encrypt("ch1", plaintext)
        assert ep == 1
        assert ciphertext != plaintext

        decrypted = mgr.decrypt("ch1", nonce, ciphertext, epoch=1)
        assert decrypted == plaintext

    def test_wrong_epoch_fails(self):
        mgr = SealedChannelManager()
        mgr.generate_key("ch2")
        nonce, ciphertext, _ = mgr.encrypt("ch2", b"data")

        with pytest.raises(SealedChannelError, match="epoch 999 unavailable"):
            mgr.decrypt("ch2", nonce, ciphertext, epoch=999)

    def test_key_rotation(self):
        mgr = SealedChannelManager()
        key1, epoch1 = mgr.generate_key("ch3")
        key2, epoch2 = mgr.rotate_key("ch3")
        assert epoch2 == epoch1 + 1
        assert key2 != key1

    def test_no_key_encrypt_fails(self):
        mgr = SealedChannelManager()
        with pytest.raises(SealedChannelError, match="No key"):
            mgr.encrypt("nonexistent", b"data")

    def test_decrypt_after_rotation_uses_previous_key(self):
        """Ciphertext encrypted before a rotation must remain decryptable."""
        mgr = SealedChannelManager()
        mgr.generate_key("ch_rot")
        nonce, ciphertext, ep = mgr.encrypt("ch_rot", b"pre-rotation payload")
        assert ep == 1

        mgr.rotate_key("ch_rot")  # current epoch is now 2
        assert mgr.get_epoch("ch_rot") == 2

        # Without epoch the active key is tried (and fails); with the
        # original epoch the prior key in _previous_keys is used.
        decrypted = mgr.decrypt("ch_rot", nonce, ciphertext, epoch=1)
        assert decrypted == b"pre-rotation payload"

    def test_decrypt_at_oldest_retained_epoch_succeeds(self):
        """The oldest epoch within the retention window is still decryptable."""
        mgr = SealedChannelManager()
        mgr.generate_key("ch_window")
        nonce, ciphertext, ep = mgr.encrypt("ch_window", b"oldest")
        assert ep == 1

        # Rotate exactly _MAX_PREVIOUS_KEYS times so epoch 1 is still in
        # _previous_keys (rotations 1..5 push epochs 1..5; current is 6).
        for _ in range(5):
            mgr.rotate_key("ch_window")
        assert mgr.get_epoch("ch_window") == 6

        decrypted = mgr.decrypt("ch_window", nonce, ciphertext, epoch=1)
        assert decrypted == b"oldest"

    def test_decrypt_at_evicted_epoch_raises(self):
        """Beyond the retention window the original epoch is unrecoverable."""
        mgr = SealedChannelManager()
        mgr.generate_key("ch_evict")
        nonce, ciphertext, ep = mgr.encrypt("ch_evict", b"data")
        assert ep == 1

        # 6 rotations push epoch 1 out of the 5-slot history (window now
        # holds 2..6, current is 7).
        for _ in range(6):
            mgr.rotate_key("ch_evict")
        assert mgr.get_epoch("ch_evict") == 7

        with pytest.raises(SealedChannelError, match="epoch 1 unavailable"):
            mgr.decrypt("ch_evict", nonce, ciphertext, epoch=1)
