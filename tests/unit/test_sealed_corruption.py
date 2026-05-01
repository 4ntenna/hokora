# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Sealed channel corruption handling tests."""

import os

import pytest

from hokora.security.sealed import SealedChannelManager


class TestSealedChannelCorruption:
    def _setup(self):
        mgr = SealedChannelManager()
        mgr.generate_key("sealed_ch")
        return mgr

    def test_corrupted_ciphertext_raises(self):
        mgr = self._setup()
        nonce, ciphertext, epoch = mgr.encrypt("sealed_ch", b"secret data")
        # Corrupt the ciphertext by flipping bytes
        corrupted = bytes([b ^ 0xFF for b in ciphertext])
        with pytest.raises(Exception):
            mgr.decrypt("sealed_ch", nonce, corrupted, epoch)

    def test_truncated_ciphertext_raises(self):
        mgr = self._setup()
        nonce, ciphertext, epoch = mgr.encrypt("sealed_ch", b"secret data")
        # Truncate to half
        truncated = ciphertext[: len(ciphertext) // 2]
        with pytest.raises(Exception):
            mgr.decrypt("sealed_ch", nonce, truncated, epoch)

    def test_wrong_nonce_raises(self):
        mgr = self._setup()
        nonce, ciphertext, epoch = mgr.encrypt("sealed_ch", b"secret data")
        wrong_nonce = os.urandom(12)
        with pytest.raises(Exception):
            mgr.decrypt("sealed_ch", wrong_nonce, ciphertext, epoch)
