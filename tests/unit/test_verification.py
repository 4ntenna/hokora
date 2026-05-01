# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Test verification service."""

import time

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hokora.security.verification import VerificationService
from hokora.constants import NONCE_SIZE
from hokora.exceptions import VerificationError


class TestVerificationService:
    def test_ed25519_signature_valid(self):
        private_key = Ed25519PrivateKey.generate()
        public_key_bytes = private_key.public_key().public_bytes_raw()
        message = b"test message"
        signature = private_key.sign(message)

        assert (
            VerificationService.verify_ed25519_signature(
                public_key_bytes,
                message,
                signature,
            )
            is True
        )

    def test_ed25519_signature_invalid(self):
        private_key = Ed25519PrivateKey.generate()
        public_key_bytes = private_key.public_key().public_bytes_raw()
        message = b"test message"
        bad_signature = b"\x00" * 64

        assert (
            VerificationService.verify_ed25519_signature(
                public_key_bytes,
                message,
                bad_signature,
            )
            is False
        )

    def test_ed25519_rejects_64_byte_blob(self, caplog):
        """Passing the full RNS 64-byte public_key blob (X25519 ||
        Ed25519 concat) MUST return False with a clear diagnostic
        rather than raising deep inside Ed25519PublicKey."""
        import logging

        private_key = Ed25519PrivateKey.generate()
        sig_pk = private_key.public_key().public_bytes_raw()
        # Simulate RNS.Identity.get_public_key() shape: X25519_pk || Ed25519_pk.
        rns_blob = (b"\x00" * 32) + sig_pk
        assert len(rns_blob) == 64

        with caplog.at_level(logging.WARNING):
            result = VerificationService.verify_ed25519_signature(
                rns_blob,
                b"msg",
                b"\x00" * 64,
            )
        assert result is False
        assert any("invalid public_key length=64" in rec.message for rec in caplog.records)

    def test_ed25519_rejects_none_public_key(self):
        result = VerificationService.verify_ed25519_signature(
            None,  # type: ignore[arg-type]
            b"msg",
            b"\x00" * 64,
        )
        assert result is False

    def test_ed25519_rejects_empty_public_key(self):
        result = VerificationService.verify_ed25519_signature(b"", b"msg", b"\x00" * 64)
        assert result is False

    def test_ed25519_rejects_non_bytes_public_key(self):
        result = VerificationService.verify_ed25519_signature("not_bytes", b"msg", b"\x00" * 64)  # type: ignore[arg-type]
        assert result is False

    def test_nonce_match(self):
        nonce = b"\x42" * NONCE_SIZE
        assert VerificationService.verify_sync_nonce(nonce, nonce) is True

    def test_nonce_mismatch(self):
        with pytest.raises(VerificationError, match="Nonce mismatch"):
            VerificationService.verify_sync_nonce(
                b"\x01" * NONCE_SIZE,
                b"\x02" * NONCE_SIZE,
            )

    def test_node_time_within_tolerance(self):
        assert VerificationService.verify_node_time(time.time()) is True

    def test_node_time_exceeds_tolerance(self):
        with pytest.raises(VerificationError, match="Clock drift"):
            VerificationService.verify_node_time(time.time() - 600)

    def test_sequence_integrity_perfect(self):
        ok, warning = VerificationService.check_sequence_integrity(5, 6)
        assert ok is True
        assert warning is None

    def test_sequence_integrity_large_gap(self):
        ok, warning = VerificationService.check_sequence_integrity(5, 50)
        assert ok is True
        assert warning is not None
