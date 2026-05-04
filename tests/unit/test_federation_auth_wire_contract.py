# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Wire-contract tests for federation Ed25519 public key handling.

Pin the boundary contract: ``peer_public_key`` on every federation
handshake step is the 32-byte Ed25519 portion of the RNS identity, never
the 64-byte X25519+Ed25519 concatenation that ``get_public_key()``
returns. A mocked-fixture test could miss this because mocks accept
either shape; these tests force the real wire format.
"""

from __future__ import annotations

import os

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _make_real_rns_identity():
    """Build a real RNS.Identity (not a mock).

    The whole point of this regression test is to verify behaviour against
    the actual RNS public-key shape, which a mock can't enforce.
    """
    import RNS

    return RNS.Identity()


class TestRnsIdentityShapeAssumptions:
    """Pin the RNS public-key API shape that the rest of the contract relies on."""

    def test_rns_identity_get_public_key_is_64_bytes(self):
        identity = _make_real_rns_identity()
        pk = identity.get_public_key()
        assert isinstance(pk, (bytes, bytearray))
        assert len(pk) == 64, (
            "RNS.Identity.get_public_key() should return X25519+Ed25519 (64 bytes); "
            "if this changed upstream, the federation wire helpers need re-review."
        )

    def test_rns_identity_sig_pub_bytes_is_32_bytes(self):
        identity = _make_real_rns_identity()
        assert isinstance(identity.sig_pub_bytes, (bytes, bytearray))
        assert len(identity.sig_pub_bytes) == 32, (
            "RNS.Identity.sig_pub_bytes must be a 32-byte Ed25519 public key; "
            "this is the canonical wire field for federation_handshake."
        )

    def test_rns_identity_pub_bytes_and_sig_pub_bytes_concat_equals_get_public_key(self):
        identity = _make_real_rns_identity()
        assert identity.pub_bytes + identity.sig_pub_bytes == identity.get_public_key()


class TestSigningPublicKeyHelper:
    """Wire-shaping helper at hokora.federation.auth.signing_public_key."""

    def test_returns_32_bytes_against_real_rns_identity(self):
        from hokora.federation.auth import (
            ED25519_PUBLIC_KEY_SIZE,
            signing_public_key,
        )

        identity = _make_real_rns_identity()
        pk = signing_public_key(identity)
        assert isinstance(pk, bytes)
        assert len(pk) == ED25519_PUBLIC_KEY_SIZE
        assert pk == identity.sig_pub_bytes

    def test_returns_signing_portion_not_full_blob(self):
        from hokora.federation.auth import signing_public_key

        identity = _make_real_rns_identity()
        pk = signing_public_key(identity)
        assert pk != identity.get_public_key(), (
            "Helper must return only the Ed25519 portion, not the full "
            "64-byte X25519+Ed25519 concatenation"
        )

    def test_raises_on_identity_with_missing_sig_pub_bytes(self):
        from hokora.exceptions import FederationError
        from hokora.federation.auth import signing_public_key

        class FakeIdentity:
            sig_pub_bytes = None

        with pytest.raises(FederationError, match="Invalid Ed25519 sig_pub_bytes"):
            signing_public_key(FakeIdentity())

    def test_raises_on_identity_with_wrong_length_sig_pub_bytes(self):
        from hokora.exceptions import FederationError
        from hokora.federation.auth import signing_public_key

        class FakeIdentity:
            sig_pub_bytes = b"x" * 64  # the historical bug shape

        with pytest.raises(FederationError, match="expected 32 bytes, got 64"):
            signing_public_key(FakeIdentity())


class TestVerifyResponseLengthGuards:
    """verify_response distinguishes structural vs cryptographic failures."""

    def test_accepts_valid_32_byte_key(self):
        from hokora.federation.auth import FederationAuth

        prv = Ed25519PrivateKey.generate()
        pk = prv.public_key().public_bytes_raw()
        challenge = os.urandom(32)
        signature = prv.sign(challenge)
        assert FederationAuth.verify_response(challenge, signature, pk) is True

    def test_rejects_64_byte_key_without_raising(self, caplog):
        from hokora.federation.auth import FederationAuth

        challenge = os.urandom(32)
        signature = os.urandom(64)
        result = FederationAuth.verify_response(challenge, signature, b"x" * 64)
        assert result is False
        assert any("invalid Ed25519 pk length" in rec.message for rec in caplog.records)

    def test_rejects_31_byte_key_without_raising(self):
        from hokora.federation.auth import FederationAuth

        challenge = os.urandom(32)
        signature = os.urandom(64)
        assert FederationAuth.verify_response(challenge, signature, b"x" * 31) is False

    def test_rejects_non_bytes_input(self):
        from hokora.federation.auth import FederationAuth

        challenge = os.urandom(32)
        signature = os.urandom(64)
        assert FederationAuth.verify_response(challenge, signature, "not-bytes") is False
        assert FederationAuth.verify_response(challenge, signature, None) is False

    def test_logs_invalid_signature_distinctly_from_length(self, caplog):
        from hokora.federation.auth import FederationAuth

        prv = Ed25519PrivateKey.generate()
        pk = prv.public_key().public_bytes_raw()
        challenge = os.urandom(32)
        wrong_signature = os.urandom(64)
        result = FederationAuth.verify_response(challenge, wrong_signature, pk)
        assert result is False
        # Distinct log line — operators can tell forged signatures apart from
        # wire-format violations.
        assert any("invalid signature" in rec.message for rec in caplog.records)
        assert not any("invalid Ed25519 pk length" in rec.message for rec in caplog.records)


class TestEndToEndHandshakeRoundTripWithRealKeys:
    """A full sign/verify round-trip using actual RNS identities.

    Single-process equivalent of a fresh-peer handshake — uses real
    keys, not mocked values, so a wire-format regression is caught.
    """

    def test_real_identity_sign_then_verify_via_signing_public_key(self):
        from hokora.federation.auth import FederationAuth, signing_public_key

        signer = _make_real_rns_identity()
        challenge = FederationAuth.create_challenge()
        signature = signer.sign(challenge)
        peer_public_key = signing_public_key(signer)

        assert len(peer_public_key) == 32
        assert FederationAuth.verify_response(challenge, signature, peer_public_key) is True

    def test_real_identity_64_byte_blob_fails_cleanly_not_via_exception(self):
        """The pre-fix bug: sending get_public_key() (64 bytes) instead of
        signing_public_key() (32 bytes) is rejected with a structural-mismatch
        log line, never an unhandled exception."""
        from hokora.federation.auth import FederationAuth

        signer = _make_real_rns_identity()
        challenge = FederationAuth.create_challenge()
        signature = signer.sign(challenge)

        # The historically-broken send: full 64-byte blob.
        broken_wire_field = signer.get_public_key()
        assert len(broken_wire_field) == 64

        result = FederationAuth.verify_response(challenge, signature, broken_wire_field)
        assert result is False  # rejected, not crashed
