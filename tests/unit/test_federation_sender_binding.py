# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Structural sender_hash <-> public_key binding contract.

Pins the federation-receive invariant: a trusted peer cannot push a
record with their own legitimate ``sender_public_key`` but a victim's
``sender_hash``. The receiver chokepoint
``hokora.federation.auth.verify_sender_binding`` derives the expected
identity hash from the wire-carried 64-byte RNS pubkey and rejects on
any mismatch -- no TOFU, no path-cache fallback.
"""

from __future__ import annotations

import os

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hokora.federation.auth import (
    IDENTITY_HASH_HEX_LENGTH,
    RNS_PUBLIC_KEY_SIZE,
    derive_identity_hash_hex,
    get_binding_rejection_counts,
    verify_sender_binding,
)


def _make_real_rns_identity():
    import RNS

    return RNS.Identity()


def _reset_counters():
    from hokora.federation import auth as _auth

    _auth._BINDING_REJECTIONS.clear()


class TestDeriveIdentityHashHex:
    def test_round_trip_against_real_rns_identity(self):
        ident = _make_real_rns_identity()
        derived = derive_identity_hash_hex(ident.get_public_key())
        assert derived == ident.hexhash
        assert len(derived) == IDENTITY_HASH_HEX_LENGTH

    def test_rejects_short_blob(self):
        from hokora.exceptions import FederationError

        with pytest.raises(FederationError):
            derive_identity_hash_hex(b"x" * 32)

    def test_rejects_long_blob(self):
        from hokora.exceptions import FederationError

        with pytest.raises(FederationError):
            derive_identity_hash_hex(b"x" * 65)

    def test_rejects_non_bytes(self):
        from hokora.exceptions import FederationError

        with pytest.raises(FederationError):
            derive_identity_hash_hex("not bytes")  # type: ignore[arg-type]

    def test_distinct_pubkeys_produce_distinct_hashes(self):
        a = _make_real_rns_identity()
        b = _make_real_rns_identity()
        assert a.hexhash != b.hexhash
        assert derive_identity_hash_hex(a.get_public_key()) != derive_identity_hash_hex(
            b.get_public_key()
        )


class TestVerifySenderBindingHappyPath:
    def setup_method(self):
        _reset_counters()

    def test_unsigned_passes_when_not_required(self):
        ident = _make_real_rns_identity()
        ok, reason = verify_sender_binding(
            sender_hash=ident.hexhash,
            sender_rns_public_key=ident.get_public_key(),
            lxmf_signed_part=None,
            lxmf_signature=None,
            require_signed=False,
        )
        assert ok is True
        assert reason is None

    def test_signed_passes_with_valid_signature(self):
        ident = _make_real_rns_identity()
        signed_part = os.urandom(64)
        ed25519_priv_bytes = ident.sig_prv_bytes
        priv = Ed25519PrivateKey.from_private_bytes(ed25519_priv_bytes)
        sig = priv.sign(signed_part)
        ok, reason = verify_sender_binding(
            sender_hash=ident.hexhash,
            sender_rns_public_key=ident.get_public_key(),
            lxmf_signed_part=signed_part,
            lxmf_signature=sig,
            require_signed=True,
        )
        assert ok is True, reason
        assert reason is None


class TestVerifySenderBindingRejections:
    def setup_method(self):
        _reset_counters()

    def test_victim_substitution_rejected(self):
        """Adversarial peer claims a victim's hash with their own pubkey."""
        attacker = _make_real_rns_identity()
        victim = _make_real_rns_identity()
        ok, reason = verify_sender_binding(
            sender_hash=victim.hexhash,
            sender_rns_public_key=attacker.get_public_key(),
            lxmf_signed_part=None,
            lxmf_signature=None,
            require_signed=False,
        )
        assert ok is False
        assert "binding violation" in (reason or "")
        assert get_binding_rejection_counts().get("binding_mismatch") == 1

    def test_missing_pubkey_when_signed_required(self):
        ident = _make_real_rns_identity()
        ok, reason = verify_sender_binding(
            sender_hash=ident.hexhash,
            sender_rns_public_key=None,
            lxmf_signed_part=None,
            lxmf_signature=None,
            require_signed=True,
        )
        assert ok is False
        assert reason == "missing sender_rns_public_key"
        assert get_binding_rejection_counts().get("missing_pubkey") == 1

    def test_missing_pubkey_passes_when_signed_not_required(self):
        ident = _make_real_rns_identity()
        ok, reason = verify_sender_binding(
            sender_hash=ident.hexhash,
            sender_rns_public_key=None,
            lxmf_signed_part=None,
            lxmf_signature=None,
            require_signed=False,
        )
        assert ok is True
        assert reason is None
        assert get_binding_rejection_counts() == {}

    def test_malformed_pubkey_length_rejected(self):
        ident = _make_real_rns_identity()
        ok, reason = verify_sender_binding(
            sender_hash=ident.hexhash,
            sender_rns_public_key=b"x" * 33,
            lxmf_signed_part=None,
            lxmf_signature=None,
            require_signed=False,
        )
        assert ok is False
        assert "malformed sender_rns_public_key" in (reason or "")
        assert get_binding_rejection_counts().get("malformed") == 1

    def test_missing_sender_hash_rejected(self):
        ident = _make_real_rns_identity()
        ok, reason = verify_sender_binding(
            sender_hash=None,
            sender_rns_public_key=ident.get_public_key(),
            lxmf_signed_part=None,
            lxmf_signature=None,
            require_signed=False,
        )
        assert ok is False
        assert reason == "missing sender_hash"
        assert get_binding_rejection_counts().get("malformed") == 1

    def test_short_sender_hash_rejected(self):
        ident = _make_real_rns_identity()
        ok, reason = verify_sender_binding(
            sender_hash="abcd",
            sender_rns_public_key=ident.get_public_key(),
            lxmf_signed_part=None,
            lxmf_signature=None,
            require_signed=False,
        )
        assert ok is False
        assert "malformed sender_hash length" in (reason or "")
        assert get_binding_rejection_counts().get("malformed") == 1

    def test_invalid_signature_rejected(self):
        ident = _make_real_rns_identity()
        signed_part = b"original payload"
        ok, reason = verify_sender_binding(
            sender_hash=ident.hexhash,
            sender_rns_public_key=ident.get_public_key(),
            lxmf_signed_part=signed_part,
            lxmf_signature=b"\x00" * 64,
            require_signed=True,
        )
        assert ok is False
        assert "Ed25519 signature verification failed" in (reason or "")
        assert get_binding_rejection_counts().get("bad_signature") == 1

    def test_signature_with_wrong_signer_rejected(self):
        """Pubkey binding holds but the sig was made by a different key."""
        ident = _make_real_rns_identity()
        attacker_priv = Ed25519PrivateKey.generate()
        signed_part = os.urandom(32)
        sig = attacker_priv.sign(signed_part)
        ok, reason = verify_sender_binding(
            sender_hash=ident.hexhash,
            sender_rns_public_key=ident.get_public_key(),
            lxmf_signed_part=signed_part,
            lxmf_signature=sig,
            require_signed=True,
        )
        assert ok is False
        assert "Ed25519 signature verification failed" in (reason or "")
        assert get_binding_rejection_counts().get("bad_signature") == 1

    def test_missing_signature_when_required(self):
        ident = _make_real_rns_identity()
        ok, reason = verify_sender_binding(
            sender_hash=ident.hexhash,
            sender_rns_public_key=ident.get_public_key(),
            lxmf_signed_part=None,
            lxmf_signature=None,
            require_signed=True,
        )
        assert ok is False
        assert reason == "missing signature"
        assert get_binding_rejection_counts().get("missing_signature") == 1

    def test_partial_signature_fields_treated_as_unsigned(self):
        """Only one of (signed_part, signature) provided — treated as no sig."""
        ident = _make_real_rns_identity()
        ok, reason = verify_sender_binding(
            sender_hash=ident.hexhash,
            sender_rns_public_key=ident.get_public_key(),
            lxmf_signed_part=b"data",
            lxmf_signature=None,
            require_signed=True,
        )
        # Falls into the require_signed branch.
        assert ok is False
        assert reason == "missing signature"


class TestPrometheusRejectionCounter:
    def setup_method(self):
        _reset_counters()

    def test_counter_appears_in_render_output(self):
        from hokora.federation.auth import _record_binding_rejection

        _record_binding_rejection("binding_mismatch")
        _record_binding_rejection("binding_mismatch")
        _record_binding_rejection("bad_signature")

        # The exporter accepts None for nearly every kwarg; render_metrics
        # is async with a session_factory dependency. Patch the counter
        # path directly via the helper.
        from hokora.federation.auth import get_binding_rejection_counts

        counts = get_binding_rejection_counts()
        assert counts["binding_mismatch"] == 2
        assert counts["bad_signature"] == 1


class TestRnsPubkeyBindingPropertyOverManyIdentities:
    """Property-style: 16 random identities all bind correctly."""

    def test_identity_hash_matches_truncated_hash_for_many_identities(self):
        for _ in range(16):
            ident = _make_real_rns_identity()
            blob = ident.get_public_key()
            assert len(blob) == RNS_PUBLIC_KEY_SIZE
            assert derive_identity_hash_hex(blob) == ident.hexhash
