# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for forward secrecy cryptographic primitives."""

import struct

import pytest

from hokora.federation.epoch_crypto import (
    generate_x25519_keypair,
    derive_epoch_keys,
    compute_chain_hash,
    generate_nonce_prefix,
    build_nonce,
    encrypt_payload,
    decrypt_payload,
    secure_erase,
)


class TestX25519:
    def test_keypair_generation(self):
        priv, pub = generate_x25519_keypair()
        assert len(pub) == 32
        assert priv is not None

    def test_dh_shared_secret_matches(self):
        """Both sides derive the same shared secret from their keypairs."""
        priv_a, pub_a = generate_x25519_keypair()
        priv_b, pub_b = generate_x25519_keypair()

        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

        shared_a = priv_a.exchange(X25519PublicKey.from_public_bytes(pub_b))
        shared_b = priv_b.exchange(X25519PublicKey.from_public_bytes(pub_a))
        assert shared_a == shared_b


class TestHKDF:
    def test_directional_keys_differ(self):
        priv_a, pub_a = generate_x25519_keypair()
        priv_b, pub_b = generate_x25519_keypair()

        i2r_a, r2i_a = derive_epoch_keys(priv_a, pub_b, epoch_id=1, is_initiator=True)
        assert i2r_a != r2i_a
        assert len(i2r_a) == 32
        assert len(r2i_a) == 32

    def test_role_dependent_assignment(self):
        """Initiator's i2r matches responder's i2r (same DH)."""
        priv_a, pub_a = generate_x25519_keypair()
        priv_b, pub_b = generate_x25519_keypair()

        i2r_init, r2i_init = derive_epoch_keys(priv_a, pub_b, epoch_id=1, is_initiator=True)
        i2r_resp, r2i_resp = derive_epoch_keys(priv_b, pub_a, epoch_id=1, is_initiator=False)

        assert bytes(i2r_init) == bytes(i2r_resp)
        assert bytes(r2i_init) == bytes(r2i_resp)

    def test_keys_are_bytearray(self):
        priv_a, pub_a = generate_x25519_keypair()
        priv_b, pub_b = generate_x25519_keypair()
        i2r, r2i = derive_epoch_keys(priv_a, pub_b, epoch_id=1, is_initiator=True)
        assert isinstance(i2r, bytearray)
        assert isinstance(r2i, bytearray)


class TestChainHash:
    def test_deterministic(self):
        key = b"\x42" * 32
        h1 = compute_chain_hash(key)
        h2 = compute_chain_hash(key)
        assert h1 == h2
        assert len(h1) == 32

    def test_different_keys_different_hash(self):
        h1 = compute_chain_hash(b"\x01" * 32)
        h2 = compute_chain_hash(b"\x02" * 32)
        assert h1 != h2


class TestNonce:
    def test_nonce_is_24_bytes(self):
        prefix = generate_nonce_prefix()
        assert len(prefix) == 16
        nonce = build_nonce(prefix, 0)
        assert len(nonce) == 24

    def test_counter_encodes_correctly(self):
        prefix = b"\x00" * 16
        nonce = build_nonce(prefix, 42)
        counter_part = struct.unpack(">Q", nonce[16:])[0]
        assert counter_part == 42


class TestEncryptDecrypt:
    def test_round_trip(self):
        key = b"\xab" * 32
        nonce = b"\x00" * 24
        plaintext = b"Hello, forward secrecy!"
        aad = b"\x01\x02\x03"

        ct = encrypt_payload(key, nonce, plaintext, aad)
        pt = decrypt_payload(key, nonce, ct, aad)
        assert pt == plaintext

    def test_wrong_key_fails(self):
        key1 = b"\xab" * 32
        key2 = b"\xcd" * 32
        nonce = b"\x00" * 24
        plaintext = b"secret"
        aad = b""

        ct = encrypt_payload(key1, nonce, plaintext, aad)
        with pytest.raises(Exception):
            decrypt_payload(key2, nonce, ct, aad)

    def test_tampered_ciphertext_fails(self):
        key = b"\xab" * 32
        nonce = b"\x00" * 24
        plaintext = b"secret"
        aad = b""

        ct = bytearray(encrypt_payload(key, nonce, plaintext, aad))
        ct[0] ^= 0xFF  # flip a byte
        with pytest.raises(Exception):
            decrypt_payload(key, nonce, bytes(ct), aad)


class TestSecureErase:
    def test_zeros_bytearray(self):
        buf = bytearray(b"\xff" * 64)
        secure_erase(buf)
        assert buf == bytearray(64)

    def test_rejects_bytes(self):
        with pytest.raises(TypeError):
            secure_erase(b"\xff" * 32)

    def test_empty_bytearray(self):
        buf = bytearray()
        secure_erase(buf)  # should not raise
        assert len(buf) == 0
