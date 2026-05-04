# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Pure cryptographic operations for forward secrecy epoch protocol."""

import ctypes
import hashlib
import hmac
import os
import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

import nacl.bindings

EPOCH_SALT = b"hokora-epoch-v1"


def generate_x25519_keypair() -> tuple[X25519PrivateKey, bytes]:
    """Generate an ephemeral X25519 keypair. Returns (private_key, public_key_bytes)."""
    private_key = X25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes_raw()
    return private_key, public_bytes


def derive_epoch_keys(
    local_private: X25519PrivateKey,
    remote_public_bytes: bytes,
    epoch_id: int,
    is_initiator: bool,
) -> tuple[bytearray, bytearray]:
    """Derive directional epoch keys via X25519 DH + HKDF-SHA256.

    Returns (i2r_key, r2i_key) as mutable bytearrays for secure erasure.
    The initiator uses i2r to send and r2i to receive; responder reverses.
    """
    remote_public = X25519PublicKey.from_public_bytes(remote_public_bytes)
    shared_secret = local_private.exchange(remote_public)

    epoch_id_bytes = struct.pack(">Q", epoch_id)

    i2r_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=EPOCH_SALT,
        info=b"epoch" + epoch_id_bytes + b"i2r",
    ).derive(shared_secret)

    r2i_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=EPOCH_SALT,
        info=b"epoch" + epoch_id_bytes + b"r2i",
    ).derive(shared_secret)

    return bytearray(i2r_key), bytearray(r2i_key)


def compute_chain_hash(epoch_key: bytes) -> bytes:
    """Compute chain hash for epoch continuity verification."""
    return hmac.new(epoch_key, b"epoch_chain", hashlib.sha256).digest()


def generate_nonce_prefix() -> bytes:
    """Generate a random 16-byte nonce prefix."""
    return os.urandom(16)


def build_nonce(prefix: bytes, counter: int) -> bytes:
    """Build a 24-byte nonce from 16-byte prefix + 8-byte big-endian counter."""
    return prefix + struct.pack(">Q", counter)


def encrypt_payload(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """Encrypt with XChaCha20-Poly1305 (libsodium via pynacl)."""
    return nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, key)


def decrypt_payload(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """Decrypt with XChaCha20-Poly1305 (libsodium via pynacl)."""
    return nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, aad, nonce, key)


def derive_kek(node_identity_key: bytes) -> bytes:
    """Derive a key-encryption-key from the node identity for wrapping epoch keys at rest."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=EPOCH_SALT,
        info=b"epoch-kek-v1",
    ).derive(node_identity_key)


def wrap_key(kek: bytes, plaintext_key: bytes) -> bytes:
    """Encrypt an epoch key for storage using XChaCha20-Poly1305.

    Returns nonce (24 bytes) || ciphertext+tag.
    """
    nonce = os.urandom(24)
    ciphertext = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext_key, b"epoch-key-wrap", nonce, kek
    )
    return nonce + ciphertext


def unwrap_key(kek: bytes, wrapped: bytes) -> bytes:
    """Decrypt a wrapped epoch key from storage."""
    nonce = wrapped[:24]
    ciphertext = wrapped[24:]
    return nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
        ciphertext, b"epoch-key-wrap", nonce, kek
    )


def secure_erase(buf: bytearray) -> None:
    """Best-effort secure erasure of a bytearray."""
    if not isinstance(buf, bytearray):
        raise TypeError("secure_erase only accepts bytearray")
    n = len(buf)
    if n == 0:
        return
    try:
        ctypes.memset(ctypes.addressof((ctypes.c_char * n).from_buffer(buf)), 0, n)
    except Exception:
        for i in range(n):
            buf[i] = 0
