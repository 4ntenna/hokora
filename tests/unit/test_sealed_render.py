# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for hokora_tui.security.sealed_render.body_for_render."""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from hokora_tui.security.sealed_render import (
    DECRYPT_FAILED_MARKER,
    body_for_render,
)


class _StubStore:
    """Test double for SealedKeyStore.get."""

    def __init__(self, mapping):
        self._m = mapping

    def get(self, channel_id):
        return self._m.get(channel_id)


def _seal(key: bytes, channel_id: str, plaintext: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, channel_id.encode("utf-8"))
    return nonce, ct


def test_returns_plaintext_body_when_present():
    msg = {"body": "hello", "channel_id": "ch"}
    assert body_for_render(msg, _StubStore({})) == "hello"


def test_decrypts_ciphertext_when_body_empty():
    key = AESGCM.generate_key(bit_length=256)
    nonce, ct = _seal(key, "ch", b"sealed text")
    msg = {
        "body": None,
        "channel_id": "ch",
        "encrypted_body": ct,
        "encryption_nonce": nonce,
        "encryption_epoch": 1,
    }
    store = _StubStore({"ch": (key, 1)})
    assert body_for_render(msg, store) == "sealed text"


def test_returns_marker_when_key_missing():
    msg = {
        "body": None,
        "channel_id": "ch",
        "encrypted_body": b"\x00" * 16,
        "encryption_nonce": b"\x00" * 12,
        "encryption_epoch": 1,
    }
    assert body_for_render(msg, _StubStore({})) == DECRYPT_FAILED_MARKER


def test_returns_marker_on_epoch_mismatch():
    key = AESGCM.generate_key(bit_length=256)
    nonce, ct = _seal(key, "ch", b"old data")
    msg = {
        "body": None,
        "channel_id": "ch",
        "encrypted_body": ct,
        "encryption_nonce": nonce,
        "encryption_epoch": 1,
    }
    store = _StubStore({"ch": (key, 2)})  # held key is at epoch 2; row at epoch 1
    assert body_for_render(msg, store) == DECRYPT_FAILED_MARKER


def test_returns_marker_on_integrity_failure():
    key = AESGCM.generate_key(bit_length=256)
    nonce, ct = _seal(key, "ch", b"data")
    tampered = bytes([ct[0] ^ 0xFF]) + ct[1:]
    msg = {
        "body": None,
        "channel_id": "ch",
        "encrypted_body": tampered,
        "encryption_nonce": nonce,
        "encryption_epoch": 1,
    }
    store = _StubStore({"ch": (key, 1)})
    assert body_for_render(msg, store) == DECRYPT_FAILED_MARKER


def test_empty_when_no_body_and_no_ciphertext():
    msg = {"body": None, "channel_id": "ch"}
    assert body_for_render(msg, _StubStore({})) == ""


def test_aad_mismatch_fails():
    """Ciphertext encrypted with channel A cannot decrypt as channel B."""
    key = AESGCM.generate_key(bit_length=256)
    nonce, ct = _seal(key, "ch_A", b"belongs to A")
    msg = {
        "body": None,
        "channel_id": "ch_B",  # different channel id used as AAD
        "encrypted_body": ct,
        "encryption_nonce": nonce,
        "encryption_epoch": 1,
    }
    store = _StubStore({"ch_B": (key, 1)})
    assert body_for_render(msg, store) == DECRYPT_FAILED_MARKER
