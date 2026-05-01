# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for the daemon's wire-shape capability split.

``encode_message_for_wire`` emits two shapes for sealed-channel rows
depending on the ``subscriber_supports_sealed_at_rest`` flag:

* False (legacy) — server-side decrypt, body carries plaintext.
* True — ciphertext fields on the wire, body is empty.

Non-sealed rows are unchanged regardless of capability.
"""

from __future__ import annotations

import os
from types import SimpleNamespace

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from hokora.protocol.sync_utils import encode_message_for_wire


class _SealedManagerStub:
    """Minimal SealedChannelManager stand-in for tests."""

    def __init__(self, channel_id: str, key: bytes):
        self._channel_id = channel_id
        self._key = key

    def decrypt(self, channel_id, nonce, ciphertext, epoch=None):
        return AESGCM(self._key).decrypt(nonce, ciphertext, channel_id.encode("utf-8"))


def _msg(channel_id: str, body=None, encrypted=None, nonce=None, epoch=None):
    """Build a minimal ORM-shaped object for encode_message_for_wire."""
    return SimpleNamespace(
        msg_hash="h" * 64,
        channel_id=channel_id,
        sender_hash="s" * 32,
        seq=1,
        thread_seq=None,
        timestamp=1234.5,
        type=0x01,
        body=body,
        media_path=None,
        media_meta=None,
        reply_to=None,
        deleted=False,
        pinned=False,
        pinned_at=None,
        edit_chain=None,
        reactions={},
        lxmf_signature=None,
        lxmf_signed_part=None,
        display_name=None,
        mentions=None,
        encrypted_body=encrypted,
        encryption_nonce=nonce,
        encryption_epoch=epoch,
    )


def test_legacy_path_decrypts_server_side():
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, b"hello sealed", b"chS")
    msg = _msg("chS", body=None, encrypted=ct, nonce=nonce, epoch=1)
    sm = _SealedManagerStub("chS", key)

    d = encode_message_for_wire(msg, sealed_manager=sm)

    assert d["body"] == "hello sealed"
    # Legacy clients don't get ciphertext.
    assert "encrypted_body" not in d


def test_capable_path_emits_ciphertext():
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, b"hello sealed", b"chS")
    msg = _msg("chS", body=None, encrypted=ct, nonce=nonce, epoch=2)
    sm = _SealedManagerStub("chS", key)

    d = encode_message_for_wire(msg, sealed_manager=sm, subscriber_supports_sealed_at_rest=True)

    assert d["body"] == ""
    assert d["encrypted_body"] == ct
    assert d["encryption_nonce"] == nonce
    assert d["encryption_epoch"] == 2


def test_non_sealed_row_unchanged_for_capable_subscriber():
    msg = _msg("chPlain", body="plaintext")

    d = encode_message_for_wire(msg, sealed_manager=None, subscriber_supports_sealed_at_rest=True)

    assert d["body"] == "plaintext"
    assert d.get("encrypted_body") is None or "encrypted_body" not in d


def test_legacy_path_preserves_marker_on_decrypt_failure():
    key = AESGCM.generate_key(bit_length=256)
    other_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, b"hello", b"chS")
    msg = _msg("chS", body=None, encrypted=ct, nonce=nonce, epoch=1)
    # Wrong key on the manager → decrypt fails.
    sm = _SealedManagerStub("chS", other_key)

    d = encode_message_for_wire(msg, sealed_manager=sm)

    assert d["body"] == "[encrypted - key unavailable]"
