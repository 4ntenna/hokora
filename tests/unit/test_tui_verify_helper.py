# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for the TUI's shared message-signature verifier.

`verify_message_signature` is the single chokepoint used by both
`HistoryClient.handle_history` and `commands.event_dispatcher` for
"message" events. Three-state return:
  True  — sig material present and verifies (TOFU pubkey cached)
  False — sig present but verification fails OR TOFU MITM detected
  None  — no sig material on the wire (no opinion)
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from hokora_tui.sync._verify import verify_message_signature


def _signed_msg(body: bytes = b"hello"):
    """Build (msg_dict, pubkey_bytes) with a real Ed25519 signature."""
    sk = Ed25519PrivateKey.generate()
    pk_bytes = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    sig = sk.sign(body)
    return {
        "msg_hash": "h" * 64,
        "sender_hash": "s" * 32,
        "sender_public_key": pk_bytes,
        "lxmf_signature": sig,
        "lxmf_signed_part": body,
    }, pk_bytes


class TestVerifyMessageSignature:
    def test_returns_true_and_caches_pubkey_on_valid_sig(self):
        msg, pk = _signed_msg()
        cache: dict[str, bytes] = {}
        assert verify_message_signature(msg, cache) is True
        assert cache[msg["sender_hash"]] == pk

    def test_returns_false_on_bad_sig(self):
        msg, _ = _signed_msg()
        msg["lxmf_signature"] = b"\x00" * 64  # not a valid sig for this part
        cache: dict[str, bytes] = {}
        assert verify_message_signature(msg, cache) is False
        # Failed sig must NOT cache the pubkey (TOFU only on success).
        assert msg["sender_hash"] not in cache

    def test_returns_none_when_no_pubkey(self):
        msg, _ = _signed_msg()
        msg["sender_public_key"] = None
        assert verify_message_signature(msg, {}) is None

    def test_returns_none_when_no_signature(self):
        msg, _ = _signed_msg()
        msg["lxmf_signature"] = None
        assert verify_message_signature(msg, {}) is None

    def test_returns_none_when_no_signed_part(self):
        msg, _ = _signed_msg()
        msg["lxmf_signed_part"] = None
        assert verify_message_signature(msg, {}) is None

    def test_returns_none_when_no_sender_hash(self):
        msg, _ = _signed_msg()
        msg["sender_hash"] = None
        assert verify_message_signature(msg, {}) is None

    def test_tofu_mismatch_returns_false(self):
        msg, pk = _signed_msg()
        # Cache says we previously saw a different pubkey for this sender —
        # MITM guard. Must reject even if the new pubkey would verify the sig.
        cache = {msg["sender_hash"]: b"\xff" * 32}
        assert verify_message_signature(msg, cache) is False
        # The original cached value must be preserved on rejection.
        assert cache[msg["sender_hash"]] == b"\xff" * 32

    def test_tofu_match_passes(self):
        """Same pubkey on second sight → still verifies, cache stays."""
        msg, pk = _signed_msg()
        cache: dict[str, bytes] = {msg["sender_hash"]: pk}
        assert verify_message_signature(msg, cache) is True
        assert cache[msg["sender_hash"]] == pk

    def test_first_message_caches_pubkey(self):
        """Empty cache → success populates it for next-call MITM detection."""
        msg, pk = _signed_msg()
        cache: dict[str, bytes] = {}
        verify_message_signature(msg, cache)
        # Second call with mismatching pubkey on same sender → False.
        msg2, _ = _signed_msg()
        msg2["sender_hash"] = msg["sender_hash"]
        msg2["sender_public_key"] = b"\x11" * 32
        assert verify_message_signature(msg2, cache) is False
