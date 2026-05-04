# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for TUI sync engine: signature verification, MITM detection,
sequence tracking, nonce lifecycle, cursor management, and event routing."""

import time
from unittest.mock import MagicMock, patch

import msgpack
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hokora.constants import NONCE_SIZE


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_engine():
    """Create a SyncEngine with mocked RNS/LXMF dependencies.

    RNS/LXMF usage lives in subsystem modules (sync.link_manager,
    sync.dm_router). Reloading just sync_engine leaves cached
    subsystems bound to the real modules — so we reload those too
    under the same sys.modules patch.
    """
    with patch.dict(
        "sys.modules",
        {
            "RNS": MagicMock(),
            "LXMF": MagicMock(),
        },
    ):
        import importlib

        import hokora_tui.sync.cdsp_client as cdsp_mod
        import hokora_tui.sync.dm_router as dm_mod
        import hokora_tui.sync.history_client as hc_mod
        import hokora_tui.sync.invite_client as ic_mod
        import hokora_tui.sync.link_manager as lm_mod
        import hokora_tui.sync.media_client as mc_mod
        import hokora_tui.sync.query_client as qc_mod
        import hokora_tui.sync.rich_message_client as rmc_mod
        import hokora_tui.sync_engine as mod

        importlib.reload(lm_mod)
        importlib.reload(dm_mod)
        importlib.reload(cdsp_mod)
        importlib.reload(hc_mod)
        importlib.reload(qc_mod)
        importlib.reload(ic_mod)
        importlib.reload(rmc_mod)
        importlib.reload(mc_mod)
        importlib.reload(mod)

        reticulum = MagicMock()
        identity = MagicMock()
        engine = mod.SyncEngine(reticulum, identity)
        return engine


def _sign_message(private_key, message_bytes):
    """Sign bytes with an Ed25519 private key, return (pub_bytes, sig)."""
    pub_bytes = private_key.public_key().public_bytes_raw()
    sig = private_key.sign(message_bytes)
    return pub_bytes, sig


def _make_history_response(messages, channel_id="test-chan"):
    """Build a history response dict."""
    return {
        "action": "history",
        "channel_id": channel_id,
        "messages": messages,
    }


# ===========================================================================
# Signature Verification
# ===========================================================================


class TestSyncEngineSignatureVerification:
    """Test Ed25519 signature verification in _handle_response."""

    def test_valid_signature_marks_verified_true(self):
        engine = _make_engine()
        key = Ed25519PrivateKey.generate()
        signed_part = b"hello world"
        pub_bytes, sig = _sign_message(key, signed_part)

        msg = {
            "msg_hash": "abc",
            "sender_hash": "sender1",
            "sender_public_key": pub_bytes,
            "lxmf_signature": sig,
            "lxmf_signed_part": signed_part,
            "seq": 1,
        }
        engine._handle_response(_make_history_response([msg]))
        assert msg["verified"] is True

    def test_invalid_signature_marks_verified_false(self):
        engine = _make_engine()
        key = Ed25519PrivateKey.generate()
        signed_part = b"hello world"
        pub_bytes, _ = _sign_message(key, signed_part)

        msg = {
            "msg_hash": "abc",
            "sender_hash": "sender2",
            "sender_public_key": pub_bytes,
            "lxmf_signature": b"\x00" * 64,  # wrong signature
            "lxmf_signed_part": signed_part,
            "seq": 1,
        }
        engine._handle_response(_make_history_response([msg]))
        assert msg["verified"] is False

    def test_missing_signature_marks_verified_false(self):
        engine = _make_engine()
        msg = {
            "msg_hash": "abc",
            "sender_hash": "sender3",
            "sender_public_key": None,
            "lxmf_signature": None,
            "lxmf_signed_part": None,
            "seq": 1,
        }
        engine._handle_response(_make_history_response([msg]))
        assert msg["verified"] is False

    def test_key_change_detected_as_mitm(self):
        engine = _make_engine()
        key_a = Ed25519PrivateKey.generate()
        key_b = Ed25519PrivateKey.generate()
        signed_part = b"content"
        pub_a, sig_a = _sign_message(key_a, signed_part)
        pub_b, sig_b = _sign_message(key_b, signed_part)

        # First message caches key_a
        msg1 = {
            "msg_hash": "m1",
            "sender_hash": "sender_mitm",
            "sender_public_key": pub_a,
            "lxmf_signature": sig_a,
            "lxmf_signed_part": signed_part,
            "seq": 1,
        }
        engine._handle_response(_make_history_response([msg1]))
        assert msg1["verified"] is True

        # Second message with different key → MITM detection
        msg2 = {
            "msg_hash": "m2",
            "sender_hash": "sender_mitm",
            "sender_public_key": pub_b,
            "lxmf_signature": sig_b,
            "lxmf_signed_part": signed_part,
            "seq": 2,
        }
        engine._handle_response(_make_history_response([msg2]))
        assert msg2["verified"] is False

    def test_verified_key_cached_for_future(self):
        engine = _make_engine()
        key = Ed25519PrivateKey.generate()
        signed_part = b"cache me"
        pub_bytes, sig = _sign_message(key, signed_part)

        msg = {
            "msg_hash": "c1",
            "sender_hash": "sender_cache",
            "sender_public_key": pub_bytes,
            "lxmf_signature": sig,
            "lxmf_signed_part": signed_part,
            "seq": 1,
        }
        engine._handle_response(_make_history_response([msg]))
        assert engine._state.identity_keys.get("sender_cache") == pub_bytes


# ===========================================================================
# Cursor Tracking
# ===========================================================================


class TestSyncEngineCursorTracking:
    """Test sequence cursor management."""

    def test_cursor_advances_on_history_response(self):
        engine = _make_engine()
        msgs = [
            {"seq": 5, "msg_hash": "a", "sender_hash": "s"},
            {"seq": 10, "msg_hash": "b", "sender_hash": "s"},
        ]
        engine._handle_response(_make_history_response(msgs, "ch1"))
        assert engine.get_cursor("ch1") == 10

    def test_cursor_does_not_regress(self):
        engine = _make_engine()
        engine.set_cursor("ch2", 20)
        msgs = [{"seq": 15, "msg_hash": "a", "sender_hash": "s"}]
        engine._handle_response(_make_history_response(msgs, "ch2"))
        assert engine.get_cursor("ch2") == 20

    def test_sequence_gap_warning_recorded(self):
        engine = _make_engine()
        engine.set_cursor("ch3", 5)
        # seq jumps from 5 to 20 — gap of 15, exceeds SEQ_GAP_WARNING (5)
        msgs = [{"seq": 20, "msg_hash": "a", "sender_hash": "s"}]
        engine._handle_response(_make_history_response(msgs, "ch3"))
        warnings = engine.get_seq_warnings("ch3")
        assert len(warnings) >= 1

    def test_get_set_cursor(self):
        engine = _make_engine()
        assert engine.get_cursor("new") == 0
        engine.set_cursor("new", 42)
        assert engine.get_cursor("new") == 42


# ===========================================================================
# Nonce Lifecycle
# ===========================================================================


class TestSyncEngineNonceLifecycle:
    """Test nonce tracking and cleanup."""

    def test_stale_nonces_cleaned_up(self):
        engine = _make_engine()
        old_nonce = b"\x01" * NONCE_SIZE
        engine._state.pending_nonces[old_nonce] = time.time() - 120  # 2 min old
        engine._state.last_nonce_cleanup = 0  # force cleanup to run
        engine._state.cleanup_stale_nonces()
        assert old_nonce not in engine._state.pending_nonces

    def test_cleanup_throttled_by_interval(self):
        engine = _make_engine()
        old_nonce = b"\x02" * NONCE_SIZE
        engine._state.pending_nonces[old_nonce] = time.time() - 120
        engine._state.last_nonce_cleanup = time.time()  # just cleaned
        engine._state.cleanup_stale_nonces()
        # Should NOT have cleaned because interval hasn't passed
        assert old_nonce in engine._state.pending_nonces

    def test_unknown_nonce_response_discarded(self):
        engine = _make_engine()
        callback = MagicMock()
        engine.set_message_callback(callback)

        # Build a raw response with unknown nonce
        nonce = b"\x03" * NONCE_SIZE
        raw = msgpack.packb(
            {
                "nonce": nonce,
                "data": {"action": "history", "channel_id": "ch", "messages": []},
            },
            use_bin_type=True,
        )

        # _on_packet expects (message, packet)
        engine._history._on_packet(raw, MagicMock())
        callback.assert_not_called()


# ===========================================================================
# Event Routing
# ===========================================================================


class TestSyncEngineEventRouting:
    """Test push event vs sync response routing."""

    def test_push_event_routed_to_event_callback(self):
        engine = _make_engine()
        callback = MagicMock()
        engine.set_event_callback(callback)

        event = msgpack.packb(
            {
                "event": "message",
                "data": {"body": "hello"},
            },
            use_bin_type=True,
        )
        engine._history._on_packet(event, MagicMock())
        callback.assert_called_once_with("message", {"body": "hello"})

    def test_node_meta_routed_to_event_callback(self):
        engine = _make_engine()
        callback = MagicMock()
        engine.set_event_callback(callback)

        data = {"action": "node_meta", "node_name": "test"}
        engine._handle_response(data)
        callback.assert_called_once_with("node_meta", data)

    def test_invite_redeemed_routed_to_event_callback(self):
        engine = _make_engine()
        callback = MagicMock()
        engine.set_event_callback(callback)

        data = {"action": "invite_redeemed", "channel_id": "ch1"}
        engine._handle_response(data)
        callback.assert_called_once_with("invite_redeemed", data)
