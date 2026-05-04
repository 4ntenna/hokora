# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests that the TUI's live-event dispatcher runs Ed25519 verification
before invoking ``on_messages``, mirroring the history-sync chokepoint.

Without this hook, live-arrived messages were stored with whatever
``verified`` the daemon happened to put on the wire (None → 0 under the
old storage default), so the same row that rendered as verified during
the live session re-rendered as ``[UNVERIFIED]`` on next start.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from hokora_tui.commands.event_dispatcher import dispatch_event


def _make_app(identity_keys: dict | None = None):
    app = MagicMock()
    app.sync_engine = MagicMock()
    app.sync_engine.identity_keys = identity_keys if identity_keys is not None else {}
    return app


def _signed_msg(channel_id="ch1", seq=42, body=b"payload"):
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    sig = sk.sign(body)
    return {
        "msg_hash": "h" * 64,
        "channel_id": channel_id,
        "sender_hash": "s" * 32,
        "seq": seq,
        "sender_public_key": pk,
        "lxmf_signature": sig,
        "lxmf_signed_part": body,
    }


class TestLiveMessageVerification:
    """Verify is called before on_messages for ``message`` events."""

    def test_valid_sig_sets_verified_true(self):
        app = _make_app()
        msg = _signed_msg()
        with patch("hokora_tui.commands.event_dispatcher.cb.on_messages") as mock_on:
            dispatch_event(app, "message", msg)
            assert msg["verified"] is True
            mock_on.assert_called_once()
            # on_messages receives the verified-augmented msg
            assert mock_on.call_args.args[2][0]["verified"] is True

    def test_bad_sig_sets_verified_false(self):
        app = _make_app()
        msg = _signed_msg()
        msg["lxmf_signature"] = b"\x00" * 64
        with patch("hokora_tui.commands.event_dispatcher.cb.on_messages") as mock_on:
            dispatch_event(app, "message", msg)
            assert msg["verified"] is False
            mock_on.assert_called_once()

    def test_missing_pubkey_leaves_verified_unset(self):
        """Daemon hasn't been upgraded to populate sender_public_key on
        the live wire — verifier returns None, dispatcher leaves
        ``verified`` absent. Storage now persists absent-as-0 (B-lite
        retirement of the Option-A default-True backstop), so the row
        renders ``[UNVERIFIED]`` honestly until the wire is fixed.
        """
        app = _make_app()
        msg = _signed_msg()
        msg["sender_public_key"] = None
        with patch("hokora_tui.commands.event_dispatcher.cb.on_messages") as mock_on:
            dispatch_event(app, "message", msg)
            assert "verified" not in msg
            mock_on.assert_called_once()

    def test_tofu_mismatch_marks_unverified(self):
        msg = _signed_msg()
        # Pre-populate cache with a DIFFERENT pubkey for this sender.
        app = _make_app(identity_keys={msg["sender_hash"]: b"\xff" * 32})
        with patch("hokora_tui.commands.event_dispatcher.cb.on_messages") as mock_on:
            dispatch_event(app, "message", msg)
            assert msg["verified"] is False
            mock_on.assert_called_once()

    def test_no_sync_engine_skips_verification(self):
        """Defensive: app without sync_engine attribute (early init)
        must not crash; dispatcher just calls on_messages.
        """
        app = SimpleNamespace()  # no sync_engine attr
        msg = _signed_msg()
        with patch("hokora_tui.commands.event_dispatcher.cb.on_messages") as mock_on:
            dispatch_event(app, "message", msg)
            mock_on.assert_called_once()

    def test_message_with_reply_to_still_verifies(self):
        """Thread replies route through on_messages too — verify still runs."""
        app = _make_app()
        msg = _signed_msg()
        msg["reply_to"] = "p" * 64
        msg["thread_seq"] = 1
        with patch("hokora_tui.commands.event_dispatcher.cb.on_messages") as mock_on:
            with patch("hokora_tui.commands.event_dispatcher.cb.handle_thread_reply_push"):
                dispatch_event(app, "message", msg)
                assert msg["verified"] is True
                mock_on.assert_called_once()
