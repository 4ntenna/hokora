# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for SyncEngine's persisted-TOFU surface.

Covers pin hydration (``update_identity_keys``), the explicit reset path
(``forget_identity_key``), the session warn-dedup (``note_tofu_warning``),
the exception-safe hook trampolines, and the headline cross-restart case:
a pin loaded from the client DB rejects a swapped key in a fresh engine.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hokora_tui.client_db import ClientDB
from hokora_tui.sync._verify import verify_message_signature

# Production sender hashes are RNS identity.hexhash values — 32 HEX chars.
SENDER = "ab" * 16


def _signed_msg(sender_hash: str = SENDER, body: bytes = b"hello"):
    """Build (msg_dict, pubkey_bytes) with a real Ed25519 signature."""
    sk = Ed25519PrivateKey.generate()
    pk_bytes = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    sig = sk.sign(body)
    return {
        "msg_hash": "h" * 64,
        "sender_hash": sender_hash,
        "sender_public_key": pk_bytes,
        "lxmf_signature": sig,
        "lxmf_signed_part": body,
    }, pk_bytes


class TestEngineTofuSurface:
    @pytest.fixture(autouse=True)
    def _patch_rns(self):
        with (
            patch("hokora_tui.sync_engine.RNS") as mock_rns,
            patch("hokora_tui.sync.link_manager.RNS", mock_rns),
            patch("hokora_tui.sync.dm_router.RNS", mock_rns),
            patch("hokora_tui.sync.history_client.RNS", mock_rns),
            patch("hokora_tui.sync.query_client.RNS", mock_rns),
            patch("hokora_tui.sync.invite_client.RNS", mock_rns),
            patch("hokora_tui.sync.cdsp_client.RNS", mock_rns),
            patch("hokora_tui.sync.rich_message_client.RNS", mock_rns),
            patch("hokora_tui.sync.media_client.RNS", mock_rns),
            patch("hokora_tui.sync_engine.LXMF") as mock_lxmf,
            patch("hokora_tui.sync.dm_router.LXMF", mock_lxmf),
            patch("hokora_tui.sync.rich_message_client.LXMF", mock_lxmf),
            patch("hokora_tui.sync.media_client.LXMF", mock_lxmf),
        ):
            mock_rns.Link.ACTIVE = 0x01
            yield

    def _make_engine(self):
        from hokora_tui.sync_engine import SyncEngine

        engine = SyncEngine(MagicMock(), MagicMock())
        engine._dm_router._lxm_router = MagicMock()
        return engine

    # ── Hydration / forget / dedup ────────────────────────────────────

    def test_update_identity_keys_hydrates_cache(self):
        engine = self._make_engine()
        engine.update_identity_keys({SENDER: b"\x01" * 32})
        assert engine.identity_keys[SENDER] == b"\x01" * 32

    def test_forget_identity_key_removes_and_reports(self):
        engine = self._make_engine()
        engine.update_identity_keys({SENDER: b"\x01" * 32})
        assert engine.forget_identity_key(SENDER) is True
        assert SENDER not in engine.identity_keys
        assert engine.forget_identity_key(SENDER) is False

    def test_note_tofu_warning_test_and_set(self):
        engine = self._make_engine()
        assert engine.note_tofu_warning(SENDER) is True
        assert engine.note_tofu_warning(SENDER) is False

    def test_cache_identity_key_is_first_write_wins(self):
        """The test/seed API must not be a pin-overwrite path — replacing
        a pin requires forget_identity_key + re-verification."""
        engine = self._make_engine()
        engine.cache_identity_key(SENDER, b"\x01" * 32)
        engine.cache_identity_key(SENDER, b"\x02" * 32)
        assert engine.identity_keys[SENDER] == b"\x01" * 32

    def test_forget_identity_key_clears_warn_dedup(self):
        engine = self._make_engine()
        engine.update_identity_keys({SENDER: b"\x01" * 32})
        assert engine.note_tofu_warning(SENDER) is True
        engine.forget_identity_key(SENDER)
        # A later genuine key change must be able to warn again.
        assert engine.note_tofu_warning(SENDER) is True

    # ── Trampolines ───────────────────────────────────────────────────

    def test_new_key_trampoline_fires_registered_callback(self):
        engine = self._make_engine()
        cb = MagicMock()
        engine.set_tofu_new_key_callback(cb)
        engine.tofu_new_key_hook(SENDER, b"\x01" * 32)
        cb.assert_called_once_with(SENDER, b"\x01" * 32)

    def test_conflict_trampoline_fires_registered_callback(self):
        engine = self._make_engine()
        cb = MagicMock()
        engine.set_tofu_key_conflict_callback(cb)
        engine.tofu_key_conflict_hook(SENDER, b"\x01" * 32, b"\x02" * 32)
        cb.assert_called_once_with(SENDER, b"\x01" * 32, b"\x02" * 32)

    def test_trampolines_noop_when_unwired(self):
        engine = self._make_engine()
        engine.tofu_new_key_hook(SENDER, b"\x01" * 32)
        engine.tofu_key_conflict_hook(SENDER, b"\x01" * 32, b"\x02" * 32)

    def test_trampolines_swallow_callback_exceptions(self):
        """A persistence/warning failure must never break verification."""
        engine = self._make_engine()
        engine.set_tofu_new_key_callback(MagicMock(side_effect=RuntimeError("db down")))
        engine.set_tofu_key_conflict_callback(MagicMock(side_effect=RuntimeError("ui down")))
        engine.tofu_new_key_hook(SENDER, b"\x01" * 32)
        engine.tofu_key_conflict_hook(SENDER, b"\x01" * 32, b"\x02" * 32)

    # ── Cross-restart MITM detection (the headline case) ──────────────

    def test_persisted_pin_rejects_swapped_key_after_restart(self, tmp_path: Path):
        """A pin written in session one must reject a different (validly
        signed) key for the same sender in a fresh engine hydrated from
        the client DB — the cross-restart MITM detection this feature
        exists to provide.
        """
        db_path = tmp_path / "tui.db"

        # Session one: first contact pins the sender's key via the
        # write-through hook.
        msg_a, key_a = _signed_msg()
        db = ClientDB(db_path, encrypt=False)
        try:
            engine = self._make_engine()
            store = db.tofu_keys
            engine.set_tofu_new_key_callback(
                lambda sender, key: store.insert_if_absent(sender, key)
            )
            assert (
                verify_message_signature(
                    msg_a,
                    engine.identity_keys,
                    on_new_key=engine.tofu_new_key_hook,
                    on_key_conflict=engine.tofu_key_conflict_hook,
                )
                is True
            )
            assert db.tofu_keys.get(SENDER) == key_a
        finally:
            db.close()

        # "Restart": fresh engine, fresh ClientDB handle, hydrate pins.
        db2 = ClientDB(db_path, encrypt=False)
        try:
            engine2 = self._make_engine()
            engine2.update_identity_keys(db2.tofu_keys.all_keys())
            conflict = MagicMock()
            engine2.set_tofu_key_conflict_callback(conflict)

            # Same sender, different key, valid signature under the new key.
            msg_b, key_b = _signed_msg()
            assert key_b != key_a
            result = verify_message_signature(
                msg_b,
                engine2.identity_keys,
                on_new_key=engine2.tofu_new_key_hook,
                on_key_conflict=engine2.tofu_key_conflict_hook,
            )
            assert result is False
            conflict.assert_called_once_with(SENDER, key_a, key_b)
            # In-memory pin and persisted pin both keep the original key.
            assert engine2.identity_keys[SENDER] == key_a
            assert db2.tofu_keys.get(SENDER) == key_a
        finally:
            db2.close()

    def test_forget_key_command_resets_real_engine_and_store(self, tmp_path: Path):
        """End-to-end reset with production-width sender hashes: pin via
        the verify chokepoint, /forget-key removes both halves, and the
        previously conflicting key can re-pin."""
        import logging

        from hokora_tui.commands._base import CommandContext, UIGate
        from hokora_tui.commands.forget_key_command import ForgetKeyCommand

        db = ClientDB(tmp_path / "tui.db", encrypt=False)
        try:
            engine = self._make_engine()
            store = db.tofu_keys
            engine.set_tofu_new_key_callback(
                lambda sender, key: store.insert_if_absent(sender, key)
            )
            msg, key_a = _signed_msg()
            assert len(msg["sender_hash"]) == 32  # production hexhash width
            assert (
                verify_message_signature(
                    msg,
                    engine.identity_keys,
                    on_new_key=engine.tofu_new_key_hook,
                )
                is True
            )
            assert db.tofu_keys.get(SENDER) == key_a

            ctx = CommandContext(
                app=MagicMock(),
                state=MagicMock(),
                db=db,
                engine=engine,
                gate=UIGate(loop=None),
                log=logging.getLogger("test"),
                status=MagicMock(),
                emit=MagicMock(),
            )
            ForgetKeyCommand().execute(ctx, SENDER)

            assert db.tofu_keys.get(SENDER) is None
            assert SENDER not in engine.identity_keys
            assert "Forgot pinned key" in ctx.status.set_context.call_args.args[0]

            # A different key for the same sender can now re-pin.
            msg_b, key_b = _signed_msg()
            assert (
                verify_message_signature(
                    msg_b,
                    engine.identity_keys,
                    on_new_key=engine.tofu_new_key_hook,
                )
                is True
            )
            assert db.tofu_keys.get(SENDER) == key_b
        finally:
            db.close()
