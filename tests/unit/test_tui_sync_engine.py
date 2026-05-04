# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Comprehensive tests for TUI SyncEngine."""

import time
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Nonce management tests
# ---------------------------------------------------------------------------


class TestNonceManagement:
    """Tests for nonce generation and stale nonce cleanup."""

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
            self._mock_rns = mock_rns
            self._mock_lxmf = mock_lxmf
            yield

    def _make_engine(self):
        from hokora_tui.sync_engine import SyncEngine

        reticulum = MagicMock()
        identity = MagicMock()
        identity.hexhash = "a" * 32
        engine = SyncEngine(reticulum, identity)
        engine._dm_router._lxm_router = MagicMock()
        return engine

    def test_generate_nonce_produces_unique_values(self):
        """Two consecutive generate_nonce calls must return different bytes."""
        from hokora.protocol.wire import generate_nonce

        nonce1 = generate_nonce()
        nonce2 = generate_nonce()
        assert nonce1 != nonce2

    def test_cleanup_stale_nonces_removes_old_entries(self):
        """Nonces older than _NONCE_MAX_AGE are removed during cleanup."""
        from hokora_tui.sync_engine import _NONCE_MAX_AGE

        engine = self._make_engine()

        old_nonce = b"\xaa" * 16
        engine._state.pending_nonces[old_nonce] = time.time() - _NONCE_MAX_AGE - 5

        engine._state.last_nonce_cleanup = 0  # force cleanup to run
        engine._state.cleanup_stale_nonces()

        assert old_nonce not in engine._state.pending_nonces

    def test_fresh_nonces_survive_cleanup(self):
        """Nonces that are not yet stale are kept during cleanup."""

        engine = self._make_engine()

        fresh_nonce = b"\xbb" * 16
        engine._state.pending_nonces[fresh_nonce] = time.time()

        engine._state.last_nonce_cleanup = 0  # force cleanup to run
        engine._state.cleanup_stale_nonces()

        assert fresh_nonce in engine._state.pending_nonces


# ---------------------------------------------------------------------------
# Sequence integrity tests
# ---------------------------------------------------------------------------


class TestSequenceIntegrity:
    """Tests for sequence gap detection in _handle_response."""

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
            self._mock_rns = mock_rns
            self._mock_lxmf = mock_lxmf
            yield

    def _make_engine(self):
        from hokora_tui.sync_engine import SyncEngine

        reticulum = MagicMock()
        engine = SyncEngine(reticulum)
        return engine

    def _make_message(self, seq, sender="sender1"):
        """Build a minimal message dict for _handle_response."""
        return {
            "msg_hash": f"hash_{seq}",
            "sender_hash": sender,
            "seq": seq,
            "lxmf_signature": None,
            "sender_public_key": None,
            "lxmf_signed_part": None,
        }

    def test_contiguous_sequences_produce_no_warnings(self):
        """Messages with seq 2, 3, 4 after cursor=1 trigger no gap warnings."""
        with patch(
            "hokora_tui.sync_engine.VerificationService.verify_ed25519_signature",
            return_value=False,
        ):
            engine = self._make_engine()
            engine.set_cursor("ch1", 1)

            messages = [
                self._make_message(2),
                self._make_message(3),
                self._make_message(4),
            ]
            engine._handle_response(
                {
                    "action": "history",
                    "channel_id": "ch1",
                    "messages": messages,
                }
            )

            warnings = engine.get_seq_warnings("ch1")
            assert len(warnings) == 0

    def test_sequence_gap_produces_warning(self):
        """A jump from cursor=1 to seq=10 (gap=9 > SEQ_GAP_WARNING=5) adds a warning."""
        with patch(
            "hokora_tui.sync_engine.VerificationService.verify_ed25519_signature",
            return_value=False,
        ):
            engine = self._make_engine()
            engine.set_cursor("ch1", 1)

            messages = [
                self._make_message(2),
                self._make_message(10),  # gap of 8 from seq 2 -> triggers warning
            ]
            engine._handle_response(
                {
                    "action": "history",
                    "channel_id": "ch1",
                    "messages": messages,
                }
            )

            warnings = engine.get_seq_warnings("ch1")
            assert len(warnings) >= 1
            assert any("gap" in w.lower() for w in warnings)

    def test_no_warnings_when_no_gap_exists(self):
        """Sequence 2, 3 after cursor=1 results in empty warning list."""
        with patch(
            "hokora_tui.sync_engine.VerificationService.verify_ed25519_signature",
            return_value=False,
        ):
            engine = self._make_engine()
            engine.set_cursor("ch1", 1)

            messages = [
                self._make_message(2),
                self._make_message(3),
            ]
            engine._handle_response(
                {
                    "action": "history",
                    "channel_id": "ch1",
                    "messages": messages,
                }
            )

            warnings = engine.get_seq_warnings("ch1")
            assert warnings == []


# ---------------------------------------------------------------------------
# Signature verification tests
# ---------------------------------------------------------------------------


class TestSignatureVerification:
    """Tests for Ed25519 signature verification inside _handle_response."""

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
            self._mock_rns = mock_rns
            self._mock_lxmf = mock_lxmf
            yield

    def _make_engine(self):
        from hokora_tui.sync_engine import SyncEngine

        reticulum = MagicMock()
        engine = SyncEngine(reticulum)
        return engine

    def _signed_message(self, sender="abc123", seq=1):
        return {
            "msg_hash": "hash1",
            "sender_hash": sender,
            "seq": seq,
            "lxmf_signature": b"\x01" * 64,
            "sender_public_key": b"\x02" * 32,
            "lxmf_signed_part": b"\x03" * 64,
        }

    def test_valid_signature_sets_verified_true(self):
        """When verify_ed25519_signature returns True, msg['verified'] is True."""
        with patch(
            "hokora_tui.sync_engine.VerificationService.verify_ed25519_signature",
            return_value=True,
        ):
            engine = self._make_engine()
            msg = self._signed_message()
            engine._handle_response(
                {
                    "action": "history",
                    "channel_id": "ch1",
                    "messages": [msg],
                }
            )
            assert msg["verified"] is True

    def test_invalid_signature_sets_verified_false(self):
        """When verify_ed25519_signature returns False, msg['verified'] is False."""
        with patch(
            "hokora_tui.sync_engine.VerificationService.verify_ed25519_signature",
            return_value=False,
        ):
            engine = self._make_engine()
            msg = self._signed_message()
            engine._handle_response(
                {
                    "action": "history",
                    "channel_id": "ch1",
                    "messages": [msg],
                }
            )
            assert msg["verified"] is False

    def test_key_change_detected_sets_verified_false(self):
        """MITM detection: cached key differs from received key → verified=False."""
        with patch(
            "hokora_tui.sync_engine.VerificationService.verify_ed25519_signature",
            return_value=True,
        ):
            engine = self._make_engine()
            sender = "abc"
            original_key = b"\xaa" * 32
            new_key = b"\xbb" * 32  # different from cached

            # Prime the identity key cache
            engine.cache_identity_key(sender, original_key)

            msg = {
                "msg_hash": "hash_mitm",
                "sender_hash": sender,
                "seq": 1,
                "lxmf_signature": b"\x01" * 64,
                "sender_public_key": new_key,
                "lxmf_signed_part": b"\x03" * 64,
            }
            engine._handle_response(
                {
                    "action": "history",
                    "channel_id": "ch1",
                    "messages": [msg],
                }
            )
            assert msg["verified"] is False


# ---------------------------------------------------------------------------
# Request encoding tests
# ---------------------------------------------------------------------------


class TestRequestEncoding:
    """Tests verifying that sync request methods call RNS.Packet(...).send()."""

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
            self._mock_rns = mock_rns
            self._mock_lxmf = mock_lxmf
            yield

    def _make_engine(self):
        from hokora_tui.sync_engine import SyncEngine

        reticulum = MagicMock()
        engine = SyncEngine(reticulum)
        return engine

    def _active_link(self):
        link = MagicMock()
        link.status = self._mock_rns.Link.ACTIVE
        return link

    def test_sync_history_sends_packet(self):
        """sync_history() calls RNS.Packet(link, request).send()."""
        engine = self._make_engine()
        link = self._active_link()
        engine._link_manager._links["ch1"] = link

        engine.sync_history("ch1", since_seq=0, limit=25)

        self._mock_rns.Packet.assert_called_once()
        packet_instance = self._mock_rns.Packet.return_value
        packet_instance.send.assert_called_once()

    def test_sync_history_encodes_channel_id(self):
        """sync_history() passes the correct link to RNS.Packet."""
        engine = self._make_engine()
        link = self._active_link()
        engine._link_manager._links["ch_test"] = link

        engine.sync_history("ch_test")

        call_args = self._mock_rns.Packet.call_args
        assert call_args[0][0] is link  # first positional arg is the link

    def test_request_node_meta_sends_packet(self):
        """request_node_meta() calls RNS.Packet(link, request).send()."""
        engine = self._make_engine()
        link = self._active_link()
        engine._link_manager._links["ch1"] = link

        engine.request_node_meta("ch1")

        self._mock_rns.Packet.assert_called_once()
        packet_instance = self._mock_rns.Packet.return_value
        packet_instance.send.assert_called_once()

    def test_subscribe_live_sends_packet(self):
        """subscribe_live() calls RNS.Packet(link, request).send()."""
        engine = self._make_engine()
        link = self._active_link()
        engine._link_manager._links["ch1"] = link

        engine.subscribe_live("ch1")

        self._mock_rns.Packet.assert_called_once()
        packet_instance = self._mock_rns.Packet.return_value
        packet_instance.send.assert_called_once()

    def test_redeem_invite_sends_packet_with_token(self):
        """redeem_invite() calls RNS.Packet(link, request).send()."""
        import msgpack
        from hokora.protocol.wire import _strip_length_header

        engine = self._make_engine()
        link = self._active_link()
        engine._link_manager._links["ch1"] = link

        engine.redeem_invite("ch1", token="invite-token-xyz")

        self._mock_rns.Packet.assert_called_once()
        packet_instance = self._mock_rns.Packet.return_value
        packet_instance.send.assert_called_once()

        # Verify the encoded payload contains the token
        call_args = self._mock_rns.Packet.call_args
        raw_request = call_args[0][1]
        decoded = msgpack.unpackb(_strip_length_header(raw_request), raw=False)
        assert decoded["payload"]["token"] == "invite-token-xyz"


# ---------------------------------------------------------------------------
# Link lifecycle tests
# ---------------------------------------------------------------------------


class TestLinkLifecycle:
    """Tests for connect_channel and disconnect_channel."""

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
            self._mock_rns = mock_rns
            self._mock_lxmf = mock_lxmf
            yield

    def _make_engine(self):
        from hokora_tui.sync_engine import SyncEngine

        reticulum = MagicMock()
        engine = SyncEngine(reticulum)
        return engine

    def test_connect_channel_stores_link_in_links(self):
        """connect_channel() with a recalled identity stores the link in _links."""
        engine = self._make_engine()

        dest_hash = b"\x01" * 32
        # Make Identity.recall return a non-None identity
        self._mock_rns.Identity.recall.return_value = MagicMock()
        mock_link = MagicMock()
        self._mock_rns.Link.return_value = mock_link

        engine.connect_channel(dest_hash, "ch1")

        assert "ch1" in engine._link_manager._links
        assert engine._link_manager._links["ch1"] is mock_link

    def test_connect_channel_no_recall_does_not_store_link(self):
        """connect_channel() when identity recall fails stores nothing in _links."""
        engine = self._make_engine()

        dest_hash = b"\x02" * 32
        self._mock_rns.Identity.recall.return_value = None

        engine.connect_channel(dest_hash, "ch1")

        assert "ch1" not in engine._link_manager._links

    def test_disconnect_channel_removes_link_and_calls_teardown(self):
        """disconnect_channel() removes from _links and calls link.teardown()."""
        engine = self._make_engine()

        link = MagicMock()
        engine._link_manager._links["ch1"] = link

        engine.disconnect_channel("ch1")

        assert "ch1" not in engine._link_manager._links
        link.teardown.assert_called_once()


# ---------------------------------------------------------------------------
# Invite redemption tests
# ---------------------------------------------------------------------------


class TestInviteRedemption:
    """Tests for pending invite redemption flow and event callbacks."""

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
            self._mock_rns = mock_rns
            self._mock_lxmf = mock_lxmf
            yield

    def _make_engine(self):
        from hokora_tui.sync_engine import SyncEngine

        reticulum = MagicMock()
        engine = SyncEngine(reticulum)
        return engine

    def test_pending_redeem_triggers_redeem_invite_on_link_established(self):
        """If token is in _pending_redeems, _on_link_established calls redeem_invite."""
        engine = self._make_engine()
        engine._state.pending_redeems["ch1"] = "my-invite-token"

        # Set up an active link so redeem_invite won't bail out early
        mock_link = MagicMock()
        mock_link.status = self._mock_rns.Link.ACTIVE
        engine._link_manager._links["ch1"] = mock_link

        with patch.object(engine, "redeem_invite") as mock_redeem:
            engine._on_link_established("ch1", mock_link)
            mock_redeem.assert_called_once_with("ch1", "my-invite-token")

    def test_invite_redeemed_response_fires_event_callback(self):
        """action='invite_redeemed' in _handle_response triggers event_callback."""
        engine = self._make_engine()

        event_callback = MagicMock()
        engine.set_event_callback(event_callback)

        data = {
            "action": "invite_redeemed",
            "channel_id": "ch1",
            "status": "ok",
        }
        engine._handle_response(data)

        event_callback.assert_called_once_with("invite_redeemed", data)


# ---------------------------------------------------------------------------
# connect_channel pubkey-seeded identity (invite-without-announce)
# ---------------------------------------------------------------------------


class TestConnectChannelWithPubkey:
    """Verify that a pending pubkey lets connect_channel open a Link without
    waiting for an announce (the root fix for I2P invite redemption hangs)."""

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
            mock_rns.Destination.OUT = 0x01
            mock_rns.Destination.SINGLE = 0x02
            self._mock_rns = mock_rns
            self._mock_lxmf = mock_lxmf
            yield

    def _make_engine(self):
        from hokora_tui.sync_engine import SyncEngine

        reticulum = MagicMock()
        reticulum.is_connected_to_shared_instance = False
        engine = SyncEngine(reticulum)
        return engine

    def test_pubkey_consumed_and_identity_cached(self):
        engine = self._make_engine()
        dest = bytes.fromhex("deadbeef" * 4)
        dest_hex = dest.hex()
        pk = b"\x01" * 64
        engine._state.pending_pubkeys[dest_hex] = pk

        # No announce yet — recall returns None. has_path True so we skip defer.
        self._mock_rns.Identity.recall.return_value = None
        self._mock_rns.Transport.has_path.return_value = True

        mock_identity = MagicMock()
        self._mock_rns.Identity.return_value = mock_identity

        engine.connect_channel(dest, "chan0")

        # Pubkey was consumed exactly once
        assert dest_hex not in engine._state.pending_pubkeys
        # Identity was constructed and cached on the channel
        self._mock_rns.Identity.assert_called_with(create_keys=False)
        mock_identity.load_public_key.assert_called_once_with(pk)
        assert engine._state.channel_identities["chan0"] is mock_identity
        # Link was created (not deferred) because identity + path were available
        assert "chan0" in engine._link_manager._links
        assert "chan0" not in engine._state.pending_connects

    def test_pubkey_pop_survives_path_wait_via_channel_identity_cache(self):
        """If path is unknown, connect defers, but the cached identity
        lets retry_pending_connects try again without re-needing the pubkey."""
        engine = self._make_engine()
        dest = bytes.fromhex("cafebabe" * 4)
        dest_hex = dest.hex()
        engine._state.pending_pubkeys[dest_hex] = b"\x02" * 64

        self._mock_rns.Identity.recall.return_value = None
        self._mock_rns.Transport.has_path.return_value = False
        mock_identity = MagicMock()
        self._mock_rns.Identity.return_value = mock_identity

        engine.connect_channel(dest, "chan1")
        # Deferred: path unknown
        assert "chan1" in engine._state.pending_connects
        assert "chan1" not in engine._link_manager._links
        # But identity is cached — retry will skip the recall check
        assert engine._state.channel_identities["chan1"] is mock_identity
        assert dest_hex not in engine._state.pending_pubkeys  # consumed

        # Simulate path now available on retry
        self._mock_rns.Transport.has_path.return_value = True
        engine.retry_pending_connects()
        assert "chan1" in engine._link_manager._links
        assert "chan1" not in engine._state.pending_connects

    def test_no_pubkey_still_defers_on_missing_identity(self):
        """Without a pending pubkey, behaviour is unchanged: defer to announce."""
        engine = self._make_engine()
        dest = bytes.fromhex("f00dface" * 4)
        self._mock_rns.Identity.recall.return_value = None

        engine.connect_channel(dest, "chan2")
        assert "chan2" in engine._state.pending_connects
        assert "chan2" not in engine._link_manager._links


# ---------------------------------------------------------------------------
# Link establishment timeout override (high-latency transports)
# ---------------------------------------------------------------------------


class TestLinkEstablishmentTimeoutOverride:
    """Connect should extend link.establishment_timeout past RNS's 6s/hop
    default, to tolerate I2P tunnel-setup RTT and multi-hop mesh paths."""

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
            mock_rns.Destination.OUT = 0x01
            mock_rns.Destination.SINGLE = 0x02
            self._mock_rns = mock_rns
            self._mock_lxmf = mock_lxmf
            yield

    def _make_engine(self):
        from hokora_tui.sync_engine import SyncEngine

        engine = SyncEngine(MagicMock())
        return engine

    def _prepare_link(self, rns_default_timeout: int):
        """Install a Link mock that starts with a given establishment_timeout."""
        link_mock = MagicMock()
        link_mock.establishment_timeout = rns_default_timeout
        self._mock_rns.Link.return_value = link_mock
        self._mock_rns.Identity.recall.return_value = MagicMock()
        self._mock_rns.Transport.has_path.return_value = True
        return link_mock

    def test_extends_timeout_when_rns_baseline_is_low(self):
        """RNS default 6s/hop is raised to our 30s/hop floor."""
        from hokora_tui.sync_engine import LINK_ESTABLISHMENT_TIMEOUT_PER_HOP

        engine = self._make_engine()
        link_mock = self._prepare_link(rns_default_timeout=6)
        self._mock_rns.Transport.hops_to.return_value = 1

        engine.connect_channel(bytes.fromhex("deadbeef" * 4), "chan0")

        assert link_mock.establishment_timeout >= LINK_ESTABLISHMENT_TIMEOUT_PER_HOP

    def test_preserves_baseline_when_rns_already_computed_higher(self):
        """If RNS computed a longer timeout (slow interface, many hops),
        we keep it — we only raise the floor, never lower."""
        engine = self._make_engine()
        link_mock = self._prepare_link(rns_default_timeout=500)
        self._mock_rns.Transport.hops_to.return_value = 3

        engine.connect_channel(bytes.fromhex("cafebabe" * 4), "chan1")

        # RNS baseline (500) > our floor (30 * 3 = 90) — baseline preserved
        assert link_mock.establishment_timeout == 500

    def test_scales_with_hop_count(self):
        """Multi-hop mesh: floor applies per hop, so 3 hops ≥ 90s."""
        from hokora_tui.sync_engine import LINK_ESTABLISHMENT_TIMEOUT_PER_HOP

        engine = self._make_engine()
        link_mock = self._prepare_link(rns_default_timeout=18)
        self._mock_rns.Transport.hops_to.return_value = 3

        engine.connect_channel(bytes.fromhex("abcdef12" * 4), "chan2")

        assert link_mock.establishment_timeout >= LINK_ESTABLISHMENT_TIMEOUT_PER_HOP * 3

    def test_falls_back_silently_if_rns_raises(self):
        """If hops_to or attribute access raises, we log and move on — no crash."""
        engine = self._make_engine()
        self._prepare_link(rns_default_timeout=6)
        self._mock_rns.Transport.hops_to.side_effect = RuntimeError("boom")

        # Must not raise — try/except around the override
        engine.connect_channel(bytes.fromhex("11223344" * 4), "chan3")
        assert "chan3" in engine._link_manager._links


# ---------------------------------------------------------------------------
# Link-connected callback fires via _on_link_established
# ---------------------------------------------------------------------------


class TestConnectedCallback:
    """The UI transition from 'Resolving path...' to 'Connected' hangs off
    this callback; verify it fires whenever a link establishes."""

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
            self._mock_rns = mock_rns
            self._mock_lxmf = mock_lxmf
            yield

    def _make_engine(self):
        from hokora_tui.sync_engine import SyncEngine

        engine = SyncEngine(MagicMock())
        # Skip downstream post-link work that needs a real RNS link
        engine.sync_history = MagicMock()
        engine.subscribe_live = MagicMock()
        engine.send_cdsp_session_init = MagicMock()
        engine.request_node_meta = MagicMock()
        engine._ensure_lxmf_path = MagicMock()
        return engine

    def test_callback_invoked_with_channel_and_dest(self):
        engine = self._make_engine()
        cb = MagicMock()
        engine.set_connected_callback(cb)

        link = MagicMock()
        link.destination.hash = b"\xaa" * 16
        link.keepalive = 30

        engine._on_link_established("chan_x", link)

        cb.assert_called_once_with("chan_x", b"\xaa" * 16)

    def test_callback_failure_does_not_abort_post_link_setup(self):
        engine = self._make_engine()
        cb = MagicMock(side_effect=RuntimeError("handler exploded"))
        engine.set_connected_callback(cb)

        link = MagicMock()
        link.destination.hash = b"\xbb" * 16
        link.keepalive = 30

        # Must not raise — _on_link_established wraps the callback
        engine._on_link_established("chan_y", link)
        # Post-link setup still happened
        engine.sync_history.assert_called_once()
        engine.subscribe_live.assert_called_once()
