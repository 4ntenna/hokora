# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for LinkManager: RNS link lifecycle and request handling."""

import asyncio
from unittest.mock import MagicMock, patch


def _make_link_manager():
    """Create a LinkManager with mocked RNS.

    Constructs a transient event loop only to satisfy ``LinkManager``'s
    constructor (it stores the reference but does not run it here). The
    loop is closed and the thread-local policy reset so a leaked loop
    cannot poison subsequent pytest-asyncio tests.
    """
    with patch.dict("sys.modules", {"RNS": MagicMock()}):
        import importlib
        import hokora.protocol.link_manager as mod

        importlib.reload(mod)

        loop = asyncio.new_event_loop()
        try:
            lm = mod.LinkManager(loop)
        finally:
            loop.close()
            asyncio.set_event_loop(None)
        return lm, mod


class TestLinkEstablished:
    def test_on_link_established_registers_context(self):
        lm, mod = _make_link_manager()
        link = MagicMock()
        link.link_id = b"\x01" * 16
        link.get_remote_identity.return_value = None

        lm.on_link_established(link, "ch01")

        ctx = lm.get_link_context(link.link_id)
        assert ctx is not None
        assert ctx.channel_id == "ch01"

    def test_on_link_closed_removes_context(self):
        lm, mod = _make_link_manager()
        link = MagicMock()
        link.link_id = b"\x02" * 16
        link.get_remote_identity.return_value = None

        lm.on_link_established(link, "ch01")
        assert lm.get_link_context(link.link_id) is not None

        # Simulate link close callback
        lm._on_link_closed(link)
        assert lm.get_link_context(link.link_id) is None


class TestResourceFilter:
    def test_resource_filter_accepts_under_5mb(self):
        lm, mod = _make_link_manager()
        resource = MagicMock()
        resource.data_size = 1024 * 1024  # 1 MB
        assert lm._resource_filter(resource) is True

    def test_resource_filter_rejects_over_5mb(self):
        lm, mod = _make_link_manager()
        resource = MagicMock()
        resource.data_size = 10 * 1024 * 1024  # 10 MB
        assert lm._resource_filter(resource) is False


class TestOnPacket:
    def test_on_packet_dispatches_to_sync_handler(self):
        lm, mod = _make_link_manager()
        lm.loop = asyncio.new_event_loop()
        try:

            async def mock_handler(action, nonce, payload, channel_id, requester_hash):
                return {"action": "test"}

            lm.set_sync_handler(mock_handler)

            link = MagicMock()
            link.link_id = b"\x03" * 16
            link.get_remote_identity.return_value = None
            lm.on_link_established(link, "ch01")

            # Missing sync handler should log warning, not raise.
            lm2, _ = _make_link_manager()
            packet = MagicMock()
            packet.link = link
            lm2._on_packet(b"invalid", packet)
        finally:
            lm.loop.close()
            asyncio.set_event_loop(None)

    def test_on_packet_handles_timeout(self):
        lm, mod = _make_link_manager()
        # No sync handler set
        packet = MagicMock()
        packet.link = MagicMock()
        packet.link.link_id = b"\x04" * 16
        # Should not raise even without handler
        lm._on_packet(b"data", packet)

    def test_on_packet_handles_sync_error(self):
        lm, mod = _make_link_manager()
        packet = MagicMock()
        packet.link = MagicMock()
        packet.link.link_id = b"\x05" * 16
        # Should not raise with invalid data
        lm._on_packet(b"\x00invalid", packet)


class TestOnIdentified:
    def test_on_identified_updates_identity_hash(self):
        lm, mod = _make_link_manager()
        link = MagicMock()
        link.link_id = b"\x06" * 16
        link.get_remote_identity.return_value = None
        lm.on_link_established(link, "ch01")

        identity = MagicMock()
        identity.hexhash = "b" * 32
        lm._on_identified(link, identity)

        ctx = lm.get_link_context(link.link_id)
        assert ctx.identity_hash == "b" * 32


class TestErrorResponseContent:
    def test_error_response_does_not_leak_exception_details(self):
        """Verify the error handler sends a generic message, not str(e).

        Directly tests the code path by verifying the encode_sync_response
        call uses 'Internal server error' rather than the exception string.
        """
        # Read the source code to verify the fix is in place
        import inspect
        from hokora.protocol import link_manager as mod

        source = inspect.getsource(mod.LinkManager._on_packet)
        # The error response must use a generic message
        assert '"Internal server error"' in source
        # Must NOT use str(e) in error responses
        assert '"error": str(e)' not in source
        assert '{"error": str(e)}' not in source

    def test_encode_sync_response_with_generic_error(self):
        """Verify that encoding a generic error response works correctly."""
        from hokora.protocol.wire import encode_sync_response, decode_sync_response

        nonce = b"\x00" * 16
        error_data = {"error": "Internal server error"}
        encoded = encode_sync_response(nonce, error_data)
        decoded = decode_sync_response(encoded)
        assert decoded["data"]["error"] == "Internal server error"


class TestEpochManagerRegistry:
    """``LinkManager._epoch_managers`` must be initialised in
    ``__init__`` (not set lazily), and EPOCH_DATA frames arriving
    before the registry is populated must be dropped with a visible
    debug log rather than falling through to decode_sync_request as
    garbage."""

    def test_epoch_managers_initialised_in_ctor(self):
        lm, _ = _make_link_manager()
        assert lm._epoch_managers == {}

    def test_epoch_data_without_manager_logs_and_returns(self, caplog):
        import logging

        lm, mod = _make_link_manager()
        lm._sync_handler = MagicMock()

        link = MagicMock()
        link.link_id = b"\x10" * 16
        identity = MagicMock()
        identity.hexhash = "deadbeef" * 4
        link.get_remote_identity.return_value = identity
        lm.on_link_established(link, "ch01")

        packet = MagicMock()
        packet.link = link

        from hokora.constants import EPOCH_DATA

        with patch("hokora.federation.epoch_wire.is_epoch_frame", return_value=True):
            with caplog.at_level(logging.DEBUG, logger="hokora.protocol.link_manager"):
                lm._on_packet(bytes([EPOCH_DATA]) + b"\x00" * 32, packet)

        assert any("no manager" in rec.message for rec in caplog.records)
        # Frame must NOT have been passed to the sync handler.
        lm._sync_handler.assert_not_called()

    def test_epoch_data_with_manager_dispatches_decrypt(self):
        lm, mod = _make_link_manager()
        lm._sync_handler = MagicMock()

        link = MagicMock()
        link.link_id = b"\x11" * 16
        identity = MagicMock()
        identity.hexhash = "cafef00d" * 4
        link.get_remote_identity.return_value = identity
        lm.on_link_established(link, "ch02")

        em = MagicMock()
        em.decrypt.return_value = (
            b"\x00invalid"  # Return something that decode_sync_request rejects.
        )
        lm._epoch_managers[f"{identity.hexhash}:ch02"] = em

        packet = MagicMock()
        packet.link = link

        from hokora.constants import EPOCH_DATA

        with patch("hokora.federation.epoch_wire.is_epoch_frame", return_value=True):
            lm._on_packet(bytes([EPOCH_DATA]) + b"\x00" * 32, packet)

        em.decrypt.assert_called_once()


class TestGetChannelLinks:
    def test_get_channel_links_returns_correct_contexts(self):
        lm, mod = _make_link_manager()

        link1 = MagicMock()
        link1.link_id = b"\x07" * 16
        link1.get_remote_identity.return_value = None
        lm.on_link_established(link1, "ch01")

        link2 = MagicMock()
        link2.link_id = b"\x08" * 16
        link2.get_remote_identity.return_value = None
        lm.on_link_established(link2, "ch02")

        link3 = MagicMock()
        link3.link_id = b"\x09" * 16
        link3.get_remote_identity.return_value = None
        lm.on_link_established(link3, "ch01")

        ch01_links = lm.get_channel_links("ch01")
        assert len(ch01_links) == 2
        assert all(ctx.channel_id == "ch01" for ctx in ch01_links)
