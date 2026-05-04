# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Federation channel mirror tests: response handling, cursor updates, error resilience."""

from unittest.mock import MagicMock, patch

from hokora.protocol.wire import encode_sync_response


class TestChannelMirror:
    """Test ChannelMirror.handle_response processing."""

    def _make_mirror(self, ingest_callback=None):
        with patch("hokora.federation.mirror.RNS"):
            from hokora.federation.mirror import ChannelMirror

            mirror = ChannelMirror(
                remote_destination_hash=b"\x01" * 16,
                channel_id="test_ch",
                ingest_callback=ingest_callback,
            )
            mirror._running = True
            return mirror

    def _build_response(self, messages, has_more=False):
        nonce = b"\x00" * 16
        return encode_sync_response(
            nonce=nonce,
            payload={
                "action": "history",
                "messages": messages,
                "has_more": has_more,
            },
        )

    def test_handle_response_updates_cursor(self):
        ingested = []
        mirror = self._make_mirror(ingest_callback=lambda m: ingested.append(m))

        messages = [
            {"seq": 1, "body": "first"},
            {"seq": 5, "body": "fifth"},
            {"seq": 3, "body": "third"},
        ]
        response_data = self._build_response(messages, has_more=False)

        with patch("hokora.federation.mirror.RNS"):
            mirror.handle_response(response_data)

        # Cursor should be at highest seq
        assert mirror._cursor == 5
        assert len(ingested) == 3

    def test_handle_response_has_more_triggers_sync(self):
        mirror = self._make_mirror()
        mirror._sync_history = MagicMock()

        messages = [{"seq": 1, "body": "msg"}]
        response_data = self._build_response(messages, has_more=True)

        with patch("hokora.federation.mirror.RNS"):
            mirror.handle_response(response_data)

        mirror._sync_history.assert_called_once()

    def test_handle_response_no_more_does_not_resync(self):
        mirror = self._make_mirror()
        mirror._sync_history = MagicMock()

        messages = [{"seq": 1, "body": "msg"}]
        response_data = self._build_response(messages, has_more=False)

        with patch("hokora.federation.mirror.RNS"):
            mirror.handle_response(response_data)

        mirror._sync_history.assert_not_called()

    def test_handle_response_empty_messages_noop(self):
        ingested = []
        mirror = self._make_mirror(ingest_callback=lambda m: ingested.append(m))
        mirror._sync_history = MagicMock()

        response_data = self._build_response([], has_more=False)

        with patch("hokora.federation.mirror.RNS"):
            mirror.handle_response(response_data)

        assert mirror._cursor == 0
        assert len(ingested) == 0
        mirror._sync_history.assert_not_called()

    def test_handle_response_not_running_skips_resync(self):
        mirror = self._make_mirror()
        mirror._running = False
        mirror._sync_history = MagicMock()

        messages = [{"seq": 1, "body": "msg"}]
        response_data = self._build_response(messages, has_more=True)

        with patch("hokora.federation.mirror.RNS"):
            mirror.handle_response(response_data)

        # has_more=True but _running=False -> no resync
        mirror._sync_history.assert_not_called()

    def test_handle_response_malformed_bytes(self):
        """B4: Garbage input should not crash the mirror."""
        mirror = self._make_mirror()
        with patch("hokora.federation.mirror.RNS"):
            # Should not raise — error is caught internally
            mirror.handle_response(b"\xff\xfe\xfd\x00garbage")
        assert mirror._cursor == 0

    def test_handle_response_missing_seq_key(self):
        """B4: Messages without 'seq' key should not crash."""
        ingested = []
        mirror = self._make_mirror(ingest_callback=lambda m: ingested.append(m))

        messages = [{"body": "no seq here"}]
        response_data = self._build_response(messages)

        with patch("hokora.federation.mirror.RNS"):
            mirror.handle_response(response_data)

        # Message still ingested, cursor stays at 0
        assert len(ingested) == 1
        assert mirror._cursor == 0

    def test_handle_response_missing_messages_key(self):
        """B4: Response without 'messages' key should not crash."""
        mirror = self._make_mirror()
        nonce = b"\x00" * 16
        response_data = encode_sync_response(
            nonce=nonce,
            payload={"action": "history", "has_more": False},
        )

        with patch("hokora.federation.mirror.RNS"):
            mirror.handle_response(response_data)

        assert mirror._cursor == 0
