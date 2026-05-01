# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Test wire protocol encode/decode round-trips."""

import pytest

from hokora.constants import SYNC_HISTORY, SYNC_NODE_META, NONCE_SIZE
from hokora.protocol.wire import (
    encode_sync_request,
    decode_sync_request,
    encode_sync_response,
    decode_sync_response,
    generate_nonce,
    encode_push_event,
)
from hokora.exceptions import SyncError


class TestWireProtocol:
    def test_nonce_generation(self):
        nonce = generate_nonce()
        assert len(nonce) == NONCE_SIZE
        assert generate_nonce() != nonce  # extremely unlikely collision

    def test_sync_request_roundtrip(self):
        nonce = generate_nonce()
        payload = {"channel_id": "test123", "since_seq": 42}
        encoded = encode_sync_request(SYNC_HISTORY, nonce, payload)
        decoded = decode_sync_request(encoded)

        assert decoded["action"] == SYNC_HISTORY
        assert decoded["nonce"] == nonce
        assert decoded["payload"]["channel_id"] == "test123"
        assert decoded["payload"]["since_seq"] == 42

    def test_sync_request_no_payload(self):
        nonce = generate_nonce()
        encoded = encode_sync_request(SYNC_NODE_META, nonce)
        decoded = decode_sync_request(encoded)
        assert decoded["action"] == SYNC_NODE_META
        assert "payload" not in decoded

    def test_sync_response_roundtrip(self):
        nonce = generate_nonce()
        data = {"action": "history", "messages": [{"body": "test"}]}
        encoded = encode_sync_response(nonce, data, node_time=1700000000.0)
        decoded = decode_sync_response(encoded)

        assert decoded["nonce"] == nonce
        assert decoded["data"]["action"] == "history"
        assert decoded["node_time"] == 1700000000.0

    def test_invalid_nonce_size(self):
        with pytest.raises(SyncError, match="Nonce must be"):
            encode_sync_request(SYNC_HISTORY, b"\x00" * 8)

    def test_malformed_request(self):
        from hokora.protocol.wire import _add_length_header

        with pytest.raises(SyncError):
            decode_sync_request(_add_length_header(b"not msgpack"))

    def test_missing_action(self):
        import msgpack
        from hokora.protocol.wire import _add_length_header

        raw = msgpack.packb({"nonce": b"\x00" * NONCE_SIZE})
        data = _add_length_header(raw)
        with pytest.raises(SyncError, match="missing 'action'"):
            decode_sync_request(data)

    def test_missing_nonce(self):
        import msgpack
        from hokora.protocol.wire import _add_length_header

        raw = msgpack.packb({"action": 1})
        data = _add_length_header(raw)
        with pytest.raises(SyncError, match="missing 'nonce'"):
            decode_sync_request(data)

    def test_push_event_encoding(self):
        import msgpack

        encoded = encode_push_event("message", {"body": "hello"})
        decoded = msgpack.unpackb(encoded, raw=False)
        assert decoded["event"] == "message"
        assert decoded["data"]["body"] == "hello"


class TestWireProtocolNegative:
    """Negative tests: malformed, truncated, oversized wire protocol frames."""

    def test_empty_bytes_rejected(self):
        with pytest.raises(SyncError):
            decode_sync_request(b"")

    def test_single_byte_rejected(self):
        with pytest.raises(SyncError):
            decode_sync_request(b"\x00")

    def test_length_header_exceeds_data(self):
        import struct

        data = struct.pack("!H", 100) + b"\x00\x00"
        with pytest.raises(SyncError, match="length mismatch"):
            decode_sync_request(data)

    def test_invalid_msgpack_rejected(self):
        import struct

        garbage = b"\xff\xfe\xfd\xfc"
        data = struct.pack("!H", len(garbage)) + garbage
        with pytest.raises(SyncError, match="Failed to decode"):
            decode_sync_request(data)

    def test_non_dict_msgpack_rejected(self):
        import struct
        import msgpack

        payload = msgpack.packb([1, 2, 3])
        data = struct.pack("!H", len(payload)) + payload
        with pytest.raises(SyncError, match="must be a dict"):
            decode_sync_request(data)

    def test_missing_action_rejected(self):
        import struct
        import msgpack

        payload = msgpack.packb({"nonce": b"\x00" * 16})
        data = struct.pack("!H", len(payload)) + payload
        with pytest.raises(SyncError, match="missing 'action'"):
            decode_sync_request(data)

    def test_wrong_nonce_size_rejected(self):
        import struct
        import msgpack

        payload = msgpack.packb({"action": 1, "nonce": b"\x00" * 8})
        data = struct.pack("!H", len(payload)) + payload
        with pytest.raises(SyncError, match="Invalid nonce"):
            decode_sync_request(data)

    def test_string_nonce_rejected(self):
        import struct
        import msgpack

        payload = msgpack.packb({"action": 1, "nonce": "not_bytes"})
        data = struct.pack("!H", len(payload)) + payload
        with pytest.raises(SyncError, match="Invalid nonce"):
            decode_sync_request(data)

    def test_oversized_frame_rejected(self):
        from hokora.protocol.wire import _add_length_header

        with pytest.raises(SyncError, match="Frame too large"):
            _add_length_header(b"\x00" * 65536)

    def test_max_size_frame_accepted(self):
        from hokora.protocol.wire import _add_length_header

        data = _add_length_header(b"\x00" * 65535)
        assert len(data) == 65535 + 2

    def test_response_non_dict_rejected(self):
        import struct
        import msgpack

        payload = msgpack.packb("just a string")
        data = struct.pack("!H", len(payload)) + payload
        with pytest.raises(SyncError, match="must be a dict"):
            decode_sync_response(data)

    def test_response_missing_nonce_rejected(self):
        import struct
        import msgpack

        payload = msgpack.packb({"data": {}})
        data = struct.pack("!H", len(payload)) + payload
        with pytest.raises(SyncError, match="missing 'nonce'"):
            decode_sync_response(data)
