# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Wire protocol robustness tests: malformed payloads, corrupt msgpack, oversized nonces."""

import msgpack
import pytest

from hokora.exceptions import SyncError
from hokora.protocol.wire import (
    encode_sync_request,
    decode_sync_request,
)


class TestWireProtocolRobustness:
    def test_decode_non_dict_raises(self):
        from hokora.protocol.wire import _add_length_header

        # Encode a list instead of dict
        raw = msgpack.packb([1, 2, 3], use_bin_type=True)
        data = _add_length_header(raw)
        with pytest.raises(SyncError, match="must be a dict"):
            decode_sync_request(data)

    def test_decode_corrupt_msgpack_raises(self):
        from hokora.protocol.wire import _add_length_header

        data = _add_length_header(b"\xff\xfe\xfd\xfc")
        with pytest.raises(SyncError, match="Failed to decode"):
            decode_sync_request(data)

    def test_oversized_nonce_raises(self):
        from hokora.protocol.wire import _add_length_header

        # Valid msgpack dict but nonce is wrong size
        raw = msgpack.packb(
            {
                "v": 1,
                "action": 0x01,
                "nonce": b"\x00" * 32,  # 32 bytes instead of 16
            },
            use_bin_type=True,
        )
        data = _add_length_header(raw)
        with pytest.raises(SyncError, match="Invalid nonce"):
            decode_sync_request(data)

    def test_encode_with_oversized_nonce_raises(self):
        with pytest.raises(SyncError, match="Nonce must be"):
            encode_sync_request(0x01, b"\x00" * 32)
