# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for forward secrecy wire codec."""

import pytest

from hokora.constants import EPOCH_ROTATE, EPOCH_ROTATE_ACK, EPOCH_DATA
from hokora.exceptions import EpochError
from hokora.federation.epoch_wire import (
    encode_epoch_rotate,
    decode_epoch_rotate,
    encode_epoch_rotate_ack,
    decode_epoch_rotate_ack,
    encode_epoch_data,
    decode_epoch_data,
    is_epoch_frame,
    EPOCH_ROTATE_LEN,
    EPOCH_ROTATE_ACK_LEN,
    EPOCH_DATA_HEADER_LEN,
)


class TestEpochRotate:
    def test_round_trip(self):
        pubkey = b"\x01" * 32
        prev_hash = b"\x02" * 32
        sig = b"\x03" * 64

        data = encode_epoch_rotate(42, 3600, pubkey, prev_hash, sig)
        assert len(data) == EPOCH_ROTATE_LEN

        parsed = decode_epoch_rotate(data)
        assert parsed["epoch_id"] == 42
        assert parsed["epoch_duration"] == 3600
        assert parsed["eph_pubkey"] == pubkey
        assert parsed["prev_epoch_hash"] == prev_hash
        assert parsed["signature"] == sig

    def test_exact_byte_length(self):
        data = encode_epoch_rotate(1, 300, b"\x00" * 32, b"\x00" * 32, b"\x00" * 64)
        assert len(data) == 141

    def test_truncated_frame_rejected(self):
        with pytest.raises(EpochError):
            decode_epoch_rotate(b"\x20" + b"\x00" * 10)


class TestEpochRotateAck:
    def test_round_trip(self):
        pubkey = b"\x04" * 32
        prev_hash = b"\x05" * 32
        sig = b"\x06" * 64

        data = encode_epoch_rotate_ack(99, pubkey, prev_hash, sig)
        assert len(data) == EPOCH_ROTATE_ACK_LEN

        parsed = decode_epoch_rotate_ack(data)
        assert parsed["epoch_id"] == 99
        assert parsed["eph_pubkey"] == pubkey
        assert parsed["prev_epoch_hash"] == prev_hash
        assert parsed["signature"] == sig

    def test_exact_byte_length(self):
        data = encode_epoch_rotate_ack(1, b"\x00" * 32, b"\x00" * 32, b"\x00" * 64)
        assert len(data) == 137

    def test_truncated_frame_rejected(self):
        with pytest.raises(EpochError):
            decode_epoch_rotate_ack(b"\x21" + b"\x00" * 5)


class TestEpochData:
    def test_round_trip(self):
        nonce = b"\x07" * 24
        payload = b"encrypted_data_here"

        data = encode_epoch_data(7, nonce, payload)
        assert len(data) == EPOCH_DATA_HEADER_LEN + len(payload)

        parsed = decode_epoch_data(data)
        assert parsed["epoch_id"] == 7
        assert parsed["nonce"] == nonce
        assert parsed["ciphertext"] == payload

    def test_variable_length(self):
        small = encode_epoch_data(1, b"\x00" * 24, b"x")
        big = encode_epoch_data(1, b"\x00" * 24, b"x" * 1000)
        assert len(big) - len(small) == 999

    def test_truncated_frame_rejected(self):
        with pytest.raises(EpochError):
            decode_epoch_data(b"\x22" + b"\x00" * 5)


class TestIsEpochFrame:
    def test_epoch_rotate(self):
        assert is_epoch_frame(bytes([EPOCH_ROTATE]) + b"\x00" * 140)

    def test_epoch_rotate_ack(self):
        assert is_epoch_frame(bytes([EPOCH_ROTATE_ACK]) + b"\x00" * 136)

    def test_epoch_data(self):
        assert is_epoch_frame(bytes([EPOCH_DATA]) + b"\x00" * 32)

    def test_non_epoch_frame(self):
        assert not is_epoch_frame(b"\x01\x02\x03")

    def test_empty_data(self):
        assert not is_epoch_frame(b"")

    def test_msgpack_frame(self):
        # Typical msgpack sync request starts with 0x83 or similar
        assert not is_epoch_frame(b"\x83\x01\x02")
