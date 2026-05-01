# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Binary wire codec for forward secrecy epoch frames (0x20/0x21/0x22)."""

import struct

from hokora.constants import EPOCH_ROTATE, EPOCH_ROTATE_ACK, EPOCH_DATA
from hokora.exceptions import EpochError

# EpochRotate: 0x20 + uint64 epoch_id + uint32 duration + 32B pubkey + 32B hash + 64B sig = 141
EPOCH_ROTATE_LEN = 1 + 8 + 4 + 32 + 32 + 64  # 141

# EpochRotateAck: 0x21 + uint64 epoch_id + 32B pubkey + 32B hash + 64B sig = 137
EPOCH_ROTATE_ACK_LEN = 1 + 8 + 32 + 32 + 64  # 137

# EpochData header: 0x22 + uint64 epoch_id + 16B nonce_prefix (not full nonce — see below)
# Actually: 0x22 + uint64 epoch_id + 24B nonce = 33 bytes header
EPOCH_DATA_HEADER_LEN = 1 + 8 + 24  # 33


def encode_epoch_rotate(
    epoch_id: int,
    epoch_duration: int,
    eph_pubkey: bytes,
    prev_epoch_hash: bytes,
    signature: bytes,
) -> bytes:
    """Encode an EpochRotate frame (141 bytes)."""
    return (
        struct.pack(">BQI", EPOCH_ROTATE, epoch_id, epoch_duration)
        + eph_pubkey
        + prev_epoch_hash
        + signature
    )


def decode_epoch_rotate(data: bytes) -> dict:
    """Decode an EpochRotate frame."""
    if len(data) < EPOCH_ROTATE_LEN:
        raise EpochError(f"EpochRotate frame too short: {len(data)} < {EPOCH_ROTATE_LEN}")
    frame_type, epoch_id, epoch_duration = struct.unpack_from(">BQI", data, 0)
    if frame_type != EPOCH_ROTATE:
        raise EpochError(f"Expected EpochRotate (0x20), got 0x{frame_type:02x}")
    offset = 13  # 1+8+4
    eph_pubkey = data[offset : offset + 32]
    offset += 32
    prev_epoch_hash = data[offset : offset + 32]
    offset += 32
    signature = data[offset : offset + 64]
    return {
        "epoch_id": epoch_id,
        "epoch_duration": epoch_duration,
        "eph_pubkey": bytes(eph_pubkey),
        "prev_epoch_hash": bytes(prev_epoch_hash),
        "signature": bytes(signature),
    }


def encode_epoch_rotate_ack(
    epoch_id: int,
    eph_pubkey: bytes,
    prev_epoch_hash: bytes,
    signature: bytes,
) -> bytes:
    """Encode an EpochRotateAck frame (137 bytes)."""
    return struct.pack(">BQ", EPOCH_ROTATE_ACK, epoch_id) + eph_pubkey + prev_epoch_hash + signature


def decode_epoch_rotate_ack(data: bytes) -> dict:
    """Decode an EpochRotateAck frame."""
    if len(data) < EPOCH_ROTATE_ACK_LEN:
        raise EpochError(f"EpochRotateAck frame too short: {len(data)} < {EPOCH_ROTATE_ACK_LEN}")
    frame_type, epoch_id = struct.unpack_from(">BQ", data, 0)
    if frame_type != EPOCH_ROTATE_ACK:
        raise EpochError(f"Expected EpochRotateAck (0x21), got 0x{frame_type:02x}")
    offset = 9  # 1+8
    eph_pubkey = data[offset : offset + 32]
    offset += 32
    prev_epoch_hash = data[offset : offset + 32]
    offset += 32
    signature = data[offset : offset + 64]
    return {
        "epoch_id": epoch_id,
        "eph_pubkey": bytes(eph_pubkey),
        "prev_epoch_hash": bytes(prev_epoch_hash),
        "signature": bytes(signature),
    }


def encode_epoch_data(epoch_id: int, nonce: bytes, encrypted_payload: bytes) -> bytes:
    """Encode an EpochData frame (33-byte header + payload)."""
    return struct.pack(">BQ", EPOCH_DATA, epoch_id) + nonce + encrypted_payload


def decode_epoch_data(data: bytes) -> dict:
    """Decode an EpochData frame."""
    if len(data) < EPOCH_DATA_HEADER_LEN:
        raise EpochError(f"EpochData frame too short: {len(data)} < {EPOCH_DATA_HEADER_LEN}")
    frame_type, epoch_id = struct.unpack_from(">BQ", data, 0)
    if frame_type != EPOCH_DATA:
        raise EpochError(f"Expected EpochData (0x22), got 0x{frame_type:02x}")
    nonce = data[9:33]
    ciphertext = data[33:]
    return {
        "epoch_id": epoch_id,
        "nonce": bytes(nonce),
        "ciphertext": bytes(ciphertext),
    }


def is_epoch_frame(data: bytes) -> bool:
    """Check if the first byte indicates an epoch frame (0x20/0x21/0x22)."""
    if not data:
        return False
    return data[0] in (EPOCH_ROTATE, EPOCH_ROTATE_ACK, EPOCH_DATA)
