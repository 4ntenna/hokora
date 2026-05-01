# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Short invite codes: human-friendly format for invite tokens.

Encodes a composite invite (token + destination hash) into a short
Base32 code formatted as ``<PREFIX>-XXXXX-XXXXX-XXXXX`` with a CRC8
checksum. The prefix is centralised in :data:`INVITE_CODE_PREFIX` —
every encode/decode site must reference the constant rather than
inlining the literal, so a future change is a one-line edit.
"""

import base64
import struct

#: Brand prefix prepended to every encoded invite code.
#:
#: Treated as an on-the-wire format constant: bumping this value is
#: a breaking change for any in-flight invite codes a user has
#: written down. The value is part of the public release contract.
INVITE_CODE_PREFIX = "HOK-"


def _crc8(data: bytes) -> int:
    """Return the CRC-8/MAXIM checksum of ``data``."""
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x80:
                crc = (crc << 1) ^ 0x31
            else:
                crc <<= 1
            crc &= 0xFF
    return crc


def encode_invite(token: str, dest_hash: str) -> str:
    """Encode a composite invite token into a human-readable code.

    Args:
        token: The raw invite token (hex string).
        dest_hash: The destination hash (hex string).

    Returns:
        A formatted code like ``HOK-ABCDE-FGHIJ-KLMNO`` (the ``HOK-``
        prefix is :data:`INVITE_CODE_PREFIX`).
    """
    raw = bytes.fromhex(token) + bytes.fromhex(dest_hash)
    checksum = _crc8(raw)
    raw_with_checksum = raw + struct.pack("B", checksum)

    encoded = base64.b32encode(raw_with_checksum).decode("ascii").rstrip("=")
    chunks = [encoded[i : i + 5] for i in range(0, len(encoded), 5)]
    return INVITE_CODE_PREFIX + "-".join(chunks)


def decode_invite(code: str) -> tuple[str, str]:
    """Decode a short invite code back to ``(token_hex, dest_hash_hex)``.

    Args:
        code: A formatted code like ``HOK-ABCDE-FGHIJ-KLMNO``. The
            prefix must match :data:`INVITE_CODE_PREFIX` (case-insensitive).

    Returns:
        ``(token_hex, dest_hash_hex)``.

    Raises:
        ValueError: If the prefix doesn't match, the encoding is
            malformed, or the CRC8 checksum fails.
    """
    upper = code.upper().strip()
    if not upper.startswith(INVITE_CODE_PREFIX):
        raise ValueError(f"Invite code must start with {INVITE_CODE_PREFIX!r}, got {code[:8]!r}")

    clean = upper[len(INVITE_CODE_PREFIX) :].replace("-", "")

    padding = (8 - len(clean) % 8) % 8
    padded = clean + "=" * padding

    try:
        raw_with_checksum = base64.b32decode(padded)
    except Exception as e:
        raise ValueError(f"Invalid invite code encoding: {e}")

    if len(raw_with_checksum) < 2:
        raise ValueError("Invite code too short")

    raw = raw_with_checksum[:-1]
    expected_checksum = raw_with_checksum[-1]
    actual_checksum = _crc8(raw)

    if actual_checksum != expected_checksum:
        raise ValueError(
            f"Invite code checksum mismatch: expected {expected_checksum:#04x}, "
            f"got {actual_checksum:#04x}"
        )

    # Invite tokens are 16 bytes (INVITE_TOKEN_SIZE), dest hashes are 16 bytes.
    if len(raw) < 32:
        raise ValueError(f"Invite code data too short: {len(raw)} bytes")

    token_bytes = raw[:16]
    dest_bytes = raw[16:32]

    return token_bytes.hex(), dest_bytes.hex()
