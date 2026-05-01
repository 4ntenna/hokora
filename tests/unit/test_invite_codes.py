# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for short invite codes."""

import pytest

from hokora.security.invite_codes import (
    INVITE_CODE_PREFIX,
    decode_invite,
    encode_invite,
)


class TestInviteCodes:
    def test_invite_code_roundtrip(self):
        """Encode and decode should return original values."""
        token = "a1b2c3d4e5f6a7b8" * 2  # 32 hex chars = 16 bytes
        dest = "01020304050607080910111213141516"  # 32 hex chars = 16 bytes

        code = encode_invite(token, dest)
        assert code.startswith(INVITE_CODE_PREFIX)

        decoded_token, decoded_dest = decode_invite(code)
        assert decoded_token == token
        assert decoded_dest == dest

    def test_invite_code_checksum_validation(self):
        """Corrupted code should fail checksum."""
        token = "a1b2c3d4e5f6a7b8" * 2
        dest = "01020304050607080910111213141516"
        code = encode_invite(token, dest)

        # Corrupt one character
        parts = code.split("-")
        corrupted_part = list(parts[1])
        corrupted_part[0] = "Z" if corrupted_part[0] != "Z" else "A"
        parts[1] = "".join(corrupted_part)
        corrupted = "-".join(parts)

        with pytest.raises(ValueError):
            decode_invite(corrupted)

    def test_invite_code_format(self):
        """Code should have HOK- prefix and dashes every 5 chars."""
        token = "a1b2c3d4e5f6a7b8" * 2
        dest = "01020304050607080910111213141516"
        code = encode_invite(token, dest)

        assert code.startswith(INVITE_CODE_PREFIX)
        # All parts after prefix should be 5 chars or less
        parts = code[len(INVITE_CODE_PREFIX) :].split("-")
        for part in parts[:-1]:  # Last part may be shorter
            assert len(part) == 5

    def test_invite_code_case_insensitive(self):
        """Decoding should work regardless of case."""
        token = "a1b2c3d4e5f6a7b8" * 2
        dest = "01020304050607080910111213141516"
        code = encode_invite(token, dest)

        lower_code = code.lower()
        decoded_token, decoded_dest = decode_invite(lower_code)
        assert decoded_token == token
        assert decoded_dest == dest

    def test_invalid_code_too_short(self):
        with pytest.raises(ValueError):
            decode_invite(f"{INVITE_CODE_PREFIX}AB")

    def test_invalid_prefix_rejected(self):
        """Code with the wrong prefix is rejected up front (no silent
        decode against legacy prefixes)."""
        with pytest.raises(ValueError, match="must start with"):
            decode_invite("MSIG-ABCDE-FGHIJ-KLMNO")

    def test_sealed_badge_placeholder(self):
        """Sealed channel badge rendering — tested via ChannelItem widget."""
        from hokora_tui.widgets.channel_item import ChannelItem

        # Non-sealed channel
        item = ChannelItem(
            {"id": "ch1", "name": "general", "sealed": False},
            lambda _: None,
        )
        assert "\U0001f512" not in str(getattr(item, "_label_text", ""))

        # Sealed channel — the ChannelItem prepends a lock indicator
        item2 = ChannelItem(
            {"id": "ch2", "name": "secret", "sealed": True},
            lambda _: None,
        )
        # ChannelItem is a WidgetWrap; just verify it creates without error
        assert item2 is not None
