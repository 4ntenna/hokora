# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the LXMF inbound binding chokepoint."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import LXMF
import pytest

from hokora.security.lxmf_inbound import (
    PathRequestCache,
    get_lxmf_inbound_action_counts,
    get_lxmf_inbound_counts,
    reset_for_tests,
    verify_lxmf_inbound,
)


@pytest.fixture(autouse=True)
def _reset():
    reset_for_tests()
    yield
    reset_for_tests()


def _make_message(*, signature_validated=False, unverified_reason=None, source_hash=b"\x01" * 16):
    msg = MagicMock(spec=LXMF.LXMessage)
    msg.signature_validated = signature_validated
    msg.unverified_reason = unverified_reason
    msg.source_hash = source_hash
    return msg


class TestFastPath:
    async def test_signature_validated_returns_identity(self):
        ident = MagicMock()
        ident.hexhash = "deadbeef" * 4
        msg = _make_message(signature_validated=True)
        msg.source = MagicMock()
        msg.source.identity = ident

        ok, reason, returned = await verify_lxmf_inbound(msg, require_signed=True)

        assert ok is True
        assert reason is None
        assert returned is ident

    async def test_signature_validated_no_source_yields_none_identity(self):
        msg = _make_message(signature_validated=True)
        msg.source = None

        ok, reason, returned = await verify_lxmf_inbound(msg, require_signed=True)

        assert ok is True
        assert reason is None
        assert returned is None


class TestSignatureInvalid:
    async def test_always_rejected_regardless_of_require_signed(self):
        for require in (True, False):
            reset_for_tests()
            msg = _make_message(unverified_reason=LXMF.LXMessage.SIGNATURE_INVALID)
            ok, reason, _ = await verify_lxmf_inbound(msg, require_signed=require)
            assert ok is False
            assert "signature invalid" in reason
            assert get_lxmf_inbound_counts()["signature_invalid"] == 1
            assert get_lxmf_inbound_action_counts()["rejected"] == 1


class TestOptOutPassthrough:
    async def test_source_unknown_with_require_signed_false(self):
        msg = _make_message(unverified_reason=LXMF.LXMessage.SOURCE_UNKNOWN)
        ok, reason, ident = await verify_lxmf_inbound(msg, require_signed=False)
        assert ok is True
        assert reason is None
        assert ident is None
        assert get_lxmf_inbound_action_counts()["opt_out_passthrough"] == 1


class TestSourceUnknownPathResolution:
    async def test_recall_resolves_and_signature_verifies(self):
        ident = MagicMock()
        ident.sig_pub_bytes = b"\x10" * 32
        ident.hexhash = "11" * 16
        msg = _make_message(
            unverified_reason=LXMF.LXMessage.SOURCE_UNKNOWN,
            source_hash=b"\x02" * 16,
        )
        msg.signature = b"\x33" * 64
        msg.hash = b"\x44" * 32
        msg.packed = b"\x55" * 200
        msg.destination_hash = b"\x66" * 16

        with (
            patch("hokora.security.lxmf_inbound.RNS.Transport.request_path") as mock_rp,
            patch(
                "hokora.security.lxmf_inbound.RNS.Identity.recall", return_value=ident
            ) as mock_recall,
            patch(
                "hokora.security.lxmf_inbound.reconstruct_lxmf_signed_part",
                return_value=b"signed_bytes",
            ),
            patch(
                "hokora.security.verification.VerificationService.verify_ed25519_signature",
                return_value=True,
            ) as mock_verify,
        ):
            ok, reason, returned = await verify_lxmf_inbound(
                msg, require_signed=True, path_wait_seconds=1.0
            )

        assert ok is True
        assert reason is None
        assert returned is ident
        mock_rp.assert_called_once()
        mock_recall.assert_called()
        mock_verify.assert_called_once_with(b"\x10" * 32, b"signed_bytes", b"\x33" * 64)
        assert get_lxmf_inbound_action_counts()["recovered"] == 1

    async def test_recall_resolves_but_signature_fails(self):
        ident = MagicMock()
        ident.sig_pub_bytes = b"\x10" * 32
        msg = _make_message(unverified_reason=LXMF.LXMessage.SOURCE_UNKNOWN)
        msg.signature = b"\x33" * 64

        with (
            patch("hokora.security.lxmf_inbound.RNS.Transport.request_path"),
            patch("hokora.security.lxmf_inbound.RNS.Identity.recall", return_value=ident),
            patch(
                "hokora.security.lxmf_inbound.reconstruct_lxmf_signed_part",
                return_value=b"signed",
            ),
            patch(
                "hokora.security.verification.VerificationService.verify_ed25519_signature",
                return_value=False,
            ),
        ):
            ok, reason, returned = await verify_lxmf_inbound(
                msg, require_signed=True, path_wait_seconds=0.5
            )

        assert ok is False
        assert "signature verification failed" in reason
        assert returned is None
        assert get_lxmf_inbound_counts()["bad_signature"] == 1
        assert get_lxmf_inbound_action_counts()["signature_failed"] == 1

    async def test_recall_never_resolves_rejects_after_wait(self):
        msg = _make_message(unverified_reason=LXMF.LXMessage.SOURCE_UNKNOWN)

        with (
            patch("hokora.security.lxmf_inbound.RNS.Transport.request_path"),
            patch("hokora.security.lxmf_inbound.RNS.Identity.recall", return_value=None),
        ):
            ok, reason, _ = await verify_lxmf_inbound(
                msg, require_signed=True, path_wait_seconds=0.6
            )

        assert ok is False
        assert "source unknown" in reason
        assert get_lxmf_inbound_counts()["source_unknown_after_path_request"] == 1
        assert get_lxmf_inbound_action_counts()["rejected"] == 1

    async def test_signed_part_reconstruction_failure_rejects(self):
        ident = MagicMock()
        ident.sig_pub_bytes = b"\x10" * 32
        msg = _make_message(unverified_reason=LXMF.LXMessage.SOURCE_UNKNOWN)
        msg.signature = b"\x33" * 64

        with (
            patch("hokora.security.lxmf_inbound.RNS.Transport.request_path"),
            patch("hokora.security.lxmf_inbound.RNS.Identity.recall", return_value=ident),
            patch(
                "hokora.security.lxmf_inbound.reconstruct_lxmf_signed_part",
                return_value=None,
            ),
        ):
            ok, reason, _ = await verify_lxmf_inbound(
                msg, require_signed=True, path_wait_seconds=0.2
            )

        assert ok is False
        assert "signed part" in reason
        assert get_lxmf_inbound_counts()["signed_part_reconstruction_failed"] == 1

    async def test_missing_signature_after_recall_rejects(self):
        ident = MagicMock()
        ident.sig_pub_bytes = b"\x10" * 32
        msg = _make_message(unverified_reason=LXMF.LXMessage.SOURCE_UNKNOWN)
        msg.signature = None

        with (
            patch("hokora.security.lxmf_inbound.RNS.Transport.request_path"),
            patch("hokora.security.lxmf_inbound.RNS.Identity.recall", return_value=ident),
            patch(
                "hokora.security.lxmf_inbound.reconstruct_lxmf_signed_part",
                return_value=b"signed",
            ),
        ):
            ok, reason, _ = await verify_lxmf_inbound(
                msg, require_signed=True, path_wait_seconds=0.2
            )

        assert ok is False
        assert "missing signature" in reason
        assert get_lxmf_inbound_counts()["missing_signature"] == 1

    async def test_invalid_pubkey_after_recall_rejects(self):
        ident = MagicMock()
        ident.sig_pub_bytes = None
        ident.get_public_key.return_value = b"\x00" * 12
        msg = _make_message(unverified_reason=LXMF.LXMessage.SOURCE_UNKNOWN)
        msg.signature = b"\x33" * 64

        with (
            patch("hokora.security.lxmf_inbound.RNS.Transport.request_path"),
            patch("hokora.security.lxmf_inbound.RNS.Identity.recall", return_value=ident),
            patch(
                "hokora.security.lxmf_inbound.reconstruct_lxmf_signed_part",
                return_value=b"signed",
            ),
        ):
            ok, reason, _ = await verify_lxmf_inbound(
                msg, require_signed=True, path_wait_seconds=0.2
            )

        assert ok is False
        assert "pubkey" in reason
        assert get_lxmf_inbound_counts()["invalid_pubkey"] == 1


class TestPathRequestCache:
    def test_first_request_permitted(self):
        cache = PathRequestCache(ttl_seconds=60.0, max_entries=10)
        assert cache.should_request(b"\x01" * 16) is True

    def test_duplicate_within_ttl_suppressed(self):
        cache = PathRequestCache(ttl_seconds=60.0, max_entries=10)
        h = b"\x01" * 16
        cache.should_request(h)
        assert cache.should_request(h) is False

    def test_lru_evicts_oldest_at_cap(self):
        cache = PathRequestCache(ttl_seconds=60.0, max_entries=3)
        for i in range(4):
            cache.should_request(bytes([i]) * 16)
        assert bytes([0]) * 16 not in cache._entries
        assert bytes([3]) * 16 in cache._entries

    def test_reset_clears_entries(self):
        cache = PathRequestCache(ttl_seconds=60.0, max_entries=10)
        cache.should_request(b"\x01" * 16)
        cache.reset()
        assert cache.should_request(b"\x01" * 16) is True


class TestPathRequestSuppression:
    async def test_repeat_unknown_source_suppresses_path_request(self):
        msg1 = _make_message(
            unverified_reason=LXMF.LXMessage.SOURCE_UNKNOWN,
            source_hash=b"\x09" * 16,
        )
        msg2 = _make_message(
            unverified_reason=LXMF.LXMessage.SOURCE_UNKNOWN,
            source_hash=b"\x09" * 16,
        )
        cache = PathRequestCache()

        with (
            patch("hokora.security.lxmf_inbound.RNS.Transport.request_path") as mock_rp,
            patch("hokora.security.lxmf_inbound.RNS.Identity.recall", return_value=None),
        ):
            await verify_lxmf_inbound(msg1, require_signed=True, path_wait_seconds=0.1, cache=cache)
            await verify_lxmf_inbound(msg2, require_signed=True, path_wait_seconds=0.1, cache=cache)

        assert mock_rp.call_count == 1


class TestValidationStatusUnknown:
    async def test_no_validation_status_rejects(self):
        msg = _make_message(unverified_reason=None)
        msg.signature_validated = False
        ok, reason, _ = await verify_lxmf_inbound(msg, require_signed=True)
        assert ok is False
        assert "validation status" in reason
        assert get_lxmf_inbound_counts()["validation_status_unknown"] == 1
