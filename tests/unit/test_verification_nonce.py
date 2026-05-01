# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Nonce replay detection tests: NonceTracker and VerificationService nonce checks."""

import pytest

from hokora.exceptions import VerificationError
from hokora.security.verification import NonceTracker, VerificationService


class TestNonceTracker:
    def test_fresh_nonce_returns_true(self):
        tracker = NonceTracker()
        assert tracker.check_and_record(b"\x01" * 16) is True

    def test_replayed_nonce_returns_false(self):
        tracker = NonceTracker()
        nonce = b"\x02" * 16
        tracker.check_and_record(nonce)
        assert tracker.check_and_record(nonce) is False

    def test_different_nonces_both_fresh(self):
        tracker = NonceTracker()
        assert tracker.check_and_record(b"\x03" * 16) is True
        assert tracker.check_and_record(b"\x04" * 16) is True

    def test_bounded_size_evicts_oldest(self):
        tracker = NonceTracker(max_size=3)
        tracker.check_and_record(b"\x01" * 16)
        tracker.check_and_record(b"\x02" * 16)
        tracker.check_and_record(b"\x03" * 16)
        # Adding a 4th should evict the first
        tracker.check_and_record(b"\x04" * 16)
        assert len(tracker) == 3
        # The first nonce should be evicted, so it's "fresh" again
        assert tracker.check_and_record(b"\x01" * 16) is True


class TestVerificationServiceNonce:
    def test_fresh_nonce_returns_true(self):
        svc = VerificationService()
        assert svc.check_nonce_replay(b"\xaa" * 16) is True

    def test_replayed_nonce_raises(self):
        svc = VerificationService()
        nonce = b"\xbb" * 16
        svc.check_nonce_replay(nonce)
        with pytest.raises(VerificationError, match="replay"):
            svc.check_nonce_replay(nonce)

    def test_nonce_tracker_attribute_exists(self):
        svc = VerificationService()
        assert hasattr(svc, "nonce_tracker")
        assert isinstance(svc.nonce_tracker, NonceTracker)
