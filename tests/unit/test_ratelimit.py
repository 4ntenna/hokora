# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Test rate limiting."""

import time
from unittest.mock import patch

import pytest

from hokora.security.ratelimit import RateLimiter, TokenBucket
from hokora.exceptions import RateLimitExceeded


class TestTokenBucket:
    def test_consume_within_limit(self):
        bucket = TokenBucket(tokens=5, max_tokens=10, refill_rate=1.0)
        for _ in range(5):
            assert bucket.consume() is True

    def test_consume_exceeds_limit(self):
        bucket = TokenBucket(tokens=2, max_tokens=2, refill_rate=0)
        assert bucket.consume() is True
        assert bucket.consume() is True
        assert bucket.consume() is False


class TestRateLimiter:
    def test_allows_within_limit(self):
        limiter = RateLimiter(max_tokens=5, refill_rate=0)
        for _ in range(5):
            limiter.check_rate_limit("user1")

    def test_rejects_over_limit(self):
        limiter = RateLimiter(max_tokens=2, refill_rate=0)
        limiter.check_rate_limit("user2")
        limiter.check_rate_limit("user2")
        with pytest.raises(RateLimitExceeded):
            limiter.check_rate_limit("user2")

    def test_slowmode_enforced(self):
        limiter = RateLimiter()
        limiter.check_slowmode("user1", "ch1", 60)
        with pytest.raises(RateLimitExceeded, match="Slowmode"):
            limiter.check_slowmode("user1", "ch1", 60)

    def test_slowmode_zero_always_passes(self):
        limiter = RateLimiter()
        for _ in range(10):
            limiter.check_slowmode("user1", "ch1", 0)

    @patch("hokora.security.ratelimit.MAX_RATE_LIMIT_BUCKETS", 5)
    def test_bucket_cap_triggers_cleanup(self):
        """H7: When MAX_RATE_LIMIT_BUCKETS is reached, stale entries are cleaned."""
        limiter = RateLimiter(max_tokens=10, refill_rate=1.0)

        # Fill up buckets
        for i in range(5):
            limiter.check_rate_limit(f"user_{i:04d}")
        assert len(limiter._buckets) == 5

        # Make all buckets stale
        for b in limiter._buckets.values():
            b.last_refill = time.time() - 700

        # Next call should trigger cleanup and succeed
        limiter.check_rate_limit("new_user")
        assert "new_user" in limiter._buckets

    @patch("hokora.security.ratelimit.MAX_RATE_LIMIT_BUCKETS", 5)
    def test_bucket_cap_rejects_when_full(self):
        """H7: When MAX_RATE_LIMIT_BUCKETS is full and nothing is stale, reject."""
        limiter = RateLimiter(max_tokens=10, refill_rate=1.0)

        for i in range(5):
            limiter.check_rate_limit(f"user_{i:04d}")

        # All buckets are fresh — new identity should be rejected
        with pytest.raises(RateLimitExceeded, match="Too many tracked"):
            limiter.check_rate_limit("overflow_user")
