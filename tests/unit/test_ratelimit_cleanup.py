# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Rate limiter and invite manager cleanup tests."""

import time


class TestRateLimiterCleanup:
    """3A: RateLimiter.cleanup_stale works correctly."""

    def test_cleanup_stale_removes_old_buckets(self):
        from hokora.security.ratelimit import RateLimiter

        rl = RateLimiter(max_tokens=5, refill_rate=0)
        rl.check_rate_limit("user1")
        # Manually age the bucket
        rl._buckets["user1"].last_refill = time.time() - 7200
        rl.cleanup_stale(max_age=3600)
        assert "user1" not in rl._buckets

    def test_cleanup_stale_keeps_recent_buckets(self):
        from hokora.security.ratelimit import RateLimiter

        rl = RateLimiter(max_tokens=5, refill_rate=0)
        rl.check_rate_limit("user1")
        rl.cleanup_stale(max_age=3600)
        assert "user1" in rl._buckets

    def test_cleanup_stale_removes_old_slowmode(self):
        from hokora.security.ratelimit import RateLimiter

        rl = RateLimiter()
        rl._slowmode_last["user1:ch1"] = time.time() - 7200
        rl.cleanup_stale(max_age=3600)
        assert "user1:ch1" not in rl._slowmode_last


class TestInviteManagerCleanup:
    """3B: InviteManager.cleanup_stale prunes in-memory dicts."""

    async def test_cleanup_stale_removes_old_entries(self):
        from hokora.security.invites import InviteManager

        im = InviteManager()
        old_time = time.time() - 7200
        im._redemption_attempts["user1"] = [old_time]
        im._failure_attempts["user2"] = [old_time]
        im._blocked_until["user3"] = old_time

        await im.cleanup_stale(max_age=3600)

        assert "user1" not in im._redemption_attempts
        assert "user2" not in im._failure_attempts
        assert "user3" not in im._blocked_until

    async def test_cleanup_stale_keeps_recent(self):
        from hokora.security.invites import InviteManager

        im = InviteManager()
        recent = time.time()
        im._redemption_attempts["user1"] = [recent]
        im._failure_attempts["user2"] = [recent]
        im._blocked_until["user3"] = recent + 600  # still blocked

        await im.cleanup_stale(max_age=3600)

        assert "user1" in im._redemption_attempts
        assert "user2" in im._failure_attempts
        assert "user3" in im._blocked_until
