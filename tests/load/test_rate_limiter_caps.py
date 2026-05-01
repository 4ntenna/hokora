# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Load test: RateLimiter._buckets cap holds under concurrent pressure.

The audit flagged MAX_RATE_LIMIT_BUCKETS (10_000) as asserted but never
validated. Spawn ~50 concurrent identities, each firing requests in a
tight loop, and verify the bucket dict never exceeds the cap.
"""

import threading

import pytest

from hokora.constants import MAX_RATE_LIMIT_BUCKETS
from hokora.security.ratelimit import RateLimiter

pytestmark = pytest.mark.load


def test_bucket_count_never_exceeds_cap_under_concurrent_load():
    """50 threads × 300 unique identities each = 15,000 attempts; buckets
    should cap at MAX_RATE_LIMIT_BUCKETS."""
    limiter = RateLimiter(max_tokens=100, refill_rate=10.0)
    thread_count = 50
    ids_per_thread = 300

    def worker(thread_id: int) -> None:
        for i in range(ids_per_thread):
            identity = f"t{thread_id:02d}-i{i:05d}"
            try:
                limiter.check_rate_limit(identity)
            except Exception:  # noqa: BLE001 — rate-limit exceeded is expected
                pass

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(thread_count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Bucket eviction keeps us at or below the cap.
    assert len(limiter._buckets) <= MAX_RATE_LIMIT_BUCKETS, (
        f"RateLimiter._buckets grew to {len(limiter._buckets)}, "
        f"exceeding cap of {MAX_RATE_LIMIT_BUCKETS}"
    )


def test_cap_holds_when_eviction_cannot_free_space():
    """Feed >> cap of distinct identities with refill too slow to go stale.

    The limiter should stay at-or-below the cap, rejecting further new
    identities with RateLimitExceeded rather than growing unbounded.
    """
    from hokora.exceptions import RateLimitExceeded

    limiter = RateLimiter(max_tokens=1, refill_rate=0.1)
    rejects = 0
    target = MAX_RATE_LIMIT_BUCKETS + 500
    for i in range(target):
        try:
            limiter.check_rate_limit(f"i{i:07d}")
        except RateLimitExceeded:
            rejects += 1

    assert len(limiter._buckets) <= MAX_RATE_LIMIT_BUCKETS
    # Once the cap filled, the overflow attempts are rejected.
    assert rejects > 0, "expected RateLimitExceeded once cap filled"
