# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Per-identity token bucket rate limiting and slowmode enforcement."""

import threading
import time
import logging
from dataclasses import dataclass, field

from hokora.constants import (
    DEFAULT_RATE_LIMIT_TOKENS,
    DEFAULT_RATE_LIMIT_REFILL,
    MAX_RATE_LIMIT_BUCKETS,
)
from hokora.exceptions import RateLimitExceeded

logger = logging.getLogger(__name__)


@dataclass
class TokenBucket:
    """Token bucket for rate limiting."""

    tokens: float
    max_tokens: float
    refill_rate: float  # tokens per second
    last_refill: float = field(default_factory=time.time)

    def consume(self, count: int = 1) -> bool:
        """Try to consume tokens. Returns True if allowed."""
        now = time.time()
        elapsed = now - self.last_refill
        self.tokens = min(self.max_tokens, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now

        if self.tokens >= count:
            self.tokens -= count
            return True
        return False


class RateLimiter:
    """Per-identity rate limiting with slowmode support."""

    def __init__(
        self,
        max_tokens: int = DEFAULT_RATE_LIMIT_TOKENS,
        refill_rate: float = DEFAULT_RATE_LIMIT_REFILL,
    ):
        self.max_tokens = max_tokens
        self.refill_rate = refill_rate
        self._buckets: dict[str, TokenBucket] = {}
        self._slowmode_last: dict[str, float] = {}  # (identity:channel) -> last msg time
        # threading.Lock (not asyncio.Lock): accessed from both the asyncio
        # event loop and RNS callback threads. Held for microseconds, so
        # acheck_rate_limit/acheck_slowmode acquire it on the event-loop
        # thread directly rather than via run_in_executor.
        self._lock = threading.Lock()

    def check_rate_limit(self, identity_hash: str) -> bool:
        """Check global rate limit for an identity."""
        with self._lock:
            if identity_hash not in self._buckets:
                # Cap bucket dict size to prevent memory exhaustion
                if len(self._buckets) >= MAX_RATE_LIMIT_BUCKETS:
                    self._cleanup_stale_locked(600)
                    if len(self._buckets) >= MAX_RATE_LIMIT_BUCKETS:
                        raise RateLimitExceeded("Too many tracked identities")
                self._buckets[identity_hash] = TokenBucket(
                    tokens=self.max_tokens,
                    max_tokens=self.max_tokens,
                    refill_rate=self.refill_rate,
                )

            bucket = self._buckets[identity_hash]
            if not bucket.consume():
                raise RateLimitExceeded(f"Rate limit exceeded for {identity_hash[:8]}...")
            return True

    def check_slowmode(
        self,
        identity_hash: str,
        channel_id: str,
        slowmode_seconds: int,
    ) -> bool:
        """Check per-channel slowmode for an identity."""
        if slowmode_seconds <= 0:
            return True

        with self._lock:
            key = f"{identity_hash}:{channel_id}"
            now = time.time()

            if len(self._slowmode_last) >= MAX_RATE_LIMIT_BUCKETS:
                self._cleanup_stale_locked(600)
                if len(self._slowmode_last) >= MAX_RATE_LIMIT_BUCKETS:
                    raise RateLimitExceeded("Too many tracked slowmode entries")

            last = self._slowmode_last.get(key, 0)

            if now - last < slowmode_seconds:
                remaining = slowmode_seconds - (now - last)
                raise RateLimitExceeded(f"Slowmode active: wait {remaining:.0f}s")

            self._slowmode_last[key] = now
            return True

    async def acheck_rate_limit(self, identity_hash: str) -> bool:
        """Async-callable form of :meth:`check_rate_limit`.

        The lock is held for microseconds, so acquiring it on the event-loop
        thread is safe — no executor dispatch needed.
        """
        return self.check_rate_limit(identity_hash)

    async def acheck_slowmode(
        self,
        identity_hash: str,
        channel_id: str,
        slowmode_seconds: int,
    ) -> bool:
        """Async-callable form of :meth:`check_slowmode`."""
        return self.check_slowmode(identity_hash, channel_id, slowmode_seconds)

    def _cleanup_stale_locked(self, max_age: float = 3600):
        """Remove stale buckets (must be called with self._lock held)."""
        now = time.time()
        stale = [k for k, b in self._buckets.items() if now - b.last_refill > max_age]
        for k in stale:
            del self._buckets[k]
        stale_slow = [k for k, t in self._slowmode_last.items() if now - t > max_age]
        for k in stale_slow:
            del self._slowmode_last[k]

    def cleanup_stale(self, max_age: float = 3600):
        """Remove buckets and slowmode entries that haven't been used recently."""
        with self._lock:
            self._cleanup_stale_locked(max_age)
