# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Signature verification, nonce validation, clock drift, sequence integrity."""

import collections
import logging
import threading
import time
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from hokora.constants import CLOCK_DRIFT_TOLERANCE, NONCE_SIZE, SEQ_GAP_WARNING
from hokora.exceptions import VerificationError

logger = logging.getLogger(__name__)

# Default max nonces to track (bounded to prevent memory exhaustion)
DEFAULT_NONCE_CACHE_SIZE = 10000
# Default TTL for nonces in seconds (10 minutes)
DEFAULT_NONCE_TTL = 600


class NonceTracker:
    """Tracks seen nonces to detect replay attacks.

    Uses an OrderedDict as a bounded LRU cache — oldest nonces are evicted
    when the cache exceeds max_size. Also rejects nonces older than TTL.
    """

    def __init__(
        self,
        max_size: int = DEFAULT_NONCE_CACHE_SIZE,
        ttl: int = DEFAULT_NONCE_TTL,
    ):
        self.max_size = max_size
        self.ttl = ttl
        self._seen: collections.OrderedDict[bytes, float] = collections.OrderedDict()
        # threading.Lock (not asyncio.Lock): check_nonce_replay is called from
        # LinkManager._on_packet which runs in an RNS thread.
        self._lock = threading.Lock()

    def check_and_record(self, nonce: bytes, timestamp: Optional[float] = None) -> bool:
        """Check if a nonce has been seen before.

        Returns True if the nonce is fresh (not a replay).
        Returns False if the nonce has been seen (replay detected) or expired.
        Thread-safe: protected by threading.Lock for cross-thread access.
        """
        with self._lock:
            if nonce in self._seen:
                return False

            # Reject nonces with timestamps older than TTL
            if timestamp is not None and self.ttl > 0:
                age = time.time() - timestamp
                if age > self.ttl:
                    logger.warning(f"Rejecting expired nonce: age={age:.0f}s > TTL={self.ttl}s")
                    return False

            self._seen[nonce] = time.time()
            # Evict oldest entries if over capacity
            while len(self._seen) > self.max_size:
                self._seen.popitem(last=False)
            return True

    def evict_expired(self):
        """Remove nonces older than TTL from the cache."""
        with self._lock:
            if self.ttl <= 0:
                return
            cutoff = time.time() - self.ttl
            while self._seen:
                nonce, ts = next(iter(self._seen.items()))
                if ts < cutoff:
                    self._seen.popitem(last=False)
                else:
                    break

    def clear(self):
        with self._lock:
            self._seen.clear()

    def __len__(self):
        return len(self._seen)


class VerificationService:
    """Mandatory security verification for all protocol operations."""

    def __init__(self):
        self.nonce_tracker = NonceTracker()

    def check_nonce_replay(self, nonce: bytes) -> bool:
        """Check if a nonce is fresh (not replayed).

        Returns True if fresh, raises VerificationError if replayed.
        """
        if not isinstance(nonce, bytes):
            raise VerificationError(f"Nonce must be bytes, got {type(nonce).__name__}")
        if not self.nonce_tracker.check_and_record(nonce):
            raise VerificationError("Nonce replay detected")
        return True

    @staticmethod
    def verify_ed25519_signature(
        public_key_bytes: bytes,
        message: bytes,
        signature: bytes,
    ) -> bool:
        """Verify an Ed25519 signature.

        Length guard: ``public_key_bytes`` MUST be exactly 32 bytes (the
        Ed25519 signing key). Historically the caller sometimes passed
        ``RNS.Identity.get_public_key()`` which is 64 bytes (X25519 ||
        Ed25519 concatenated) — that always raised inside
        ``Ed25519PublicKey.from_public_bytes`` with a cryptic message and
        silently turned every verification call into a no-op. The guard
        here fails fast with a grep-friendly log line so a future
        regression surfaces immediately instead of hiding as a cascade
        of ``verified=False`` flags.
        """
        if not isinstance(public_key_bytes, (bytes, bytearray)) or len(public_key_bytes) != 32:
            pk_len = len(public_key_bytes) if public_key_bytes is not None else None
            logger.warning(
                "verify_ed25519_signature: invalid public_key length=%s "
                "(expected 32 bytes, Ed25519 key only — the full RNS 64-byte "
                "get_public_key() blob must be sliced to sig_pub_bytes first)",
                pk_len,
            )
            return False
        try:
            public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            public_key.verify(signature, message)
            return True
        except Exception as e:
            logger.warning(f"Ed25519 signature verification failed: {e}")
            return False

    @staticmethod
    def verify_sync_nonce(sent_nonce: bytes, received_nonce: bytes) -> bool:
        """Verify that the response nonce matches the request nonce."""
        if len(sent_nonce) != NONCE_SIZE:
            raise VerificationError(f"Invalid sent nonce size: {len(sent_nonce)}")
        if len(received_nonce) != NONCE_SIZE:
            raise VerificationError(f"Invalid received nonce size: {len(received_nonce)}")

        if sent_nonce != received_nonce:
            raise VerificationError("Nonce mismatch: possible replay attack")
        return True

    @staticmethod
    def verify_node_time(
        node_time: float,
        tolerance: int = CLOCK_DRIFT_TOLERANCE,
    ) -> bool:
        """Verify node time is within acceptable drift tolerance."""
        local_time = time.time()
        drift = abs(local_time - node_time)
        if drift > tolerance:
            raise VerificationError(f"Clock drift too large: {drift:.1f}s (max {tolerance}s)")
        if drift > tolerance / 2:
            logger.warning(f"Significant clock drift: {drift:.1f}s")
        return True

    @staticmethod
    def check_sequence_integrity(
        expected_seq: int,
        received_seq: int,
    ) -> tuple[bool, Optional[str]]:
        """Check for sequence gaps.

        Returns (ok, warning_message).
        Gaps <= SEQ_GAP_WARNING are normal (may be deletions).
        Gaps > SEQ_GAP_WARNING trigger a warning.
        """
        if received_seq <= expected_seq:
            return True, None  # Already seen or old

        gap = received_seq - expected_seq
        if gap == 1:
            return True, None  # Perfect sequence
        elif gap <= SEQ_GAP_WARNING:
            return True, None  # Normal gap
        else:
            warning = (
                f"Large sequence gap detected: expected ~{expected_seq + 1}, "
                f"got {received_seq} (gap={gap})"
            )
            logger.warning(warning)
            return True, warning

    @staticmethod
    def verify_lxmf_signature(lxmf_message) -> bool:
        """Verify LXMF message signature (delegates to LXMF's built-in check)."""
        if hasattr(lxmf_message, "signature_validated"):
            if not lxmf_message.signature_validated:
                raise VerificationError("LXMF signature not validated")
            return True
        raise VerificationError("LXMF message has no signature validation status")
