# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Inbound LXMF channel-message verification chokepoint.

LXMF's own ``unpack_from_bytes`` cannot verify a signature when the
source identity is unknown to the local RNS path cache. The historical
handler accepted such messages with only a warning, which made the
wire-claimed ``source_hash`` attacker-controlled and the role/permission
gates downstream meaningless. This module is the structural binding
chokepoint that closes that gap, mirroring
``federation.auth.verify_sender_binding`` for the LXMF-receive path.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import OrderedDict
from typing import Any, Optional

import LXMF
import msgpack
import RNS

logger = logging.getLogger(__name__)

_PATH_REQUEST_CACHE_TTL_SECONDS = 60.0
_PATH_REQUEST_CACHE_MAX_ENTRIES = 1024

_LXMF_INBOUND_REJECTIONS: dict[str, int] = {}
_LXMF_INBOUND_RESULTS = {
    "rejected": 0,
    "recovered": 0,
    "signature_failed": 0,
    "opt_out_passthrough": 0,
}


def get_lxmf_inbound_counts() -> dict[str, int]:
    """Snapshot of LXMF inbound rejection counts (cheap, prometheus-render path)."""
    return dict(_LXMF_INBOUND_REJECTIONS)


def get_lxmf_inbound_action_counts() -> dict[str, int]:
    """Snapshot of LXMF inbound action counts keyed on outcome label."""
    return dict(_LXMF_INBOUND_RESULTS)


def _record_rejection(label: str) -> None:
    _LXMF_INBOUND_REJECTIONS[label] = _LXMF_INBOUND_REJECTIONS.get(label, 0) + 1


def _record_action(label: str) -> None:
    if label in _LXMF_INBOUND_RESULTS:
        _LXMF_INBOUND_RESULTS[label] += 1


class PathRequestCache:
    """Bounded TTL cache that suppresses duplicate ``request_path`` packets.

    A flood of forged frames claiming the same unknown ``source_hash`` must
    not translate into a flood of path-request packets onto the transport.
    This cache records the monotonic timestamp of the last request per
    ``source_hash`` and reports whether a fresh request is permitted under
    the configured TTL. Hard-capped via LRU eviction.
    """

    def __init__(
        self,
        ttl_seconds: float = _PATH_REQUEST_CACHE_TTL_SECONDS,
        max_entries: int = _PATH_REQUEST_CACHE_MAX_ENTRIES,
    ) -> None:
        self._ttl = ttl_seconds
        self._max = max_entries
        self._entries: OrderedDict[bytes, float] = OrderedDict()

    def should_request(self, source_hash: bytes) -> bool:
        now = time.monotonic()
        last = self._entries.get(source_hash)
        if last is not None and (now - last) < self._ttl:
            self._entries.move_to_end(source_hash)
            return False
        self._entries[source_hash] = now
        self._entries.move_to_end(source_hash)
        while len(self._entries) > self._max:
            self._entries.popitem(last=False)
        return True

    def reset(self) -> None:
        self._entries.clear()


_default_cache = PathRequestCache()


def reset_for_tests() -> None:
    """Test hook: reset module-level state (counters, path-request cache)."""
    _LXMF_INBOUND_REJECTIONS.clear()
    for k in _LXMF_INBOUND_RESULTS:
        _LXMF_INBOUND_RESULTS[k] = 0
    _default_cache.reset()


def reconstruct_lxmf_signed_part(message: LXMF.LXMessage) -> Optional[bytes]:
    """Rebuild the bytes the LXMF sender signed.

    Mirrors ``LXMessage.unpack_from_bytes`` exactly. The naive recipe of
    re-packing ``message.payload`` via ``msgpack.packb`` produces
    different bytes when a stamp was appended to the payload after
    signing, so callers must use this helper rather than rolling their
    own. Returns None if reconstruction fails or the sanity check
    against ``message.hash`` does not match.
    """
    if not (
        hasattr(message, "hash")
        and message.hash
        and hasattr(message, "packed")
        and message.packed
        and len(message.packed) >= 96
    ):
        return None

    packed_payload = message.packed[96:]
    try:
        unpacked = msgpack.unpackb(packed_payload)
        if isinstance(unpacked, list) and len(unpacked) > 4:
            packed_payload = msgpack.packb(unpacked[:4])
    except Exception:
        logger.warning(
            "lxmf_signed_part payload unpack failed; client re-verify will be unavailable",
            exc_info=True,
        )
        return None

    dest_hash = message.destination_hash if isinstance(message.destination_hash, bytes) else b""
    src_hash = message.source_hash if isinstance(message.source_hash, bytes) else b""
    hashed_part = dest_hash + src_hash + packed_payload

    try:
        recomputed = RNS.Identity.full_hash(hashed_part)
    except Exception:
        logger.debug("hashed_part recompute check failed", exc_info=True)
        return None
    if recomputed != message.hash:
        logger.warning(
            "Reconstructed lxmf hashed_part does not match message.hash; "
            "LXMF payload schema may have drifted"
        )
        return None

    return bytes(hashed_part + message.hash)


async def verify_lxmf_inbound(
    message: LXMF.LXMessage,
    *,
    require_signed: bool,
    path_wait_seconds: float = 5.0,
    cache: Optional[PathRequestCache] = None,
) -> tuple[bool, Optional[str], Optional[Any]]:
    """Verify a inbound LXMF message and return the validated identity.

    Decision matrix:

    - ``message.signature_validated`` is True (LXMF already verified):
      accept; return the identity LXMF resolved.
    - ``unverified_reason`` is ``SIGNATURE_INVALID``: reject unconditionally.
    - ``unverified_reason`` is ``SOURCE_UNKNOWN`` and ``require_signed`` is
      False: accept (lab/test opt-out path); no identity returned.
    - ``unverified_reason`` is ``SOURCE_UNKNOWN`` and ``require_signed`` is
      True: issue ``Transport.request_path``, async-poll
      ``Identity.recall`` until ``path_wait_seconds`` elapses, then
      verify the signature against the recovered identity. Reject if
      recall fails or signature does not match.

    Returns:
        ``(ok, reason, identity)``. On ``ok=True`` the caller has a
        verified-bound identity (or ``None`` in the opt-out
        passthrough). On ``ok=False`` the caller MUST drop the message.

    Args:
        message: the inbound LXMF message to verify.
        require_signed: when True, SOURCE_UNKNOWN frames are accepted
            only after a successful path resolution + signature verify.
            Mirrors ``NodeConfig.require_signed_lxmf``.
        path_wait_seconds: how long to wait for a path resolution before
            giving up. Mirrors ``NodeConfig.lxmf_path_wait_seconds``.
        cache: path-request cache; defaults to the module singleton.
    """
    if cache is None:
        cache = _default_cache

    if getattr(message, "signature_validated", False):
        identity = None
        if message.source and hasattr(message.source, "identity"):
            identity = message.source.identity
        return True, None, identity

    reason = getattr(message, "unverified_reason", None)
    if reason == LXMF.LXMessage.SIGNATURE_INVALID:
        _record_rejection("signature_invalid")
        _record_action("rejected")
        return False, "signature invalid", None

    if reason != LXMF.LXMessage.SOURCE_UNKNOWN:
        _record_rejection("validation_status_unknown")
        _record_action("rejected")
        return False, "validation status unknown", None

    if not require_signed:
        _record_action("opt_out_passthrough")
        return True, None, None

    source_hash = message.source_hash
    if not isinstance(source_hash, (bytes, bytearray)) or not source_hash:
        _record_rejection("missing_source_hash")
        _record_action("rejected")
        return False, "missing source_hash", None

    # The ``recall`` form here mirrors LXMF's own resolver in
    # ``unpack_from_bytes`` so we look at the same cache LXMF was looking
    # at when it set SOURCE_UNKNOWN. The ``from_identity_hash=True``
    # variant used by sealed-key distribution operates on a different key
    # space and would resolve nothing for an LXMF source_hash.
    if cache.should_request(bytes(source_hash)):
        try:
            RNS.Transport.request_path(source_hash)
        except Exception:
            logger.debug("Transport.request_path raised", exc_info=True)

    deadline = time.monotonic() + max(0.0, path_wait_seconds)
    identity = RNS.Identity.recall(source_hash)
    while identity is None and time.monotonic() < deadline:
        await asyncio.sleep(0.25)
        identity = RNS.Identity.recall(source_hash)

    if identity is None:
        _record_rejection("source_unknown_after_path_request")
        _record_action("rejected")
        return False, "source unknown after path request", None

    signed_part = reconstruct_lxmf_signed_part(message)
    if signed_part is None:
        _record_rejection("signed_part_reconstruction_failed")
        _record_action("rejected")
        return False, "signed part reconstruction failed", None

    sig = getattr(message, "signature", None)
    if not isinstance(sig, (bytes, bytearray)) or len(sig) == 0:
        _record_rejection("missing_signature")
        _record_action("rejected")
        return False, "missing signature", None

    pk = getattr(identity, "sig_pub_bytes", None)
    if pk is None:
        full = identity.get_public_key()
        pk = full[32:] if full and len(full) == 64 else None
    if not isinstance(pk, (bytes, bytearray)) or len(pk) != 32:
        _record_rejection("invalid_pubkey")
        _record_action("rejected")
        return False, "invalid recovered pubkey", None

    from hokora.security.verification import VerificationService

    if not VerificationService.verify_ed25519_signature(bytes(pk), bytes(signed_part), bytes(sig)):
        _record_rejection("bad_signature")
        _record_action("signature_failed")
        return False, "Ed25519 signature verification failed after path resolution", None

    _record_action("recovered")
    return True, None, identity
