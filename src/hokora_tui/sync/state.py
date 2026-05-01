# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""SyncState — mutable state shared across sync subsystems.

Each subsystem holds a reference to the same instance. Serialization of
mutations is the responsibility of each subsystem's public methods
(they hold the relevant locks). External callers never mutate SyncState
directly; they go through subsystem methods or SyncEngine public accessors.

Why a single blob rather than per-subsystem state: link establishment
writes ``channel_dest_hashes`` and ``channel_identities`` that are then
read by the LXMF sender, the CDSP client's session-init payload, the
reconnect scheduler, and the history sync. The coupling is genuine, not
accidental — splitting across 4 state holders produces worse cross-class
coupling than one shared dataclass.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, ClassVar, Optional

from hokora.constants import CDSP_PROFILE_FULL

if TYPE_CHECKING:
    import RNS


@dataclass
class SyncState:
    """Mutable state shared across sync subsystems."""

    # Class-level nonce cleanup knobs — shared by every send client via
    # ``cleanup_stale_nonces``. Kept as ClassVar so dataclasses.field doesn't
    # treat them as instance fields.
    _NONCE_CLEANUP_INTERVAL: ClassVar[float] = 30.0
    _NONCE_MAX_AGE: ClassVar[float] = 60.0

    # ── Connection state ───────────────────────────────────────────────
    # channel_id -> RNS.Identity cached from node_meta / pubkey-seeded invite
    channel_identities: dict[str, "RNS.Identity"] = field(default_factory=dict)
    # channel_id -> destination_hash (16-byte bytes)
    channel_dest_hashes: dict[str, bytes] = field(default_factory=dict)
    # dest_hex -> public_key_bytes (from 4-field invites, consumed once by connect)
    pending_pubkeys: dict[str, bytes] = field(default_factory=dict)
    # channel_id -> destination_hash awaiting path resolution
    pending_connects: dict[str, bytes] = field(default_factory=dict)
    # channel_key -> token for pending invite redemptions
    pending_redeems: dict[str, str] = field(default_factory=dict)

    # ── Sync protocol state ────────────────────────────────────────────
    # channel_id -> last_seq_seen
    cursors: dict[str, int] = field(default_factory=dict)
    # nonce_bytes -> send_timestamp (for stale-nonce cleanup)
    pending_nonces: dict[bytes, float] = field(default_factory=dict)
    # Last time stale-nonce cleanup ran (throttled)
    last_nonce_cleanup: float = 0.0
    # channel_id -> list of sequence gap warning strings
    seq_warnings: dict[str, list[str]] = field(default_factory=dict)

    # ── Identity cache for signature verification ──────────────────────
    # identity_hash_hex -> public_key_bytes
    identity_keys: dict[str, bytes] = field(default_factory=dict)

    # ── Display / identity ─────────────────────────────────────────────
    display_name: Optional[str] = None

    # ── CDSP session state ─────────────────────────────────────────────
    sync_profile: int = CDSP_PROFILE_FULL
    cdsp_session_id: Optional[str] = None
    resume_token: Optional[bytes] = None
    deferred_count: int = 0

    # ── Media download pending state ───────────────────────────────────
    pending_media_path: Optional[str] = None
    pending_media_save_path: Optional[str] = None

    # ── Shared helpers ─────────────────────────────────────────────────

    def cleanup_stale_nonces(self) -> list[bytes]:
        """Remove pending nonces older than ``_NONCE_MAX_AGE`` seconds.

        Throttled to run at most every ``_NONCE_CLEANUP_INTERVAL`` seconds;
        callers can invoke this before every request with negligible cost.
        Returns the list of evicted nonces (empty if throttled or nothing
        stale) so callers / tests can assert on it without scanning the
        dict themselves.
        """
        now = time.time()
        if now - self.last_nonce_cleanup < self._NONCE_CLEANUP_INTERVAL:
            return []
        self.last_nonce_cleanup = now
        stale = [n for n, ts in self.pending_nonces.items() if now - ts > self._NONCE_MAX_AGE]
        for n in stale:
            del self.pending_nonces[n]
        return stale
