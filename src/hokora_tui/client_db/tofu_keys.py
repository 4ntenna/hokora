# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""TofuKeyStore — persisted TOFU pins (sender_hash → Ed25519 public key).

The wire carries only a sender's 32-byte Ed25519 key, not the full
X25519||Ed25519 identity its hash is derived from, so the client cannot
re-derive the sender hash to bind it structurally. Pinning the first key
seen per sender is the client's only key-change defense; a
same-hash/different-key event is always anomalous. Persisting the pins
keeps that detection working across restarts.

Writes are first-write-wins; a pin is replaced only by an explicit
``delete`` (the ``/forget-key`` command) plus re-pinning on next contact,
mirroring the daemon's ``PeerKeyStore.update_key``. ``updated_at`` thus
always equals ``first_seen``, kept only for parity with the sibling
stores.
"""

from __future__ import annotations

import time
from typing import Optional

from hokora_tui.client_db._base import StoreBase


class TofuKeyStore(StoreBase):
    """Persistent store of pinned sender Ed25519 public keys (TOFU)."""

    def insert_if_absent(self, sender_hash: str, public_key: bytes) -> None:
        """Pin a sender's public key on first sight; never overwrite a pin.

        Idempotent. Conflict (key-change) handling lives in the verify
        chokepoint, not the store.
        """
        with self._lock_unless_tx():
            now = time.time()
            self._conn.execute(
                """
                INSERT INTO tofu_keys (sender_hash, public_key, first_seen, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(sender_hash) DO NOTHING
                """,
                (sender_hash, public_key, now, now),
            )
            self._commit_unless_tx()

    def get(self, sender_hash: str) -> Optional[bytes]:
        """Return the pinned public key for a sender, or ``None``."""
        row = self._conn.execute(
            "SELECT public_key FROM tofu_keys WHERE sender_hash = ?",
            (sender_hash,),
        ).fetchone()
        if row is None:
            return None
        return bytes(row["public_key"])

    def all_keys(self) -> dict[str, bytes]:
        """Return every pinned key, keyed by sender hash."""
        rows = self._conn.execute("SELECT sender_hash, public_key FROM tofu_keys").fetchall()
        return {r["sender_hash"]: bytes(r["public_key"]) for r in rows}

    def delete(self, sender_hash: str) -> None:
        """Drop a sender's pin (explicit reset; no-op if absent)."""
        with self._lock_unless_tx():
            self._conn.execute("DELETE FROM tofu_keys WHERE sender_hash = ?", (sender_hash,))
            self._commit_unless_tx()
