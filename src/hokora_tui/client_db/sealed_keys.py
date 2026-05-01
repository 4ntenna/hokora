# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""SealedKeyStore — per-channel symmetric keys for sealed-channel decrypt.

The TUI persists a copy of each sealed-channel symmetric key it has been
granted membership for, so it can decrypt sealed-channel ciphertext at
render-time without round-tripping to the daemon. Storage shape mirrors
the daemon's ``SealedKey`` table: one row per (channel_id, epoch),
``key`` is the raw 32-byte AES-256-GCM key.

Sealed at rest: the ``tui.db`` itself is SQLCipher-encrypted, so the
per-channel keys here are protected at one layer; the channel
ciphertext stored alongside them is protected by both SQLCipher and
the channel-specific envelope.
"""

from __future__ import annotations

import time
from typing import Optional

from hokora_tui.client_db._base import StoreBase


class SealedKeyStore(StoreBase):
    """Persistent store of sealed-channel symmetric keys."""

    def upsert(self, channel_id: str, key: bytes, epoch: int) -> None:
        """Insert or replace the symmetric key for a sealed channel."""
        with self._lock_unless_tx():
            self._conn.execute(
                """
                INSERT INTO sealed_keys (channel_id, key, epoch, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(channel_id) DO UPDATE SET
                    key = excluded.key,
                    epoch = excluded.epoch,
                    updated_at = excluded.updated_at
                """,
                (channel_id, key, epoch, time.time()),
            )
            self._commit_unless_tx()

    def get(self, channel_id: str) -> Optional[tuple[bytes, int]]:
        """Return ``(key, epoch)`` or ``None`` if no key is held for the channel."""
        row = self._conn.execute(
            "SELECT key, epoch FROM sealed_keys WHERE channel_id = ?",
            (channel_id,),
        ).fetchone()
        if row is None:
            return None
        return (bytes(row["key"]), int(row["epoch"]))

    def all_keys(self) -> dict[str, tuple[bytes, int]]:
        """Return every stored sealed key, keyed by channel_id."""
        rows = self._conn.execute("SELECT channel_id, key, epoch FROM sealed_keys").fetchall()
        return {r["channel_id"]: (bytes(r["key"]), int(r["epoch"])) for r in rows}

    def delete(self, channel_id: str) -> None:
        """Remove the stored key for a channel (e.g., on revoke)."""
        with self._lock_unless_tx():
            self._conn.execute("DELETE FROM sealed_keys WHERE channel_id = ?", (channel_id,))
            self._commit_unless_tx()
