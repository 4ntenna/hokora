# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""ChannelStore — cached channel metadata + per-channel unread counts.

Channels and ``unread_counts`` share this store because unread is
per-channel state — keeping them together avoids a trivially-small
extra store.
"""

from __future__ import annotations

from hokora_tui.client_db._base import StoreBase


class ChannelStore(StoreBase):
    """Cached channel metadata + per-channel unread counts."""

    # ── Channels ───────────────────────────────────────────────────

    def store(self, channels: list[dict]) -> None:
        with self._lock_unless_tx():
            self._store_unlocked(channels)

    def _store_unlocked(self, channels: list[dict]) -> None:
        for ch in channels:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO channels
                (id, name, description, access_mode, category_id, position,
                 identity_hash, latest_seq, sealed, node_identity_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    ch.get("id"),
                    ch.get("name"),
                    ch.get("description", ""),
                    ch.get("access_mode", "public"),
                    ch.get("category_id"),
                    ch.get("position", 0),
                    ch.get("identity_hash"),
                    ch.get("latest_seq", 0),
                    1 if ch.get("sealed") else 0,
                    ch.get("node_identity_hash"),
                ),
            )
        self._commit_unless_tx()

    def get_all(self) -> list[dict]:
        rows = self._conn.execute("SELECT * FROM channels ORDER BY position").fetchall()
        return [dict(r) for r in rows]

    # ── Unread counts ──────────────────────────────────────────────

    def get_unread(self, channel_id: str) -> int:
        """Get the unread message count for a channel."""
        row = self._conn.execute(
            "SELECT count FROM unread_counts WHERE channel_id = ?", (channel_id,)
        ).fetchone()
        return row["count"] if row else 0

    def set_unread(self, channel_id: str, count: int) -> None:
        """Set the unread count for a channel."""
        with self._lock_unless_tx():
            self._conn.execute(
                "INSERT OR REPLACE INTO unread_counts (channel_id, count) VALUES (?, ?)",
                (channel_id, count),
            )
            self._commit_unless_tx()

    def increment_unread(self, channel_id: str) -> None:
        """Increment the unread count for a channel by 1."""
        with self._lock_unless_tx():
            self._conn.execute(
                """
                INSERT INTO unread_counts (channel_id, count) VALUES (?, 1)
                ON CONFLICT(channel_id) DO UPDATE SET count = count + 1
                """,
                (channel_id,),
            )
            self._commit_unless_tx()

    def reset_unread(self, channel_id: str) -> None:
        """Reset the unread count for a channel to 0."""
        with self._lock_unless_tx():
            self._conn.execute(
                "INSERT OR REPLACE INTO unread_counts (channel_id, count) VALUES (?, 0)",
                (channel_id,),
            )
            self._commit_unless_tx()
