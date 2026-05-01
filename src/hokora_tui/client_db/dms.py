# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""DmStore — direct-messages + conversation tracking.

Conversations are aggregate state for DMs (last_message_time + unread
count per peer). Pair them in one store because every DM write must
update both tables in lock-step.
"""

from __future__ import annotations

from typing import Optional

from hokora_tui.client_db._base import StoreBase


class DmStore(StoreBase):
    """Direct messages + per-peer conversation aggregates."""

    # ── Direct messages ───────────────────────────────────────────

    def store(
        self,
        sender_hash: str,
        receiver_hash: str,
        timestamp: float,
        body: str,
        signature: Optional[bytes] = None,
    ) -> None:
        """Store a direct message."""
        with self._lock_unless_tx():
            self._conn.execute(
                """
                INSERT INTO direct_messages
                (sender_hash, receiver_hash, timestamp, body, lxmf_signature)
                VALUES (?, ?, ?, ?, ?)
                """,
                (sender_hash, receiver_hash, timestamp, body, signature),
            )
            self._commit_unless_tx()

    def get(
        self, peer_hash: str, limit: int = 50, before_time: Optional[float] = None
    ) -> list[dict]:
        """Return DMs where either sender or receiver is ``peer_hash``,
        newest-first, limited to ``limit``."""
        if before_time is not None:
            rows = self._conn.execute(
                """
                SELECT * FROM direct_messages
                WHERE (sender_hash = ? OR receiver_hash = ?) AND timestamp < ?
                ORDER BY timestamp DESC LIMIT ?
                """,
                (peer_hash, peer_hash, before_time, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                """
                SELECT * FROM direct_messages
                WHERE sender_hash = ? OR receiver_hash = ?
                ORDER BY timestamp DESC LIMIT ?
                """,
                (peer_hash, peer_hash, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    # ── Conversations ─────────────────────────────────────────────

    def get_conversations(self) -> list[dict]:
        """Get all conversations, ordered by last_message_time descending."""
        rows = self._conn.execute(
            "SELECT * FROM conversations ORDER BY last_message_time DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def update_conversation(
        self, peer_hash: str, peer_name: Optional[str], timestamp: float
    ) -> None:
        """Create or update a conversation entry for a peer."""
        with self._lock_unless_tx():
            self._conn.execute(
                """
                INSERT INTO conversations (peer_hash, peer_name, last_message_time, unread_count)
                VALUES (?, ?, ?, 0)
                ON CONFLICT(peer_hash) DO UPDATE SET
                    peer_name = excluded.peer_name,
                    last_message_time = excluded.last_message_time
                """,
                (peer_hash, peer_name, timestamp),
            )
            self._commit_unless_tx()

    def mark_conversation_read(self, peer_hash: str) -> None:
        """Mark all messages in a conversation as read (reset unread count)."""
        with self._lock_unless_tx():
            self._conn.execute(
                "UPDATE conversations SET unread_count = 0 WHERE peer_hash = ?",
                (peer_hash,),
            )
            self._conn.execute(
                """
                UPDATE direct_messages SET read = 1
                WHERE (sender_hash = ? OR receiver_hash = ?) AND read = 0
                """,
                (peer_hash, peer_hash),
            )
            self._commit_unless_tx()

    def increment_unread(self, peer_hash: str) -> None:
        """Increment the unread count for a conversation."""
        with self._lock_unless_tx():
            self._conn.execute(
                """
                UPDATE conversations SET unread_count = unread_count + 1
                WHERE peer_hash = ?
                """,
                (peer_hash,),
            )
            self._commit_unless_tx()
