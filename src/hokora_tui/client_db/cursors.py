# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""CursorStore — per-channel sync cursor (last_seq) persistence."""

from __future__ import annotations

import time

from hokora_tui.client_db._base import StoreBase


class CursorStore(StoreBase):
    """Tracks the last synced seq per channel so resume-sync is cheap."""

    def get(self, channel_id: str) -> int:
        row = self._conn.execute(
            "SELECT last_seq FROM sync_cursors WHERE channel_id = ?", (channel_id,)
        ).fetchone()
        return row["last_seq"] if row else 0

    def get_all(self) -> dict:
        """Return all persisted cursors as {channel_id: last_seq}."""
        rows = self._conn.execute("SELECT channel_id, last_seq FROM sync_cursors").fetchall()
        return {row["channel_id"]: row["last_seq"] for row in rows}

    def set(self, channel_id: str, seq: int) -> None:
        with self._lock_unless_tx():
            self._set_unlocked(channel_id, seq)

    def _set_unlocked(self, channel_id: str, seq: int) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO sync_cursors (channel_id, last_seq, last_sync) "
            "VALUES (?, ?, ?)",
            (channel_id, seq, time.time()),
        )
        self._commit_unless_tx()
