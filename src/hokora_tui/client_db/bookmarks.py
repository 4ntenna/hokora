# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""BookmarkStore — saved node bookmarks (friendly name → destination_hash)."""

from __future__ import annotations

import time
from typing import Optional

from hokora_tui.client_db._base import StoreBase


class BookmarkStore(StoreBase):
    """User-saved daemon bookmarks for quick reconnect."""

    def save(self, name: str, destination_hash: str, node_name: Optional[str] = None) -> None:
        with self._lock_unless_tx():
            self._conn.execute(
                "INSERT OR REPLACE INTO bookmarks "
                "(name, destination_hash, node_name, last_connected) VALUES (?, ?, ?, ?)",
                (name, destination_hash, node_name, time.time()),
            )
            self._commit_unless_tx()

    def get(self, name: str) -> Optional[dict]:
        row = self._conn.execute("SELECT * FROM bookmarks WHERE name = ?", (name,)).fetchone()
        return dict(row) if row else None

    def get_all(self) -> list[dict]:
        rows = self._conn.execute("SELECT * FROM bookmarks ORDER BY last_connected DESC").fetchall()
        return [dict(r) for r in rows]

    def delete(self, name: str) -> bool:
        with self._lock_unless_tx():
            cursor = self._conn.execute("DELETE FROM bookmarks WHERE name = ?", (name,))
            self._commit_unless_tx()
            return cursor.rowcount > 0
