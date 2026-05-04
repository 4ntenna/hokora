# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""SettingsStore — simple key/value store for TUI preferences."""

from __future__ import annotations

from typing import Optional

from hokora_tui.client_db._base import StoreBase


class SettingsStore(StoreBase):
    """Persists TUI preferences (display_name, status_text, seed_nodes, etc.)."""

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        row = self._conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default

    def set(self, key: str, value: str) -> None:
        with self._lock_unless_tx():
            self._conn.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                (key, value),
            )
            self._commit_unless_tx()
