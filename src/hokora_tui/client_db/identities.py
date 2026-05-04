# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""IdentityStore — cached sender identity → display_name lookup."""

from __future__ import annotations

import time
from typing import Optional

from hokora_tui.client_db._base import StoreBase


class IdentityStore(StoreBase):
    """Caches identity hash → display_name so senders don't render as raw hex."""

    def upsert(self, identity_hash: str, display_name: Optional[str] = None) -> None:
        with self._lock_unless_tx():
            self._conn.execute(
                "INSERT OR REPLACE INTO identities (hash, display_name, last_seen) "
                "VALUES (?, ?, ?)",
                (identity_hash, display_name, time.time()),
            )
            self._commit_unless_tx()

    def get(self, identity_hash: str) -> Optional[dict]:
        row = self._conn.execute(
            "SELECT * FROM identities WHERE hash = ?", (identity_hash,)
        ).fetchone()
        return dict(row) if row else None
