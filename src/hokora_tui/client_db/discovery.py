# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""DiscoveryStore — discovered nodes + peers from RNS announces.

Both kinds of discovery (node announces = daemons hosting channels; peer
announces = user profiles) share this store because the UX treats them
as twin views on the same Discovery screen.
"""

from __future__ import annotations

from typing import Optional

from hokora_tui.client_db._base import StoreBase


class DiscoveryStore(StoreBase):
    """Discovered node + peer announces, persisted for the Discovery view."""

    # ── Nodes ─────────────────────────────────────────────────────

    def store_node(
        self,
        hash: str,
        name: str,
        channel_count: int,
        last_seen: float,
        channels_json: str,
        channel_dests_json: str = "",
    ) -> None:
        """Store or update a discovered node."""
        with self._lock_unless_tx():
            self._conn.execute(
                """
                INSERT INTO discovered_nodes
                    (hash, node_name, channel_count, last_seen,
                     channels_json, channel_dests_json)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(hash) DO UPDATE SET
                    node_name = excluded.node_name,
                    channel_count = excluded.channel_count,
                    last_seen = excluded.last_seen,
                    channels_json = excluded.channels_json,
                    channel_dests_json = COALESCE(
                        NULLIF(excluded.channel_dests_json, ''),
                        discovered_nodes.channel_dests_json
                    )
                """,
                (hash, name, channel_count, last_seen, channels_json, channel_dests_json),
            )
            self._commit_unless_tx()

    def get_nodes(self) -> list[dict]:
        """Get all discovered nodes, ordered by last_seen descending."""
        rows = self._conn.execute(
            "SELECT * FROM discovered_nodes ORDER BY last_seen DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def toggle_node_bookmark(self, hash: str) -> bool:
        """Toggle the bookmarked status of a discovered node. Returns new state."""
        with self._lock_unless_tx():
            row = self._conn.execute(
                "SELECT bookmarked FROM discovered_nodes WHERE hash = ?", (hash,)
            ).fetchone()
            if not row:
                return False
            new_val = 0 if row["bookmarked"] else 1
            self._conn.execute(
                "UPDATE discovered_nodes SET bookmarked = ? WHERE hash = ?",
                (new_val, hash),
            )
            self._commit_unless_tx()
            return bool(new_val)

    # ── Peers ─────────────────────────────────────────────────────

    def store_peer(
        self,
        hash: str,
        display_name: Optional[str],
        status_text: Optional[str],
        last_seen: float,
    ) -> None:
        """Store or update a discovered peer."""
        with self._lock_unless_tx():
            self._conn.execute(
                """
                INSERT INTO discovered_peers (hash, display_name, status_text, last_seen)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(hash) DO UPDATE SET
                    display_name = excluded.display_name,
                    status_text = excluded.status_text,
                    last_seen = excluded.last_seen
                """,
                (hash, display_name, status_text, last_seen),
            )
            self._commit_unless_tx()

    def get_peers(self) -> list[dict]:
        """Get all discovered peers, ordered by last_seen descending."""
        rows = self._conn.execute(
            "SELECT * FROM discovered_peers ORDER BY last_seen DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def toggle_peer_bookmark(self, hash: str) -> bool:
        """Toggle the bookmarked status of a discovered peer. Returns new state."""
        with self._lock_unless_tx():
            row = self._conn.execute(
                "SELECT bookmarked FROM discovered_peers WHERE hash = ?", (hash,)
            ).fetchone()
            if not row:
                return False
            new_val = 0 if row["bookmarked"] else 1
            self._conn.execute(
                "UPDATE discovered_peers SET bookmarked = ? WHERE hash = ?",
                (new_val, hash),
            )
            self._commit_unless_tx()
            return bool(new_val)
