# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""FTS5 virtual table management for full-text search."""

import logging

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from hokora.exceptions import SyncError

logger = logging.getLogger(__name__)


class FTSManager:
    """Manages FTS5 virtual table for message search."""

    def __init__(self, engine: AsyncEngine):
        self.engine = engine

    async def init_fts(self):
        """Create FTS5 virtual table if it doesn't exist."""
        async with self.engine.begin() as conn:
            await conn.execute(
                text("""
                CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts
                USING fts5(
                    msg_hash UNINDEXED,
                    channel_id UNINDEXED,
                    body,
                    content='messages',
                    content_rowid='rowid'
                )
            """)
            )
            # Triggers to keep FTS in sync.
            #
            # Defence-in-depth: insert/update triggers gate on
            # ``body IS NOT NULL AND encrypted_body IS NULL`` so a
            # direct INSERT that bypassed ``security.sealed_invariant``
            # cannot leak sealed-channel plaintext into the FTS index.
            # The primary enforcement remains the chokepoint module;
            # these triggers exist to close the fallback.
            await conn.execute(
                text("""
                CREATE TRIGGER IF NOT EXISTS messages_ai AFTER INSERT ON messages
                WHEN new.body IS NOT NULL AND new.encrypted_body IS NULL BEGIN
                    INSERT INTO messages_fts(rowid, msg_hash, channel_id, body)
                    VALUES (new.rowid, new.msg_hash, new.channel_id, new.body);
                END
            """)
            )
            await conn.execute(
                text("""
                CREATE TRIGGER IF NOT EXISTS messages_ad AFTER DELETE ON messages BEGIN
                    INSERT INTO messages_fts(messages_fts, rowid, msg_hash, channel_id, body)
                    VALUES ('delete', old.rowid, old.msg_hash, old.channel_id, old.body);
                END
            """)
            )
            await conn.execute(
                text("""
                CREATE TRIGGER IF NOT EXISTS messages_au AFTER UPDATE ON messages
                WHEN new.body IS NOT NULL AND new.encrypted_body IS NULL BEGIN
                    INSERT INTO messages_fts(messages_fts, rowid, msg_hash, channel_id, body)
                    VALUES ('delete', old.rowid, old.msg_hash, old.channel_id, old.body);
                    INSERT INTO messages_fts(rowid, msg_hash, channel_id, body)
                    VALUES (new.rowid, new.msg_hash, new.channel_id, new.body);
                END
            """)
            )
        logger.info("FTS5 virtual table initialized")

    async def search(self, channel_id: str, query: str, limit: int = 20) -> list[dict]:
        """Search messages using FTS5 with BM25 ranking."""
        if not query or not query.strip():
            return []
        try:
            async with self.engine.connect() as conn:
                result = await conn.execute(
                    text("""
                        SELECT msg_hash, channel_id, body, rank
                        FROM messages_fts
                        WHERE messages_fts MATCH :query
                        AND channel_id = :channel_id
                        ORDER BY rank
                        LIMIT :limit
                    """),
                    {"query": query, "channel_id": channel_id, "limit": limit},
                )
                return [
                    {"msg_hash": row[0], "channel_id": row[1], "body": row[2], "rank": row[3]}
                    for row in result.fetchall()
                ]
        except Exception as e:
            error_msg = str(e).lower()
            if "fts5" in error_msg or "match" in error_msg or "syntax" in error_msg:
                raise SyncError(f"Invalid search query: {query!r}") from e
            raise

    async def rebuild(self):
        """Rebuild FTS index from messages table."""
        async with self.engine.begin() as conn:
            await conn.execute(text("INSERT INTO messages_fts(messages_fts) VALUES ('rebuild')"))
        logger.info("FTS5 index rebuilt")
