# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Schema DDL + migration ladder for the TUI client-side SQLite cache.

Schema version is an integer tracked in a one-row ``schema_version`` table.
Every additive migration is idempotent — ``ALTER TABLE ADD COLUMN`` guards
with a ``PRAGMA table_info`` check so re-running a migrator on a
half-migrated DB is safe.

Current head: v8 — adds sealed-channel envelope columns
(``messages.encrypted_body`` / ``encryption_nonce`` / ``encryption_epoch``)
plus ``sealed_keys`` for at-rest sealed-channel encryption parity with
the daemon.
"""

from __future__ import annotations

import sqlite3
import threading

SCHEMA_VERSION = 8

_INIT_SQL = """
CREATE TABLE IF NOT EXISTS messages (
    msg_hash TEXT PRIMARY KEY,
    channel_id TEXT NOT NULL,
    sender_hash TEXT,
    seq INTEGER NOT NULL,
    timestamp REAL NOT NULL,
    type INTEGER NOT NULL,
    body TEXT,
    display_name TEXT,
    reply_to TEXT,
    deleted INTEGER DEFAULT 0,
    pinned INTEGER DEFAULT 0,
    reactions TEXT DEFAULT '{}',
    lxmf_signature BLOB,
    received_at REAL,
    verified INTEGER DEFAULT 0,
    edited INTEGER DEFAULT 0,
    has_thread INTEGER DEFAULT 0,
    encrypted_body BLOB,
    encryption_nonce BLOB,
    encryption_epoch INTEGER
);
CREATE INDEX IF NOT EXISTS ix_msg_channel_seq ON messages(channel_id, seq);

CREATE TABLE IF NOT EXISTS identities (
    hash TEXT PRIMARY KEY,
    display_name TEXT,
    last_seen REAL
);

CREATE TABLE IF NOT EXISTS sync_cursors (
    channel_id TEXT PRIMARY KEY,
    last_seq INTEGER DEFAULT 0,
    last_sync REAL
);

CREATE TABLE IF NOT EXISTS channels (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    access_mode TEXT DEFAULT 'public',
    category_id TEXT,
    position INTEGER DEFAULT 0,
    identity_hash TEXT,
    latest_seq INTEGER DEFAULT 0,
    sealed INTEGER DEFAULT 0,
    node_identity_hash TEXT
);

CREATE TABLE IF NOT EXISTS bookmarks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    destination_hash TEXT NOT NULL,
    node_name TEXT,
    last_connected REAL,
    auto_connect INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS schema_version (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS discovered_nodes (
    hash TEXT PRIMARY KEY,
    node_name TEXT,
    channel_count INTEGER,
    last_seen REAL,
    channels_json TEXT,
    bookmarked INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS discovered_peers (
    hash TEXT PRIMARY KEY,
    display_name TEXT,
    status_text TEXT,
    last_seen REAL,
    bookmarked INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS direct_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_hash TEXT NOT NULL,
    receiver_hash TEXT NOT NULL,
    timestamp REAL NOT NULL,
    body TEXT NOT NULL,
    lxmf_signature BLOB,
    read INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_dm_peers_time
    ON direct_messages(sender_hash, receiver_hash, timestamp);

CREATE TABLE IF NOT EXISTS conversations (
    peer_hash TEXT PRIMARY KEY,
    peer_name TEXT,
    last_message_time REAL,
    unread_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS unread_counts (
    channel_id TEXT PRIMARY KEY,
    count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sealed_keys (
    channel_id TEXT PRIMARY KEY,
    key BLOB NOT NULL,
    epoch INTEGER NOT NULL,
    updated_at REAL NOT NULL
);
"""


class SchemaMigrator:
    """Runs the schema DDL + migration ladder under a shared write lock."""

    def __init__(self, conn: sqlite3.Connection, lock: threading.Lock) -> None:
        self._conn = conn
        self._lock = lock

    def init_and_migrate(self) -> None:
        """Create any missing tables, then advance the migration ladder."""
        with self._lock:
            self._conn.executescript(_INIT_SQL)
            self._conn.commit()
            self._run_migrations()

    # ── Internal ───────────────────────────────────────────────────

    def _get_version(self) -> int:
        """Return current schema version, 0 if untracked."""
        try:
            row = self._conn.execute("SELECT version FROM schema_version WHERE id = 1").fetchone()
            return row["version"] if row else 0
        except Exception:
            return 0

    def _set_version(self, version: int) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO schema_version (id, version) VALUES (1, ?)",
            (version,),
        )
        self._conn.commit()

    def _columns(self, table: str) -> set[str]:
        return {row[1] for row in self._conn.execute(f"PRAGMA table_info({table})").fetchall()}

    def _run_migrations(self) -> None:
        current = self._get_version()
        if current >= SCHEMA_VERSION:
            return

        # v1 → v2: add channels.sealed + bookmarks (bookmarks via CREATE IF NOT EXISTS).
        if current < 2:
            if "sealed" not in self._columns("channels"):
                self._conn.execute("ALTER TABLE channels ADD COLUMN sealed INTEGER DEFAULT 0")

        # v2 → v3: new v2 tables covered by CREATE IF NOT EXISTS; no-op.
        if current < 3:
            pass

        # v3 → v4: add discovered_nodes.channel_dests_json.
        if current < 4:
            if "channel_dests_json" not in self._columns("discovered_nodes"):
                self._conn.execute(
                    "ALTER TABLE discovered_nodes ADD COLUMN channel_dests_json TEXT"
                )

        # v4 → v5: add messages.edited.
        if current < 5:
            if "edited" not in self._columns("messages"):
                self._conn.execute("ALTER TABLE messages ADD COLUMN edited INTEGER DEFAULT 0")

        # v5 → v6: add messages.has_thread.
        if current < 6:
            if "has_thread" not in self._columns("messages"):
                self._conn.execute("ALTER TABLE messages ADD COLUMN has_thread INTEGER DEFAULT 0")

        # v6 → v7: add channels.node_identity_hash for multi-node disambiguation.
        if current < 7:
            if "node_identity_hash" not in self._columns("channels"):
                self._conn.execute("ALTER TABLE channels ADD COLUMN node_identity_hash TEXT")

        # v7 → v8: sealed-channel envelope columns + sealed_keys table.
        # ``sealed_keys`` covered by CREATE IF NOT EXISTS in _INIT_SQL above.
        if current < 8:
            msg_cols = self._columns("messages")
            if "encrypted_body" not in msg_cols:
                self._conn.execute("ALTER TABLE messages ADD COLUMN encrypted_body BLOB")
            if "encryption_nonce" not in msg_cols:
                self._conn.execute("ALTER TABLE messages ADD COLUMN encryption_nonce BLOB")
            if "encryption_epoch" not in msg_cols:
                self._conn.execute("ALTER TABLE messages ADD COLUMN encryption_epoch INTEGER")

        self._set_version(SCHEMA_VERSION)
        self._conn.commit()
