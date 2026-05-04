# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Comprehensive tests for hokora_tui.client_db.ClientDB."""

import sqlite3
import time

import pytest

from hokora_tui.client_db import ClientDB


@pytest.fixture
def db(tmp_path):
    """Return a fresh ClientDB backed by a temp SQLite file."""
    client_db = ClientDB(tmp_path / "test.db", encrypt=False)
    yield client_db
    client_db.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_msg(msg_hash, channel_id, seq, body="hello", sender_hash="abc123"):
    return {
        "msg_hash": msg_hash,
        "channel_id": channel_id,
        "sender_hash": sender_hash,
        "seq": seq,
        "timestamp": time.time(),
        "type": 1,
        "body": body,
    }


def _make_channel(channel_id, name, position=0, sealed=False):
    return {
        "id": channel_id,
        "name": name,
        "position": position,
        "sealed": sealed,
    }


# ---------------------------------------------------------------------------
# Messages
# ---------------------------------------------------------------------------


class TestMessages:
    def test_store_and_retrieve_message(self, db):
        msg = _make_msg("hash1", "chan-a", seq=1, body="first message")
        db.store_messages([msg])
        results = db.get_messages("chan-a")
        assert len(results) == 1
        assert results[0]["msg_hash"] == "hash1"
        assert results[0]["body"] == "first message"

    def test_store_upsert_replaces_existing(self, db):
        msg = _make_msg("hash1", "chan-a", seq=1, body="original")
        db.store_messages([msg])
        updated = _make_msg("hash1", "chan-a", seq=1, body="updated")
        db.store_messages([updated])
        results = db.get_messages("chan-a")
        assert len(results) == 1
        assert results[0]["body"] == "updated"

    def test_get_messages_ordered_by_seq_ascending(self, db):
        msgs = [
            _make_msg("h3", "chan-a", seq=3),
            _make_msg("h1", "chan-a", seq=1),
            _make_msg("h2", "chan-a", seq=2),
        ]
        db.store_messages(msgs)
        results = db.get_messages("chan-a")
        seqs = [r["seq"] for r in results]
        assert seqs == [1, 2, 3]

    def test_get_messages_empty_channel_returns_empty_list(self, db):
        results = db.get_messages("nonexistent-channel")
        assert results == []

    def test_get_messages_limit(self, db):
        msgs = [_make_msg(f"h{i}", "chan-a", seq=i) for i in range(1, 11)]
        db.store_messages(msgs)
        results = db.get_messages("chan-a", limit=5)
        assert len(results) == 5
        # Should return the last 5 (highest seq), still in ascending order
        seqs = [r["seq"] for r in results]
        assert seqs == [6, 7, 8, 9, 10]

    def test_get_messages_before_seq_pagination(self, db):
        msgs = [_make_msg(f"h{i}", "chan-a", seq=i) for i in range(1, 11)]
        db.store_messages(msgs)
        results = db.get_messages("chan-a", limit=3, before_seq=6)
        seqs = [r["seq"] for r in results]
        assert seqs == [3, 4, 5]

    def test_get_messages_before_seq_at_start_returns_empty(self, db):
        msgs = [_make_msg(f"h{i}", "chan-a", seq=i) for i in range(1, 4)]
        db.store_messages(msgs)
        results = db.get_messages("chan-a", before_seq=1)
        assert results == []

    def test_store_multiple_messages_in_one_call(self, db):
        msgs = [_make_msg(f"h{i}", "chan-b", seq=i) for i in range(1, 6)]
        db.store_messages(msgs)
        results = db.get_messages("chan-b")
        assert len(results) == 5

    def test_get_messages_isolated_by_channel(self, db):
        db.store_messages([_make_msg("h1", "chan-a", seq=1)])
        db.store_messages([_make_msg("h2", "chan-b", seq=1)])
        assert len(db.get_messages("chan-a")) == 1
        assert db.get_messages("chan-a")[0]["msg_hash"] == "h1"


# ---------------------------------------------------------------------------
# Channels
# ---------------------------------------------------------------------------


class TestChannels:
    def test_store_and_retrieve_channel(self, db):
        db.store_channels([_make_channel("ch1", "general")])
        channels = db.get_channels()
        assert len(channels) == 1
        assert channels[0]["id"] == "ch1"
        assert channels[0]["name"] == "general"

    def test_store_upsert_replaces_channel(self, db):
        db.store_channels([_make_channel("ch1", "general")])
        db.store_channels([_make_channel("ch1", "renamed")])
        channels = db.get_channels()
        assert len(channels) == 1
        assert channels[0]["name"] == "renamed"

    def test_get_channels_ordered_by_position(self, db):
        db.store_channels(
            [
                _make_channel("ch3", "third", position=3),
                _make_channel("ch1", "first", position=1),
                _make_channel("ch2", "second", position=2),
            ]
        )
        channels = db.get_channels()
        names = [c["name"] for c in channels]
        assert names == ["first", "second", "third"]

    def test_sealed_flag_persists(self, db):
        db.store_channels([_make_channel("ch1", "sealed-chan", sealed=True)])
        channels = db.get_channels()
        assert channels[0]["sealed"] == 1

    def test_sealed_false_persists(self, db):
        db.store_channels([_make_channel("ch1", "open-chan", sealed=False)])
        channels = db.get_channels()
        assert channels[0]["sealed"] == 0

    def test_get_channels_empty_returns_empty_list(self, db):
        assert db.get_channels() == []

    def test_node_identity_hash_persists(self, db):
        ch = _make_channel("ch1", "general")
        ch["node_identity_hash"] = "abcdef1234567890" * 2
        db.store_channels([ch])
        channels = db.get_channels()
        assert channels[0]["node_identity_hash"] == "abcdef1234567890" * 2

    def test_node_identity_hash_nullable(self, db):
        """Channels stored without node_identity_hash get NULL — no crash."""
        db.store_channels([_make_channel("ch1", "general")])
        channels = db.get_channels()
        assert channels[0]["node_identity_hash"] is None

    def test_migration_v6_to_v7_adds_column(self, tmp_path):
        """Simulate a pre-v7 DB and verify the migration adds the column."""
        db_path = tmp_path / "old.db"
        raw = sqlite3.connect(str(db_path))
        raw.executescript(
            """
            CREATE TABLE channels (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT DEFAULT '',
                access_mode TEXT DEFAULT 'public',
                category_id TEXT,
                position INTEGER DEFAULT 0,
                identity_hash TEXT,
                latest_seq INTEGER DEFAULT 0,
                sealed INTEGER DEFAULT 0
            );
            CREATE TABLE schema_version (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                version INTEGER NOT NULL
            );
            INSERT INTO channels (id, name) VALUES ('legacy', 'old-channel');
            INSERT INTO schema_version (id, version) VALUES (1, 6);
            """
        )
        raw.commit()
        raw.close()

        # Opening via ClientDB triggers migrations
        upgraded = ClientDB(db_path, encrypt=False)
        try:
            cols = {
                row[1] for row in upgraded.conn.execute("PRAGMA table_info(channels)").fetchall()
            }
            assert "node_identity_hash" in cols
            assert upgraded._get_schema_version() == ClientDB._SCHEMA_VERSION
            # Pre-existing rows preserved with NULL for the new column
            rows = upgraded.get_channels()
            assert len(rows) == 1
            assert rows[0]["id"] == "legacy"
            assert rows[0]["node_identity_hash"] is None
        finally:
            upgraded.close()


# ---------------------------------------------------------------------------
# Cursors
# ---------------------------------------------------------------------------


class TestCursors:
    def test_set_and_get_cursor_round_trip(self, db):
        db.set_cursor("chan-a", 42)
        assert db.get_cursor("chan-a") == 42

    def test_get_cursor_unknown_channel_returns_zero(self, db):
        assert db.get_cursor("unknown-channel") == 0

    def test_set_cursor_update_overwrites_previous(self, db):
        db.set_cursor("chan-a", 10)
        db.set_cursor("chan-a", 99)
        assert db.get_cursor("chan-a") == 99

    def test_cursors_isolated_by_channel(self, db):
        db.set_cursor("chan-a", 5)
        db.set_cursor("chan-b", 20)
        assert db.get_cursor("chan-a") == 5
        assert db.get_cursor("chan-b") == 20


# ---------------------------------------------------------------------------
# Identities
# ---------------------------------------------------------------------------


class TestIdentities:
    def test_upsert_and_get_identity(self, db):
        db.upsert_identity("idhash1", display_name="Alice")
        result = db.get_identity("idhash1")
        assert result is not None
        assert result["hash"] == "idhash1"
        assert result["display_name"] == "Alice"

    def test_get_identity_unknown_returns_none(self, db):
        assert db.get_identity("nobody") is None

    def test_upsert_updates_display_name(self, db):
        db.upsert_identity("idhash1", display_name="Alice")
        db.upsert_identity("idhash1", display_name="Alice Smith")
        result = db.get_identity("idhash1")
        assert result["display_name"] == "Alice Smith"

    def test_upsert_identity_without_display_name(self, db):
        db.upsert_identity("idhash2")
        result = db.get_identity("idhash2")
        assert result is not None
        assert result["display_name"] is None


# ---------------------------------------------------------------------------
# Bookmarks
# ---------------------------------------------------------------------------


class TestBookmarks:
    def test_save_and_get_bookmark_round_trip(self, db):
        db.save_bookmark("home-node", "dest123abc", node_name="HomeNode")
        bm = db.get_bookmark("home-node")
        assert bm is not None
        assert bm["name"] == "home-node"
        assert bm["destination_hash"] == "dest123abc"
        assert bm["node_name"] == "HomeNode"

    def test_get_bookmark_unknown_returns_none(self, db):
        assert db.get_bookmark("nonexistent") is None

    def test_get_bookmarks_returns_all(self, db):
        db.save_bookmark("node-a", "destA")
        db.save_bookmark("node-b", "destB")
        bms = db.get_bookmarks()
        assert len(bms) == 2
        names = {b["name"] for b in bms}
        assert names == {"node-a", "node-b"}

    def test_get_bookmarks_empty_returns_empty_list(self, db):
        assert db.get_bookmarks() == []

    def test_get_bookmarks_ordered_by_last_connected_desc(self, db):
        db.save_bookmark("older", "dest1")
        time.sleep(0.05)
        db.save_bookmark("newer", "dest2")
        bms = db.get_bookmarks()
        assert bms[0]["name"] == "newer"
        assert bms[1]["name"] == "older"

    def test_delete_bookmark_removes_it(self, db):
        db.save_bookmark("to-delete", "destX")
        result = db.delete_bookmark("to-delete")
        assert result is True
        assert db.get_bookmark("to-delete") is None

    def test_delete_bookmark_unknown_returns_false(self, db):
        result = db.delete_bookmark("ghost")
        assert result is False

    def test_save_bookmark_without_node_name(self, db):
        db.save_bookmark("bare", "destBare")
        bm = db.get_bookmark("bare")
        assert bm is not None
        assert bm["node_name"] is None


# ---------------------------------------------------------------------------
# Schema / Migrations
# ---------------------------------------------------------------------------


class TestSchema:
    def test_fresh_db_gets_current_schema_version(self, db):
        from hokora_tui.client_db import ClientDB

        assert db._get_schema_version() == ClientDB._SCHEMA_VERSION

    def test_v1_to_v2_migration_adds_sealed_column_and_bookmarks(self, tmp_path):
        db_path = tmp_path / "v1.db"

        # Build a v1 schema manually (no sealed column, no bookmarks table)
        conn = sqlite3.connect(str(db_path))
        conn.executescript("""
            CREATE TABLE messages (
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
                verified INTEGER DEFAULT 0
            );
            CREATE TABLE identities (
                hash TEXT PRIMARY KEY,
                display_name TEXT,
                last_seen REAL
            );
            CREATE TABLE sync_cursors (
                channel_id TEXT PRIMARY KEY,
                last_seq INTEGER DEFAULT 0,
                last_sync REAL
            );
            CREATE TABLE channels (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT DEFAULT '',
                access_mode TEXT DEFAULT 'public',
                category_id TEXT,
                position INTEGER DEFAULT 0,
                identity_hash TEXT,
                latest_seq INTEGER DEFAULT 0
            );
            CREATE TABLE schema_version (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                version INTEGER NOT NULL
            );
            INSERT INTO schema_version (id, version) VALUES (1, 1);
        """)
        conn.commit()
        conn.close()

        # Open the DB via ClientDB — should trigger v1→v2 migration
        migrated = ClientDB(db_path, encrypt=False)
        try:
            # Schema version should have climbed to the current version
            assert migrated._get_schema_version() == ClientDB._SCHEMA_VERSION

            # 'sealed' column must exist in channels
            cols = {
                row[1] for row in migrated.conn.execute("PRAGMA table_info(channels)").fetchall()
            }
            assert "sealed" in cols

            # bookmarks table must exist and be functional
            migrated.save_bookmark("test-bm", "destABC")
            bm = migrated.get_bookmark("test-bm")
            assert bm is not None
            assert bm["destination_hash"] == "destABC"
        finally:
            migrated.close()
