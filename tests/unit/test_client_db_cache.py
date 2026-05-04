# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""TUI client-side SQLite cache tests: channels, messages, cursors, identities."""

import time

import pytest


class TestClientDB:
    """Test the TUI client-side SQLite cache."""

    @pytest.fixture(autouse=True)
    def _setup(self, tmp_dir):
        from hokora_tui.client_db import ClientDB

        self.db = ClientDB(tmp_dir / "client.db", encrypt=False)
        yield
        self.db.close()

    def test_init_creates_tables(self):
        tables = self.db.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        names = {row["name"] for row in tables}
        assert "messages" in names
        assert "identities" in names
        assert "sync_cursors" in names
        assert "channels" in names

    def test_store_and_get_channels_roundtrip(self):
        channels = [
            {
                "id": "ch1",
                "name": "general",
                "description": "Main channel",
                "access_mode": "public",
                "position": 0,
                "latest_seq": 5,
            },
            {
                "id": "ch2",
                "name": "random",
                "description": "",
                "access_mode": "private",
                "position": 1,
                "latest_seq": 0,
            },
        ]
        self.db.store_channels(channels)
        result = self.db.get_channels()
        assert len(result) == 2
        assert result[0]["id"] == "ch1"
        assert result[0]["name"] == "general"
        assert result[1]["id"] == "ch2"

    def test_get_cursor_unknown_returns_zero(self):
        assert self.db.get_cursor("unknown_channel") == 0

    def test_set_and_get_cursor_roundtrip(self):
        self.db.set_cursor("ch1", 42)
        assert self.db.get_cursor("ch1") == 42

    def test_set_cursor_updates_existing(self):
        self.db.set_cursor("ch1", 10)
        self.db.set_cursor("ch1", 25)
        assert self.db.get_cursor("ch1") == 25

    def test_store_and_get_messages(self):
        now = time.time()
        messages = [
            {
                "msg_hash": "h1",
                "channel_id": "ch1",
                "sender_hash": "u1",
                "seq": 1,
                "timestamp": now,
                "type": 1,
                "body": "Hello",
            },
            {
                "msg_hash": "h2",
                "channel_id": "ch1",
                "sender_hash": "u2",
                "seq": 2,
                "timestamp": now + 1,
                "type": 1,
                "body": "World",
            },
            {
                "msg_hash": "h3",
                "channel_id": "ch1",
                "sender_hash": "u1",
                "seq": 3,
                "timestamp": now + 2,
                "type": 1,
                "body": "Third",
            },
        ]
        self.db.store_messages(messages)
        result = self.db.get_messages("ch1")
        assert len(result) == 3
        assert result[0]["body"] == "Hello"
        assert result[2]["body"] == "Third"

    def test_get_messages_before_seq(self):
        now = time.time()
        messages = [
            {
                "msg_hash": f"m{i}",
                "channel_id": "ch1",
                "sender_hash": "u1",
                "seq": i,
                "timestamp": now + i,
                "type": 1,
                "body": f"msg{i}",
            }
            for i in range(1, 6)
        ]
        self.db.store_messages(messages)
        result = self.db.get_messages("ch1", limit=10, before_seq=3)
        # before_seq=3 -> seq < 3 -> seq 1, 2
        assert len(result) == 2
        assert all(r["seq"] < 3 for r in result)

    def test_upsert_and_get_identity(self):
        self.db.upsert_identity("user_hash_1", display_name="Alice")
        ident = self.db.get_identity("user_hash_1")
        assert ident is not None
        assert ident["display_name"] == "Alice"

    def test_get_identity_unknown_returns_none(self):
        assert self.db.get_identity("nonexistent") is None

    def test_upsert_identity_updates_existing(self):
        self.db.upsert_identity("user1", display_name="Name1")
        self.db.upsert_identity("user1", display_name="Name2")
        ident = self.db.get_identity("user1")
        assert ident["display_name"] == "Name2"

    def test_close_works_without_error(self):
        from hokora_tui.client_db import ClientDB

        db2 = ClientDB(self.db.db_path.parent / "close_test.db", encrypt=False)
        db2.close()
        # No exception means success
