# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for TUI bookmarks."""

import tempfile
from pathlib import Path

import pytest

from hokora_tui.client_db import ClientDB


class TestBookmarks:
    @pytest.fixture
    def client_db(self):
        tmp = tempfile.mkdtemp()
        db = ClientDB(Path(tmp) / "client.db", encrypt=False)
        yield db
        db.close()

    def test_bookmark_save_and_load(self, client_db):
        client_db.save_bookmark("mynode", "abcdef1234567890" * 2)
        bookmark = client_db.get_bookmark("mynode")
        assert bookmark is not None
        assert bookmark["name"] == "mynode"
        assert bookmark["destination_hash"] == "abcdef1234567890" * 2

    def test_bookmark_connect_by_name(self, client_db):
        """Bookmarks can be looked up by name for /connect."""
        client_db.save_bookmark("testnode", "0123456789abcdef" * 2)

        bookmark = client_db.get_bookmark("testnode")
        assert bookmark is not None
        # Simulate /connect testnode by looking up dest hash
        dest_hash = bookmark["destination_hash"]
        assert dest_hash == "0123456789abcdef" * 2

    def test_bookmark_list(self, client_db):
        client_db.save_bookmark("node1", "a" * 32)
        client_db.save_bookmark("node2", "b" * 32)
        bookmarks = client_db.get_bookmarks()
        assert len(bookmarks) == 2

    def test_bookmark_delete(self, client_db):
        client_db.save_bookmark("temp", "c" * 32)
        assert client_db.delete_bookmark("temp") is True
        assert client_db.get_bookmark("temp") is None

    def test_bookmark_update(self, client_db):
        client_db.save_bookmark("node", "a" * 32)
        client_db.save_bookmark("node", "b" * 32)
        bookmark = client_db.get_bookmark("node")
        assert bookmark["destination_hash"] == "b" * 32

    def test_bookmark_nonexistent(self, client_db):
        assert client_db.get_bookmark("nope") is None
        assert client_db.delete_bookmark("nope") is False
