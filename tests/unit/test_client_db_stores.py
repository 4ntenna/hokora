# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Per-store unit tests for the ``client_db`` package.

Each store exercises its public API against a real SQLite file. The
existing ``test_client_db.py`` + ``test_client_db_cache.py`` act as
facade-integration coverage; these tests exercise the stores directly
so a regression in a single store isolates cleanly.

The ``ClientDB`` facade builds the SQLite connection, write lock, and
schema ladder. Tests grab its ``.conn`` / ``._write_lock`` and the
already-constructed sub-stores rather than reinstantiating.
"""

from __future__ import annotations

import time

import pytest

from hokora_tui.client_db import ClientDB
from hokora_tui.client_db._schema import SCHEMA_VERSION, SchemaMigrator


@pytest.fixture
def db(tmp_path):
    """Fresh ClientDB backed by a temp SQLite file."""
    client = ClientDB(tmp_path / "test.db", encrypt=False)
    yield client
    client.close()


# ─────────────────────────────────────────────────────────────────
# MessageStore
# ─────────────────────────────────────────────────────────────────


class TestMessageStore:
    def test_store_and_get_basic(self, db):
        db.messages.store(
            [
                {
                    "msg_hash": "a" * 64,
                    "channel_id": "ch1",
                    "sender_hash": "s" * 64,
                    "seq": 1,
                    "timestamp": 100.0,
                    "type": 1,
                    "body": "hello",
                }
            ]
        )
        got = db.messages.get("ch1")
        assert len(got) == 1
        assert got[0]["body"] == "hello"

    def test_get_empty_channel(self, db):
        assert db.messages.get("nope") == []

    def test_store_idempotent_by_hash(self, db):
        """INSERT OR REPLACE — same msg_hash updates, doesn't duplicate."""
        row = {
            "msg_hash": "a" * 64,
            "channel_id": "ch1",
            "sender_hash": "s" * 64,
            "seq": 1,
            "timestamp": 100.0,
            "type": 1,
            "body": "v1",
        }
        db.messages.store([row])
        row["body"] = "v2"
        db.messages.store([row])
        got = db.messages.get("ch1")
        assert len(got) == 1
        assert got[0]["body"] == "v2"

    def test_get_returns_ascending_by_seq(self, db):
        db.messages.store(
            [
                {
                    "msg_hash": f"{i:064d}",
                    "channel_id": "ch1",
                    "seq": i,
                    "timestamp": 100.0 + i,
                    "type": 1,
                    "body": f"m{i}",
                }
                for i in (3, 1, 2)
            ]
        )
        got = db.messages.get("ch1")
        assert [m["seq"] for m in got] == [1, 2, 3]

    def test_get_before_seq_limits(self, db):
        db.messages.store(
            [
                {
                    "msg_hash": f"{i:064d}",
                    "channel_id": "ch1",
                    "seq": i,
                    "timestamp": 100.0 + i,
                    "type": 1,
                    "body": f"m{i}",
                }
                for i in range(1, 6)
            ]
        )
        got = db.messages.get("ch1", limit=2, before_seq=4)
        # seqs <4, newest-first is (3,2) reversed → (2,3)
        assert [m["seq"] for m in got] == [2, 3]

    def test_verified_default_false_when_field_absent(self, db):
        """``verify_message_signature`` is the single chokepoint that fills
        ``verified`` on both live and history paths. An absent field at
        storage time means no cryptographic check happened — store False so
        ``[UNVERIFIED]`` renders honestly.
        """
        db.messages.store(
            [
                {
                    "msg_hash": "a" * 64,
                    "channel_id": "ch1",
                    "sender_hash": "s" * 64,
                    "seq": 1,
                    "timestamp": 100.0,
                    "type": 1,
                    "body": "row with no verified field — expect 0",
                }
            ]
        )
        got = db.messages.get("ch1")
        assert got[0]["verified"] == 0

    def test_verified_explicit_false_persists(self, db):
        """History-sync sets ``verified`` explicitly after running an
        Ed25519 check; an explicit False must round to 0, not get masked
        by the default-True for missing-field."""
        db.messages.store(
            [
                {
                    "msg_hash": "b" * 64,
                    "channel_id": "ch1",
                    "sender_hash": "s" * 64,
                    "seq": 2,
                    "timestamp": 101.0,
                    "type": 1,
                    "body": "history-sync row, verification failed",
                    "verified": False,
                }
            ]
        )
        got = db.messages.get("ch1")
        assert got[0]["verified"] == 0

    def test_verified_explicit_true_persists(self, db):
        db.messages.store(
            [
                {
                    "msg_hash": "c" * 64,
                    "channel_id": "ch1",
                    "sender_hash": "s" * 64,
                    "seq": 3,
                    "timestamp": 102.0,
                    "type": 1,
                    "body": "history-sync row, verified ok",
                    "verified": True,
                }
            ]
        )
        got = db.messages.get("ch1")
        assert got[0]["verified"] == 1

    def test_delete_channel_clears_only_that_channel(self, db):
        db.messages.store(
            [
                {"msg_hash": "a" * 64, "channel_id": "ch1", "seq": 1, "timestamp": 1, "type": 1},
                {"msg_hash": "b" * 64, "channel_id": "ch2", "seq": 1, "timestamp": 1, "type": 1},
            ]
        )
        db.messages.delete_channel("ch1")
        assert db.messages.get("ch1") == []
        assert len(db.messages.get("ch2")) == 1

    def test_reactions_roundtrip_dict_in_dict_out(self, db):
        """In-memory contract: reactions go in as a dict, come back as a dict.

        On-disk shape is JSON text (storage detail), but ``MessageStore.get``
        deserialises so callers never have to handle the JSON-string form.
        Symmetric round-trip prevents the doubly-encoded bug where a
        cached message's stringified reactions get re-wrapped by
        ``json.dumps`` on a subsequent re-store.
        """
        db.messages.store(
            [
                {
                    "msg_hash": "a" * 64,
                    "channel_id": "ch1",
                    "seq": 1,
                    "timestamp": 1,
                    "type": 1,
                    "reactions": {":+1:": ["alice"]},
                }
            ]
        )
        got = db.messages.get("ch1")
        assert got[0]["reactions"] == {":+1:": ["alice"]}
        assert isinstance(got[0]["reactions"], dict)

    def test_reactions_empty_dict_roundtrip_does_not_double_encode(self, db):
        """Regression for the General-channel seq=6 crash: store an empty
        reactions dict, load it from cache, mutate (e.g. has_thread=True),
        store again. The reactions value must remain a dict — never round-
        trip to ``'"{}"'`` (doubly-encoded) which would crash
        ``MessageWidget._build_markup`` with AttributeError.
        """
        original = {
            "msg_hash": "a" * 64,
            "channel_id": "ch1",
            "seq": 1,
            "timestamp": 1,
            "type": 1,
            "reactions": {},
        }
        db.messages.store([original])

        # Simulate the cache → mutate → re-store cycle that
        # handle_thread_reply_push exercises.
        cached = db.messages.get("ch1")[0]
        cached["has_thread"] = True
        db.messages.store([cached])

        # Re-read after the cycle; reactions stays a clean dict.
        final = db.messages.get("ch1")[0]
        assert final["reactions"] == {}
        assert isinstance(final["reactions"], dict)
        assert final["has_thread"] == 1

    def test_reactions_get_heals_existing_doubly_encoded_row(self, db):
        """Defensive read path: a row already corrupted on disk (the
        seq=6 case) reads back as ``{}`` instead of crashing — the
        deserialiser unwraps repeatedly until it reaches a dict, or
        gives up safely.
        """
        # Seed a row directly with the doubly-encoded shape, bypassing
        # the storage chokepoint to mimic the pre-fix on-disk state.
        db.conn.execute(
            "INSERT INTO messages (msg_hash, channel_id, sender_hash, seq, "
            "timestamp, type, body, reactions) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("d" * 64, "ch1", "s" * 64, 1, 1.0, 1, "yo", '"{}"'),
        )
        db.conn.commit()

        got = db.messages.get("ch1")
        assert len(got) == 1
        assert got[0]["reactions"] == {}
        assert isinstance(got[0]["reactions"], dict)

    def test_reactions_store_accepts_already_serialised_string(self, db):
        """Defensive write path: an unaudited caller that hands in a
        JSON string (instead of a dict) for ``reactions`` must not
        get its value re-wrapped to a doubly-encoded form. The
        serialiser detects already-valid JSON and passes through.
        """
        db.messages.store(
            [
                {
                    "msg_hash": "a" * 64,
                    "channel_id": "ch1",
                    "seq": 1,
                    "timestamp": 1,
                    "type": 1,
                    "reactions": '{":heart:": ["bob"]}',
                }
            ]
        )
        got = db.messages.get("ch1")
        assert got[0]["reactions"] == {":heart:": ["bob"]}

    def test_reactions_store_malformed_string_falls_back_to_empty(self, db):
        """Defensive write path: garbage JSON input doesn't poison the
        column. Stored as ``{}`` rather than crashing or persisting
        unparseable data.
        """
        db.messages.store(
            [
                {
                    "msg_hash": "a" * 64,
                    "channel_id": "ch1",
                    "seq": 1,
                    "timestamp": 1,
                    "type": 1,
                    "reactions": "not-json",
                }
            ]
        )
        got = db.messages.get("ch1")
        assert got[0]["reactions"] == {}

    def test_reactions_store_non_dict_non_string_falls_back_to_empty(self, db):
        """Defensive write path: list/None/int inputs get coerced to ``{}``."""
        for bad_value in ([1, 2, 3], None, 42, True):
            db.messages.store(
                [
                    {
                        "msg_hash": "a" * 64,
                        "channel_id": "ch1",
                        "seq": 1,
                        "timestamp": 1,
                        "type": 1,
                        "reactions": bad_value,
                    }
                ]
            )
            got = db.messages.get("ch1")
            assert got[0]["reactions"] == {}


# ─────────────────────────────────────────────────────────────────
# CursorStore
# ─────────────────────────────────────────────────────────────────


class TestCursorStore:
    def test_get_missing_returns_zero(self, db):
        assert db.cursors.get("nope") == 0

    def test_set_then_get(self, db):
        db.cursors.set("ch1", 42)
        assert db.cursors.get("ch1") == 42

    def test_set_overwrites(self, db):
        db.cursors.set("ch1", 1)
        db.cursors.set("ch1", 99)
        assert db.cursors.get("ch1") == 99

    def test_get_all_returns_dict(self, db):
        db.cursors.set("ch1", 1)
        db.cursors.set("ch2", 5)
        assert db.cursors.get_all() == {"ch1": 1, "ch2": 5}

    def test_get_all_empty(self, db):
        assert db.cursors.get_all() == {}


# ─────────────────────────────────────────────────────────────────
# ChannelStore (channels + unread_counts)
# ─────────────────────────────────────────────────────────────────


class TestChannelStore:
    def test_store_and_get_all(self, db):
        db.channels.store([{"id": "ch1", "name": "general", "position": 0}])
        all_ = db.channels.get_all()
        assert len(all_) == 1
        assert all_[0]["name"] == "general"

    def test_get_all_ordered_by_position(self, db):
        db.channels.store(
            [
                {"id": "b", "name": "B", "position": 2},
                {"id": "a", "name": "A", "position": 1},
            ]
        )
        names = [c["name"] for c in db.channels.get_all()]
        assert names == ["A", "B"]

    def test_sealed_flag_roundtrips(self, db):
        db.channels.store([{"id": "s", "name": "sealed", "sealed": True}])
        got = db.channels.get_all()
        assert got[0]["sealed"] == 1

    def test_node_identity_hash_stored(self, db):
        db.channels.store([{"id": "ch1", "name": "A", "node_identity_hash": "nodehash123"}])
        assert db.channels.get_all()[0]["node_identity_hash"] == "nodehash123"

    def test_unread_default_zero(self, db):
        assert db.channels.get_unread("ch1") == 0

    def test_set_and_get_unread(self, db):
        db.channels.set_unread("ch1", 5)
        assert db.channels.get_unread("ch1") == 5

    def test_increment_unread_from_zero(self, db):
        db.channels.increment_unread("ch1")
        db.channels.increment_unread("ch1")
        assert db.channels.get_unread("ch1") == 2

    def test_reset_unread(self, db):
        db.channels.set_unread("ch1", 10)
        db.channels.reset_unread("ch1")
        assert db.channels.get_unread("ch1") == 0


# ─────────────────────────────────────────────────────────────────
# IdentityStore
# ─────────────────────────────────────────────────────────────────


class TestIdentityStore:
    def test_upsert_new(self, db):
        db.identities.upsert("a" * 64, display_name="alice")
        got = db.identities.get("a" * 64)
        assert got["display_name"] == "alice"

    def test_upsert_updates_existing(self, db):
        db.identities.upsert("a" * 64, display_name="alice")
        db.identities.upsert("a" * 64, display_name="alice-v2")
        got = db.identities.get("a" * 64)
        assert got["display_name"] == "alice-v2"

    def test_get_missing(self, db):
        assert db.identities.get("b" * 64) is None

    def test_upsert_with_no_name(self, db):
        db.identities.upsert("a" * 64)
        got = db.identities.get("a" * 64)
        assert got["display_name"] is None
        assert got["last_seen"] is not None


# ─────────────────────────────────────────────────────────────────
# BookmarkStore
# ─────────────────────────────────────────────────────────────────


class TestBookmarkStore:
    def test_save_and_get(self, db):
        db.bookmarks_store.save("seed", "deadbeef", node_name="VPS Seed")
        got = db.bookmarks_store.get("seed")
        assert got["destination_hash"] == "deadbeef"
        assert got["node_name"] == "VPS Seed"

    def test_get_all_ordered_by_last_connected_desc(self, db):
        db.bookmarks_store.save("old", "h1")
        time.sleep(0.01)
        db.bookmarks_store.save("new", "h2")
        names = [b["name"] for b in db.bookmarks_store.get_all()]
        assert names == ["new", "old"]

    def test_delete_existing_returns_true(self, db):
        db.bookmarks_store.save("k", "h")
        assert db.bookmarks_store.delete("k") is True
        assert db.bookmarks_store.get("k") is None

    def test_delete_missing_returns_false(self, db):
        assert db.bookmarks_store.delete("nope") is False

    def test_save_overwrites_by_name(self, db):
        db.bookmarks_store.save("k", "h1")
        db.bookmarks_store.save("k", "h2")
        got = db.bookmarks_store.get("k")
        assert got["destination_hash"] == "h2"


# ─────────────────────────────────────────────────────────────────
# SettingsStore
# ─────────────────────────────────────────────────────────────────


class TestSettingsStore:
    def test_get_default_when_missing(self, db):
        assert db.settings.get("nope", default="fallback") == "fallback"

    def test_get_returns_none_without_default(self, db):
        assert db.settings.get("nope") is None

    def test_set_and_get(self, db):
        db.settings.set("display_name", "alice")
        assert db.settings.get("display_name") == "alice"

    def test_set_overwrites(self, db):
        db.settings.set("k", "v1")
        db.settings.set("k", "v2")
        assert db.settings.get("k") == "v2"


# ─────────────────────────────────────────────────────────────────
# DiscoveryStore
# ─────────────────────────────────────────────────────────────────


class TestDiscoveryStore:
    def test_store_node_inserts(self, db):
        db.discovery.store_node("h1", "Node-A", 3, 100.0, "[]")
        nodes = db.discovery.get_nodes()
        assert len(nodes) == 1
        assert nodes[0]["node_name"] == "Node-A"

    def test_store_node_updates_on_conflict(self, db):
        db.discovery.store_node("h1", "Old", 1, 100.0, "[]")
        db.discovery.store_node("h1", "New", 5, 200.0, '["ch"]')
        nodes = db.discovery.get_nodes()
        assert len(nodes) == 1
        assert nodes[0]["node_name"] == "New"
        assert nodes[0]["channel_count"] == 5

    def test_store_node_preserves_channel_dests_when_empty(self, db):
        """channel_dests_json='' must not overwrite a prior non-empty value."""
        db.discovery.store_node("h1", "N", 1, 1.0, "[]", channel_dests_json='{"ch":"dest"}')
        db.discovery.store_node("h1", "N", 1, 2.0, "[]", channel_dests_json="")
        nodes = db.discovery.get_nodes()
        assert nodes[0]["channel_dests_json"] == '{"ch":"dest"}'

    def test_get_nodes_ordered_by_last_seen_desc(self, db):
        db.discovery.store_node("a", "A", 1, 100.0, "[]")
        db.discovery.store_node("b", "B", 1, 200.0, "[]")
        names = [n["node_name"] for n in db.discovery.get_nodes()]
        assert names == ["B", "A"]

    def test_toggle_node_bookmark_missing_returns_false(self, db):
        assert db.discovery.toggle_node_bookmark("nope") is False

    def test_toggle_node_bookmark_flips(self, db):
        db.discovery.store_node("h1", "N", 1, 1.0, "[]")
        assert db.discovery.toggle_node_bookmark("h1") is True
        assert db.discovery.toggle_node_bookmark("h1") is False

    def test_store_peer_inserts(self, db):
        db.discovery.store_peer("p1", "alice", "online", 100.0)
        assert len(db.discovery.get_peers()) == 1

    def test_store_peer_updates_on_conflict(self, db):
        db.discovery.store_peer("p1", "alice", None, 100.0)
        db.discovery.store_peer("p1", "alice-v2", "away", 200.0)
        peers = db.discovery.get_peers()
        assert peers[0]["display_name"] == "alice-v2"
        assert peers[0]["status_text"] == "away"

    def test_toggle_peer_bookmark_flips(self, db):
        db.discovery.store_peer("p1", "x", None, 1.0)
        assert db.discovery.toggle_peer_bookmark("p1") is True
        assert db.discovery.toggle_peer_bookmark("p1") is False


# ─────────────────────────────────────────────────────────────────
# DmStore
# ─────────────────────────────────────────────────────────────────


class TestDmStore:
    def test_store_and_get_basic(self, db):
        db.dms.store("alice", "bob", 100.0, "hi")
        got = db.dms.get("bob")
        assert len(got) == 1
        assert got[0]["body"] == "hi"

    def test_get_returns_newest_first(self, db):
        db.dms.store("a", "b", 1.0, "old")
        db.dms.store("a", "b", 2.0, "new")
        got = db.dms.get("b")
        assert [r["body"] for r in got] == ["new", "old"]

    def test_get_before_time_filters(self, db):
        db.dms.store("a", "b", 1.0, "old")
        db.dms.store("a", "b", 5.0, "new")
        got = db.dms.get("b", before_time=3.0)
        assert len(got) == 1
        assert got[0]["body"] == "old"

    def test_get_matches_either_side(self, db):
        """peer_hash matches as sender OR receiver."""
        db.dms.store("me", "peer", 1.0, "out")
        db.dms.store("peer", "me", 2.0, "in")
        assert len(db.dms.get("peer")) == 2

    def test_update_conversation_inserts(self, db):
        db.dms.update_conversation("peer", "Peer Name", 100.0)
        convs = db.dms.get_conversations()
        assert len(convs) == 1
        assert convs[0]["peer_name"] == "Peer Name"

    def test_update_conversation_updates_existing_without_clobbering_unread(self, db):
        db.dms.update_conversation("peer", "N", 100.0)
        db.dms.increment_unread("peer")
        db.dms.increment_unread("peer")
        db.dms.update_conversation("peer", "N", 200.0)
        convs = db.dms.get_conversations()
        assert convs[0]["last_message_time"] == 200.0
        assert convs[0]["unread_count"] == 2

    def test_mark_conversation_read_clears_unread(self, db):
        db.dms.update_conversation("peer", "N", 100.0)
        db.dms.store("peer", "me", 100.0, "x")
        db.dms.increment_unread("peer")
        db.dms.mark_conversation_read("peer")
        assert db.dms.get_conversations()[0]["unread_count"] == 0
        # Also flips direct_messages.read
        dms = db.dms.get("peer")
        assert all(m["read"] == 1 for m in dms)

    def test_increment_unread_noop_when_conversation_absent(self, db):
        """UPDATE ... WHERE peer_hash=? touches zero rows if none exist."""
        db.dms.increment_unread("nonexistent")
        assert db.dms.get_conversations() == []

    def test_get_conversations_ordered_by_last_message_time_desc(self, db):
        db.dms.update_conversation("a", "A", 100.0)
        db.dms.update_conversation("b", "B", 200.0)
        order = [c["peer_name"] for c in db.dms.get_conversations()]
        assert order == ["B", "A"]


# ─────────────────────────────────────────────────────────────────
# SchemaMigrator
# ─────────────────────────────────────────────────────────────────


class TestSchemaMigrator:
    def test_fresh_db_reaches_head(self, db):
        assert db._get_schema_version() == SCHEMA_VERSION

    def test_re_running_migrator_is_idempotent(self, db):
        SchemaMigrator(db.conn, db._write_lock).init_and_migrate()
        assert db._get_schema_version() == SCHEMA_VERSION


# ─────────────────────────────────────────────────────────────────
# Shared connection / lock invariants
# ─────────────────────────────────────────────────────────────────


class TestSharedResources:
    def test_all_stores_share_same_connection(self, db):
        """Store boundaries are logical; they must not open separate
        SQLite connections — that would break the WAL write guarantee."""
        conn = db.conn
        assert db.messages._conn is conn
        assert db.cursors._conn is conn
        assert db.channels._conn is conn
        assert db.identities._conn is conn
        assert db.bookmarks_store._conn is conn
        assert db.settings._conn is conn
        assert db.discovery._conn is conn
        assert db.dms._conn is conn

    def test_all_stores_share_same_write_lock(self, db):
        lock = db._write_lock
        assert db.messages._lock is lock
        assert db.cursors._lock is lock
        assert db.channels._lock is lock
        assert db.identities._lock is lock
        assert db.bookmarks_store._lock is lock
        assert db.settings._lock is lock
        assert db.discovery._lock is lock
        assert db.dms._lock is lock


# ─────────────────────────────────────────────────────────────────
# Facade back-compat
# ─────────────────────────────────────────────────────────────────


class TestFacadeBackCompat:
    """Ensure every public method on the ``ClientDB`` facade keeps its
    documented signature. Call-site churn in hokora_tui/ is zero if and
    only if this stays green."""

    def test_messages_methods(self, db):
        assert callable(db.store_messages)
        assert callable(db.get_messages)
        assert callable(db.delete_channel_messages)

    def test_cursors_methods(self, db):
        assert callable(db.get_cursor)
        assert callable(db.get_all_cursors)
        assert callable(db.set_cursor)

    def test_channels_methods(self, db):
        assert callable(db.store_channels)
        assert callable(db.get_channels)
        assert callable(db.get_unread_count)
        assert callable(db.set_unread_count)
        assert callable(db.increment_channel_unread)
        assert callable(db.reset_channel_unread)

    def test_identity_methods(self, db):
        assert callable(db.upsert_identity)
        assert callable(db.get_identity)

    def test_bookmark_methods(self, db):
        assert callable(db.save_bookmark)
        assert callable(db.get_bookmark)
        assert callable(db.get_bookmarks)
        assert callable(db.delete_bookmark)

    def test_settings_methods(self, db):
        assert callable(db.get_setting)
        assert callable(db.set_setting)

    def test_discovery_methods(self, db):
        assert callable(db.store_discovered_node)
        assert callable(db.get_discovered_nodes)
        assert callable(db.toggle_node_bookmark)
        assert callable(db.store_discovered_peer)
        assert callable(db.get_discovered_peers)
        assert callable(db.toggle_peer_bookmark)

    def test_dm_methods(self, db):
        assert callable(db.store_dm)
        assert callable(db.get_dms)
        assert callable(db.get_conversations)
        assert callable(db.update_conversation)
        assert callable(db.mark_conversation_read)
        assert callable(db.increment_unread)

    def test_close_method(self, tmp_path):
        client = ClientDB(tmp_path / "close.db", encrypt=False)
        client.close()  # no raise


class TestTransactionContextManager:
    """``db.transaction()`` atomic multi-store writes."""

    def test_transaction_commits_all_stores_on_success(self, db):
        with db.transaction() as tx:
            tx.channels.store([{"id": "tx_c1", "name": "tx_channel"}])
            tx.cursors.set("tx_c1", 42)
            tx.messages.store(
                [
                    {
                        "msg_hash": "tx_msg_01",
                        "channel_id": "tx_c1",
                        "sender_hash": "s",
                        "seq": 1,
                        "timestamp": time.time(),
                        "type": 1,
                        "body": "atomic batch",
                    }
                ]
            )

        # All three writes visible after exit.
        assert db.get_cursor("tx_c1") == 42
        assert any(ch["id"] == "tx_c1" for ch in db.get_channels())
        msgs = db.get_messages("tx_c1")
        assert len(msgs) == 1
        assert msgs[0]["body"] == "atomic batch"

    def test_transaction_rolls_back_on_exception(self, db):
        # Seed one row so we can prove the failed tx didn't overwrite it.
        db.set_cursor("roll_ch", 10)

        class _Boom(RuntimeError):
            pass

        with pytest.raises(_Boom):
            with db.transaction() as tx:
                tx.cursors.set("roll_ch", 999)
                # Write visible to this connection during the tx.
                assert tx.get_cursor("roll_ch") == 999
                raise _Boom("simulate mid-tx failure")

        # After rollback, the original value is restored.
        assert db.get_cursor("roll_ch") == 10

    def test_transaction_flag_reset_after_exit(self, db):
        assert db._tx_state.active is False
        with db.transaction():
            assert db._tx_state.active is True
        assert db._tx_state.active is False

    def test_transaction_flag_reset_after_exception(self, db):
        assert db._tx_state.active is False
        try:
            with db.transaction():
                assert db._tx_state.active is True
                raise ValueError("ka-boom")
        except ValueError:
            pass
        assert db._tx_state.active is False

    def test_transaction_rejects_reentrancy(self, db):
        with db.transaction():
            with pytest.raises(RuntimeError, match="not reentrant"):
                with db.transaction():
                    pass

    def test_transaction_batches_without_interior_commits(self, db):
        """Regression guard: inside a transaction, interior store methods
        must not issue their own ``conn.commit()`` — otherwise rollback
        would only revert the tail of the batch, not the whole thing."""
        # Seed baseline
        db.set_cursor("batch_ch", 1)

        class _StopMark(RuntimeError):
            pass

        try:
            with db.transaction() as tx:
                tx.cursors.set("batch_ch", 2)
                tx.cursors.set("batch_ch", 3)
                tx.cursors.set("batch_ch", 4)
                raise _StopMark("abort before commit")
        except _StopMark:
            pass

        # All three intermediate writes rolled back — cursor still at 1.
        assert db.get_cursor("batch_ch") == 1
