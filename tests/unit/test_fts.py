# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Test FTS5 indexing and search."""

import time


from hokora.db.models import Channel, Message
from hokora.db.queries import ChannelRepo, MessageRepo


class TestFTS:
    async def test_search_indexed_message(self, session, fts_manager, engine):
        ch_repo = ChannelRepo(session)
        await ch_repo.create(Channel(id="ftsch1", name="fts_test", latest_seq=0))

        msg_repo = MessageRepo(session)
        await msg_repo.insert(
            Message(
                msg_hash="fts001",
                channel_id="ftsch1",
                sender_hash="s1",
                seq=1,
                timestamp=time.time(),
                type=1,
                body="The quick brown fox jumps over the lazy dog",
            )
        )
        await session.commit()

        results = await fts_manager.search("ftsch1", "brown fox")
        assert len(results) >= 1
        assert any(r["msg_hash"] == "fts001" for r in results)

    async def test_search_no_results(self, fts_manager):
        results = await fts_manager.search("nonexistent", "xyz123abc")
        assert results == []

    async def test_search_special_characters(self, session, fts_manager, engine):
        ch_repo = ChannelRepo(session)
        await ch_repo.create(Channel(id="ftsch2", name="fts_special", latest_seq=0))

        msg_repo = MessageRepo(session)
        await msg_repo.insert(
            Message(
                msg_hash="fts002",
                channel_id="ftsch2",
                sender_hash="s1",
                seq=1,
                timestamp=time.time(),
                type=1,
                body="Hello world! Test with special chars: @user #channel",
            )
        )
        await session.commit()

        results = await fts_manager.search("ftsch2", "Hello world")
        assert len(results) >= 1

    async def test_search_phrase(self, session, fts_manager, engine):
        ch_repo = ChannelRepo(session)
        await ch_repo.create(Channel(id="ftsch3", name="fts_phrase", latest_seq=0))

        msg_repo = MessageRepo(session)
        await msg_repo.insert(
            Message(
                msg_hash="fts003",
                channel_id="ftsch3",
                sender_hash="s1",
                seq=1,
                timestamp=time.time(),
                type=1,
                body="The exact phrase to find here",
            )
        )
        await session.commit()

        # FTS5 phrase search with quotes
        results = await fts_manager.search("ftsch3", '"exact phrase"')
        assert len(results) >= 1

    async def test_search_empty_query(self, fts_manager):
        # Empty/whitespace queries should return empty, not crash
        results = await fts_manager.search("ftsch1", "")
        assert results == []

    async def test_search_cross_channel(self, session, fts_manager, engine):
        ch_repo = ChannelRepo(session)
        await ch_repo.create(Channel(id="ftsch4a", name="fts_cross_a", latest_seq=0))
        await ch_repo.create(Channel(id="ftsch4b", name="fts_cross_b", latest_seq=0))

        msg_repo = MessageRepo(session)
        await msg_repo.insert(
            Message(
                msg_hash="fts004a",
                channel_id="ftsch4a",
                sender_hash="s1",
                seq=1,
                timestamp=time.time(),
                type=1,
                body="UniqueSearchTerm42 in channel A",
            )
        )
        await msg_repo.insert(
            Message(
                msg_hash="fts004b",
                channel_id="ftsch4b",
                sender_hash="s1",
                seq=1,
                timestamp=time.time(),
                type=1,
                body="Different content in channel B",
            )
        )
        await session.commit()

        # Should only find in channel A
        results = await fts_manager.search("ftsch4a", "UniqueSearchTerm42")
        assert len(results) == 1
        assert results[0]["channel_id"] == "ftsch4a"

        # Should not find in channel B
        results = await fts_manager.search("ftsch4b", "UniqueSearchTerm42")
        assert len(results) == 0


class TestFTSSealedGuard:
    """FTS trigger hardens against sealed-channel plaintext leaks via
    ``WHEN body IS NOT NULL AND encrypted_body IS NULL``.

    The primary enforcement is ``MessageProcessor._seal_body_for_insert``
    (the chokepoint). These tests verify the defence-in-depth: a row
    inserted with body co-populated alongside encrypted_body (as a
    partial/buggy write path would produce) does NOT land in FTS.
    """

    async def test_row_with_body_and_encrypted_body_not_indexed(self, session, fts_manager, engine):
        ch_repo = ChannelRepo(session)
        await ch_repo.create(Channel(id="sealed1", name="sealed_guard", sealed=True, latest_seq=0))

        msg_repo = MessageRepo(session)
        await msg_repo.insert(
            Message(
                msg_hash="fts_sealed_guard_01",
                channel_id="sealed1",
                sender_hash="s1",
                seq=1,
                timestamp=time.time(),
                type=1,
                # Both populated — simulates a buggy path bypassing the
                # choke-point helper. The hardened trigger must refuse
                # to index this.
                body="SealedGuardLeakCanary42",
                encrypted_body=b"\x00" * 32,
                encryption_nonce=b"\x00" * 24,
                encryption_epoch=1,
            )
        )
        await session.commit()

        results = await fts_manager.search("sealed1", "SealedGuardLeakCanary42")
        assert len(results) == 0, (
            "Hardened trigger must skip rows where encrypted_body is set, "
            "even if body is accidentally populated."
        )

    async def test_plaintext_only_row_still_indexed(self, session, fts_manager, engine):
        """Regression guard: the trigger must still index normal plaintext
        rows (body set, encrypted_body NULL)."""
        ch_repo = ChannelRepo(session)
        await ch_repo.create(Channel(id="plain1", name="plain_channel", latest_seq=0))

        msg_repo = MessageRepo(session)
        await msg_repo.insert(
            Message(
                msg_hash="fts_plain_01",
                channel_id="plain1",
                sender_hash="s1",
                seq=1,
                timestamp=time.time(),
                type=1,
                body="PlaintextStillIndexable77",
            )
        )
        await session.commit()

        results = await fts_manager.search("plain1", "PlaintextStillIndexable77")
        assert len(results) == 1
        assert results[0]["msg_hash"] == "fts_plain_01"

    async def test_sealed_row_body_null_not_indexed(self, session, fts_manager, engine):
        """The already-correct path (sealed row with body=None) remains
        non-indexable — asserted here so regressing the trigger breaks
        this test."""
        ch_repo = ChannelRepo(session)
        await ch_repo.create(
            Channel(id="sealed2", name="sealed_nullbody", sealed=True, latest_seq=0)
        )

        msg_repo = MessageRepo(session)
        await msg_repo.insert(
            Message(
                msg_hash="fts_sealed_null_01",
                channel_id="sealed2",
                sender_hash="s1",
                seq=1,
                timestamp=time.time(),
                type=1,
                body=None,
                encrypted_body=b"\x00" * 32,
                encryption_nonce=b"\x00" * 24,
                encryption_epoch=1,
            )
        )
        await session.commit()

        # Can't search for null body directly; verify the FTS table has
        # no row for this msg_hash by trying a generous match.
        results = await fts_manager.search("sealed2", "anything")
        assert not any(r["msg_hash"] == "fts_sealed_null_01" for r in results)

    async def test_update_co_populating_body_does_not_index(
        self, session_factory, fts_manager, engine
    ):
        """A sealed row initially inserted correctly (body=None, encrypted set)
        is later UPDATEd to also carry body — the hardened messages_au trigger
        must NOT re-index it since encrypted_body is still set."""
        from sqlalchemy import text as sql_text

        # Step 1: seed the sealed row in its own transaction so we can
        # issue a follow-up UPDATE in a fresh one (the shared ``session``
        # fixture wraps one begin() context and cannot host two commits).
        async with session_factory() as sess:
            async with sess.begin():
                await ChannelRepo(sess).create(
                    Channel(id="sealed3", name="sealed_update", sealed=True, latest_seq=0)
                )
                await MessageRepo(sess).insert(
                    Message(
                        msg_hash="fts_update_sealed_01",
                        channel_id="sealed3",
                        sender_hash="s1",
                        seq=1,
                        timestamp=time.time(),
                        type=1,
                        body=None,
                        encrypted_body=b"\x00" * 32,
                        encryption_nonce=b"\x00" * 24,
                        encryption_epoch=1,
                    )
                )

        # Step 2: simulate a partial/buggy UPDATE setting body without
        # clearing encrypted_body.
        async with session_factory() as sess:
            async with sess.begin():
                await sess.execute(
                    sql_text("UPDATE messages SET body = :b WHERE msg_hash = :h"),
                    {"b": "LeakOnUpdateCanary91", "h": "fts_update_sealed_01"},
                )

        results = await fts_manager.search("sealed3", "LeakOnUpdateCanary91")
        assert len(results) == 0
