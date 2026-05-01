# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Test repository queries: pagination, ordering."""

import time


from hokora.db.models import Channel, Message
from hokora.db.queries import ChannelRepo, IdentityRepo, MessageRepo


class TestMessageRepo:
    async def test_insert_and_get(self, session):
        # Setup channel
        ch_repo = ChannelRepo(session)
        await ch_repo.create(Channel(id="qch1", name="query_test", latest_seq=0))

        msg_repo = MessageRepo(session)
        msg = Message(
            msg_hash="abc123",
            channel_id="qch1",
            sender_hash="s1",
            seq=1,
            timestamp=time.time(),
            type=1,
            body="Hello",
        )
        await msg_repo.insert(msg)

        retrieved = await msg_repo.get_by_hash("abc123")
        assert retrieved is not None
        assert retrieved.body == "Hello"

    async def test_history_pagination_forward(self, session):
        ch_repo = ChannelRepo(session)
        await ch_repo.create(Channel(id="qch2", name="pag_test", latest_seq=0))

        msg_repo = MessageRepo(session)
        for i in range(1, 21):
            await msg_repo.insert(
                Message(
                    msg_hash=f"msg{i:03d}",
                    channel_id="qch2",
                    sender_hash="s1",
                    seq=i,
                    timestamp=time.time(),
                    type=1,
                    body=f"Message {i}",
                )
            )

        # Forward from seq 0, limit 5
        messages = await msg_repo.get_history("qch2", since_seq=0, limit=5)
        assert len(messages) == 5
        assert messages[0].seq == 1
        assert messages[4].seq == 5

        # Forward from seq 5, limit 5
        messages = await msg_repo.get_history("qch2", since_seq=5, limit=5)
        assert len(messages) == 5
        assert messages[0].seq == 6

    async def test_history_pagination_backward(self, session):
        ch_repo = ChannelRepo(session)
        await ch_repo.create(Channel(id="qch3", name="back_test", latest_seq=0))

        msg_repo = MessageRepo(session)
        for i in range(1, 11):
            await msg_repo.insert(
                Message(
                    msg_hash=f"bk{i:03d}",
                    channel_id="qch3",
                    sender_hash="s1",
                    seq=i,
                    timestamp=time.time(),
                    type=1,
                    body=f"Message {i}",
                )
            )

        messages = await msg_repo.get_history(
            "qch3",
            direction="backward",
            before_seq=8,
            limit=3,
        )
        assert len(messages) == 3
        assert messages[0].seq == 5
        assert messages[2].seq == 7

    async def test_soft_delete(self, session):
        ch_repo = ChannelRepo(session)
        await ch_repo.create(Channel(id="qch4", name="del_test", latest_seq=0))

        msg_repo = MessageRepo(session)
        await msg_repo.insert(
            Message(
                msg_hash="del001",
                channel_id="qch4",
                sender_hash="s1",
                seq=1,
                timestamp=time.time(),
                type=1,
                body="Delete me",
            )
        )

        result = await msg_repo.soft_delete("del001", "mod1")
        assert result.deleted is True
        assert result.body is None

    async def test_pinned_messages(self, session):
        ch_repo = ChannelRepo(session)
        await ch_repo.create(Channel(id="qch5", name="pin_test", latest_seq=0))

        msg_repo = MessageRepo(session)
        await msg_repo.insert(
            Message(
                msg_hash="pin001",
                channel_id="qch5",
                sender_hash="s1",
                seq=1,
                timestamp=time.time(),
                type=1,
                body="Pin me",
            )
        )

        await msg_repo.set_pinned("pin001", True)
        pinned = await msg_repo.get_pinned("qch5")
        assert len(pinned) == 1
        assert pinned[0].msg_hash == "pin001"


class TestChannelRepo:
    async def test_create_and_list(self, session):
        repo = ChannelRepo(session)
        await repo.create(Channel(id="clch1", name="ch1", position=1))
        await repo.create(Channel(id="clch2", name="ch2", position=0))

        channels = await repo.list_all()
        assert len(channels) >= 2
        # Should be ordered by position
        positions = [ch.position for ch in channels]
        assert positions == sorted(positions)

    async def test_increment_seq(self, session):
        repo = ChannelRepo(session)
        await repo.create(Channel(id="incch1", name="inc_test", latest_seq=0))

        seq = await repo.increment_seq("incch1")
        assert seq == 1
        seq = await repo.increment_seq("incch1")
        assert seq == 2

    async def test_delete_channel(self, session):
        repo = ChannelRepo(session)
        await repo.create(Channel(id="delch1", name="del_test"))

        # Add a message to test cascade
        msg_repo = MessageRepo(session)
        await msg_repo.insert(
            Message(
                msg_hash="delmsg1",
                channel_id="delch1",
                sender_hash="s1",
                seq=1,
                timestamp=time.time(),
                type=1,
                body="Will be deleted",
            )
        )

        result = await repo.delete_channel("delch1")
        assert result is True

        # Channel gone
        ch = await repo.get_by_id("delch1")
        assert ch is None

    async def test_delete_channel_not_found(self, session):
        repo = ChannelRepo(session)
        result = await repo.delete_channel("nonexistent_ch")
        assert result is False

    async def test_update_channel(self, session):
        repo = ChannelRepo(session)
        await repo.create(Channel(id="updch1", name="original", description="old"))

        updated = await repo.update_channel("updch1", name="renamed", description="new")
        assert updated is not None
        assert updated.name == "renamed"
        assert updated.description == "new"

        # Verify persistence
        ch = await repo.get_by_id("updch1")
        assert ch.name == "renamed"

    async def test_update_channel_not_found(self, session):
        repo = ChannelRepo(session)
        result = await repo.update_channel("nonexistent_upd", name="x")
        assert result is None


class TestIdentityRepo:
    async def test_is_blocked_true(self, session):
        repo = IdentityRepo(session)
        await repo.upsert("blocked_user", blocked=True)
        assert await repo.is_blocked("blocked_user") is True

    async def test_is_blocked_false(self, session):
        repo = IdentityRepo(session)
        await repo.upsert("normal_user", blocked=False)
        assert await repo.is_blocked("normal_user") is False

    async def test_is_blocked_unknown(self, session):
        repo = IdentityRepo(session)
        assert await repo.is_blocked("unknown_user") is False
