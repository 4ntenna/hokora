# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Test sequence manager monotonicity and concurrency."""

from hokora.core.sequencer import SequenceManager
from hokora.db.models import Channel
from hokora.db.queries import ChannelRepo


class TestSequenceManager:
    async def test_monotonic_increment(self, session):
        repo = ChannelRepo(session)
        channel = Channel(id="seqch1", name="seqtest", latest_seq=0)
        await repo.create(channel)

        seq_mgr = SequenceManager()
        await seq_mgr.load_from_db(session, "seqch1")

        seqs = []
        for _ in range(10):
            s = await seq_mgr.next_seq(session, "seqch1")
            seqs.append(s)

        assert seqs == list(range(1, 11))

    async def test_cached_seq(self, session):
        repo = ChannelRepo(session)
        channel = Channel(id="seqch2", name="seqtest2", latest_seq=5)
        await repo.create(channel)

        seq_mgr = SequenceManager()
        await seq_mgr.load_from_db(session, "seqch2")

        assert seq_mgr.get_cached_seq("seqch2") == 5

        s = await seq_mgr.next_seq(session, "seqch2")
        assert s == 6
        assert seq_mgr.get_cached_seq("seqch2") == 6

    async def test_unknown_channel_returns_zero(self):
        seq_mgr = SequenceManager()
        assert seq_mgr.get_cached_seq("unknown") == 0
