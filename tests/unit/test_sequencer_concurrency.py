# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Sequencer concurrency tests: concurrent next_seq calls produce unique values."""

import asyncio


from hokora.core.sequencer import SequenceManager
from hokora.db.models import Channel
from hokora.db.queries import ChannelRepo


class TestSequencerConcurrency:
    async def test_concurrent_next_seq_unique(self, session):
        ch_repo = ChannelRepo(session)
        channel = Channel(id="concch1", name="conc_test", latest_seq=0)
        await ch_repo.create(channel)

        sequencer = SequenceManager()
        await sequencer.load_from_db(session, "concch1")

        # Run 10 next_seq calls concurrently
        results = await asyncio.gather(*[sequencer.next_seq(session, "concch1") for _ in range(10)])

        # All returned values must be unique
        assert len(set(results)) == 10
        # Values should be 1..10
        assert sorted(results) == list(range(1, 11))
