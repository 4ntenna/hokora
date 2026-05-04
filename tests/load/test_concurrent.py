# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Load tests: concurrent message sending and history sync."""

import asyncio
import time

import pytest

from hokora.core.sequencer import SequenceManager
from hokora.db.models import Channel, Message
from hokora.db.queries import MessageRepo

pytestmark = pytest.mark.load


async def test_concurrent_message_sending(load_session_factory):
    """10 concurrent clients sending messages should not cause conflicts."""
    sequencer = SequenceManager()

    async with load_session_factory() as session:
        async with session.begin():
            ch = Channel(id="concurrent_ch", name="concurrent", latest_seq=0)
            session.add(ch)
            await session.flush()
            await sequencer.load_from_db(session, "concurrent_ch")

    async def send_messages(client_id, count):
        results = []
        for i in range(count):
            async with load_session_factory() as session:
                async with session.begin():
                    seq = await sequencer.next_seq(session, "concurrent_ch")
                    msg = Message(
                        msg_hash=f"msg_{client_id}_{i}",
                        channel_id="concurrent_ch",
                        sender_hash=f"client_{client_id:03d}" + "0" * 22,
                        seq=seq,
                        timestamp=time.time(),
                        type=1,
                        body=f"Message {i} from client {client_id}",
                    )
                    session.add(msg)
                    results.append(seq)
        return results

    tasks = [send_messages(i, 10) for i in range(10)]
    all_results = await asyncio.gather(*tasks)

    all_seqs = [seq for results in all_results for seq in results]
    assert len(all_seqs) == 100
    assert len(set(all_seqs)) == 100


async def test_concurrent_history_sync(load_session_factory):
    """Multiple concurrent history reads should not interfere."""
    async with load_session_factory() as session:
        async with session.begin():
            ch = Channel(id="hist_ch", name="history", latest_seq=50)
            session.add(ch)
            for i in range(50):
                msg = Message(
                    msg_hash=f"hist_msg_{i}",
                    channel_id="hist_ch",
                    sender_hash="a" * 32,
                    seq=i + 1,
                    timestamp=time.time(),
                    type=1,
                    body=f"History message {i}",
                )
                session.add(msg)

    async def read_history(since_seq):
        async with load_session_factory() as session:
            async with session.begin():
                repo = MessageRepo(session)
                return await repo.get_history("hist_ch", since_seq=since_seq, limit=50)

    tasks = [read_history(i * 2) for i in range(20)]
    results = await asyncio.gather(*tasks)

    for msgs in results:
        assert len(msgs) > 0
        assert all(isinstance(m.body, str) for m in msgs)
