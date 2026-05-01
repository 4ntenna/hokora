# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Load tests: high-volume message ingest, pagination, resource tracking."""

import time

import pytest

from hokora.db.models import Channel, Message
from hokora.db.queries import MessageRepo
from hokora.core.sequencer import SequenceManager

pytestmark = pytest.mark.load


async def test_1000_message_ingest(load_session_factory):
    """Ingest 1000 messages and verify all are stored."""
    sequencer = SequenceManager()

    async with load_session_factory() as session:
        async with session.begin():
            ch = Channel(id="vol_ch", name="volume", latest_seq=0)
            session.add(ch)
            await session.flush()
            await sequencer.load_from_db(session, "vol_ch")

    for batch_start in range(0, 1000, 50):
        async with load_session_factory() as session:
            async with session.begin():
                for i in range(batch_start, min(batch_start + 50, 1000)):
                    seq = await sequencer.next_seq(session, "vol_ch")
                    msg = Message(
                        msg_hash=f"vol_msg_{i:04d}",
                        channel_id="vol_ch",
                        sender_hash="a" * 32,
                        seq=seq,
                        timestamp=time.time(),
                        type=1,
                        body=f"Volume message {i}",
                    )
                    session.add(msg)

    # Verify count by paginating
    total = 0
    cursor = 0
    async with load_session_factory() as session:
        async with session.begin():
            repo = MessageRepo(session)
            while True:
                page = await repo.get_history("vol_ch", since_seq=cursor, limit=100)
                if not page:
                    break
                total += len(page)
                cursor = page[-1].seq
                if len(page) < 100:
                    break
    assert total == 1000


async def test_pagination_with_5000_messages(load_session_factory):
    """Paginate through 5000 messages using since_seq."""
    async with load_session_factory() as session:
        async with session.begin():
            ch = Channel(id="page_ch", name="paginate", latest_seq=5000)
            session.add(ch)
            for i in range(5000):
                msg = Message(
                    msg_hash=f"page_{i:05d}",
                    channel_id="page_ch",
                    sender_hash="a" * 32,
                    seq=i + 1,
                    timestamp=time.time(),
                    type=1,
                    body=f"Page message {i}",
                )
                session.add(msg)

    # Paginate through all messages in 100-message pages
    total = 0
    cursor = 0
    async with load_session_factory() as session:
        async with session.begin():
            repo = MessageRepo(session)
            while True:
                page = await repo.get_history(
                    "page_ch",
                    since_seq=cursor,
                    limit=100,
                )
                if not page:
                    break
                total += len(page)
                cursor = page[-1].seq
                if len(page) < 100:
                    break

    assert total == 5000


async def test_db_size_tracking(load_session_factory, load_config):
    """Track DB file size after large insert."""
    import os

    async with load_session_factory() as session:
        async with session.begin():
            ch = Channel(id="size_ch", name="size", latest_seq=0)
            session.add(ch)
            for i in range(500):
                msg = Message(
                    msg_hash=f"size_{i:04d}",
                    channel_id="size_ch",
                    sender_hash="a" * 32,
                    seq=i + 1,
                    timestamp=time.time(),
                    type=1,
                    body="x" * 1000,  # ~1KB per message
                )
                session.add(msg)

    db_path = load_config.db_path
    # Check all SQLite-related files (main + WAL + shm)
    db_size = 0
    for suffix in ["", "-wal", "-shm"]:
        path = str(db_path) + suffix
        if os.path.exists(path):
            db_size += os.path.getsize(path)
    # 500 messages * ~1KB + overhead, should be reasonable
    assert db_size < 10 * 1024 * 1024  # Under 10MB
    assert db_size > 1024  # At least 1KB (sanity)
