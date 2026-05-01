# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Load tests: federation under stress — concurrent writes, recovery, handshakes."""

import asyncio
import time
from unittest.mock import MagicMock

import pytest

from hokora.db.models import Channel, Peer, Message
from hokora.core.sequencer import SequenceManager

pytestmark = pytest.mark.load


async def test_bidirectional_sync_under_concurrent_writes(load_session_factory):
    """Push messages while receiving — no data loss or corruption."""
    sequencer = SequenceManager()

    async with load_session_factory() as session:
        async with session.begin():
            ch = Channel(id="bidir_ch", name="bidirectional", latest_seq=0)
            session.add(ch)
            peer = Peer(identity_hash="b" * 32, federation_trusted=True)
            session.add(peer)
            await session.flush()
            await sequencer.load_from_db(session, "bidir_ch")

    # Simulate concurrent local writes and remote push ingestion
    async def local_writes(count):
        for i in range(count):
            async with load_session_factory() as session:
                async with session.begin():
                    seq = await sequencer.next_seq(session, "bidir_ch")
                    msg = Message(
                        msg_hash=f"local_{i:04d}",
                        channel_id="bidir_ch",
                        sender_hash="a" * 32,
                        seq=seq,
                        timestamp=time.time(),
                        type=1,
                        body=f"Local {i}",
                    )
                    session.add(msg)

    async def remote_push(count):
        from hokora.protocol.sync import SyncHandler
        from hokora.config import NodeConfig
        import tempfile
        from pathlib import Path

        tmp = Path(tempfile.mkdtemp())
        config = NodeConfig(
            node_name="Remote",
            data_dir=tmp,
            db_path=tmp / "t.db",
            media_dir=tmp / "media",
            identity_dir=tmp / "id",
            db_encrypt=False,
            require_signed_federation=False,
        )

        handler = SyncHandler(
            MagicMock(),
            sequencer,
            node_name="Remote",
            node_identity="a" * 32,
            config=config,
        )

        for i in range(count):
            async with load_session_factory() as session:
                async with session.begin():
                    await handler._handle_push_messages(
                        session,
                        b"\x00" * 16,
                        {
                            "channel_id": "bidir_ch",
                            "messages": [
                                {
                                    "msg_hash": f"remote_{i:04d}",
                                    "sender_hash": "c" * 32,
                                    "timestamp": time.time(),
                                    "type": 1,
                                    "body": f"Remote {i}",
                                    "origin_node": "b" * 32,
                                }
                            ],
                            "node_identity": "b" * 32,
                        },
                        None,
                    )

    await asyncio.gather(
        local_writes(50),
        remote_push(50),
    )

    # Verify all messages stored
    async with load_session_factory() as session:
        async with session.begin():
            from hokora.db.queries import MessageRepo

            repo = MessageRepo(session)
            latest = await repo.get_latest_seq("bidir_ch")
            assert latest == 100  # 50 local + 50 remote


async def test_mirror_recovery_after_disconnect(load_session_factory):
    """Mirror should resume from persisted cursor after reconnect."""
    from hokora.federation.mirror import ChannelMirror
    from hokora.protocol.wire import encode_sync_response

    callbacks = []

    def cursor_cb(ch_id, cursor):
        callbacks.append((ch_id, cursor))

    mirror = ChannelMirror(
        b"\x01" * 16,
        "recovery_ch",
        initial_cursor=100,
        cursor_callback=cursor_cb,
    )

    # Simulate receiving messages starting from cursor
    for batch in range(5):
        response = encode_sync_response(
            b"\x00" * 16,
            {
                "messages": [
                    {"msg_hash": f"rec_{batch}_{i}", "seq": 101 + batch * 10 + i, "body": "msg"}
                    for i in range(10)
                ],
                "has_more": batch < 4,
            },
        )
        mirror.handle_response(response)

    assert mirror._cursor == 150
    assert len(callbacks) == 5


async def test_concurrent_handshakes(load_session_factory):
    """Multiple peers handshaking simultaneously should not conflict."""
    from hokora.protocol.sync import SyncHandler
    from hokora.config import NodeConfig
    import tempfile
    from pathlib import Path

    tmp = Path(tempfile.mkdtemp())
    config = NodeConfig(
        node_name="Multi Handshake",
        data_dir=tmp,
        db_path=tmp / "t.db",
        media_dir=tmp / "media",
        identity_dir=tmp / "id",
        db_encrypt=False,
        federation_auto_trust=True,
    )

    handler = SyncHandler(
        MagicMock(),
        SequenceManager(),
        node_name="Multi Handshake",
        node_identity="a" * 32,
        config=config,
    )

    async def handshake(peer_id):
        async with load_session_factory() as session:
            async with session.begin():
                return await handler._handle_federation_handshake(
                    session,
                    b"\x00" * 16,
                    {
                        "step": 1,
                        "identity_hash": f"{peer_id:032x}",
                        "node_name": f"Peer {peer_id}",
                        "challenge": b"\x01" * 32,
                    },
                    None,
                )

    results = await asyncio.gather(*[handshake(i) for i in range(10)])
    assert all(r["accepted"] for r in results)
    assert all(r["step"] == 2 for r in results)
