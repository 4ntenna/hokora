# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Behavioral tests for permission enforcement — fills audit gap 7d.

Checks that a role missing ``PERM_SEND_MESSAGES`` actually blocks the
``MessageProcessor.ingest`` path (not just the bit value being correct).
"""

import time

import pytest
import pytest_asyncio
from sqlalchemy import select

from hokora.constants import MSG_TEXT
from hokora.core.message import MessageEnvelope, MessageProcessor
from hokora.core.sequencer import SequenceManager
from hokora.db.engine import create_db_engine, create_session_factory, init_db
from hokora.db.models import Channel, Identity, Role
from hokora.exceptions import PermissionDenied
from hokora.security.permissions import PermissionResolver
from hokora.security.ratelimit import RateLimiter
from hokora.security.roles import RoleManager
from hokora.security.sealed import SealedChannelManager


@pytest_asyncio.fixture
async def setup(tmp_path):
    db = tmp_path / "test.db"
    engine = create_db_engine(db, encrypt=False)
    await init_db(engine)
    sf = create_session_factory(engine)

    async with sf() as session:
        async with session.begin():
            session.add(Channel(id="ch1" + "a" * 13, name="test"))
            role_mgr = RoleManager()
            await role_mgr.ensure_builtin_roles(session)

    yield sf, engine

    await engine.dispose()


async def test_send_blocked_without_send_messages_perm(setup):
    sf, _ = setup
    ident = "deadbeef" * 8

    async with sf() as session:
        async with session.begin():
            session.add(Identity(hash=ident, display_name="NoSend"))
            # Clear 'everyone' role perms so the default grant is gone
            r = await session.execute(select(Role).where(Role.name == "everyone"))
            r.scalar_one().permissions = 0

    mp = MessageProcessor(
        sequencer=SequenceManager(),
        permission_resolver=PermissionResolver(RoleManager()),
        rate_limiter=RateLimiter(),
        sealed_manager=SealedChannelManager(),
    )

    env = MessageEnvelope(
        channel_id="ch1" + "a" * 13,
        sender_hash=ident,
        timestamp=time.time(),
        type=MSG_TEXT,
        body="should fail",
    )
    with pytest.raises(PermissionDenied, match="SEND_MESSAGES"):
        async with sf() as session:
            async with session.begin():
                await mp.ingest(session, env)


async def test_send_allowed_with_default_perms(setup):
    """Sanity: the default 'everyone' role does include SEND_MESSAGES."""
    sf, _ = setup
    ident = "cafebabe" * 8

    async with sf() as session:
        async with session.begin():
            session.add(Identity(hash=ident, display_name="Allowed"))

    mp = MessageProcessor(
        sequencer=SequenceManager(),
        permission_resolver=PermissionResolver(RoleManager()),
        rate_limiter=RateLimiter(),
        sealed_manager=SealedChannelManager(),
    )

    env = MessageEnvelope(
        channel_id="ch1" + "a" * 13,
        sender_hash=ident,
        timestamp=time.time(),
        type=MSG_TEXT,
        body="works",
    )
    async with sf() as session:
        async with session.begin():
            await mp.ingest(session, env)


async def test_blocked_identity_rejected(setup):
    sf, _ = setup
    blocked = "baddeaddead" + "e" * 53

    async with sf() as session:
        async with session.begin():
            session.add(Identity(hash=blocked, display_name="Bad", blocked=True))

    mp = MessageProcessor(
        sequencer=SequenceManager(),
        permission_resolver=PermissionResolver(RoleManager()),
        rate_limiter=RateLimiter(),
        sealed_manager=SealedChannelManager(),
    )

    env = MessageEnvelope(
        channel_id="ch1" + "a" * 13,
        sender_hash=blocked,
        timestamp=time.time(),
        type=MSG_TEXT,
        body="blocked",
    )
    with pytest.raises(PermissionDenied, match="is blocked"):
        async with sf() as session:
            async with session.begin():
                await mp.ingest(session, env)


async def test_rate_limit_enforced(setup):
    from hokora.exceptions import RateLimitExceeded

    sf, _ = setup
    ident = "feedface" * 8

    async with sf() as session:
        async with session.begin():
            session.add(Identity(hash=ident, display_name="RL"))

    # Very tight bucket
    rl = RateLimiter(max_tokens=2, refill_rate=0.0)
    mp = MessageProcessor(
        sequencer=SequenceManager(),
        permission_resolver=PermissionResolver(RoleManager()),
        rate_limiter=rl,
        sealed_manager=SealedChannelManager(),
    )

    async def _send(text):
        env = MessageEnvelope(
            channel_id="ch1" + "a" * 13,
            sender_hash=ident,
            timestamp=time.time(),
            type=MSG_TEXT,
            body=text,
        )
        async with sf() as session:
            async with session.begin():
                await mp.ingest(session, env)

    # First two should succeed, third should raise
    await _send("1")
    await _send("2")
    with pytest.raises(RateLimitExceeded):
        await _send("3")
