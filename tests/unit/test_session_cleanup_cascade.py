# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Cascade-delete test for sessions → deferred_sync_items.

Regression guard for the maintenance-loop FK IntegrityError class.
After migration 011 the parent delete must succeed AND cascade to
orphaned deferred items.
"""

from __future__ import annotations

import time

from sqlalchemy import select

from hokora.db.models import DeferredSyncItem, Session
from hokora.db.queries import SessionRepo


async def test_cleanup_expired_cascades_deferred_items(session_factory):
    """cleanup_expired must remove expired sessions AND their deferred items
    without raising IntegrityError."""
    now = time.time()
    expired_sid = "expired01" + "0" * 55
    fresh_sid = "fresh0001" + "0" * 55

    # Insert parent sessions first, in their own transaction, so the child
    # deferred items find the FK target on flush. (aiosqlite enforces FKs
    # per-statement, so batched-flush parent/child ordering is brittle.)
    async with session_factory() as s:
        async with s.begin():
            s.add(
                Session(
                    session_id=expired_sid,
                    identity_hash="a" * 64,
                    sync_profile=1,
                    state="active",
                    created_at=now - 10_000,
                    last_activity=now - 10_000,
                    expires_at=now - 100,
                )
            )
            s.add(
                Session(
                    session_id=fresh_sid,
                    identity_hash="b" * 64,
                    sync_profile=1,
                    state="active",
                    created_at=now,
                    last_activity=now,
                    expires_at=now + 10_000,
                )
            )

    async with session_factory() as s:
        async with s.begin():
            for ch in ("channel01", "channel02"):
                s.add(
                    DeferredSyncItem(
                        session_id=expired_sid,
                        channel_id=ch,
                        sync_action=1,
                        payload={"msg": "x"},
                        created_at=now - 5000,
                    )
                )
            s.add(
                DeferredSyncItem(
                    session_id=fresh_sid,
                    channel_id="channel03",
                    sync_action=1,
                    payload={"msg": "keep me"},
                    created_at=now,
                )
            )

    # Run cleanup via the repo — identical call path as the daemon's
    # maintenance scheduler.
    async with session_factory() as s:
        async with s.begin():
            repo = SessionRepo(s)
            # Pass a tiny timeout so "last_activity < now - timeout" marks
            # the expired session for deletion.
            removed = await repo.cleanup_expired(1)

    assert removed == 1, "exactly one expired session removed"

    async with session_factory() as s:
        sessions = (await s.execute(select(Session))).scalars().all()
        assert {row.session_id for row in sessions} == {fresh_sid}

        defs = (await s.execute(select(DeferredSyncItem))).scalars().all()
        # Orphans cascade-deleted; fresh-session item survives.
        assert len(defs) == 1
        assert defs[0].session_id == fresh_sid
        assert defs[0].channel_id == "channel03"
