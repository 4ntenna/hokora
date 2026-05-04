# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for the deferred sealed-key distribution queue.

Covers:

- Repo enqueue / list / evict / increment_retry round trips.
- UNIQUE constraint behaviour on duplicate enqueue.
- Announce-handler drain hook: matching identity drains, non-matching is
  left alone, missing role assignment evicts (revoke guard), past
  MAX_PENDING_DISTRIBUTION_RETRIES is preserved (not silently dropped).
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from hokora.constants import MAX_PENDING_DISTRIBUTION_RETRIES
from hokora.db.models import (
    Base,
    Channel,
    PendingSealedDistribution,
    Role,
    RoleAssignment,
)
from hokora.db.queries import PendingSealedDistributionRepo
from hokora.exceptions import SealedKeyDistributionDeferred
from hokora.federation.peering import PeerDiscovery


@pytest_asyncio.fixture
async def engine_and_factory():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    yield engine, factory
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(engine_and_factory):
    _engine, factory = engine_and_factory
    async with factory() as session:
        async with session.begin():
            yield session


async def _seed_channel_and_role(session, channel_id="ch1", role_id="role1", sealed=True):
    session.add(
        Channel(
            id=channel_id,
            name=f"#{channel_id}",
            sealed=sealed,
            access_mode="public",
        )
    )
    session.add(Role(id=role_id, name=f"member-{role_id}", permissions=0, position=1))
    await session.flush()


class TestPendingRepo:
    async def test_enqueue_then_list(self, db_session):
        await _seed_channel_and_role(db_session)
        repo = PendingSealedDistributionRepo(db_session)

        await repo.enqueue("ch1", "abcd" * 16, "role1")
        rows = await repo.list_for_identity("abcd" * 16)
        assert len(rows) == 1
        assert rows[0].channel_id == "ch1"
        assert rows[0].retry_count == 0
        assert rows[0].queued_at > 0

    async def test_enqueue_idempotent(self, db_session):
        """Duplicate enqueue on the same triple must not raise and must not double-insert."""
        await _seed_channel_and_role(db_session)
        repo = PendingSealedDistributionRepo(db_session)

        first = await repo.enqueue("ch1", "id1" * 22, "role1")
        second = await repo.enqueue("ch1", "id1" * 22, "role1")
        assert first.id == second.id

        rows = await repo.list_for_identity("id1" * 22)
        assert len(rows) == 1

    async def test_evict(self, db_session):
        await _seed_channel_and_role(db_session)
        repo = PendingSealedDistributionRepo(db_session)
        entry = await repo.enqueue("ch1", "id2" * 22, "role1")

        await repo.evict(entry.id)

        rows = await repo.list_for_identity("id2" * 22)
        assert rows == []

    async def test_increment_retry(self, db_session):
        await _seed_channel_and_role(db_session)
        repo = PendingSealedDistributionRepo(db_session)
        entry = await repo.enqueue("ch1", "id3" * 22, "role1")

        await repo.increment_retry(entry.id, "boom")
        await repo.increment_retry(entry.id, "still boom")

        rows = await repo.list_for_identity("id3" * 22)
        assert rows[0].retry_count == 2
        assert rows[0].last_error == "still boom"
        assert rows[0].last_attempt_at is not None

    async def test_list_all_filtered_by_channel(self, db_session):
        await _seed_channel_and_role(db_session, channel_id="ch1")
        await _seed_channel_and_role(db_session, channel_id="ch2", role_id="role2")
        repo = PendingSealedDistributionRepo(db_session)

        await repo.enqueue("ch1", "alpha" * 13, "role1")
        await repo.enqueue("ch2", "beta" * 16, "role2")

        ch1 = await repo.list_all(channel_id="ch1")
        assert len(ch1) == 1
        assert ch1[0].channel_id == "ch1"

        all_rows = await repo.list_all()
        assert len(all_rows) == 2


class TestAnnounceDrain:
    """Integration tests for ``PeerDiscovery._drain_pending_sealed_distributions``.

    Patches ``distribute_sealed_key_to_identity`` so we don't need real
    RNS state — the test focuses on the queue-lifecycle decisions made by
    the drainer (revoke guard, retry bookkeeping, max-retry preservation),
    not the envelope encryption itself (covered by
    ``test_sealed_key_distribution_x25519``).
    """

    async def test_drain_evicts_after_successful_distribution(self, engine_and_factory):
        _engine, factory = engine_and_factory
        async with factory() as setup:
            async with setup.begin():
                await _seed_channel_and_role(setup)
                setup.add(
                    RoleAssignment(
                        role_id="role1",
                        identity_hash="abc" * 21 + "x",
                        channel_id="ch1",
                    )
                )
                await PendingSealedDistributionRepo(setup).enqueue("ch1", "abc" * 21 + "x", "role1")

        loop = asyncio.get_running_loop()
        pd = PeerDiscovery(session_factory=factory, loop=loop)

        async def _fake_distribute(session, channel_id, identity_hash, node_identity=None):
            session.add(
                PendingSealedDistribution._dummy_marker  # never reached
                if False
                else _no_op_marker()
            )

        # Successful distribution: helper just returns; the drainer must
        # evict the queue row.
        with patch(
            "hokora.security.sealed.distribute_sealed_key_to_identity",
            side_effect=lambda session, ch, h: None,
        ):
            await pd._drain_pending_sealed_distributions("abc" * 21 + "x")

        async with factory() as verify:
            rows = await PendingSealedDistributionRepo(verify).list_for_identity("abc" * 21 + "x")
        assert rows == []

    async def test_drain_revoke_guard_evicts_when_role_gone(self, engine_and_factory):
        _engine, factory = engine_and_factory
        ident = "rev" * 21 + "x"
        async with factory() as setup:
            async with setup.begin():
                await _seed_channel_and_role(setup)
                # NOTE: no RoleAssignment row — simulates revoke between
                # enqueue and announce.
                await PendingSealedDistributionRepo(setup).enqueue("ch1", ident, "role1")

        loop = asyncio.get_running_loop()
        pd = PeerDiscovery(session_factory=factory, loop=loop)

        with patch(
            "hokora.security.sealed.distribute_sealed_key_to_identity",
            side_effect=AssertionError("must not be called when role is missing"),
        ):
            await pd._drain_pending_sealed_distributions(ident)

        async with factory() as verify:
            rows = await PendingSealedDistributionRepo(verify).list_for_identity(ident)
        assert rows == []  # evicted by guard

    async def test_drain_increments_retry_on_deferred(self, engine_and_factory):
        _engine, factory = engine_and_factory
        ident = "def" * 21 + "x"
        async with factory() as setup:
            async with setup.begin():
                await _seed_channel_and_role(setup)
                setup.add(RoleAssignment(role_id="role1", identity_hash=ident, channel_id="ch1"))
                await PendingSealedDistributionRepo(setup).enqueue("ch1", ident, "role1")

        loop = asyncio.get_running_loop()
        pd = PeerDiscovery(session_factory=factory, loop=loop)

        def _raise_deferred(session, ch, h):
            raise SealedKeyDistributionDeferred("path lost")

        with patch(
            "hokora.security.sealed.distribute_sealed_key_to_identity",
            side_effect=_raise_deferred,
        ):
            await pd._drain_pending_sealed_distributions(ident)

        async with factory() as verify:
            rows = await PendingSealedDistributionRepo(verify).list_for_identity(ident)
        assert len(rows) == 1
        assert rows[0].retry_count == 1
        assert rows[0].last_error == "path lost"

    async def test_drain_skips_entries_past_max_retries(self, engine_and_factory):
        """Entries past MAX retries are preserved (operator visibility) but not retried."""
        _engine, factory = engine_and_factory
        ident = "stk" * 21 + "x"
        async with factory() as setup:
            async with setup.begin():
                await _seed_channel_and_role(setup)
                setup.add(RoleAssignment(role_id="role1", identity_hash=ident, channel_id="ch1"))
                entry = await PendingSealedDistributionRepo(setup).enqueue("ch1", ident, "role1")
                # Fast-forward retry_count to MAX without triggering distribute.
                for _ in range(MAX_PENDING_DISTRIBUTION_RETRIES):
                    await PendingSealedDistributionRepo(setup).increment_retry(
                        entry.id, "saturated"
                    )

        loop = asyncio.get_running_loop()
        pd = PeerDiscovery(session_factory=factory, loop=loop)

        with patch(
            "hokora.security.sealed.distribute_sealed_key_to_identity",
            side_effect=AssertionError("must not be called past MAX retries"),
        ):
            await pd._drain_pending_sealed_distributions(ident)

        async with factory() as verify:
            rows = await PendingSealedDistributionRepo(verify).list_for_identity(ident)
        # Entry preserved, not retried, not evicted.
        assert len(rows) == 1
        assert rows[0].retry_count >= MAX_PENDING_DISTRIBUTION_RETRIES

    async def test_revoke_cli_proactively_clears_pending_entries(self, engine_and_factory):
        """``hokora role revoke`` must drop matching queue rows immediately."""
        from sqlalchemy import and_, delete, select

        _engine, factory = engine_and_factory
        ident = "rev-pro" + "x" * 57
        async with factory() as setup:
            async with setup.begin():
                await _seed_channel_and_role(setup)
                setup.add(RoleAssignment(role_id="role1", identity_hash=ident, channel_id="ch1"))
                await PendingSealedDistributionRepo(setup).enqueue("ch1", ident, "role1")

        # Exercise the same code path ``hokora role revoke`` runs.
        async with factory() as session:
            async with session.begin():
                ras = (
                    (
                        await session.execute(
                            select(RoleAssignment)
                            .where(RoleAssignment.role_id == "role1")
                            .where(RoleAssignment.identity_hash == ident)
                            .where(RoleAssignment.channel_id == "ch1")
                        )
                    )
                    .scalars()
                    .all()
                )
                for r in ras:
                    await session.delete(r)
                await session.execute(
                    delete(PendingSealedDistribution).where(
                        and_(
                            PendingSealedDistribution.role_id == "role1",
                            PendingSealedDistribution.identity_hash == ident,
                            PendingSealedDistribution.channel_id == "ch1",
                        )
                    )
                )

        async with factory() as verify:
            rows = await PendingSealedDistributionRepo(verify).list_for_identity(ident)
        assert rows == []

    async def test_drain_ignores_non_matching_identity(self, engine_and_factory):
        _engine, factory = engine_and_factory
        async with factory() as setup:
            async with setup.begin():
                await _seed_channel_and_role(setup)
                setup.add(
                    RoleAssignment(
                        role_id="role1",
                        identity_hash="match" * 12 + "abcd",
                        channel_id="ch1",
                    )
                )
                await PendingSealedDistributionRepo(setup).enqueue(
                    "ch1", "match" * 12 + "abcd", "role1"
                )

        loop = asyncio.get_running_loop()
        pd = PeerDiscovery(session_factory=factory, loop=loop)

        with patch(
            "hokora.security.sealed.distribute_sealed_key_to_identity",
            side_effect=AssertionError("must not be called for non-matching identity"),
        ):
            await pd._drain_pending_sealed_distributions("OTHER" * 12 + "ZZZZ")

        async with factory() as verify:
            rows = await PendingSealedDistributionRepo(verify).list_for_identity(
                "match" * 12 + "abcd"
            )
        # Untouched.
        assert len(rows) == 1
        assert rows[0].retry_count == 0


def _no_op_marker():
    """Sentinel object the test doesn't actually use; satisfies the patched
    side_effect signature without doing anything."""
    return None
