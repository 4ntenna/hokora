# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Cross-thread dispatch test for the announce-driven sealed-key drainer.

The unit tests in ``test_pending_sealed_distribution.py`` cover the
drainer's lifecycle decisions by ``await``-ing the coroutine directly.
They don't catch a regression where ``handle_announce`` (which runs on
RNS's announce-callback thread) schedules the drain incorrectly — that
is a separate cross-thread bug class.

This test simulates the cross-thread path: a real running event loop in
the main thread, ``handle_announce`` invoked from a background thread
(matching how RNS dispatches), and an assertion that the drain actually
ran and committed a DB change. If someone ever regresses
``run_coroutine_threadsafe`` to ``ensure_future``, this test fails.
"""

from __future__ import annotations

import asyncio
import threading
from types import SimpleNamespace
from unittest.mock import patch

import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from hokora.db.models import Base, Channel, Role, RoleAssignment
from hokora.db.queries import PendingSealedDistributionRepo
from hokora.federation.peering import PeerDiscovery


@pytest_asyncio.fixture
async def factory():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory_ = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    yield factory_
    await engine.dispose()


async def test_handle_announce_drains_from_background_thread(factory):
    """An announce delivered on a background thread must drain the queue."""
    ident = "f1" * 32

    # Seed: sealed channel + role + role assignment + queue entry.
    async with factory() as setup:
        async with setup.begin():
            setup.add(Channel(id="ch1", name="#ch1", sealed=True, access_mode="public"))
            setup.add(Role(id="role1", name="member-role1", permissions=0, position=1))
            setup.add(RoleAssignment(role_id="role1", identity_hash=ident, channel_id="ch1"))
            await PendingSealedDistributionRepo(setup).enqueue("ch1", ident, "role1")

    loop = asyncio.get_running_loop()
    pd = PeerDiscovery(session_factory=factory, loop=loop)

    distribute_calls: list[tuple] = []

    def _fake_distribute(session, channel_id, identity_hash):
        # Synchronous side-effect noting the call. The real helper is
        # async, but the patch replaces it with a sync callable that the
        # ``await`` in the drainer treats as None — which is fine for
        # this dispatch-path test (we're proving the drain *ran*, not
        # the encryption itself).
        distribute_calls.append((channel_id, identity_hash))

    fake_identity = SimpleNamespace(hexhash=ident)

    drain_started = threading.Event()

    # Wrap the coroutine so we can confirm it actually runs.
    original_drain = pd._drain_pending_sealed_distributions

    async def instrumented_drain(h):
        drain_started.set()
        await original_drain(h)

    pd._drain_pending_sealed_distributions = instrumented_drain  # type: ignore[assignment]

    with patch(
        "hokora.security.sealed.distribute_sealed_key_to_identity",
        side_effect=_fake_distribute,
    ):
        # Fire ``handle_announce`` from a background thread — exactly how
        # RNS does it. ``run_coroutine_threadsafe`` is the only way this
        # can reach our running loop.
        def _fire_announce():
            pd.handle_announce(b"\x00" * 16, fake_identity, b"")

        t = threading.Thread(target=_fire_announce, daemon=True)
        t.start()
        t.join(timeout=2.0)

        # Yield the loop a few times so the scheduled coroutine runs.
        for _ in range(20):
            await asyncio.sleep(0.05)
            if distribute_calls:
                break

    assert drain_started.is_set(), "drain coroutine never started"
    assert distribute_calls == [("ch1", ident)], (
        f"distribute_sealed_key_to_identity was not called as expected; got {distribute_calls}"
    )

    # And the queue row must have been evicted.
    async with factory() as verify:
        rows = await PendingSealedDistributionRepo(verify).list_for_identity(ident)
    assert rows == []
