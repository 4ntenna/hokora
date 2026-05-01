# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for ``core/service_registry.py``."""

from __future__ import annotations

import asyncio


from hokora.core.service_registry import ServiceRegistry


class TestRegistry:
    def test_empty_registry_is_empty(self):
        r = ServiceRegistry()
        assert len(r) == 0
        assert r.names() == []

    def test_register_adds_service(self):
        r = ServiceRegistry()
        r.register("svc", lambda: None)
        assert "svc" in r
        assert r.names() == ["svc"]

    def test_register_same_name_replaces(self):
        r = ServiceRegistry()
        calls = []
        r.register("svc", lambda: calls.append("first"))
        r.register("svc", lambda: calls.append("second"))
        assert len(r) == 1
        asyncio.run(r.shutdown_all())
        # Only the second teardown ran.
        assert calls == ["second"]

    def test_unregister_removes(self):
        r = ServiceRegistry()
        fn = lambda: None  # noqa: E731
        r.register("svc", fn)
        assert r.unregister("svc") is fn
        assert len(r) == 0

    def test_unregister_unknown_returns_none(self):
        r = ServiceRegistry()
        assert r.unregister("absent") is None


class TestShutdownOrdering:
    def test_reverse_registration_order(self):
        """Teardowns run in reverse of the order they were registered."""
        r = ServiceRegistry()
        order = []
        r.register("a", lambda: order.append("a"))
        r.register("b", lambda: order.append("b"))
        r.register("c", lambda: order.append("c"))
        asyncio.run(r.shutdown_all())
        assert order == ["c", "b", "a"]


class TestTeardownShapes:
    def test_sync_teardown_called(self):
        r = ServiceRegistry()
        called = []
        r.register("sync", lambda: called.append("sync"))
        asyncio.run(r.shutdown_all())
        assert called == ["sync"]

    def test_async_teardown_awaited(self):
        r = ServiceRegistry()
        called = []

        async def _async_teardown():
            await asyncio.sleep(0)
            called.append("async")

        r.register("async", _async_teardown)
        asyncio.run(r.shutdown_all())
        assert called == ["async"]

    def test_mixed_sync_async_ordering(self):
        r = ServiceRegistry()
        order = []

        async def _async_a():
            await asyncio.sleep(0)
            order.append("async_a")

        r.register("sync_a", lambda: order.append("sync_a"))
        r.register("async_a", _async_a)
        r.register("sync_b", lambda: order.append("sync_b"))
        asyncio.run(r.shutdown_all())
        # Reverse registration, regardless of sync/async.
        assert order == ["sync_b", "async_a", "sync_a"]


class TestExceptionResilience:
    def test_one_failure_doesnt_block_others(self):
        r = ServiceRegistry()
        called = []

        def _raising():
            called.append("raised")
            raise RuntimeError("boom")

        r.register("a", lambda: called.append("a"))
        r.register("raising", _raising)
        r.register("c", lambda: called.append("c"))
        # Should not raise — shutdown_all catches per-step.
        asyncio.run(r.shutdown_all())
        # Reverse order: c, then raising (which raised but was caught), then a.
        assert called == ["c", "raised", "a"]

    def test_async_failure_doesnt_block_others(self):
        r = ServiceRegistry()
        called = []

        async def _raising_async():
            called.append("raised_async")
            raise ValueError("async boom")

        r.register("a", lambda: called.append("a"))
        r.register("raising", _raising_async)
        r.register("c", lambda: called.append("c"))
        asyncio.run(r.shutdown_all())
        assert called == ["c", "raised_async", "a"]


class TestTaskRegistration:
    async def test_register_task_cancels_and_awaits(self):
        r = ServiceRegistry()

        async def _forever():
            await asyncio.sleep(3600)

        task = asyncio.create_task(_forever())
        r.register_task("bg", task)

        await r.shutdown_all()
        assert task.cancelled() or task.done()


class TestIdempotentShutdown:
    def test_second_shutdown_is_noop(self):
        r = ServiceRegistry()
        called = []
        r.register("svc", lambda: called.append("svc"))
        asyncio.run(r.shutdown_all())
        asyncio.run(r.shutdown_all())
        # Teardown invoked exactly once.
        assert called == ["svc"]
        # Registry cleared after first shutdown.
        assert len(r) == 0
