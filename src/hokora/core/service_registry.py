# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""ServiceRegistry: declarative teardown ordering for daemon subsystems.

Without a registry, ``daemon.stop()`` would have to hand-maintain a
multi-step teardown cascade, with every step wrapped in its own
``try/except`` so one hang or exception couldn't block the next. That
works but puts the ordering discipline on a human reader of ``stop()``
rather than making it an explicit property of each subsystem.

This module provides that as a small reusable helper:

* ``register(name, teardown)`` — called as each manager is constructed
  in ``daemon.start()``. The teardown callable is a zero-arg function
  (sync or async) that performs the subsystem's cleanup.
* ``register_task(name, task)`` — convenience for asyncio.Task cancellation;
  registers a teardown that cancels + awaits the task.
* ``shutdown_all()`` — runs every registered teardown in **reverse
  registration order**. Each step's exception is caught + logged; one
  failing subsystem doesn't block the rest. Safe to call multiple times
  (second call is a no-op because the registry clears on completion).

``stop()`` collapses from the 8-step cascade to a single
``await self._services.shutdown_all()`` + the pinned-``finally``
PID-file removal.

Why not full dependency resolution via a DAG? The plan's original
2.10 scope included topological ordering. In practice every subsystem
we care about has a single well-defined teardown position relative to
its peers, and ``start()`` constructs them in the right order already.
Reverse-registration order is a 1-line implementation that captures
the same invariant without the DAG machinery. If a future subsystem
genuinely needs out-of-order teardown (e.g., a pool that must drain
before its consumer is torn down), the registry can be extended to
accept a ``before=["other-service"]`` hint; until then, keep it
simple.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from typing import Awaitable, Callable, Optional, Union

logger = logging.getLogger(__name__)

TeardownCallable = Callable[[], Union[None, Awaitable[None]]]


class ServiceRegistry:
    """Ordered collection of (name, teardown) pairs."""

    def __init__(self) -> None:
        self._services: list[tuple[str, TeardownCallable]] = []

    def __len__(self) -> int:
        return len(self._services)

    def __contains__(self, name: str) -> bool:
        return any(n == name for n, _ in self._services)

    def names(self) -> list[str]:
        return [n for n, _ in self._services]

    def register(self, name: str, teardown: TeardownCallable) -> None:
        """Register a subsystem with its teardown callable.

        The teardown may be sync or async. Registering the same ``name``
        twice replaces the existing entry's teardown — useful when a
        subsystem is reinitialised during start(), though duplicates
        inside a single start() call indicate a bug.
        """
        for i, (existing_name, _) in enumerate(self._services):
            if existing_name == name:
                self._services[i] = (name, teardown)
                return
        self._services.append((name, teardown))

    def register_task(self, name: str, task: asyncio.Task) -> None:
        """Register an asyncio.Task for cancel+await teardown.

        Equivalent to ``register(name, lambda: _cancel(task))`` but
        with the exception catching built in so a cancelled task's
        own CancelledError doesn't escape the teardown walk.
        """

        async def _teardown() -> None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        self.register(name, _teardown)

    async def shutdown_all(self) -> None:
        """Run every registered teardown in reverse-registration order.

        Each teardown is invoked under its own try/except; a failure in
        one subsystem is logged and the walk continues. Teardowns may be
        sync or async — async ones are awaited, sync ones are called
        directly.

        The registry is cleared on completion, so a second call is a
        no-op. ``stop()`` relying on this is resilient to being called
        twice (e.g., atexit + explicit stop()).
        """
        # Copy + clear first so re-entrant shutdown_all() returns cleanly.
        services = list(self._services)
        self._services = []

        for name, teardown in reversed(services):
            try:
                result = teardown()
                if inspect.isawaitable(result):
                    await result
            except Exception:
                logger.exception("Error tearing down service %s", name)

    def unregister(self, name: str) -> Optional[TeardownCallable]:
        """Remove a service from the registry without invoking teardown.

        Returns the removed callable, or None if no service with that
        name was registered. Useful when a subsystem is destroyed mid-
        start so the registry shouldn't try to tear it down again.
        """
        for i, (existing_name, teardown) in enumerate(self._services):
            if existing_name == name:
                del self._services[i]
                return teardown
        return None
