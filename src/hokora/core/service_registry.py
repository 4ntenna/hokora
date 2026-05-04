# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""ServiceRegistry: declarative teardown ordering for daemon subsystems.

Subsystems register their teardown callable on construction;
``shutdown_all`` runs them in reverse-registration order, isolating
each step so one failure can't block the rest. Reverse-registration
order is sufficient — full DAG resolution is unnecessary while
``start()`` constructs subsystems in dependency order.
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
