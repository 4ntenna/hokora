# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Shared base for client_db stores: (connection, lock, tx-state) wrapper.

All stores in this package share a **single** ``sqlite3.Connection``, a
**single** ``threading.Lock``, and a **single** ``TxState`` flag object.
The flag controls whether mutating methods take the lock + commit
themselves (normal standalone calls) or defer to an enclosing
``db.transaction()`` block.

Splitting ClientDB into stores is about code cohesion, not transactional
isolation. Cross-store atomic writes go through ``db.transaction()``,
which takes the lock once, lets callers issue many store mutations, and
commits (or rolls back) once on exit. See ``facade.ClientDB.transaction``.
"""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass


@dataclass
class TxState:
    """Transaction-active flag shared across all stores.

    ``active`` is flipped by ``ClientDB.transaction`` on entry/exit.
    Every mutating store method guards both its own lock acquisition
    and its ``conn.commit()`` behind ``not active`` — so standalone
    calls retain their previous autocommit semantics while calls made
    inside a ``with db.transaction():`` block run as one atomic batch.
    """

    active: bool = False


class StoreBase:
    """Base class for every store — holds the shared conn, lock, tx-state."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        lock: threading.Lock,
        tx_state: TxState,
    ) -> None:
        self._conn = conn
        self._lock = lock
        self._tx = tx_state

    def _commit_unless_tx(self) -> None:
        """Commit the shared connection if we're NOT inside a transaction.

        Inside a ``db.transaction()`` block the facade commits once on
        successful exit; interior commits would split the atomic batch.
        """
        if not self._tx.active:
            self._conn.commit()

    def _lock_unless_tx(self):
        """Return a context manager that acquires the store lock iff
        we're not already inside a transaction (the transaction has
        already taken the lock on the caller's behalf).

        ``threading.Lock`` is not reentrant, so we MUST NOT re-acquire.
        A no-op context manager handles the tx-active case.
        """
        if self._tx.active:
            return _NullContext()
        return self._lock


class _NullContext:
    """Minimal ``with``-compatible no-op used when the store lock is
    already held by an enclosing transaction."""

    def __enter__(self):
        return None

    def __exit__(self, *exc_info):
        return False
