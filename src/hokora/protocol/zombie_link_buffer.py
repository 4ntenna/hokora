# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Zombie-link push buffer.

Buffers recent pushes per Link to cover the gap between transport drop
and RNS stale-link detection (~1–2 min, during which ``Link.status`` is
still ACTIVE and ``Packet.send()`` succeeds into a dead socket). On the
definitive ``link_closed`` callback the buffer replays through the
subscriber's deferred queue. Transport-agnostic — keys on ``id(link)``.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    import RNS

logger = logging.getLogger(__name__)


class ZombieLinkPushBuffer:
    """Bounded per-link deque of recent pushes, replayed on link death.

    Bounded on time (``retention_s``, default 300s — longer than RNS's
    stale window) and count (``per_link_cap``, default 500). Thread-safe.
    """

    DEFAULT_RETENTION_S: float = 300.0
    DEFAULT_PER_LINK_CAP: int = 500

    def __init__(
        self,
        retention_s: float = DEFAULT_RETENTION_S,
        per_link_cap: int = DEFAULT_PER_LINK_CAP,
        lock: Optional[threading.Lock] = None,
    ) -> None:
        self._retention_s = float(retention_s)
        self._per_link_cap = int(per_link_cap)
        # Accept an externally-owned lock so callers can serialise this
        # buffer with their own subscription state.
        self._lock = lock if lock is not None else threading.Lock()
        self._pushes: dict[int, deque] = {}

    @property
    def retention_s(self) -> float:
        return self._retention_s

    @property
    def per_link_cap(self) -> int:
        return self._per_link_cap

    def record(
        self,
        link: "RNS.Link",
        channel_id: str,
        event_type: str,
        data_dict: dict,
    ) -> None:
        """Buffer a push for replay; trims entries older than ``retention_s``."""
        now = time.time()
        with self._lock:
            buf = self._pushes.get(id(link))
            if buf is None:
                buf = deque(maxlen=self._per_link_cap)
                self._pushes[id(link)] = buf
            buf.append((now, channel_id, event_type, data_dict))
            cutoff = now - self._retention_s
            while buf and buf[0][0] < cutoff:
                buf.popleft()

    def drain(self, link: "RNS.Link") -> list[tuple[float, str, str, dict]]:
        """Pop and return all buffered pushes for this link in FIFO order."""
        with self._lock:
            buf = self._pushes.pop(id(link), None)
        if not buf:
            return []
        return list(buf)

    def clear(self, link: "RNS.Link") -> None:
        """Drop every buffered push for this link without returning them."""
        with self._lock:
            self._pushes.pop(id(link), None)

    def active_link_count(self) -> int:
        """Number of links with at least one buffered push. Test helper."""
        with self._lock:
            return len(self._pushes)

    def __len__(self) -> int:
        """Total number of buffered push entries across all links."""
        with self._lock:
            return sum(len(buf) for buf in self._pushes.values())
