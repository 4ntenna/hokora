# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Zombie-link push buffer.

Closes the 1–2 minute window between a transport-layer drop (TCP NAT reset,
I2P tunnel rebuild, LoRa dropout) and RNS's stale-link detection, during
which ``RNS.Link.status`` is still ACTIVE and ``RNS.Packet.send()`` returns
cleanly for packets that vanish into a dead socket.

The buffer keeps a bounded per-link deque of recent pushes; on the
definitive ``link_closed`` callback the buffer is replayed through the
subscriber's deferred queue via ``LiveSubscriptionManager``'s defer hook.

Transport-agnostic by construction: this class knows nothing about the
underlying transport, only about ``id(link)`` as a bucket key.
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

    Retention is bounded on two axes:

    - Time: entries older than ``retention_s`` are trimmed on every record
      and drain. Default 300 s — comfortably longer than RNS's stale-link
      detection window.
    - Count: each link keeps at most ``per_link_cap`` entries via
      ``collections.deque(maxlen=...)``. Default 500.

    Thread-safe: uses a single ``threading.Lock``. ``record`` is called from
    RNS callback threads; ``drain`` is called from the same callback path on
    the definitive link-closed event.
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
        # Accept an externally-owned lock so callers can serialize this buffer
        # with their own subscription state (LiveSubscriptionManager needs
        # this — its lock also protects _subscriptions and _link_identities).
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
        """Record a push so it can be replayed if the link turns out to be a
        zombie. Trims entries older than ``retention_s`` on every call."""
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
        """Remove and return every buffered push for this link.

        Returns a list of ``(timestamp, channel_id, event_type, data_dict)``
        tuples in FIFO order. The buffer is cleared for this link; calling
        again returns an empty list.
        """
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
