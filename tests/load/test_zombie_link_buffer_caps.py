# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Load test: ZombieLinkPushBuffer per-link cap + retention window hold
under 100 simulated links × many events."""

import time
from unittest.mock import MagicMock

import pytest

from hokora.protocol.zombie_link_buffer import ZombieLinkPushBuffer

pytestmark = pytest.mark.load


def _make_link(link_id: int) -> MagicMock:
    link = MagicMock()
    # ZombieLinkPushBuffer keys on id(link) — distinct mocks suffice.
    link.link_id = link_id
    return link


def test_per_link_cap_holds_under_burst():
    """Push 10_000 events through 100 links; each link's buffer is
    bounded to per_link_cap (500 default)."""
    buf = ZombieLinkPushBuffer(retention_s=3600.0, per_link_cap=500)
    links = [_make_link(i) for i in range(100)]

    for _ in range(100):
        for link in links:
            buf.record(link, "ch-1", "message", {"body": "x"})

    for link in links:
        entries = buf.drain(link)
        assert len(entries) <= 500, (
            f"link {link.link_id} buffer had {len(entries)} entries, exceeding per_link_cap of 500"
        )


def test_retention_window_evicts_old_entries():
    """Entries older than retention_s are trimmed on record."""
    buf = ZombieLinkPushBuffer(retention_s=0.1, per_link_cap=1000)
    link = _make_link(1)

    for _ in range(50):
        buf.record(link, "ch-1", "message", {"i": 0})
    time.sleep(0.2)  # push all above past the retention window
    buf.record(link, "ch-1", "message", {"i": 999})

    entries = buf.drain(link)
    # Only the fresh entry should survive.
    assert len(entries) == 1
    assert entries[0][2] == "message"
    assert entries[0][3] == {"i": 999}


def test_drain_clears_link_so_replay_is_one_shot():
    """drain() returns all entries AND clears so a second drain is empty."""
    buf = ZombieLinkPushBuffer(retention_s=3600.0, per_link_cap=100)
    link = _make_link(7)
    for _ in range(10):
        buf.record(link, "ch", "evt", {})
    first = buf.drain(link)
    second = buf.drain(link)
    assert len(first) == 10
    assert second == []
