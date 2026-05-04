# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for ZombieLinkPushBuffer.

These test the extracted buffer class in isolation. The integration tests
in test_link_resilience.py cover the same behavior through
LiveSubscriptionManager and continue to pass unchanged via compatibility
property shims.
"""

import threading
import time
from unittest.mock import MagicMock

from hokora.protocol.zombie_link_buffer import ZombieLinkPushBuffer


def _fake_link() -> MagicMock:
    """Return a link-like object. id(link) is what the buffer keys on."""
    return MagicMock()


class TestRecord:
    def test_records_single_push(self):
        buf = ZombieLinkPushBuffer()
        link = _fake_link()
        buf.record(link, "ch1", "message", {"seq": 1})
        assert len(buf) == 1
        assert buf.active_link_count() == 1

    def test_records_multiple_pushes_on_same_link(self):
        buf = ZombieLinkPushBuffer()
        link = _fake_link()
        for i in range(5):
            buf.record(link, "ch1", "message", {"seq": i})
        assert len(buf) == 5
        assert buf.active_link_count() == 1

    def test_records_on_different_links_are_isolated(self):
        buf = ZombieLinkPushBuffer()
        a, b = _fake_link(), _fake_link()
        buf.record(a, "ch1", "message", {"seq": 1})
        buf.record(b, "ch2", "message", {"seq": 2})
        assert len(buf) == 2
        assert buf.active_link_count() == 2

    def test_data_dict_preserved_verbatim(self):
        buf = ZombieLinkPushBuffer()
        link = _fake_link()
        payload = {"seq": 1, "body": "hello", "nested": {"k": "v"}}
        buf.record(link, "ch1", "message", payload)
        drained = buf.drain(link)
        _, ch, ev, got = drained[0]
        assert ch == "ch1"
        assert ev == "message"
        assert got is payload  # identity preserved — no deep copy


class TestDrain:
    def test_drain_returns_fifo_order(self):
        buf = ZombieLinkPushBuffer()
        link = _fake_link()
        for i in range(3):
            buf.record(link, "ch1", "message", {"seq": i})
        drained = buf.drain(link)
        seqs = [d[3]["seq"] for d in drained]
        assert seqs == [0, 1, 2]

    def test_drain_clears_the_link(self):
        buf = ZombieLinkPushBuffer()
        link = _fake_link()
        buf.record(link, "ch1", "message", {"seq": 1})
        buf.drain(link)
        assert buf.drain(link) == []
        assert buf.active_link_count() == 0

    def test_drain_on_empty_link_returns_empty_list(self):
        buf = ZombieLinkPushBuffer()
        assert buf.drain(_fake_link()) == []

    def test_drain_does_not_affect_other_links(self):
        buf = ZombieLinkPushBuffer()
        a, b = _fake_link(), _fake_link()
        buf.record(a, "ch1", "message", {"seq": 1})
        buf.record(b, "ch2", "message", {"seq": 2})
        drained_a = buf.drain(a)
        assert len(drained_a) == 1
        assert len(buf.drain(b)) == 1


class TestClear:
    def test_clear_removes_entries_without_returning_them(self):
        buf = ZombieLinkPushBuffer()
        link = _fake_link()
        for i in range(3):
            buf.record(link, "ch1", "message", {"seq": i})
        buf.clear(link)
        assert buf.drain(link) == []

    def test_clear_on_missing_link_is_noop(self):
        buf = ZombieLinkPushBuffer()
        # Should not raise
        buf.clear(_fake_link())


class TestRetention:
    def test_old_entries_trimmed_on_next_record(self):
        buf = ZombieLinkPushBuffer(retention_s=0.05)  # 50 ms window
        link = _fake_link()
        buf.record(link, "ch1", "message", {"seq": 1})
        time.sleep(0.1)
        # Next record should trim the old one
        buf.record(link, "ch1", "message", {"seq": 2})
        drained = buf.drain(link)
        assert len(drained) == 1
        assert drained[0][3]["seq"] == 2

    def test_entries_within_retention_preserved(self):
        buf = ZombieLinkPushBuffer(retention_s=60.0)
        link = _fake_link()
        for i in range(5):
            buf.record(link, "ch1", "message", {"seq": i})
        assert len(buf.drain(link)) == 5


class TestCapEnforcement:
    def test_per_link_cap_evicts_oldest(self):
        buf = ZombieLinkPushBuffer(per_link_cap=3)
        link = _fake_link()
        for i in range(5):
            buf.record(link, "ch1", "message", {"seq": i})
        drained = buf.drain(link)
        seqs = [d[3]["seq"] for d in drained]
        # Oldest (seqs 0, 1) evicted; keeps the last 3
        assert seqs == [2, 3, 4]

    def test_cap_is_per_link_not_global(self):
        buf = ZombieLinkPushBuffer(per_link_cap=2)
        a, b = _fake_link(), _fake_link()
        for i in range(2):
            buf.record(a, "ch1", "message", {"seq": i})
            buf.record(b, "ch2", "message", {"seq": i})
        assert len(buf) == 4


class TestConfig:
    def test_defaults_match_class_constants(self):
        buf = ZombieLinkPushBuffer()
        assert buf.retention_s == ZombieLinkPushBuffer.DEFAULT_RETENTION_S
        assert buf.per_link_cap == ZombieLinkPushBuffer.DEFAULT_PER_LINK_CAP

    def test_custom_config_applies(self):
        buf = ZombieLinkPushBuffer(retention_s=42.0, per_link_cap=7)
        assert buf.retention_s == 42.0
        assert buf.per_link_cap == 7


class TestThreadSafety:
    def test_concurrent_record_drain(self):
        """Stress: many threads recording while another drains repeatedly.
        No exceptions, no lost state. We don't assert on counts — that's
        inherently racy — just that no data corruption occurs."""
        buf = ZombieLinkPushBuffer(per_link_cap=10_000)
        link = _fake_link()
        stop = threading.Event()

        def producer():
            for i in range(1000):
                buf.record(link, "ch1", "message", {"seq": i})

        def drainer():
            while not stop.is_set():
                buf.drain(link)

        threads = [threading.Thread(target=producer) for _ in range(4)]
        d = threading.Thread(target=drainer)
        d.start()
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        stop.set()
        d.join()
        # Sanity: no references leaked
        buf.drain(link)
        assert buf.active_link_count() == 0

    def test_external_lock_shared_with_caller(self):
        """LiveSubscriptionManager passes its own lock so buffer operations
        serialize with its subscription dict mutations."""
        external_lock = threading.Lock()
        buf = ZombieLinkPushBuffer(lock=external_lock)
        # Grab the lock externally — record should block until released.
        external_lock.acquire()
        link = _fake_link()
        done = threading.Event()

        def try_record():
            buf.record(link, "ch1", "message", {"seq": 1})
            done.set()

        t = threading.Thread(target=try_record)
        t.start()
        # Should still be blocked
        blocked = not done.wait(timeout=0.1)
        assert blocked, "record() did not wait on the external lock"
        external_lock.release()
        t.join(timeout=1.0)
        assert done.is_set()
