# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Transport-agnostic Link-death resilience tests.

Covers two halves:

* **Server-side** — `LiveSubscriptionManager._push_to_subscribers` enqueues a
  dead-linked event through the defer hook; `CDSPSessionManager.handle_session_init`
  flushes items in FIFO order on resume; the msgpack-envelope round-trips bytes
  fields intact.
* **Client-side** — `SyncEngine._on_link_closed` triggers the reconnect
  manager when there are live targets, stays quiet on user-initiated teardown,
  and steps through the exponential backoff schedule.
"""

import time
from unittest.mock import MagicMock, patch

import msgpack
import pytest_asyncio

from hokora.constants import (
    CDSP_PROFILE_FULL,
    SYNC_LIVE_EVENT,
)
from hokora.db.models import Base
from hokora.db.queries import DeferredSyncItemRepo, SessionRepo
from hokora.protocol.live import LiveSubscriptionManager
from hokora.protocol.session import CDSPSessionManager

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker


@pytest_asyncio.fixture
async def db_session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        async with session.begin():
            yield session
    await engine.dispose()


async def _create_session(db_session, session_id="sess_1", identity_hash="id_1"):
    return await SessionRepo(db_session).create_session(
        session_id=session_id,
        identity_hash=identity_hash,
        sync_profile=CDSP_PROFILE_FULL,
        expires_at=time.time() + 3600,
    )


# ---------------------------------------------------------------------------
# Server: LiveSubscriptionManager dead-link defer
# ---------------------------------------------------------------------------


class TestLiveDeferHook:
    def _make_dead_link(self, status: int = 0x00) -> MagicMock:
        """Build a mock RNS.Link whose ``status`` != ACTIVE (0x01)."""
        link = MagicMock()
        link.status = status  # anything not 0x01 is "dead" for our purposes
        return link

    def test_dead_link_triggers_defer_hook(self):
        """A live push to a subscriber with a dead link hands the event to
        the installed defer hook instead of silently dropping it."""
        lm = LiveSubscriptionManager()
        recorded = []
        lm.set_defer_hook(lambda ih, ch, ev, d: recorded.append((ih, ch, ev, d)))

        dead = self._make_dead_link()
        # Register subscription + identity for the dead link
        lm._subscriptions["ch1"] = {dead: CDSP_PROFILE_FULL}
        lm._link_identities[id(dead)] = "identity_abc"

        msg = MagicMock()
        msg.msg_hash = "m0"
        msg.channel_id = "ch1"
        msg.sender_hash = "s0"
        msg.seq = 1
        msg.thread_seq = None
        msg.timestamp = 1.0
        msg.type = 0x01
        msg.body = "hi"
        msg.media_path = None
        msg.media_meta = None
        msg.reply_to = None
        msg.deleted = False
        msg.pinned = False
        msg.pinned_at = None
        msg.edit_chain = []
        msg.reactions = {}
        msg.lxmf_signature = None
        msg.lxmf_signed_part = None
        msg.display_name = None
        msg.mentions = None

        lm.push_message("ch1", msg)

        assert len(recorded) == 1
        ih, ch, ev, d = recorded[0]
        assert ih == "identity_abc"
        assert ch == "ch1"
        assert ev == "message"
        assert d["msg_hash"] == "m0"
        assert d["body"] == "hi"
        # Subscription cleaned up after defer
        assert dead not in lm._subscriptions.get("ch1", {})

    def test_anonymous_link_not_deferred(self):
        """No identity registered → hook must not fire (no session to buffer
        against). The subscription still gets cleaned up."""
        lm = LiveSubscriptionManager()
        recorded = []
        lm.set_defer_hook(lambda ih, ch, ev, d: recorded.append((ih, ch, ev, d)))

        dead = self._make_dead_link()
        lm._subscriptions["ch1"] = {dead: CDSP_PROFILE_FULL}
        # Deliberately no _link_identities entry

        lm.push_event("ch1", "message_updated", {"msg_hash": "x"})

        assert recorded == []
        assert dead not in lm._subscriptions.get("ch1", {})

    def test_no_defer_hook_drops_silently(self):
        """Regression guard: without a hook installed, dead-link cleanup
        behaviour is unchanged (no exception, subscription removed)."""
        lm = LiveSubscriptionManager()
        dead = self._make_dead_link()
        lm._subscriptions["ch1"] = {dead: CDSP_PROFILE_FULL}
        lm._link_identities[id(dead)] = "identity_abc"

        lm.push_event("ch1", "reaction", {"emoji": "🔥"})
        # No crash, subscription cleaned up
        assert dead not in lm._subscriptions.get("ch1", {})


# ---------------------------------------------------------------------------
# Server: zombie-link push buffer + flush on link_closed
# ---------------------------------------------------------------------------


class TestZombieLinkFlush:
    """Cover the window between transport drop and RNS stale detection —
    where link.status stays ACTIVE and RNS.send succeeds into a dead socket.
    The fix records each successful push per-link and, on the definitive
    link_closed callback, replays the buffer through the defer hook."""

    def _make_live_link(self) -> MagicMock:
        link = MagicMock()
        link.status = 0x01  # ACTIVE
        return link

    def test_successful_push_is_recorded(self):
        """Every successful push to an ACTIVE link lands in _recent_pushes
        for that link, ready for replay on link death."""
        lm = LiveSubscriptionManager()
        lm.set_defer_hook(lambda *args: None)  # presence only; not called here

        link = self._make_live_link()
        # Patch RNS.Link.MDU so the inline packet path is taken (small data)
        # and RNS.Packet.send() is a no-op.
        with patch("hokora.protocol.live.RNS") as MRNS:
            MRNS.Link.ACTIVE = 0x01
            MRNS.Link.MDU = 10_000
            MRNS.Packet = MagicMock()

            lm._subscriptions["ch1"] = {link: CDSP_PROFILE_FULL}
            lm._link_identities[id(link)] = "identity_xyz"
            lm.push_event("ch1", "message_updated", {"msg_hash": "h1"})

        buf = lm._recent_pushes.get(id(link))
        assert buf is not None
        assert len(buf) == 1
        _, ch, ev, data = buf[0]
        assert ch == "ch1"
        assert ev == "message_updated"
        assert data == {"msg_hash": "h1"}

    def test_handle_link_death_replays_via_defer_hook(self):
        """When the link is confirmed dead, all buffered pushes flow through
        the defer hook so they land in the subscriber's CDSP queue."""
        lm = LiveSubscriptionManager()
        recorded = []
        lm.set_defer_hook(lambda ih, ch, ev, d: recorded.append((ih, ch, ev, d)))

        link = self._make_live_link()
        lm._subscriptions["ch1"] = {link: CDSP_PROFILE_FULL}
        lm._link_identities[id(link)] = "identity_xyz"

        # Seed the buffer directly (simulate two earlier pushes)
        from collections import deque

        now = 1_000_000.0
        lm._recent_pushes[id(link)] = deque(
            [
                (now, "ch1", "message", {"seq": 1}),
                (now + 1, "ch1", "message_updated", {"msg_hash": "h1"}),
            ]
        )

        lm.handle_link_death(link)

        assert len(recorded) == 2
        assert recorded[0] == ("identity_xyz", "ch1", "message", {"seq": 1})
        assert recorded[1] == (
            "identity_xyz",
            "ch1",
            "message_updated",
            {"msg_hash": "h1"},
        )
        # Buffer drained; subscription cleared
        assert id(link) not in lm._recent_pushes
        assert link not in lm._subscriptions.get("ch1", {})

    def test_push_buffer_respects_time_retention(self):
        """Entries older than the retention window are trimmed on each push
        so the buffer doesn't grow unbounded on long-lived links."""
        lm = LiveSubscriptionManager()
        lm.set_defer_hook(lambda *a: None)
        lm._push_retention_s = 0.1  # 100 ms retention for the test

        link = self._make_live_link()
        from collections import deque

        old_ts = time.time() - 10  # well past retention
        lm._recent_pushes[id(link)] = deque([(old_ts, "ch1", "message", {"seq": 1})])

        with patch("hokora.protocol.live.RNS") as MRNS:
            MRNS.Link.ACTIVE = 0x01
            MRNS.Link.MDU = 10_000
            MRNS.Packet = MagicMock()
            lm._subscriptions["ch1"] = {link: CDSP_PROFILE_FULL}
            lm._link_identities[id(link)] = "identity_xyz"
            lm.push_event("ch1", "message", {"seq": 2})

        buf = lm._recent_pushes[id(link)]
        # Old entry trimmed; only the new one remains
        assert len(buf) == 1
        assert buf[0][3] == {"seq": 2}

    def test_push_buffer_respects_count_cap(self):
        """deque(maxlen=N) evicts oldest on overflow so memory is bounded."""
        lm = LiveSubscriptionManager()
        lm.set_defer_hook(lambda *a: None)
        lm._push_per_link_cap = 5  # tight cap for the test

        link = self._make_live_link()
        with patch("hokora.protocol.live.RNS") as MRNS:
            MRNS.Link.ACTIVE = 0x01
            MRNS.Link.MDU = 10_000
            MRNS.Packet = MagicMock()
            lm._subscriptions["ch1"] = {link: CDSP_PROFILE_FULL}
            lm._link_identities[id(link)] = "identity_xyz"
            for i in range(10):
                lm.push_event("ch1", "message", {"seq": i})

        buf = lm._recent_pushes[id(link)]
        assert len(buf) == 5
        # Newest 5 retained (seq 5..9)
        seqs = [entry[3]["seq"] for entry in buf]
        assert seqs == [5, 6, 7, 8, 9]

    def test_handle_link_death_without_identity_just_clears(self):
        """Anonymous zombie link: no identity, no replay target. Buffer and
        subscription get cleared without invoking the defer hook."""
        lm = LiveSubscriptionManager()
        called = []
        lm.set_defer_hook(lambda *a: called.append(a))

        link = self._make_live_link()
        lm._subscriptions["ch1"] = {link: CDSP_PROFILE_FULL}
        # No _link_identities entry
        from collections import deque

        lm._recent_pushes[id(link)] = deque([(time.time(), "ch1", "message", {"seq": 1})])

        lm.handle_link_death(link)

        assert called == []
        assert id(link) not in lm._recent_pushes
        assert link not in lm._subscriptions.get("ch1", {})


# ---------------------------------------------------------------------------
# Server: CDSP session resume flushes deferred items
# ---------------------------------------------------------------------------


class TestCDSPResumeFlush:
    async def test_resume_flushes_items_in_fifo_order(self, db_session):
        """handle_session_init with a valid resume_token returns queued items
        in creation order and removes them from the DB."""
        from hokora.config import NodeConfig

        cfg = NodeConfig(data_dir="/tmp", db_encrypt=False, db_key="k" * 64)
        mgr = CDSPSessionManager(cfg)

        sess_repo = SessionRepo(db_session)
        sess = await sess_repo.create_session(
            session_id="s1",
            identity_hash="id_1",
            sync_profile=CDSP_PROFILE_FULL,
            resume_token=b"R" * 16,
            expires_at=time.time() + 3600,
        )

        defer_repo = DeferredSyncItemRepo(db_session)
        for i in range(3):
            # Each item is a msgpack-encoded live-event envelope
            wire = msgpack.packb(
                {"event": "message", "data": {"seq": i + 1, "body": f"m{i}"}},
                use_bin_type=True,
            )
            await defer_repo.enqueue(
                sess.session_id, "ch1", SYNC_LIVE_EVENT, {"wire_hex": wire.hex()}
            )

        result = await mgr.handle_session_init(
            db_session,
            "id_1",
            {
                "cdsp_version": 1,
                "sync_profile": CDSP_PROFILE_FULL,
                "resume_token": b"R" * 16,
            },
        )

        assert result["rejected"] is False
        assert result["resumed"] is True
        assert result["flushed_count"] == 3
        items = result["flushed_items"]
        assert len(items) == 3
        # FIFO ordering preserved
        seqs = [it["payload"]["data"]["seq"] for it in items]
        assert seqs == [1, 2, 3]
        bodies = [it["payload"]["data"]["body"] for it in items]
        assert bodies == ["m0", "m1", "m2"]
        # All items deleted after flush
        remaining = await defer_repo.count_for_session(sess.session_id)
        assert remaining == 0

    async def test_envelope_preserves_bytes_fields(self, db_session):
        """Live events may carry bytes-typed fields (signatures, public keys).
        The wire_hex envelope round-trips them unchanged through the JSON
        payload column."""
        from hokora.config import NodeConfig

        cfg = NodeConfig(data_dir="/tmp", db_encrypt=False, db_key="k" * 64)
        mgr = CDSPSessionManager(cfg)

        sess_repo = SessionRepo(db_session)
        sess = await sess_repo.create_session(
            session_id="s2",
            identity_hash="id_2",
            sync_profile=CDSP_PROFILE_FULL,
            resume_token=b"T" * 16,
            expires_at=time.time() + 3600,
        )

        # Payload contains bytes fields that would break plain JSON serialization
        original_data = {
            "msg_hash": "abc",
            "lxmf_signature": b"\x01\x02\x03\x04",
            "sender_public_key": b"\xaa" * 32,
        }
        wire = msgpack.packb({"event": "message", "data": original_data}, use_bin_type=True)
        await DeferredSyncItemRepo(db_session).enqueue(
            sess.session_id, "ch1", SYNC_LIVE_EVENT, {"wire_hex": wire.hex()}
        )

        result = await mgr.handle_session_init(
            db_session,
            "id_2",
            {
                "cdsp_version": 1,
                "sync_profile": CDSP_PROFILE_FULL,
                "resume_token": b"T" * 16,
            },
        )

        item = result["flushed_items"][0]
        assert item["payload"]["event"] == "message"
        d = item["payload"]["data"]
        assert d["lxmf_signature"] == b"\x01\x02\x03\x04"
        assert d["sender_public_key"] == b"\xaa" * 32


# ---------------------------------------------------------------------------
# Client: SyncEngine reconnect state machine (no RNS runtime dependency)
# ---------------------------------------------------------------------------


class _FakeRNSLink:
    """Minimal stand-in for RNS.Link — exposes the attributes touched by
    `_on_link_closed` so the engine's state machine can be exercised without
    real networking."""

    ACTIVE = 0x01
    STALE = 0x02
    CLOSED = 0x03

    def __init__(self, status: int = CLOSED):
        self.status = status
        self.destination = MagicMock()


def _make_engine() -> "object":
    """Construct a real SyncEngine with all RNS/LXMF surfaces mocked.

    Returns the engine. Tests use ``engine._reconnect`` and
    ``engine._link_manager`` to reach the relevant subsystem — those
    are the supported architecture seams.
    """
    with (
        patch("hokora_tui.sync_engine.RNS"),
        patch("hokora_tui.sync.link_manager.RNS"),
        patch("hokora_tui.sync.dm_router.RNS"),
        patch("hokora_tui.sync.history_client.RNS"),
        patch("hokora_tui.sync.cdsp_client.RNS"),
        patch("hokora_tui.sync_engine.LXMF"),
        patch("hokora_tui.sync.dm_router.LXMF"),
    ):
        from hokora_tui.sync_engine import SyncEngine

        reticulum = MagicMock()
        identity = MagicMock()
        return SyncEngine(reticulum, identity)


class TestReconnectStateMachine:
    """Integration: SyncEngine wires ChannelLinkManager → ReconnectScheduler
    so transport drops trigger reconnect (or terminal connection_lost when
    the user explicitly disconnected). The scheduler itself is unit-tested
    in test_reconnect_scheduler.py; these cases verify the engine's wiring."""

    def test_link_close_with_targets_starts_reconnect(self):
        engine = _make_engine()
        events = []
        engine.set_event_callback(lambda ev, data: events.append(ev))
        # Add a target the way connect_channel would
        engine._reconnect.add_target("ch1", b"\xaa" * 16)

        # The link_manager fires its on_closed callback when a Link dies.
        # That callback was wired to SyncEngine._on_link_closed in __init__.
        # After the rewrite to pure subsystem-driven flow, the integration
        # path is: ChannelLinkManager.set_on_closed(SyncEngine._on_link_closed)
        # → on close → SyncEngine decides scheduler.trigger() vs terminal emit.
        with patch.object(engine._reconnect, "trigger") as trig:
            dead_link = MagicMock()
            engine._on_link_closed("ch1", dead_link)
            trig.assert_called_once()
        assert "connection_lost" not in events

    def test_user_disconnect_emits_terminal(self):
        engine = _make_engine()
        events = []
        engine.set_event_callback(lambda ev, data: events.append(ev))
        # No reconnect targets; user disconnected
        engine._reconnect.clear_targets()
        engine._reconnect.mark_user_disconnected()

        with patch.object(engine._reconnect, "trigger") as trig:
            dead_link = MagicMock()
            engine._on_link_closed("ch1", dead_link)
            trig.assert_not_called()
        assert "connection_lost" in events

    def test_disconnect_all_marks_user_disconnected_and_clears_targets(self):
        engine = _make_engine()
        engine._reconnect.add_target("ch1", b"\xaa" * 16)
        engine._reconnect.add_target("ch2", b"\xbb" * 16)

        engine.disconnect_all()

        assert engine._reconnect.is_user_disconnected() is True
        assert engine._reconnect.targets_snapshot() == {}
        assert engine._reconnect.stop_event.is_set() is True

    def test_disconnect_channel_removes_only_that_target(self):
        engine = _make_engine()
        engine._reconnect.add_target("ch1", b"\xaa" * 16)
        engine._reconnect.add_target("ch2", b"\xbb" * 16)

        engine.disconnect_channel("ch1")

        targets = engine._reconnect.targets_snapshot()
        assert "ch1" not in targets
        assert "ch2" in targets
        assert engine._reconnect.is_user_disconnected() is False

    def test_backoff_schedule_progression(self):
        """The published schedule matches the plan: 1,2,5,10,30,60 capped."""
        from hokora_tui.sync_engine import RECONNECT_BACKOFF_SCHEDULE

        assert RECONNECT_BACKOFF_SCHEDULE == (1, 2, 5, 10, 30, 60)
        max_step = len(RECONNECT_BACKOFF_SCHEDULE) - 1
        for attempt in (max_step, max_step + 3, max_step + 100):
            step = min(attempt, max_step)
            assert RECONNECT_BACKOFF_SCHEDULE[step] == 60
