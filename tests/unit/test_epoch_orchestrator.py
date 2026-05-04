# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for ``EpochOrchestrator``.

The orchestrator owns the per-mirror EpochManager registry. These tests
cover the full public API: register (+ idempotency), get, load_state
(empty DB, peer with matching mirror, peer without matching mirror,
RNS.Identity.recall failure, FS-disabled config), persist_all,
teardown, shutdown, attach_to_pushers.
"""

from __future__ import annotations

import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch


from hokora.db.models import FederationEpochState
from hokora.federation.epoch_orchestrator import EpochOrchestrator


def _make_config(fs_enabled: bool = True, fs_epoch_duration: int = 3600):
    c = MagicMock()
    c.fs_enabled = fs_enabled
    c.fs_epoch_duration = fs_epoch_duration
    return c


def _make_identity_manager():
    node_identity = MagicMock()
    node_identity.sign = MagicMock(return_value=b"sig" * 21)
    node_identity.get_public_key = MagicMock(return_value=b"pub" * 16)
    im = MagicMock()
    im.get_node_identity = MagicMock(return_value=node_identity)
    return im


def _make_mirror(remote_hash_hex: str, channel_id: str = "chan-1"):
    mirror = MagicMock()
    mirror.remote_hash = bytes.fromhex(remote_hash_hex)
    mirror.channel_id = channel_id
    mirror._link = MagicMock()
    return mirror


def _sendfn_factory(key: str):
    """Stub send_callback_factory — returns a no-op send for any key."""
    return lambda _frame: None


def _make_orchestrator(session_factory=None, loop=None, config=None):
    return EpochOrchestrator(
        config=config or _make_config(),
        loop=loop,
        session_factory=session_factory or MagicMock(),
        identity_manager=_make_identity_manager(),
        send_callback_factory=_sendfn_factory,
    )


# ── register + get + __contains__ + __len__ ────────────────────────


def test_register_creates_and_stores_em():
    orch = _make_orchestrator()
    with patch(
        "hokora.federation.epoch_orchestrator.EpochManager",
        return_value=MagicMock(),
    ) as EM:
        em = orch.register(
            "aa:ch-1",
            peer_identity_hash="aa" * 32,
            is_initiator=True,
            peer_rns_identity=MagicMock(),
        )
    EM.assert_called_once()
    assert orch.get("aa:ch-1") is em
    assert "aa:ch-1" in orch
    assert len(orch) == 1


def test_register_is_idempotent():
    """Calling register twice with the same key returns the first EM,
    never constructs a second."""
    orch = _make_orchestrator()
    with patch(
        "hokora.federation.epoch_orchestrator.EpochManager",
        return_value=MagicMock(),
    ) as EM:
        em1 = orch.register(
            "aa:ch-1",
            peer_identity_hash="aa" * 32,
            is_initiator=True,
            peer_rns_identity=MagicMock(),
        )
        em2 = orch.register(
            "aa:ch-1",
            peer_identity_hash="aa" * 32,
            is_initiator=True,
            peer_rns_identity=MagicMock(),
        )
    assert em1 is em2
    assert EM.call_count == 1
    assert len(orch) == 1


def test_get_missing_returns_none():
    orch = _make_orchestrator()
    assert orch.get("nonexistent") is None
    assert "nonexistent" not in orch


def test_register_passes_fs_epoch_duration_from_config():
    orch = _make_orchestrator(config=_make_config(fs_epoch_duration=1800))
    with patch("hokora.federation.epoch_orchestrator.EpochManager") as EM:
        orch.register(
            "aa:ch-1",
            peer_identity_hash="aa" * 32,
            is_initiator=False,
            peer_rns_identity=MagicMock(),
        )
    assert EM.call_args.kwargs["epoch_duration"] == 1800


def test_register_wires_send_callback_from_factory():
    """The send_callback_factory gets called with the mirror_key so
    the handshake orchestrator can scope the send to the right link."""
    captured_keys: list[str] = []

    def factory(key: str):
        captured_keys.append(key)
        return lambda _frame: None

    orch = EpochOrchestrator(
        config=_make_config(),
        loop=None,
        session_factory=MagicMock(),
        identity_manager=_make_identity_manager(),
        send_callback_factory=factory,
    )
    with patch("hokora.federation.epoch_orchestrator.EpochManager"):
        orch.register(
            "deadbeef:chan-X",
            peer_identity_hash="d" * 64,
            is_initiator=True,
            peer_rns_identity=MagicMock(),
        )
    assert captured_keys == ["deadbeef:chan-X"]


# ── load_state ──────────────────────────────────────────────────────


def _make_session_factory_with_states(states: list):
    """Return an async session factory whose execute() yields given states."""
    execute_result = MagicMock()
    scalars = MagicMock()
    scalars.all = MagicMock(return_value=states)
    execute_result.scalars = MagicMock(return_value=scalars)

    session = MagicMock()
    session.execute = AsyncMock(return_value=execute_result)

    class _SessionCtx:
        async def __aenter__(self_inner):
            return session

        async def __aexit__(self_inner, *args):
            return None

    class _BeginCtx:
        async def __aenter__(self_inner):
            return session

        async def __aexit__(self_inner, *args):
            return None

    session.begin = MagicMock(return_value=_BeginCtx())

    def factory():
        return _SessionCtx()

    return factory, session


async def test_load_state_noop_when_fs_disabled():
    orch = _make_orchestrator(config=_make_config(fs_enabled=False))
    await orch.load_state({})
    assert len(orch) == 0


async def test_load_state_empty_db():
    factory, _sess = _make_session_factory_with_states([])
    orch = _make_orchestrator(session_factory=factory)
    await orch.load_state({"aa:ch-1": _make_mirror("aa" * 16)})
    assert len(orch) == 0


async def test_load_state_with_matching_mirror_restores_em():
    peer_hash = "bb" * 32
    state = SimpleNamespace(
        peer_identity_hash=peer_hash,
        is_initiator=True,
        epoch_duration=3600,
        epoch_start_time=time.time() - 60,
    )
    factory, _sess = _make_session_factory_with_states([state])

    mirror = _make_mirror("bb" * 16)
    mirrors = {f"{peer_hash}:chan-1": mirror}

    orch = _make_orchestrator(session_factory=factory)

    em_mock = MagicMock()
    em_mock.load_state = AsyncMock()
    em_mock.is_initiator = True
    em_mock.is_active = True
    em_mock.start_rotation_scheduler = MagicMock()

    with (
        patch(
            "hokora.federation.epoch_orchestrator.RNS.Identity.recall",
            return_value=MagicMock(),
        ),
        patch(
            "hokora.federation.epoch_orchestrator.EpochManager",
            return_value=em_mock,
        ),
    ):
        await orch.load_state(mirrors)

    em_mock.load_state.assert_awaited_once()
    assert orch.get(f"{peer_hash}:chan-1") is em_mock
    assert mirror._epoch_manager is em_mock


async def test_load_state_skips_peer_without_matching_mirror():
    state = SimpleNamespace(peer_identity_hash="ff" * 32, is_initiator=True, epoch_duration=3600)
    factory, _sess = _make_session_factory_with_states([state])
    orch = _make_orchestrator(session_factory=factory)

    # A different peer's mirror — won't match the state's peer_hash prefix.
    mirrors = {"aa" * 32 + ":chan-1": _make_mirror("aa" * 16)}

    with patch("hokora.federation.epoch_orchestrator.EpochManager") as EM:
        await orch.load_state(mirrors)

    EM.assert_not_called()
    assert len(orch) == 0


async def test_load_state_tolerates_recall_returning_none():
    """RNS.Identity.recall returns None when peer has never announced —
    the EpochManager still gets created (it accepts None peer identity)."""
    peer_hash = "cc" * 32
    state = SimpleNamespace(peer_identity_hash=peer_hash, is_initiator=False, epoch_duration=3600)
    factory, _sess = _make_session_factory_with_states([state])
    mirror = _make_mirror("cc" * 16)
    mirrors = {f"{peer_hash}:chan-1": mirror}

    orch = _make_orchestrator(session_factory=factory)

    em_mock = MagicMock()
    em_mock.load_state = AsyncMock()
    em_mock.is_initiator = False
    em_mock.is_active = True

    with (
        patch(
            "hokora.federation.epoch_orchestrator.RNS.Identity.recall",
            return_value=None,
        ),
        patch(
            "hokora.federation.epoch_orchestrator.EpochManager",
            return_value=em_mock,
        ) as EM,
    ):
        await orch.load_state(mirrors)

    # peer_rns_identity=None was passed to EpochManager
    assert EM.call_args.kwargs["peer_rns_identity"] is None


async def test_load_state_starts_rotation_only_for_initiator_active_with_loop():
    loop = MagicMock()
    peer_hash = "dd" * 32

    def _state(initiator):
        return SimpleNamespace(
            peer_identity_hash=peer_hash, is_initiator=initiator, epoch_duration=3600
        )

    # Case 1: initiator + active + loop → scheduler started
    factory, _sess = _make_session_factory_with_states([_state(True)])
    orch = EpochOrchestrator(
        config=_make_config(),
        loop=loop,
        session_factory=factory,
        identity_manager=_make_identity_manager(),
        send_callback_factory=_sendfn_factory,
    )
    em_mock = MagicMock()
    em_mock.load_state = AsyncMock()
    em_mock.is_initiator = True
    em_mock.is_active = True
    em_mock.start_rotation_scheduler = MagicMock()
    with (
        patch(
            "hokora.federation.epoch_orchestrator.RNS.Identity.recall",
            return_value=MagicMock(),
        ),
        patch(
            "hokora.federation.epoch_orchestrator.EpochManager",
            return_value=em_mock,
        ),
    ):
        await orch.load_state({f"{peer_hash}:chan-1": _make_mirror("dd" * 16)})
    em_mock.start_rotation_scheduler.assert_called_once_with(loop)

    # Case 2: initiator but not active → scheduler NOT started
    factory2, _ = _make_session_factory_with_states([_state(True)])
    orch2 = EpochOrchestrator(
        config=_make_config(),
        loop=loop,
        session_factory=factory2,
        identity_manager=_make_identity_manager(),
        send_callback_factory=_sendfn_factory,
    )
    em2 = MagicMock()
    em2.load_state = AsyncMock()
    em2.is_initiator = True
    em2.is_active = False
    em2.start_rotation_scheduler = MagicMock()
    with (
        patch(
            "hokora.federation.epoch_orchestrator.RNS.Identity.recall",
            return_value=MagicMock(),
        ),
        patch(
            "hokora.federation.epoch_orchestrator.EpochManager",
            return_value=em2,
        ),
    ):
        await orch2.load_state({f"{peer_hash}:chan-1": _make_mirror("dd" * 16)})
    em2.start_rotation_scheduler.assert_not_called()

    # Case 3: active but NOT initiator → scheduler NOT started
    factory3, _ = _make_session_factory_with_states([_state(False)])
    orch3 = EpochOrchestrator(
        config=_make_config(),
        loop=loop,
        session_factory=factory3,
        identity_manager=_make_identity_manager(),
        send_callback_factory=_sendfn_factory,
    )
    em3 = MagicMock()
    em3.load_state = AsyncMock()
    em3.is_initiator = False
    em3.is_active = True
    em3.start_rotation_scheduler = MagicMock()
    with (
        patch(
            "hokora.federation.epoch_orchestrator.RNS.Identity.recall",
            return_value=MagicMock(),
        ),
        patch(
            "hokora.federation.epoch_orchestrator.EpochManager",
            return_value=em3,
        ),
    ):
        await orch3.load_state({f"{peer_hash}:chan-1": _make_mirror("dd" * 16)})
    em3.start_rotation_scheduler.assert_not_called()


async def test_load_state_catches_db_errors():
    """A DB failure during load_state must not crash the daemon start path."""
    broken_factory = MagicMock(side_effect=RuntimeError("db go boom"))
    orch = EpochOrchestrator(
        config=_make_config(),
        loop=None,
        session_factory=broken_factory,
        identity_manager=_make_identity_manager(),
        send_callback_factory=_sendfn_factory,
    )
    await orch.load_state({})  # must not raise


# ── persist_all ─────────────────────────────────────────────────────


async def test_persist_all_only_persists_active_managers():
    orch = _make_orchestrator()

    active = MagicMock()
    active.is_active = True
    active.persist_state = AsyncMock()
    active.peer_identity_hash = "a" * 64

    inactive = MagicMock()
    inactive.is_active = False
    inactive.persist_state = AsyncMock()
    inactive.peer_identity_hash = "b" * 64

    orch._managers["a:1"] = active
    orch._managers["b:1"] = inactive

    await orch.persist_all()

    active.persist_state.assert_awaited_once()
    inactive.persist_state.assert_not_called()


async def test_persist_all_tolerates_one_em_failing():
    """A raise in one EM's persist_state must not block the others."""
    orch = _make_orchestrator()

    good = MagicMock()
    good.is_active = True
    good.persist_state = AsyncMock()
    good.peer_identity_hash = "g" * 64

    bad = MagicMock()
    bad.is_active = True
    bad.persist_state = AsyncMock(side_effect=RuntimeError("io failed"))
    bad.peer_identity_hash = "b" * 64

    # Insert bad first; good should still be awaited.
    orch._managers["b:1"] = bad
    orch._managers["g:1"] = good

    await orch.persist_all()

    bad.persist_state.assert_awaited_once()
    good.persist_state.assert_awaited_once()


# ── teardown + shutdown ─────────────────────────────────────────────


def test_teardown_removes_and_erases():
    orch = _make_orchestrator()
    em = MagicMock()
    em.teardown = MagicMock()
    orch._managers["aa:ch-1"] = em
    orch.teardown("aa:ch-1")
    em.teardown.assert_called_once()
    assert orch.get("aa:ch-1") is None
    assert len(orch) == 0


def test_teardown_unknown_key_is_noop():
    orch = _make_orchestrator()
    orch.teardown("never-registered")  # no raise


async def test_shutdown_tears_down_all_and_clears():
    orch = _make_orchestrator()
    em1 = MagicMock()
    em1.peer_identity_hash = "a" * 64
    em1.teardown = MagicMock()
    em2 = MagicMock()
    em2.peer_identity_hash = "b" * 64
    em2.teardown = MagicMock()

    orch._managers["a:1"] = em1
    orch._managers["b:1"] = em2

    await orch.shutdown()

    em1.teardown.assert_called_once()
    em2.teardown.assert_called_once()
    assert len(orch) == 0


async def test_shutdown_tolerates_teardown_exceptions():
    orch = _make_orchestrator()
    bad = MagicMock()
    bad.peer_identity_hash = "b" * 64
    bad.teardown = MagicMock(side_effect=RuntimeError("wedged"))
    good = MagicMock()
    good.peer_identity_hash = "g" * 64
    good.teardown = MagicMock()

    orch._managers["b:1"] = bad
    orch._managers["g:1"] = good

    await orch.shutdown()

    bad.teardown.assert_called_once()
    good.teardown.assert_called_once()
    assert len(orch) == 0


# ── attach_to_pushers ──────────────────────────────────────────────


def test_attach_to_pushers_wires_existing_managers_onto_matching_pushers():
    orch = _make_orchestrator()

    em = MagicMock()
    orch._managers["xx:ch-1"] = em

    pusher = MagicMock()
    pushers = {"xx:ch-1": pusher, "yy:ch-2": MagicMock()}

    orch.attach_to_pushers(pushers)

    assert pusher._epoch_manager is em
    # The other pusher had no matching manager — must not be touched.
    assert pushers["yy:ch-2"]._epoch_manager is not em


def test_attach_to_pushers_noop_for_empty_registry():
    orch = _make_orchestrator()
    pushers = {"any:key": MagicMock()}
    orch.attach_to_pushers(pushers)
    # No _epoch_manager set on any pusher.
    assert pushers["any:key"]._epoch_manager is not orch.get("any:key")


# ── attach_to_link_manager ─────────────────────────────────────────


def test_attach_to_link_manager_shares_registry_reference():
    """Orchestrator and LinkManager must share the SAME dict object so
    handshake-time register() additions become immediately visible to
    the inbound-frame receive path without a second wire-up."""
    orch = _make_orchestrator()
    link_manager = MagicMock()
    link_manager._epoch_managers = {}

    orch.attach_to_link_manager(link_manager)
    assert link_manager._epoch_managers is orch._managers

    # Simulate a handshake that registers a new manager post-attach; the
    # LinkManager lookup must see it without any second call.
    with patch(
        "hokora.federation.epoch_orchestrator.EpochManager",
        return_value=MagicMock(),
    ):
        orch.register(
            "bb:ch-7",
            peer_identity_hash="bb" * 32,
            is_initiator=False,
            peer_rns_identity=MagicMock(),
        )

    assert "bb:ch-7" in link_manager._epoch_managers


# ── DB model import sanity ─────────────────────────────────────────


def test_federation_epoch_state_import_works():
    """Sanity: the ORM model load_state uses must be importable.
    Guards against accidental circular-import breakage during the
    extract."""
    assert FederationEpochState is not None


# ── End-to-end: register then shutdown erases keys ─────────────────


async def test_register_then_shutdown_calls_teardown():
    orch = _make_orchestrator()
    em = MagicMock()
    em.peer_identity_hash = "a" * 64
    em.teardown = MagicMock()
    with patch("hokora.federation.epoch_orchestrator.EpochManager", return_value=em):
        orch.register(
            "aa:ch-1",
            peer_identity_hash="aa" * 32,
            is_initiator=True,
            peer_rns_identity=MagicMock(),
        )
    assert "aa:ch-1" in orch
    await orch.shutdown()
    em.teardown.assert_called_once()
    assert len(orch) == 0
