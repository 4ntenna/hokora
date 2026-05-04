# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for ``FederationHandshakeOrchestrator``."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch


def _make_config(require_signed=True, fs_enabled=True, fs_epoch_duration=3600):
    c = MagicMock()
    c.node_name = "test-node"
    c.require_signed_federation = require_signed
    c.fs_enabled = fs_enabled
    c.fs_epoch_duration = fs_epoch_duration
    return c


def _make_identity_manager():
    node_identity = MagicMock()
    node_identity.sign = MagicMock(return_value=b"signed" * 16)
    # Real RNS.Identity.get_public_key() returns a 64-byte X25519+Ed25519
    # concatenation; sig_pub_bytes is the 32-byte Ed25519 portion. The
    # federation wire format uses the 32-byte signing key only — see
    # hokora.federation.auth.signing_public_key. Mocks must mirror
    # this shape so wire-contract regressions are visible in unit tests.
    node_identity.sig_pub_bytes = b"\x42" * 32
    node_identity.get_public_key = MagicMock(return_value=b"\x11" * 32 + b"\x42" * 32)
    im = MagicMock()
    im.get_node_identity = MagicMock(return_value=node_identity)
    im.get_or_create_node_identity = MagicMock(return_value=node_identity)
    im.get_node_identity_hash = MagicMock(return_value="a" * 64)
    im.get_signing_public_key = MagicMock(return_value=node_identity.sig_pub_bytes)
    return im, node_identity


def _make_mirror(with_link=True):
    mirror = MagicMock()
    mirror.remote_hash = b"\xaa" * 16
    mirror.channel_id = "chan-1"
    mirror._link = MagicMock() if with_link else None
    mirror._pending_challenge = None
    mirror._authenticated = False
    mirror._sync_history = MagicMock()
    return mirror


def _make_orchestrator(
    config=None,
    loop=None,
    mirrors=None,
    pushers=None,
    epoch_managers=None,
):
    from hokora.federation.auth import FederationAuth
    from hokora.federation.handshake_orchestrator import (
        FederationHandshakeOrchestrator,
    )

    im, node_identity = _make_identity_manager()
    mirrors = mirrors or {}
    pushers = pushers or {}

    # The handshake orchestrator receives an EpochOrchestrator via DI
    # rather than a mutable dict. A stand-in exposes the minimum surface
    # the handshake code uses (``get``, ``register``). Tests that want
    # to preseed managers pass ``epoch_managers={key: em}``; this
    # stand-in copies those into its own registry so ``get()`` returns
    # them as the real orchestrator would.
    class _FakeEpochOrchestrator:
        def __init__(self):
            self.managers = dict(epoch_managers or {})

        def get(self, key):
            return self.managers.get(key)

        def register(self, key, **_kwargs):
            # Not used by the handshake happy-path tests in this file;
            # TestEpochHandshake patches EpochManager directly and asserts
            # via the exposed dict. Keep this minimal so tests make the
            # contract obvious.
            return self.managers.get(key)

    fake_orch = _FakeEpochOrchestrator()

    orch = FederationHandshakeOrchestrator(
        config=config or _make_config(),
        loop=loop or MagicMock(),
        session_factory=MagicMock(),
        identity_manager=im,
        federation_auth=FederationAuth(),
        mirrors_view=lambda: mirrors,
        pushers_view=lambda: pushers,
        epoch_orchestrator=fake_orch,
    )
    return orch, im, node_identity, mirrors, pushers, fake_orch.managers


class TestInitiate:
    def test_sends_step1_packet_with_challenge(self):
        orch, im, _ni, _m, _p, _e = _make_orchestrator()
        mirror = _make_mirror()
        with patch("hokora.federation.handshake_orchestrator.RNS.Packet") as Packet:
            orch.initiate(mirror)
        Packet.assert_called_once()
        args, _kw = Packet.call_args
        assert args[0] is mirror._link
        assert mirror._pending_challenge is not None

    def test_stores_pending_challenge_on_mirror(self):
        orch, *_ = _make_orchestrator()
        mirror = _make_mirror()
        with patch("hokora.federation.handshake_orchestrator.RNS.Packet"):
            orch.initiate(mirror)
        assert isinstance(mirror._pending_challenge, bytes)
        assert len(mirror._pending_challenge) > 0

    def test_aborts_when_link_missing_and_require_signed(self):
        orch, *_ = _make_orchestrator(config=_make_config(require_signed=True))
        mirror = _make_mirror(with_link=False)
        with patch("hokora.federation.handshake_orchestrator.RNS.Packet") as Packet:
            orch.initiate(mirror)
        Packet.assert_not_called()
        mirror._sync_history.assert_not_called()

    def test_falls_through_to_sync_history_when_require_signed_false(self):
        orch, *_ = _make_orchestrator(config=_make_config(require_signed=False))
        mirror = _make_mirror(with_link=False)
        orch.initiate(mirror)
        mirror._sync_history.assert_called_once()


class TestOnResponseStep2:
    def test_rejects_on_verify_failure(self):
        """Security property: no fallback to unauthenticated sync."""
        orch, im, _ni, _m, pushers, _e = _make_orchestrator()
        mirror = _make_mirror()
        mirror._pending_challenge = b"chal"
        with patch(
            "hokora.federation.handshake_orchestrator.FederationAuth.verify_response",
            return_value=False,
        ):
            orch.on_handshake_response(
                mirror,
                {
                    "step": 2,
                    "accepted": True,
                    "challenge_response": b"bad",
                    "peer_public_key": b"\x42" * 32,
                },
            )
        mirror._sync_history.assert_not_called()
        assert mirror._authenticated is False

    def test_rejects_64_byte_peer_public_key_before_verifier(self):
        """Wire-contract: 64-byte X25519+Ed25519 blob (the historical bug
        shape) is rejected with a structural-mismatch log line; verifier
        is never called, peer key is never persisted."""
        orch, im, _ni, _m, pushers, _e = _make_orchestrator()
        mirror = _make_mirror()
        mirror._pending_challenge = b"chal"
        with (
            patch(
                "hokora.federation.handshake_orchestrator.FederationAuth.verify_response"
            ) as verify,
            patch(
                "hokora.federation.handshake_orchestrator.asyncio.run_coroutine_threadsafe"
            ) as sched,
        ):
            orch.on_handshake_response(
                mirror,
                {
                    "step": 2,
                    "accepted": True,
                    "challenge_response": b"sig",
                    "peer_public_key": b"\xaa" * 64,  # the bug shape
                },
            )
        verify.assert_not_called()
        sched.assert_not_called()
        assert mirror._authenticated is False

    def test_rejects_non_bytes_peer_public_key(self):
        orch, *_ = _make_orchestrator()
        mirror = _make_mirror()
        mirror._pending_challenge = b"chal"
        with patch(
            "hokora.federation.handshake_orchestrator.FederationAuth.verify_response"
        ) as verify:
            orch.on_handshake_response(
                mirror,
                {
                    "step": 2,
                    "accepted": True,
                    "challenge_response": b"sig",
                    "peer_public_key": "definitely-not-bytes",
                },
            )
        verify.assert_not_called()
        assert mirror._authenticated is False

    def test_sends_step3_with_counter_response(self):
        orch, im, _ni, _m, _p, _e = _make_orchestrator()
        mirror = _make_mirror()
        mirror._pending_challenge = b"chal"
        with (
            patch(
                "hokora.federation.handshake_orchestrator.FederationAuth.verify_response",
                return_value=True,
            ),
            patch("hokora.federation.handshake_orchestrator.asyncio.run_coroutine_threadsafe"),
            patch("hokora.federation.handshake_orchestrator.RNS.Packet") as Packet,
        ):
            orch.on_handshake_response(
                mirror,
                {
                    "step": 2,
                    "accepted": True,
                    "challenge_response": b"ok",
                    "peer_public_key": b"\x42" * 32,
                    "counter_challenge": b"cc",
                },
            )
        Packet.assert_called()
        assert mirror._authenticated is True
        mirror._sync_history.assert_called_once()

    def test_persists_peer_public_key(self):
        orch, im, _ni, _m, _p, _e = _make_orchestrator()
        mirror = _make_mirror()
        mirror._pending_challenge = b"chal"
        with (
            patch(
                "hokora.federation.handshake_orchestrator.FederationAuth.verify_response",
                return_value=True,
            ),
            patch(
                "hokora.federation.handshake_orchestrator.asyncio.run_coroutine_threadsafe"
            ) as sched,
            patch("hokora.federation.handshake_orchestrator.RNS.Packet"),
        ):
            orch.on_handshake_response(
                mirror,
                {
                    "step": 2,
                    "accepted": True,
                    "challenge_response": b"ok",
                    "peer_public_key": b"\x42" * 32,
                    "identity_hash": "z" * 64,
                },
            )
        sched.assert_called_once()
        # Close coroutine to silence "never awaited"
        sched.call_args.args[0].close()

    def test_drains_pending_push_queue(self):
        pusher = MagicMock()
        pusher.set_link = MagicMock()
        pusher.push_pending = AsyncMock()
        key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:chan-1"
        orch, *_rest = _make_orchestrator(pushers={key: pusher})
        mirror = _make_mirror()
        mirror._pending_challenge = b"chal"
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            with (
                patch(
                    "hokora.federation.handshake_orchestrator.FederationAuth.verify_response",
                    return_value=True,
                ),
                patch("hokora.federation.handshake_orchestrator.asyncio.run_coroutine_threadsafe"),
                patch("hokora.federation.handshake_orchestrator.RNS.Packet"),
            ):
                orch.on_handshake_response(
                    mirror,
                    {
                        "step": 2,
                        "accepted": True,
                        "challenge_response": b"ok",
                        "peer_public_key": b"\x42" * 32,
                    },
                )
            pusher.set_link.assert_called_once_with(mirror._link)
            pusher.push_pending.assert_called_once()
        finally:
            loop.close()
            asyncio.set_event_loop(None)


class TestOnResponseStep4:
    def test_triggers_epoch_handshake_when_fs_enabled(self):
        orch, *_ = _make_orchestrator(config=_make_config(fs_enabled=True))
        mirror = _make_mirror()
        with patch.object(orch, "_initiate_epoch_handshake") as fn:
            orch.on_handshake_response(mirror, {"step": 4, "fs_capable": True})
        fn.assert_called_once_with(mirror)
        assert mirror._authenticated is True

    def test_skips_epoch_when_fs_disabled(self):
        orch, *_ = _make_orchestrator(config=_make_config(fs_enabled=False))
        mirror = _make_mirror()
        with patch.object(orch, "_initiate_epoch_handshake") as fn:
            orch.on_handshake_response(mirror, {"step": 4, "fs_capable": True})
        fn.assert_not_called()
        assert mirror._authenticated is True

    def test_skips_epoch_when_peer_not_fs_capable(self):
        orch, *_ = _make_orchestrator(config=_make_config(fs_enabled=True))
        mirror = _make_mirror()
        with patch.object(orch, "_initiate_epoch_handshake") as fn:
            orch.on_handshake_response(mirror, {"step": 4, "fs_capable": False})
        fn.assert_not_called()


class TestOnResponseStep6:
    def test_handles_epoch_rotate_ack(self):
        em = MagicMock()
        em.handle_epoch_rotate_ack = MagicMock()
        em.start_rotation_scheduler = MagicMock()
        key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:chan-1"
        loop = MagicMock()
        orch, *_rest = _make_orchestrator(epoch_managers={key: em}, loop=loop)
        mirror = _make_mirror()
        orch.on_handshake_response(
            mirror,
            {"step": 6, "epoch_rotate_ack_frame": b"frame"},
        )
        em.handle_epoch_rotate_ack.assert_called_once_with(b"frame")
        em.start_rotation_scheduler.assert_called_once_with(loop)

    def test_step6_without_em_is_noop(self):
        orch, *_ = _make_orchestrator()
        mirror = _make_mirror()
        orch.on_handshake_response(
            mirror, {"step": 6, "epoch_rotate_ack_frame": b"frame"}
        )  # no raise


class TestOnPushAck:
    def test_routes_to_correct_pusher(self):
        pusher = MagicMock()
        pusher.handle_push_ack = MagicMock()
        key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:chan-1"
        orch, *_rest = _make_orchestrator(pushers={key: pusher})
        mirror = _make_mirror()
        data = {"ack_seq": 5}
        orch.on_push_ack(mirror, data)
        pusher.handle_push_ack.assert_called_once_with(data)

    def test_on_push_ack_with_no_pusher_is_noop(self):
        orch, *_ = _make_orchestrator()
        mirror = _make_mirror()
        orch.on_push_ack(mirror, {})  # no raise


class TestEpochHandshake:
    def test_initiate_epoch_handshake_builds_em_in_registry(self):
        """The handshake orchestrator delegates EpochManager construction
        to ``epoch_orchestrator.register(...)`` and wires the returned
        manager onto the mirror. This test verifies register is called
        with the mirror_key and that the returned manager ends up on
        ``mirror._epoch_manager``."""
        orch, im, _ni, _mirrors, _pushers, _em_map = _make_orchestrator()
        mirror = _make_mirror()
        em_mock = MagicMock()
        em_mock.create_epoch_rotate = MagicMock(return_value=b"frame")

        # Replace the fake orchestrator's register with a spy returning
        # our em_mock, then assert the handshake code path called it.
        orch._epoch_orchestrator.register = MagicMock(return_value=em_mock)

        with (
            patch(
                "hokora.federation.handshake_orchestrator.RNS.Identity.recall",
                return_value=MagicMock(),
            ),
            patch("hokora.federation.handshake_orchestrator.RNS.Packet"),
        ):
            orch._initiate_epoch_handshake(mirror)

        key = f"{mirror.remote_hash.hex()}:{mirror.channel_id}"
        orch._epoch_orchestrator.register.assert_called_once()
        call_kwargs = orch._epoch_orchestrator.register.call_args.kwargs
        assert orch._epoch_orchestrator.register.call_args.args[0] == key
        assert call_kwargs["peer_identity_hash"] == mirror.remote_hash.hex()
        assert call_kwargs["is_initiator"] is True
        assert mirror._epoch_manager is em_mock

    def test_make_epoch_send_callback_wires_packet_send(self):
        mirror = _make_mirror()
        key = f"{mirror.remote_hash.hex()}:{mirror.channel_id}"
        orch, *_ = _make_orchestrator(mirrors={key: mirror})
        send = orch._make_epoch_send_callback(key)
        with patch("hokora.federation.handshake_orchestrator.RNS.Packet") as Packet:
            send(b"frame")
        Packet.assert_called_once()

    def test_make_epoch_send_callback_noop_when_mirror_missing(self):
        orch, *_ = _make_orchestrator(mirrors={})
        send = orch._make_epoch_send_callback("missing:key")
        with patch("hokora.federation.handshake_orchestrator.RNS.Packet") as Packet:
            send(b"frame")
        Packet.assert_not_called()


class TestEpochStep5SenderContract:
    """Wire-contract: every step-5 (FS epoch) frame from this orchestrator
    must include identity_hash so the receiver can RNS.Identity.recall
    the peer for FS-frame signature verification. Pinning this contract
    because a missing identity_hash surfaces as
    'Missing identity_hash in handshake' on the receiver, blocking the
    handshake."""

    def test_initiate_epoch_handshake_payload_includes_identity_hash(self):
        from hokora.protocol.wire import decode_sync_request

        orch, im, *_ = _make_orchestrator(config=_make_config(fs_enabled=True))
        mirror = _make_mirror()
        em_mock = MagicMock()
        em_mock.create_epoch_rotate = MagicMock(return_value=b"frame")
        orch._epoch_orchestrator.register = MagicMock(return_value=em_mock)

        with (
            patch(
                "hokora.federation.handshake_orchestrator.RNS.Identity.recall",
                return_value=MagicMock(),
            ),
            patch("hokora.federation.handshake_orchestrator.RNS.Packet") as Packet,
        ):
            orch._initiate_epoch_handshake(mirror)

        Packet.assert_called_once()
        wire_bytes = Packet.call_args.args[1]
        decoded = decode_sync_request(wire_bytes)
        payload = decoded["payload"]
        assert payload["step"] == 5
        assert payload["identity_hash"] == im.get_node_identity_hash.return_value
        assert payload["epoch_rotate_frame"] == b"frame"

    def test_make_epoch_send_callback_payload_includes_identity_hash(self):
        from hokora.protocol.wire import decode_sync_request

        mirror = _make_mirror()
        key = f"{mirror.remote_hash.hex()}:{mirror.channel_id}"
        orch, im, *_ = _make_orchestrator(mirrors={key: mirror})
        send = orch._make_epoch_send_callback(key)

        with patch("hokora.federation.handshake_orchestrator.RNS.Packet") as Packet:
            send(b"rotated_frame")

        Packet.assert_called_once()
        wire_bytes = Packet.call_args.args[1]
        decoded = decode_sync_request(wire_bytes)
        payload = decoded["payload"]
        assert payload["step"] == 5
        assert payload["identity_hash"] == im.get_node_identity_hash.return_value
        assert payload["epoch_rotate_frame"] == b"rotated_frame"


class TestScheduleOnMainLoopHelper:
    """Single chokepoint for cross-thread coroutine scheduling. Must
    survive: (a) being called from RNS's packet-callback thread (no
    current asyncio loop), (b) shutdown races where self._loop is None
    or stopped, (c) coroutines that raise — exceptions surface in logs,
    not silent ``concurrent.futures.Future`` discards."""

    def test_uses_run_coroutine_threadsafe_when_loop_running(self):
        loop = MagicMock()
        loop.is_running = MagicMock(return_value=True)
        orch, *_ = _make_orchestrator(loop=loop)

        async def _coro():
            return "ok"

        with patch(
            "hokora.federation.handshake_orchestrator.asyncio.run_coroutine_threadsafe"
        ) as sched:
            future = MagicMock()
            sched.return_value = future
            coro = _coro()
            orch._schedule_on_main_loop(coro, name="probe")

        sched.assert_called_once()
        assert sched.call_args.args[0] is coro
        assert sched.call_args.args[1] is loop
        future.add_done_callback.assert_called_once()
        # Cleanup so pytest doesn't warn about un-awaited coroutine
        coro.close()

    def test_closes_coroutine_when_loop_is_none(self):
        orch, *_ = _make_orchestrator()
        # Override the default MagicMock loop with a literal None to
        # exercise the shutdown-race branch.
        orch._loop = None

        async def _coro():
            return "noreach"

        coro = _coro()
        with patch(
            "hokora.federation.handshake_orchestrator.asyncio.run_coroutine_threadsafe"
        ) as sched:
            orch._schedule_on_main_loop(coro, name="loop-none")
        sched.assert_not_called()
        # Coroutine was closed by the helper — re-execution must raise.
        import pytest as _pytest

        with _pytest.raises((RuntimeError, StopIteration)):
            coro.send(None)

    def test_closes_coroutine_when_loop_not_running(self):
        loop = MagicMock()
        loop.is_running = MagicMock(return_value=False)
        orch, *_ = _make_orchestrator(loop=loop)

        async def _coro():
            return "noreach"

        coro = _coro()
        with patch(
            "hokora.federation.handshake_orchestrator.asyncio.run_coroutine_threadsafe"
        ) as sched:
            orch._schedule_on_main_loop(coro, name="loop-stopped")
        sched.assert_not_called()
        import pytest as _pytest

        with _pytest.raises(RuntimeError):
            coro.send(None)

    def test_done_callback_logs_exception_from_failed_coroutine(self, caplog):
        """Exceptions inside the scheduled coroutine surface in
        ``logger.exception`` so operators can see push-pending failures
        instead of having them swallowed by a discarded Future."""
        import concurrent.futures as cf
        import logging

        loop = MagicMock()
        loop.is_running = MagicMock(return_value=True)
        orch, *_ = _make_orchestrator(loop=loop)

        async def _coro():
            return None

        coro = _coro()
        with patch(
            "hokora.federation.handshake_orchestrator.asyncio.run_coroutine_threadsafe"
        ) as sched:
            real_future = cf.Future()
            sched.return_value = real_future
            with caplog.at_level(logging.ERROR):
                orch._schedule_on_main_loop(coro, name="probe")
                # Simulate the coroutine raising on the loop thread by
                # setting an exception on the returned future.
                real_future.set_exception(RuntimeError("boom in coroutine"))

        coro.close()
        assert any("Background task probe failed" in rec.message for rec in caplog.records), (
            "Exception in scheduled coroutine must surface via logger.exception"
        )

    def test_pusher_push_pending_no_longer_uses_ensure_future(self):
        """Regression guard: ensure the bug shape (asyncio.ensure_future
        without loop=) cannot come back. Step-2 happy path must call
        run_coroutine_threadsafe via the helper, never ensure_future,
        so it is safe to invoke from RNS's packet thread."""
        pusher = MagicMock()
        pusher.set_link = MagicMock()
        pusher.push_pending = AsyncMock()
        key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:chan-1"
        loop = MagicMock()
        loop.is_running = MagicMock(return_value=True)
        orch, *_ = _make_orchestrator(pushers={key: pusher}, loop=loop)
        mirror = _make_mirror()
        mirror._pending_challenge = b"chal"

        with (
            patch(
                "hokora.federation.handshake_orchestrator.FederationAuth.verify_response",
                return_value=True,
            ),
            patch(
                "hokora.federation.handshake_orchestrator.asyncio.run_coroutine_threadsafe"
            ) as sched,
            patch(
                "hokora.federation.handshake_orchestrator.asyncio.ensure_future"
            ) as ensure_future,
            patch("hokora.federation.handshake_orchestrator.RNS.Packet"),
        ):
            orch.on_handshake_response(
                mirror,
                {
                    "step": 2,
                    "accepted": True,
                    "challenge_response": b"ok",
                    "peer_public_key": b"\x42" * 32,
                },
            )

        ensure_future.assert_not_called()
        # Two threadsafe schedules expected: persist_peer_pk + push_pending.
        assert sched.call_count == 2
        for call in sched.call_args_list:
            assert call.args[1] is loop
            call.args[0].close()  # close coroutines to silence warnings

    def test_step2_pusher_drain_runs_from_non_asyncio_thread(self):
        """Cross-thread invariant: ``_handle_step2`` must complete without
        ``RuntimeError: no current event loop`` when called from a thread
        that has no asyncio loop bound — which is RNS's packet-callback
        thread in production."""
        import threading

        pusher = MagicMock()
        pusher.set_link = MagicMock()
        pusher.push_pending = AsyncMock()
        key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:chan-1"
        loop = MagicMock()
        loop.is_running = MagicMock(return_value=True)
        orch, *_ = _make_orchestrator(pushers={key: pusher}, loop=loop)
        mirror = _make_mirror()
        mirror._pending_challenge = b"chal"

        thread_error: list = []

        def _on_rns_thread():
            try:
                with (
                    patch(
                        "hokora.federation.handshake_orchestrator.FederationAuth.verify_response",
                        return_value=True,
                    ),
                    patch(
                        "hokora.federation.handshake_orchestrator.asyncio.run_coroutine_threadsafe"
                    ) as sched,
                    patch("hokora.federation.handshake_orchestrator.RNS.Packet"),
                ):
                    sched.return_value = MagicMock()
                    orch.on_handshake_response(
                        mirror,
                        {
                            "step": 2,
                            "accepted": True,
                            "challenge_response": b"ok",
                            "peer_public_key": b"\x42" * 32,
                        },
                    )
                    # Close any scheduled coroutines.
                    for call in sched.call_args_list:
                        call.args[0].close()
            except Exception as exc:
                thread_error.append(exc)

        t = threading.Thread(target=_on_rns_thread)
        t.start()
        t.join(timeout=5)

        assert not thread_error, (
            f"Cross-thread invocation raised: {thread_error[0]!r}. The helper "
            f"must not depend on a current event loop in the calling thread."
        )
        assert mirror._authenticated is True
