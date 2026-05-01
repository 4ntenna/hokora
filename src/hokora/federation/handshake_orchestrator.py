# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""FederationHandshakeOrchestrator: 3-step handshake + FS epoch-handshake init."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any, Callable, Coroutine

import RNS

from hokora.constants import SYNC_FEDERATION_HANDSHAKE
from hokora.federation.auth import FederationAuth
from hokora.protocol.wire import encode_sync_request, generate_nonce

if TYPE_CHECKING:
    from hokora.config import NodeConfig
    from hokora.core.identity import IdentityManager
    from hokora.federation.epoch_orchestrator import EpochOrchestrator
    from hokora.federation.mirror import ChannelMirror

logger = logging.getLogger(__name__)


class FederationHandshakeOrchestrator:
    """Drives the 3-step challenge/response handshake + FS epoch-handshake
    initiation for federation mirrors.

    Instantiated once per daemon; stateless between handshakes — per-mirror
    state lives on the ``ChannelMirror`` itself (``_pending_challenge``,
    ``_authenticated``, ``_epoch_manager``).

    ``mirrors_view`` / ``pushers_view`` are callables returning live dict
    views owned by MirrorLifecycleManager, keeping ownership there.
    ``epoch_orchestrator`` owns the per-mirror EpochManager registry —
    register/get/teardown all go through its public API.
    """

    def __init__(
        self,
        config: "NodeConfig",
        loop: asyncio.AbstractEventLoop,
        session_factory,
        identity_manager: "IdentityManager",
        federation_auth: FederationAuth,
        mirrors_view: Callable[[], dict],
        pushers_view: Callable[[], dict],
        epoch_orchestrator: "EpochOrchestrator",
    ) -> None:
        self._config = config
        self._loop = loop
        self._session_factory = session_factory
        self._identity_manager = identity_manager
        self._federation_auth = federation_auth
        self._mirrors_view = mirrors_view
        self._pushers_view = pushers_view
        self._epoch_orchestrator = epoch_orchestrator

    # ── Cross-thread coroutine scheduling ───────────────────────────────

    def _schedule_on_main_loop(
        self,
        coro: Coroutine[Any, Any, Any],
        *,
        name: str,
    ) -> None:
        """Schedule a coroutine on the daemon's asyncio loop from any thread.

        RNS link callbacks (``_on_packet`` and the response-callback chain
        that flows from it) fire on RNS's internal receiver thread, not
        the asyncio event loop. ``asyncio.ensure_future`` without a
        ``loop=`` argument resolves the loop from the calling thread; on
        any thread without a running loop that raises ``RuntimeError:
        There is no current event loop in thread '...'``. This helper is
        the single chokepoint for the cross-thread schedule.

        - On a healthy loop: submits the coroutine via
          ``run_coroutine_threadsafe`` and attaches a done-callback that
          surfaces exceptions through ``logger.exception`` instead of
          letting them die silently inside a discarded
          ``concurrent.futures.Future``.
        - On a torn-down loop (daemon shutdown race): closes the
          coroutine cleanly so Python's garbage collector does not emit
          a "coroutine was never awaited" warning, and logs a warning
          naming the dropped task.

        Every code path scheduling work onto ``self._loop`` from this
        orchestrator MUST go through this helper. Direct calls to
        ``asyncio.run_coroutine_threadsafe`` or ``asyncio.ensure_future``
        are deprecated within this class.
        """
        loop = self._loop
        if loop is None or not loop.is_running():
            logger.warning("Cannot schedule background task %s: no running asyncio loop", name)
            coro.close()
            return

        future = asyncio.run_coroutine_threadsafe(coro, loop)

        def _surface_exception(fut) -> None:
            try:
                fut.result()
            except Exception:
                logger.exception("Background task %s failed", name)

        future.add_done_callback(_surface_exception)

    # ── Step 1: initiate handshake ──────────────────────────────────────

    def initiate(self, mirror: "ChannelMirror") -> None:
        """Send step 1 (challenge) to the remote peer on this mirror's link."""
        node_identity = self._identity_manager.get_node_identity()
        if not node_identity or not mirror._link:
            logger.warning("Cannot initiate handshake: missing identity or link")
            if not self._config.require_signed_federation:
                mirror._sync_history()
            return

        node_hash = self._identity_manager.get_node_identity_hash()
        challenge = FederationAuth.create_challenge()
        mirror._pending_challenge = challenge

        nonce = generate_nonce()
        request = encode_sync_request(
            SYNC_FEDERATION_HANDSHAKE,
            nonce,
            {
                "step": 1,
                "node_name": self._config.node_name,
                "identity_hash": node_hash,
                "challenge": challenge,
            },
        )

        try:
            RNS.Packet(mirror._link, request).send()
            logger.info(
                f"Sent federation handshake to {mirror.remote_hash.hex()[:16]} "
                f"for channel {mirror.channel_id}"
            )
        except Exception:
            logger.exception("Failed to send federation handshake")
            if not self._config.require_signed_federation:
                mirror._sync_history()

    # ── Step 2/4/6: response dispatch ───────────────────────────────────

    def on_handshake_response(self, mirror: "ChannelMirror", resp_data: dict) -> None:
        """Route a handshake response to the correct step handler."""
        step = resp_data.get("step")

        if step == 2 and resp_data.get("accepted"):
            self._handle_step2(mirror, resp_data)
        elif step == 4:
            mirror._authenticated = True
            fs_capable = resp_data.get("fs_capable", False)
            if fs_capable and self._config.fs_enabled:
                self._initiate_epoch_handshake(mirror)
        elif step == 6:
            self._handle_step6(mirror, resp_data)

    def _handle_step2(self, mirror: "ChannelMirror", resp_data: dict) -> None:
        from hokora.federation.auth import ED25519_PUBLIC_KEY_SIZE

        challenge_response = resp_data.get("challenge_response")
        peer_public_key = resp_data.get("peer_public_key")
        pending = getattr(mirror, "_pending_challenge", None)

        if pending and challenge_response and peer_public_key:
            # Wire-contract guard: peer_public_key must be a 32-byte Ed25519
            # signing key. Reject malformed wire shapes before the verifier
            # so the failure mode is visible as a protocol-violation log
            # rather than a generic verification failure.
            if (
                not isinstance(peer_public_key, (bytes, bytearray))
                or len(peer_public_key) != ED25519_PUBLIC_KEY_SIZE
            ):
                logger.warning(
                    "Federation handshake step 2: invalid peer_public_key length from "
                    f"{mirror.remote_hash.hex()[:16]} "
                    f"({0 if peer_public_key is None else len(peer_public_key)} "
                    f"bytes; expected {ED25519_PUBLIC_KEY_SIZE}). "
                    "Peer is on a stale build; aborting handshake."
                )
                return

            if not FederationAuth.verify_response(pending, challenge_response, peer_public_key):
                logger.warning(
                    f"Federation handshake verification failed for {mirror.remote_hash.hex()[:16]}"
                )
                # Do NOT fall back to unauthenticated sync on auth failure.
                return

            peer_hash = resp_data.get("identity_hash", mirror.remote_hash.hex())
            self._schedule_on_main_loop(
                self._persist_peer_public_key(peer_hash, peer_public_key),
                name=f"persist_peer_pk[{peer_hash[:16]}]",
            )

        # Send step 3 (counter_challenge response) if the peer requested one.
        counter_challenge = resp_data.get("counter_challenge")
        if counter_challenge and mirror._link:
            node_identity = self._identity_manager.get_node_identity()
            if node_identity:
                counter_response = node_identity.sign(counter_challenge)
                nonce = generate_nonce()
                step3 = encode_sync_request(
                    SYNC_FEDERATION_HANDSHAKE,
                    nonce,
                    {
                        "step": 3,
                        "identity_hash": self._identity_manager.get_node_identity_hash(),
                        "counter_response": counter_response,
                        "peer_public_key": self._identity_manager.get_signing_public_key(),
                    },
                )
                RNS.Packet(mirror._link, step3).send()
                logger.info(f"Sent handshake step 3 to {mirror.remote_hash.hex()[:16]}")

        mirror._authenticated = True
        key = f"{mirror.remote_hash.hex()}:{mirror.channel_id}"
        pusher = self._pushers_view().get(key)
        if pusher and mirror._link:
            pusher.set_link(mirror._link)
            # _handle_step2 runs on RNS's packet-callback thread, which has
            # no current asyncio loop. Use the cross-thread helper so the
            # pending push drain is scheduled on the daemon's main loop
            # and any exception is surfaced through logger.exception
            # rather than swallowed by a discarded future.
            self._schedule_on_main_loop(
                pusher.push_pending(),
                name=f"pusher.push_pending[{key[:16]}]",
            )

        logger.info(f"Federation handshake complete with {mirror.remote_hash.hex()[:16]}")
        mirror._sync_history()

    def _handle_step6(self, mirror: "ChannelMirror", resp_data: dict) -> None:
        key = f"{mirror.remote_hash.hex()}:{mirror.channel_id}"
        em = self._epoch_orchestrator.get(key)
        if not em:
            return
        frame = resp_data.get("epoch_rotate_ack_frame")
        if not frame:
            return
        try:
            em.handle_epoch_rotate_ack(frame)
            if self._loop:
                em.start_rotation_scheduler(self._loop)
            logger.info(f"Forward secrecy epoch established with {mirror.remote_hash.hex()[:16]}")
        except Exception:
            logger.exception("Failed to complete epoch handshake")

    # ── Push-ack routing ────────────────────────────────────────────────

    def on_push_ack(self, mirror: "ChannelMirror", data: dict) -> None:
        """Route a push ack to the owning FederationPusher."""
        key = f"{mirror.remote_hash.hex()}:{mirror.channel_id}"
        pusher = self._pushers_view().get(key)
        if pusher:
            pusher.handle_push_ack(data)

    # ── Epoch handshake (step 5) ────────────────────────────────────────

    def _initiate_epoch_handshake(self, mirror: "ChannelMirror") -> None:
        key = f"{mirror.remote_hash.hex()}:{mirror.channel_id}"
        node_identity = self._identity_manager.get_node_identity()
        if not node_identity or not mirror._link:
            return

        peer_identity = RNS.Identity.recall(mirror.remote_hash)

        em = self._epoch_orchestrator.register(
            key,
            peer_identity_hash=mirror.remote_hash.hex(),
            is_initiator=True,
            peer_rns_identity=peer_identity,
        )

        try:
            frame = em.create_epoch_rotate()
            nonce = generate_nonce()
            request = encode_sync_request(
                SYNC_FEDERATION_HANDSHAKE,
                nonce,
                {
                    "step": 5,
                    # The receiver needs identity_hash to recall our RNS
                    # identity for FS-frame signature verification. Every
                    # step in the handshake state machine carries it.
                    "identity_hash": self._identity_manager.get_node_identity_hash(),
                    "epoch_rotate_frame": frame,
                },
            )
            RNS.Packet(mirror._link, request).send()
            logger.info(f"Sent epoch handshake step 5 to {mirror.remote_hash.hex()[:16]}")
        except Exception:
            logger.exception("Failed to send epoch handshake step 5")

        mirror._epoch_manager = em
        pusher = self._pushers_view().get(key)
        if pusher:
            pusher._epoch_manager = em

    def _make_epoch_send_callback(self, mirror_key: str):
        """Build the send-frame callback EpochManager invokes on rotation."""

        def send(frame_bytes: bytes) -> None:
            mirror = self._mirrors_view().get(mirror_key)
            if mirror and mirror._link:
                nonce = generate_nonce()
                request = encode_sync_request(
                    SYNC_FEDERATION_HANDSHAKE,
                    nonce,
                    {
                        "step": 5,
                        "identity_hash": self._identity_manager.get_node_identity_hash(),
                        "epoch_rotate_frame": frame_bytes,
                    },
                )
                RNS.Packet(mirror._link, request).send()

        return send

    # ── TOFU peer-key persistence ───────────────────────────────────────

    async def _persist_peer_public_key(
        self,
        peer_identity_hash: str,
        public_key_bytes: bytes,
    ) -> None:
        """Persist verified peer public key for TOFU cache.

        Defends the TOFU cache against wire-format regressions: a non-32-byte
        key reaching this point is a structural protocol violation and must
        not be persisted, or a future verifier read would crash on the cached
        value.
        """
        from hokora.federation.auth import ED25519_PUBLIC_KEY_SIZE

        if (
            not isinstance(public_key_bytes, (bytes, bytearray))
            or len(public_key_bytes) != ED25519_PUBLIC_KEY_SIZE
        ):
            logger.warning(
                f"Refusing to persist peer public key for {peer_identity_hash[:16]}: "
                f"invalid length ({0 if public_key_bytes is None else len(public_key_bytes)} "
                f"bytes; expected {ED25519_PUBLIC_KEY_SIZE})"
            )
            return
        try:
            from sqlalchemy import select

            from hokora.db.models import Peer

            async with self._session_factory() as session:
                async with session.begin():
                    result = await session.execute(
                        select(Peer).where(Peer.identity_hash == peer_identity_hash)
                    )
                    peer = result.scalar_one_or_none()
                    if peer:
                        peer.public_key = bytes(public_key_bytes)
        except Exception:
            logger.exception("Failed to persist peer public key")
