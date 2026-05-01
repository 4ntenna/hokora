# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""EpochOrchestrator: central registry + lifecycle for per-peer EpochManagers.

The orchestrator promotes the EpochManager registry to a first-class
subsystem with a narrow public API:

* It **owns the dict**. No shared-mutable registry across
  modules. Collaborators receive the orchestrator via DI and call its
  public methods (``register``, ``get``, ``persist_all``, ``teardown``,
  ``shutdown``) rather than reaching into its internals.
* ``load_state(mirrors)`` runs on daemon start: it reads all persisted
  ``FederationEpochState`` rows, constructs an ``EpochManager`` per
  mirror-key match, loads keys + nonce prefix from the DB, and — for
  initiator-active rows — starts the async rotation scheduler.
* ``register(...)`` is called from the handshake orchestrator during
  step 5 (epoch rotate init). Idempotent: returns the existing manager
  if the key is already known (handshake retry after transient failure).
* ``persist_all`` runs on the maintenance tick. Each active manager's
  state is written back under the session lock.
* ``teardown(key)`` runs when a single mirror is removed. Erases keys
  and drops the manager from the registry.
* ``shutdown()`` runs on daemon stop: teardown every manager, clear
  the registry.

Follows the extract pattern of ``core/mirror_manager.py`` and
``core/sealed_bootstrap.py`` — single-responsibility subsystem with a
small, explicit public surface.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Callable, Optional

import RNS
from sqlalchemy import select

from hokora.federation.epoch_manager import EpochManager

if TYPE_CHECKING:
    from hokora.config import NodeConfig
    from hokora.core.identity import IdentityManager
    from hokora.federation.mirror import ChannelMirror
    from hokora.federation.pusher import FederationPusher
    from hokora.protocol.link_manager import LinkManager

logger = logging.getLogger(__name__)


class EpochOrchestrator:
    """Owns + lifecycles all per-mirror ``EpochManager`` instances.

    Keyed by ``mirror_key`` = ``f"{remote_hash_hex}:{channel_id}"`` — same
    convention as ``MirrorLifecycleManager`` / ``FederationPusher`` so the
    three registries stay in lock-step.
    """

    def __init__(
        self,
        *,
        config: "NodeConfig",
        loop: Optional[asyncio.AbstractEventLoop],
        session_factory,
        identity_manager: "IdentityManager",
        send_callback_factory: Callable[[str], Callable[[bytes], None]],
    ) -> None:
        """
        Args:
            config: Node config. Reads ``fs_enabled`` + ``fs_epoch_duration``.
            loop: Daemon event loop. Used by initiator managers to schedule
                rotation. May be ``None`` in tests.
            session_factory: AsyncSession factory for epoch state persistence.
            identity_manager: Exposes the local node RNS identity, needed
                for EpochManager construction.
            send_callback_factory: Given a mirror_key, returns the send-frame
                callback EpochManager invokes on rotation. Factory lives on
                the handshake orchestrator (which knows how to wrap a frame
                in a sync_request + send it on the mirror's link).
        """
        self._config = config
        self._loop = loop
        self._session_factory = session_factory
        self._identity_manager = identity_manager
        self._send_callback_factory = send_callback_factory
        self._managers: dict[str, EpochManager] = {}

    # ── Public: registry access ────────────────────────────────────

    def get(self, mirror_key: str) -> Optional[EpochManager]:
        """Return the manager for a mirror_key, or None if absent."""
        return self._managers.get(mirror_key)

    def __contains__(self, mirror_key: str) -> bool:
        return mirror_key in self._managers

    def __len__(self) -> int:
        return len(self._managers)

    # ── Public: construction ────────────────────────────────────────

    def register(
        self,
        mirror_key: str,
        *,
        peer_identity_hash: str,
        is_initiator: bool,
        peer_rns_identity,
    ) -> EpochManager:
        """Create + store an EpochManager for this mirror. Idempotent.

        If a manager already exists for ``mirror_key``, return it unchanged
        — the handshake orchestrator can call this during a retry without
        leaking managers or double-starting the rotation scheduler.
        """
        existing = self._managers.get(mirror_key)
        if existing is not None:
            return existing

        node_identity = self._identity_manager.get_node_identity()
        em = EpochManager(
            peer_identity_hash=peer_identity_hash,
            is_initiator=is_initiator,
            local_rns_identity=node_identity,
            epoch_duration=self._config.fs_epoch_duration,
            on_send=self._send_callback_factory(mirror_key),
            session_factory=self._session_factory,
            peer_rns_identity=peer_rns_identity,
        )
        self._managers[mirror_key] = em
        return em

    # ── Public: startup + maintenance + shutdown ───────────────────

    async def load_state(self, mirrors: dict[str, "ChannelMirror"]) -> None:
        """Restore forward-secrecy epoch state for every mirror with a
        persisted row.

        Called once from daemon start after mirrors are constructed. For
        each ``FederationEpochState`` row, finds the first mirror whose
        key matches the peer identity hash, recalls the peer's RNS
        identity (for signature verification), constructs a manager, and
        loads its keys + nonce prefix from the DB. Initiator-active
        managers get the rotation scheduler started.

        Tolerant of partial state: a peer row with no matching mirror is
        logged and skipped, not an error. Same for ``RNS.Identity.recall``
        returning None (peer has never announced).
        """
        if not self._config.fs_enabled:
            return

        # Local import — FederationEpochState lives in core DB models;
        # top-level import would couple federation/ to db/ at module load.
        from hokora.db.models import FederationEpochState

        try:
            async with self._session_factory() as session:
                async with session.begin():
                    result = await session.execute(select(FederationEpochState))
                    states = result.scalars().all()
                    for state in states:
                        await self._restore_one(state, mirrors)
        except Exception:
            logger.exception("Failed to load epoch state")

    async def _restore_one(self, state, mirrors: dict[str, "ChannelMirror"]) -> None:
        """Restore a single EpochManager from a persisted state row."""
        peer_hash = state.peer_identity_hash

        # Find the first mirror key whose prefix matches this peer_hash.
        # One EpochManager is shared across all channels with the same peer
        # (same handshake), so matching the first mirror is correct.
        matched_key = None
        matched_mirror: Optional["ChannelMirror"] = None
        for key, mirror in mirrors.items():
            if key.startswith(peer_hash + ":"):
                matched_key = key
                matched_mirror = mirror
                break

        if matched_key is None or matched_mirror is None:
            logger.debug(
                "Skipping epoch state restore for peer %s: no matching mirror",
                peer_hash[:16],
            )
            return

        peer_identity = RNS.Identity.recall(matched_mirror.remote_hash)
        # peer_identity may be None if the peer has never announced; the
        # EpochManager accepts None and will fail signature checks
        # gracefully when a frame arrives before the next announce.

        em = self.register(
            matched_key,
            peer_identity_hash=peer_hash,
            is_initiator=state.is_initiator,
            peer_rns_identity=peer_identity,
        )
        await em.load_state()

        # Wire the manager onto the mirror + its pusher, so the hot path
        # uses the restored keys without a fresh rotation.
        matched_mirror._epoch_manager = em

        if em.is_initiator and em.is_active and self._loop is not None:
            em.start_rotation_scheduler(self._loop)

    def attach_to_pushers(self, pushers: dict[str, "FederationPusher"]) -> None:
        """Wire restored managers onto matching pushers.

        Called after ``load_state`` + pushers registration. Kept separate
        so ``load_state`` doesn't take both dicts — the orchestrator stays
        focused on managers and leaves the pusher↔manager binding to the
        daemon's init sequence.
        """
        for key, em in self._managers.items():
            pusher = pushers.get(key)
            if pusher is not None:
                pusher._epoch_manager = em

    def attach_to_link_manager(self, link_manager: "LinkManager") -> None:
        """Share the manager registry with the inbound Link receive path.

        LinkManager receives epoch frames (EPOCH_DATA, EPOCH_ROTATE,
        EPOCH_ROTATE_ACK) on its ``_on_packet`` and needs to look up the
        right EpochManager by ``{identity_hash}:{channel_id}``. Rather than
        duplicating the dict and risking drift when ``register()`` adds a
        new manager during handshake step 5, we hand LinkManager the same
        dict object. Any subsequent ``register()`` or ``teardown()``
        mutation is immediately visible to the receive path.

        Called from daemon.start() right after ``attach_to_pushers``.
        """
        link_manager._epoch_managers = self._managers

    async def persist_all(self) -> None:
        """Persist every active EpochManager's state.

        Called from the maintenance tick. Inactive managers (handshake
        still in progress, no keys derived yet) are skipped — there's
        nothing to persist until ``_activate_epoch`` has run.
        """
        for em in self._managers.values():
            if em.is_active:
                try:
                    await em.persist_state()
                except Exception:
                    logger.exception(
                        "Failed to persist epoch state for %s",
                        em.peer_identity_hash[:16],
                    )

    def teardown(self, mirror_key: str) -> None:
        """Remove + erase the manager for a single mirror.

        Called from daemon.remove_mirror. No-op if the key isn't known.
        """
        em = self._managers.pop(mirror_key, None)
        if em is not None:
            em.teardown()

    async def shutdown(self) -> None:
        """Teardown every manager, clear the registry.

        Called from daemon.stop(). Erases all key material.
        """
        for em in self._managers.values():
            try:
                em.teardown()
            except Exception:
                logger.exception(
                    "Error tearing down epoch manager for %s",
                    em.peer_identity_hash[:16],
                )
        self._managers.clear()
