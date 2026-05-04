# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""EpochOrchestrator: central registry + lifecycle for per-peer EpochManagers.

Owns the registry; collaborators get it via DI and use the narrow
public API (``register`` / ``get`` / ``persist_all`` / ``teardown``
/ ``shutdown``). ``load_state`` reads persisted FS state at daemon
start; ``persist_all`` writes state back on the maintenance tick.

Follows the same single-responsibility extract pattern as
``core/mirror_manager.py`` and ``core/sealed_bootstrap.py``.
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
        """``send_callback_factory(mirror_key)`` is provided by the handshake
        orchestrator and called by EpochManager on rotation."""
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
        """Restore FS epoch state for every persisted mirror.

        Tolerant of partial state — peers with no matching mirror or
        unrecallable identities are skipped, not errored.
        """
        if not self._config.fs_enabled:
            return

        # Local import avoids coupling federation/ to db/ at module load.
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

        # One EpochManager is shared across all channels with the same peer.
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

        # ``recall`` may return None for an unannounced peer; EpochManager
        # accepts that and fails sig checks until the next announce.
        peer_identity = RNS.Identity.recall(matched_mirror.remote_hash)

        em = self.register(
            matched_key,
            peer_identity_hash=peer_hash,
            is_initiator=state.is_initiator,
            peer_rns_identity=peer_identity,
        )
        await em.load_state()

        # Wire the manager onto the mirror so the hot path uses restored keys.
        matched_mirror._epoch_manager = em

        if em.is_initiator and em.is_active and self._loop is not None:
            em.start_rotation_scheduler(self._loop)

    def attach_to_pushers(self, pushers: dict[str, "FederationPusher"]) -> None:
        """Wire restored managers onto matching pushers (called after load_state)."""
        for key, em in self._managers.items():
            pusher = pushers.get(key)
            if pusher is not None:
                pusher._epoch_manager = em

    def attach_to_link_manager(self, link_manager: "LinkManager") -> None:
        """Hand LinkManager our registry dict by reference so future
        ``register``/``teardown`` mutations are immediately visible to
        the receive path (no duplicated state, no drift)."""
        link_manager._epoch_managers = self._managers

    async def persist_all(self) -> None:
        """Persist every active EpochManager (called from the maintenance tick)."""
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
