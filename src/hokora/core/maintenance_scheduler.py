# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Maintenance task scheduler: runs periodic maintenance routines."""

import logging
import time

logger = logging.getLogger(__name__)


class MaintenanceScheduler:
    """Schedules and runs periodic maintenance tasks for the daemon."""

    def __init__(
        self,
        session_factory,
        maintenance_manager,
        config,
        cdsp_manager=None,
        live_manager=None,
        rate_limiter=None,
        sync_handler=None,
        epoch_orchestrator=None,
        sealed_manager=None,
        node_rns_identity=None,
        lxmf_bridge=None,
        lxm_router=None,
    ):
        self._session_factory = session_factory
        self._maintenance = maintenance_manager
        self._config = config
        self._cdsp_manager = cdsp_manager
        self._live_manager = live_manager
        self._rate_limiter = rate_limiter
        self._sync_handler = sync_handler
        self._epoch_orchestrator = epoch_orchestrator
        self._sealed_manager = sealed_manager
        self._node_rns_identity = node_rns_identity
        self._lxmf_bridge = lxmf_bridge
        self._lxm_router = lxm_router

    async def run_maintenance(self):
        """Run all periodic maintenance tasks. Called from daemon's announce loop."""
        try:
            # DB maintenance (retention, expiry, metadata scrub)
            async with self._session_factory() as session:
                async with session.begin():
                    if self._config.retention_days > 0:
                        await self._maintenance.prune_old_messages(
                            session, self._config.retention_days
                        )
                    await self._maintenance.prune_expired_messages(session)
                    await self._maintenance.prune_retention(session)
                    await self._maintenance.prune_expired_invites(session)
                    if self._config.metadata_scrub_days > 0:
                        await self._maintenance.scrub_metadata(
                            session, self._config.metadata_scrub_days
                        )

            # VACUUM after pruning to reclaim space (runs outside session)
            await self._maintenance.vacuum()

            # CDSP session cleanup
            if self._cdsp_manager:
                async with self._session_factory() as session:
                    async with session.begin():
                        await self._cdsp_manager.cleanup_expired_sessions(session)

            # Flush batched live push events
            if self._live_manager:
                self._live_manager.flush_batches(
                    lxmf_router=self._lxm_router,
                    cdsp_manager=self._cdsp_manager,
                )

            # Persist forward secrecy epoch state
            if self._epoch_orchestrator is not None:
                await self._epoch_orchestrator.persist_all()

            # Auto-rotate sealed channel keys past rotation threshold
            if self._sealed_manager and self._node_rns_identity and self._lxmf_bridge:
                await self._check_sealed_key_rotation()

            # In-memory cleanup (no DB session needed)
            if self._rate_limiter:
                self._rate_limiter.cleanup_stale()
            if self._sync_handler:
                if self._sync_handler.invite_manager:
                    await self._sync_handler.invite_manager.cleanup_stale()
                await self._sync_handler.cleanup_stale_challenges()
        except (Exception,) as exc:
            # Log the specific error type for better debuggability.
            # Broad catch is intentional here: maintenance must not crash the daemon.
            logger.exception(f"Maintenance error ({type(exc).__name__})")

    async def _check_sealed_key_rotation(self):
        """Rotate sealed channel keys older than SEALED_KEY_ROTATION_DAYS."""
        from hokora.constants import SEALED_KEY_ROTATION_DAYS
        from hokora.db.models import SealedKey, Channel
        from hokora.db.queries import RoleRepo
        from sqlalchemy import select

        threshold = time.time() - (SEALED_KEY_ROTATION_DAYS * 86400)

        async with self._session_factory() as session:
            async with session.begin():
                result = await session.execute(select(Channel).where(Channel.sealed.is_(True)))
                sealed_channels = result.scalars().all()

                for ch in sealed_channels:
                    # Find the latest sealed key for this channel
                    key_result = await session.execute(
                        select(SealedKey)
                        .where(SealedKey.channel_id == ch.id)
                        .order_by(SealedKey.created_at.desc())
                        .limit(1)
                    )
                    latest_key = key_result.scalar_one_or_none()
                    if not latest_key or latest_key.created_at >= threshold:
                        continue

                    # Key is stale — rotate and distribute via per-channel router
                    role_repo = RoleRepo(session)
                    member_hashes = await role_repo.get_channel_member_hashes(ch.id)
                    if not member_hashes:
                        continue

                    lxmf_router = self._lxmf_bridge.get_router(ch.id)
                    if not lxmf_router:
                        lxmf_router = self._lxmf_bridge.get_any_router()
                    if not lxmf_router:
                        logger.warning(f"No LXMF router for sealed key rotation on {ch.id}")
                        continue

                    self._sealed_manager.rotate_and_distribute(
                        ch.id,
                        member_hashes,
                        lxmf_router,
                        self._node_rns_identity,
                    )
                    await self._sealed_manager.persist_key(session, ch.id, self._node_rns_identity)
                    logger.info(
                        f"Auto-rotated sealed key for channel {ch.id} "
                        f"({len(member_hashes)} members)"
                    )
