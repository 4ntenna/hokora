# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""HokoraDaemon: main orchestrator for startup, shutdown, asyncio bridge."""

import asyncio
import atexit
import json
import logging
import os
import sys
import time
from typing import Optional

import RNS
import LXMF

from hokora.config import NodeConfig
from hokora.core.identity import IdentityManager
from hokora.core.channel import ChannelManager
from hokora.core.message import MessageProcessor
from hokora.core.sequencer import SequenceManager
from hokora.core.announce import AnnounceHandler
from hokora.core.mirror_manager import MirrorLifecycleManager
from hokora.core.maintenance_scheduler import MaintenanceScheduler
from hokora.core.lxmf_ingestor import LxmfMessageIngestor
from hokora.core.heartbeat import HeartbeatWriter
from hokora.core.observability import ObservabilityListener
from hokora.core.service_registry import ServiceRegistry
from hokora.core.pid_file import PidFile
from hokora.core.sealed_bootstrap import SealedKeyBootstrap
from hokora.db.engine import (
    create_db_engine,
    create_session_factory,
    init_db,
    check_alembic_revision,
)
from hokora.db.fts import FTSManager
from hokora.db.maintenance import MaintenanceManager
from hokora.protocol.link_manager import LinkManager
from hokora.protocol.lxmf_bridge import LXMFBridge
from hokora.protocol.sync import SyncHandler
from hokora.protocol.live import LiveSubscriptionManager
from hokora.protocol.session import CDSPSessionManager
from hokora.constants import CDSP_PROFILE_FULL
from hokora.security.roles import RoleManager
from hokora.security.ratelimit import RateLimiter
from hokora.security.permissions import PermissionResolver
from hokora.security.sealed import SealedChannelManager
from hokora.federation.mirror import ChannelMirror
from hokora.federation.mirror_ingestor import MirrorMessageIngestor
from hokora.federation.peering import PeerDiscovery
from hokora.federation.auth import FederationAuth
from hokora.federation.epoch_orchestrator import EpochOrchestrator
from hokora.federation.handshake_orchestrator import FederationHandshakeOrchestrator
from hokora.federation.pusher import FederationPusher
from hokora.media.transfer import MediaTransfer
from hokora.media.storage import MediaStorage
from hokora.security.fs import (
    secure_existing_file,
    secure_identity_dir,
    write_identity_secure,
)

logger = logging.getLogger(__name__)


class HokoraDaemon:
    """Main daemon orchestrator."""

    def __init__(self, config: NodeConfig):
        self.config = config
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.reticulum: Optional[RNS.Reticulum] = None
        self.lxm_router: Optional[LXMF.LXMRouter] = None

        # Managers (initialized in start())
        self.identity_manager: Optional[IdentityManager] = None
        self.channel_manager: Optional[ChannelManager] = None
        self.sequencer: Optional[SequenceManager] = None
        self.message_processor: Optional[MessageProcessor] = None
        self.link_manager: Optional[LinkManager] = None
        self.lxmf_bridge: Optional[LXMFBridge] = None
        self.sync_handler: Optional[SyncHandler] = None
        self.live_manager: Optional[LiveSubscriptionManager] = None
        self.fts_manager: Optional[FTSManager] = None
        self.maintenance: Optional[MaintenanceManager] = None
        self.role_manager: Optional[RoleManager] = None
        self.rate_limiter: Optional[RateLimiter] = None
        self.permission_resolver: Optional[PermissionResolver] = None
        self.announce_handler: Optional[AnnounceHandler] = None
        self.sealed_manager: Optional[SealedChannelManager] = None
        self.federation_auth: Optional[FederationAuth] = None
        self.cdsp_manager: Optional[CDSPSessionManager] = None

        self._session_factory = None
        self._engine = None
        self._announce_task: Optional[asyncio.Task] = None
        self._push_retry_task: Optional[asyncio.Task] = None
        self._mirror_health_task: Optional[asyncio.Task] = None
        self._batch_flush_task: Optional[asyncio.Task] = None
        self._running = False
        self._start_time: Optional[float] = None

        # Federation (delegated to MirrorLifecycleManager)
        self.peer_discovery: Optional[PeerDiscovery] = None
        self.media_transfer: Optional[MediaTransfer] = None
        self._mirror_manager: Optional[MirrorLifecycleManager] = None
        self._maintenance_scheduler: Optional[MaintenanceScheduler] = None
        # EpochOrchestrator owns the per-mirror EpochManager registry.
        # Built in start() once session_factory + identity_manager +
        # handshake send-callback factory are all available.
        self._epoch_orchestrator: Optional[EpochOrchestrator] = None

        # Atomic PID file for sibling-tool auto-discovery (TUI, hokora daemon status).
        self._pid_file = PidFile(self.config.data_dir / "hokorad.pid")
        # ``hokora seed apply --restart`` reads this sibling file to
        # re-exec the daemon with the same argv after SIGTERM on dev
        # boxes (where no supervisor respawns). Written alongside the
        # pid file at start(), removed via the same atexit backstop.
        # 0o600 to match pid_file hygiene.
        self._argv_file = self.config.data_dir / "hokorad.argv"
        # SealedKeyBootstrap, LxmfMessageIngestor, MirrorMessageIngestor, and
        # FederationHandshakeOrchestrator are built in start() once deps exist.
        self._sealed_bootstrap: Optional[SealedKeyBootstrap] = None
        self._lxmf_ingestor: Optional[LxmfMessageIngestor] = None
        self._mirror_ingestor: Optional[MirrorMessageIngestor] = None
        self._handshake_orchestrator: Optional[FederationHandshakeOrchestrator] = None

        # Universal liveness contract:
        # - HeartbeatWriter is a transport-independent liveness signal written
        #   every config.heartbeat_interval_s seconds, gated on RNS-alive and
        #   maintenance-fresh invariants. Universal across all node types so
        #   systemd watchdogs / air-gapped LoRa ops / external probes share a
        #   signal.
        # - ObservabilityListener is a loopback-only HTTP surface serving
        #   /health/live, /health/ready, /api/metrics/ (the last API-key
        #   gated). Enables fleet-scale Prometheus scraping of relay nodes
        #   without running the full web dashboard.
        self._heartbeat: Optional[HeartbeatWriter] = None
        self._observability: Optional[ObservabilityListener] = None
        # Wall-clock time of the last successful maintenance loop tick.
        # Read by HeartbeatWriter's invariant check and /health/ready.
        self._last_maintenance_run: Optional[float] = None

        # Declarative teardown ordering. Each subsystem registers its
        # own shutdown when constructed in start(); stop() invokes them
        # all in reverse-registration order via a single shutdown_all()
        # call.
        self._services = ServiceRegistry()

    # Convenience accessors for backward compatibility
    @property
    def _mirrors(self) -> dict:
        return self._mirror_manager.mirrors if self._mirror_manager else {}

    @property
    def _federation_pushers(self) -> dict:
        return self._mirror_manager.federation_pushers if self._mirror_manager else {}

    async def start(self):
        """Initialize all subsystems and start the daemon."""
        self.loop = asyncio.get_running_loop()

        from hokora.core.logging_config import configure_logging

        # Ensure directories (configure_logging needs data_dir present, and we
        # also need media_dir + identity_dir below).
        self.config.data_dir.mkdir(parents=True, exist_ok=True)
        configure_logging(
            log_dir=self.config.data_dir,
            log_level=self.config.log_level,
            json_logging=self.config.log_json,
            log_to_stdout=self.config.log_to_stdout,
        )

        logger.info(f"Starting Hokora daemon: {self.config.node_name}")

        # Ensure directories (data_dir already created above by configure_logging).
        self.config.media_dir.mkdir(parents=True, exist_ok=True)
        self.config.identity_dir.mkdir(parents=True, exist_ok=True)

        # Write a PID file so sibling tools (TUI auto-discovery, `hokora daemon
        # status`, external monitors) can identify a running daemon regardless
        # of how it was launched. Atomic write + 0o600 perms — same pattern as
        # `hokora daemon start` to keep single source of truth.
        self._pid_file.write()
        # Backstop: ensure the PID file is removed on any Python exit path,
        # even when stop() can't complete (stalled engine.dispose, hung
        # mirror shutdown, interpreter-level exceptions). Idempotent with
        # the explicit cleanup at the end of stop().
        atexit.register(self._pid_file.remove)
        self._write_argv_file()
        atexit.register(self._remove_argv_file)

        # 1. Init Reticulum
        rns_config = str(self.config.rns_config_dir) if self.config.rns_config_dir else None
        self.reticulum = RNS.Reticulum(configdir=rns_config)
        logger.info("Reticulum initialized")

        # 2. Init LXMRouter
        #
        # Identity files route through security/fs helpers so relay-only
        # daemons (which short-circuit before IdentityManager is built)
        # still enforce the hygiene contract: identity_dir at 0o700,
        # identity files at 0o600. The fallback RNS.Identity.to_file()
        # defers mode to default umask, which is too permissive.
        self.config.identity_dir.mkdir(parents=True, exist_ok=True)
        secure_identity_dir(self.config.identity_dir)
        identity_path = self.config.identity_dir / "node_identity"
        if identity_path.exists():
            secure_existing_file(identity_path, 0o600)
            node_identity = RNS.Identity.from_file(str(identity_path))
        else:
            node_identity = RNS.Identity()
            write_identity_secure(node_identity, identity_path)

        static_peers = (
            [bytes.fromhex(h) for h in self.config.propagation_static_peers]
            if self.config.propagation_static_peers
            else []
        )

        self.lxm_router = LXMF.LXMRouter(
            identity=node_identity,
            storagepath=str(self.config.data_dir / "lxmf_node"),
            static_peers=static_peers,
            autopeer=self.config.propagation_autopeer,
            autopeer_maxdepth=self.config.propagation_autopeer_maxdepth,
            max_peers=self.config.propagation_max_peers,
        )
        self._lxmf_storagepath = str(self.config.data_dir / "lxmf")
        logger.info("LXMRouter initialized")

        # Relay-only mode: transport + LXMF propagation, skip community subsystems
        if self.config.relay_only:
            if self.config.propagation_enabled:
                self.lxm_router.enable_propagation()
                self.lxm_router.set_message_storage_limit(self.config.propagation_storage_mb)
                logger.info(
                    f"LXMF propagation enabled "
                    f"(storage limit: {self.config.propagation_storage_mb}MB, "
                    f"autopeer={self.config.propagation_autopeer}, "
                    f"max_peers={self.config.propagation_max_peers}, "
                    f"static_peers={len(static_peers)})"
                )
            self._running = True
            self._start_time = time.time()
            # Liveness surface for relay nodes. Same contract as
            # community nodes: heartbeat file + loopback HTTP. No
            # maintenance-fresh invariant (relay has no maintenance
            # loop). Prometheus /api/metrics/ works iff an api_key file
            # is present in data_dir — operators can generate one via
            # the web dashboard's first-run if they want scraping.
            self._start_observability(role="relay", node_identity=node_identity)
            logger.info(f"Relay node started: {self.config.node_name} ({node_identity.hexhash})")
            # Keepalive loop with periodic propagation announces
            announce_interval = self.config.announce_interval
            while self._running:
                await asyncio.sleep(announce_interval)
                if self._running and self.lxm_router and self.config.propagation_enabled:
                    try:
                        self.lxm_router.announce_propagation_node()
                    except Exception:
                        logger.debug("Propagation announce failed", exc_info=True)
            return

        # 3. Database
        self._engine = create_db_engine(
            self.config.db_path,
            encrypt=self.config.db_encrypt,
            db_key=self.config.resolve_db_key(),
        )
        await init_db(self._engine)
        self._services.register("db_engine", self._engine.dispose)
        # Tighten DB file mode to 0o600 to match api_key + identity +
        # config hygiene. Content is already SQLCipher-encrypted when
        # db_encrypt=True; file-mode tightening is defence-in-depth for
        # the rare unencrypted-relay deployment and for consistency with
        # the rest of the data_dir surface. Idempotent.
        secure_existing_file(self.config.db_path, 0o600)
        try:
            await check_alembic_revision(self._engine)
        except RuntimeError as e:
            logger.error(f"Migration check failed: {e}")
            await self._engine.dispose()
            raise
        self._session_factory = create_session_factory(self._engine)
        logger.info("Database initialized")

        # 4. FTS5
        if self.config.enable_fts:
            self.fts_manager = FTSManager(self._engine)
            await self.fts_manager.init_fts()

        # 5. Init managers
        self.identity_manager = IdentityManager(self.config.identity_dir, self.reticulum)
        self.identity_manager.get_or_create_node_identity()

        self.sequencer = SequenceManager()
        self.link_manager = LinkManager(self.loop)
        # Sealed-channel manager is constructed here (before LiveSubscriptionManager)
        # so the live layer can reference it for server-side decrypt of sealed rows
        # before pushing to Link subscribers. Without this, sealed messages pushed
        # live would carry body=None at the wire because the at-rest invariant
        # forbids storing plaintext for sealed rows.
        self.sealed_manager = SealedChannelManager()
        self.live_manager = LiveSubscriptionManager(sealed_manager=self.sealed_manager)
        # Install the transport-agnostic defer hook: when a live push can't
        # reach a subscriber (Link dead for any reason — TCP reset, I2P
        # tunnel rebuild, LoRa dropout), the event is queued on the
        # subscriber's CDSP session via DeferredSyncItemRepo and replayed on
        # the next session resume. The hook runs from RNS callback threads,
        # so it marshals into this daemon's event loop with
        # run_coroutine_threadsafe.
        self._install_live_defer_hook()
        # Bridge link-death notifications from the link manager into the
        # live layer so zombie-link push buffers get flushed into the
        # deferred queue before subscriptions are torn down.
        self.link_manager.set_closed_hook(self.live_manager.handle_link_death)
        self.rate_limiter = RateLimiter(
            self.config.rate_limit_tokens,
            self.config.rate_limit_refill,
        )
        self.role_manager = RoleManager()
        self.maintenance = MaintenanceManager(self._engine, self.config.media_dir)
        self.announce_handler = AnnounceHandler(self.identity_manager)

        # Permission resolver
        node_owner_hash = self.identity_manager.get_node_identity_hash()
        self.permission_resolver = PermissionResolver(node_owner_hash)

        # MessageProcessor AFTER permission_resolver, rate_limiter, and sealed_manager
        self.message_processor = MessageProcessor(
            self.sequencer,
            permission_resolver=self.permission_resolver,
            rate_limiter=self.rate_limiter,
            node_identity_hash=node_owner_hash,
            sealed_manager=self.sealed_manager,
        )

        # CDSP session manager
        if self.config.cdsp_enabled:
            self.cdsp_manager = CDSPSessionManager(self.config)

        # Federation auth
        self.federation_auth = FederationAuth()

        # Media transfer
        self.media_storage = MediaStorage(
            self.config.media_dir,
            self.config.max_upload_bytes,
            self.config.max_storage_bytes,
            self.config.max_global_storage_bytes,
        )
        self.media_transfer = MediaTransfer(self.media_storage)

        # Mirror lifecycle manager — built BEFORE PeerDiscovery so the
        # announce listener can wake parked mirrors directly (the N3
        # cold-start fix: announce arrives → recall succeeds →
        # mirror_manager.wake_for_hash short-circuits backoff).
        self._mirror_manager = MirrorLifecycleManager(self._session_factory, self.loop)
        self._services.register("mirror_manager", self._mirror_manager.shutdown)

        # Peer discovery — constructed with session_factory + loop so
        # rotation announces land in the DB and channel announce
        # identity-mismatches get logged. The mirror_manager ref turns
        # each inbound announce into an unconditional
        # wake-up call for any parked mirror keyed on the announcing
        # identity. The RNS announce handler is registered separately
        # in step 11 (below) after the Reticulum instance has been
        # fully initialised.
        self.peer_discovery = PeerDiscovery(
            session_factory=self._session_factory,
            loop=self.loop,
            mirror_manager=self._mirror_manager,
        )

        # 6. Channel manager with link callback
        self.channel_manager = ChannelManager(self.config, self.identity_manager)

        # 7. Sync handler
        node_rns_identity = self.identity_manager.get_node_identity()
        self.sync_handler = SyncHandler(
            self.channel_manager,
            self.sequencer,
            self.fts_manager,
            self.config.node_name,
            self.config.node_description,
            node_identity=node_owner_hash,
            live_manager=self.live_manager,
            media_transfer=self.media_transfer,
            permission_resolver=self.permission_resolver,
            federation_auth=self.federation_auth,
            sealed_manager=self.sealed_manager,
            config=self.config,
            node_rns_identity=node_rns_identity,
            rate_limiter=self.rate_limiter,
            cdsp_manager=self.cdsp_manager,
        )

        # Wire up link manager -> sync handler
        self.link_manager.set_sync_handler(self._handle_sync_request)

        # 8. Mirror ingestor — validates + ingests messages pushed by
        # federation peers. Enforces signed-federation policy.
        self._mirror_ingestor = MirrorMessageIngestor(
            session_factory=self._session_factory,
            sequencer=self.sequencer,
            live_manager=self.live_manager,
            require_signed_federation=self.config.require_signed_federation,
        )

        # 8a. Epoch orchestrator — owns the per-mirror EpochManager
        # registry. Constructed BEFORE the handshake orchestrator so we
        # can inject it via DI. The send_callback_factory is a closure
        # over self so it late-binds to the handshake orchestrator built
        # on the next line (the closure isn't invoked until step-5 of a
        # handshake or load_state, both of which happen after start()).
        self._epoch_orchestrator = EpochOrchestrator(
            config=self.config,
            loop=self.loop,
            session_factory=self._session_factory,
            identity_manager=self.identity_manager,
            send_callback_factory=lambda mirror_key: (
                self._handshake_orchestrator._make_epoch_send_callback(mirror_key)
                if self._handshake_orchestrator is not None
                else (lambda _frame: None)
            ),
        )
        self._services.register("epoch_orchestrator", self._epoch_orchestrator.shutdown)

        # 8b. Federation handshake orchestrator — 3-step challenge/response
        # + FS epoch-handshake init. Shares mirrors/pushers via live views
        # (ownership stays with MirrorLifecycleManager).
        self._handshake_orchestrator = FederationHandshakeOrchestrator(
            config=self.config,
            loop=self.loop,
            session_factory=self._session_factory,
            identity_manager=self.identity_manager,
            federation_auth=self.federation_auth,
            mirrors_view=lambda: self._mirrors,
            pushers_view=lambda: self._federation_pushers,
            epoch_orchestrator=self._epoch_orchestrator,
        )

        # 8b. LXMF bridge (per-channel routers for store-and-forward delivery)
        self._lxmf_ingestor = LxmfMessageIngestor(
            loop=self.loop,
            session_factory=self._session_factory,
            message_processor=self.message_processor,
            live_manager=self.live_manager,
            media_storage=self.media_storage,
            federation_trigger=self._trigger_federation_push,
            sealed_manager=self.sealed_manager,
        )
        self.lxmf_bridge = LXMFBridge(
            self._lxmf_storagepath,
            self._lxmf_ingestor.ingest,
            node_lxm_router=self.lxm_router,
            loop=self.loop,
            config=self.config,
        )

        # 9. Ensure built-in roles
        async with self._session_factory() as session:
            async with session.begin():
                await self.role_manager.ensure_builtin_roles(session)

        # 10. Load existing channels
        async with self._session_factory() as session:
            async with session.begin():
                await self.channel_manager.load_channels(
                    session,
                    link_established_callback=self._make_link_callback(),
                )

                # Load sequence cache
                for ch in self.channel_manager.list_channels():
                    await self.sequencer.load_from_db(session, ch.id)

        # Backfill destination_hash for channels that don't have it yet
        import binascii

        async with self._session_factory() as session:
            async with session.begin():
                for ch in self.channel_manager.list_channels():
                    if not ch.destination_hash:
                        dest = self.identity_manager.get_destination(ch.id)
                        if dest:
                            dest_hash_hex = binascii.hexlify(dest.hash).decode()
                            ch.destination_hash = dest_hash_hex
                            self.channel_manager.update_destination_hash(ch.id, dest_hash_hex)
                            session.add(ch)
                            logger.info(
                                f"Backfilled destination_hash for channel {ch.id}: "
                                f"{dest_hash_hex[:16]}..."
                            )

        # Register channels with LXMF
        for ch in self.channel_manager.list_channels():
            identity = self.identity_manager.get_identity(ch.id)
            dest = self.identity_manager.get_destination(ch.id)
            if identity and dest:
                self.lxmf_bridge.register_channel(ch.id, identity, dest)

        # Wire LXMF bridge to channel manager so it can announce delivery destinations
        self.channel_manager._lxmf_bridge = self.lxmf_bridge

        # 11. Register PeerDiscovery with RNS transport so key-rotation and
        # channel announces from federated peers land in our DB. Must come
        # after Reticulum is up (step near top) but before any outbound
        # announce from us — ordering isn't strict on RNS side, but
        # conceptually we want to be ready to receive before we broadcast.
        self.peer_discovery.register_with_rns_transport()

        # 12. Announce channels (both hokora + LXMF delivery destinations).
        # Silent/invite-only nodes set announce_enabled = false and rely on
        # pubkey-seeded invite tokens for onboarding.
        if self.config.announce_enabled:
            await self.channel_manager.announce_channels()
        else:
            logger.info("announce_enabled = false — startup announce skipped")

        # 12. Start periodic announce task
        self._running = True
        self._start_time = time.time()
        self._announce_task = asyncio.create_task(self._periodic_announce())
        self._services.register_task("announce_task", self._announce_task)
        self._batch_flush_task = asyncio.create_task(self._periodic_batch_flush())
        self._services.register_task("batch_flush_task", self._batch_flush_task)

        # 13. Start configured mirrors
        await self._mirror_manager.load_configured_mirrors(self.add_mirror)

        # 13b. Start periodic push retry task
        self._push_retry_task = asyncio.create_task(
            self._mirror_manager.periodic_push_retry(
                lambda: self._running,
                self.config.federation_push_retry_interval,
            )
        )
        self._services.register_task("push_retry_task", self._push_retry_task)

        # 13c. Start periodic mirror-health task (N3 cold-start fix —
        # bounded fallback to the announce-driven wake-up). Pokes any
        # mirror parked in WAITING_FOR_PATH or CLOSED so a missed
        # announce can never permanently strand federation.
        self._mirror_health_task = asyncio.create_task(
            self._mirror_manager.periodic_mirror_health(
                lambda: self._running,
                self.config.mirror_retry_interval,
            )
        )
        self._services.register_task("mirror_health_task", self._mirror_health_task)

        # 14. Sealed-channel invariant enforcement: load persisted keys, bootstrap
        # missing node-owner keys, purge any pre-invariant plaintext rows. All
        # three phases idempotent — no-op on clean deploys.
        self._sealed_bootstrap = SealedKeyBootstrap(
            self._session_factory,
            self.sealed_manager,
            self.identity_manager,
        )
        await self._sealed_bootstrap.run_all()

        # 15. Restore forward-secrecy epoch state. Loads all persisted
        # FederationEpochState rows into live EpochManagers on matching
        # mirrors, then binds each restored manager onto its pusher.
        await self._epoch_orchestrator.load_state(self._mirrors)
        self._epoch_orchestrator.attach_to_pushers(self._federation_pushers)
        # Inbound epoch frame path: the LinkManager's _on_packet needs to
        # resolve EPOCH_DATA / EPOCH_ROTATE frames to the right manager.
        # Sharing the orchestrator's registry (same dict object) keeps
        # handshake-time register() additions immediately visible here
        # without a second wire-up.
        self._epoch_orchestrator.attach_to_link_manager(self.link_manager)

        # Maintenance scheduler (created last so all managers are wired)
        self._maintenance_scheduler = MaintenanceScheduler(
            session_factory=self._session_factory,
            maintenance_manager=self.maintenance,
            config=self.config,
            cdsp_manager=self.cdsp_manager,
            live_manager=self.live_manager,
            rate_limiter=self.rate_limiter,
            sync_handler=self.sync_handler,
            epoch_orchestrator=self._epoch_orchestrator,
            sealed_manager=self.sealed_manager,
            node_rns_identity=node_rns_identity,
            lxmf_bridge=self.lxmf_bridge,
            lxm_router=self.lxm_router,
        )

        # Start universal liveness surface (heartbeat + loopback HTTP
        # listener). Done after all subsystems are wired so invariant
        # checks can see real state.
        self._start_observability(role="community", node_identity=node_identity)

        logger.info("Hokora daemon started successfully")

    def _start_observability(self, role: str, node_identity) -> None:
        """Construct + start HeartbeatWriter and ObservabilityListener.

        Called from both the community and relay start paths. The
        invariants registered depend on ``role`` — relay nodes have no
        maintenance loop, so the ``maintenance_fresh`` check is omitted
        for them (returning True would be a lie; returning False would
        make readiness always fail).
        """
        node_identity_hash = getattr(node_identity, "hexhash", "unknown")

        def _rns_alive() -> bool:
            # The authoritative list lives on ``RNS.Transport.interfaces``
            # (not on the ``Reticulum`` instance — that has no such attr).
            # Healthy daemon has at least one transport interface with
            # ``.online == True``. Defensive: tolerate RNS internals
            # changing shape, and treat "no interfaces at all" as alive
            # during the brief startup window before the transport
            # subsystem finishes registration.
            try:
                ifaces = list(getattr(RNS.Transport, "interfaces", []) or [])
                if not ifaces:
                    return True  # startup grace
                return any(getattr(iface, "online", False) for iface in ifaces)
            except Exception:
                return False

        if role == "community":

            def _maintenance_fresh() -> bool:
                if self._last_maintenance_run is None:
                    # Grace: during startup before first tick, don't
                    # report stale. The 5× interval threshold below
                    # means real wedges surface within ~10 min anyway.
                    return True
                age = time.time() - self._last_maintenance_run
                return age <= (self.config.announce_interval * 5)
        else:
            _maintenance_fresh = None  # type: ignore[assignment]

        if self.config.heartbeat_enabled:
            heartbeat_path = self.config.data_dir / "heartbeat"
            self._heartbeat = HeartbeatWriter(
                path=heartbeat_path,
                role=role,
                node_identity_hash=node_identity_hash,
                interval_s=self.config.heartbeat_interval_s,
                rns_alive=_rns_alive,
                maintenance_fresh=_maintenance_fresh,
            )
            self._heartbeat.start()
            self._services.register("heartbeat", self._heartbeat.stop)
            logger.info(f"Heartbeat writer started at {heartbeat_path}")

        if self.config.observability_enabled:
            # api_key file is written by ``hokora init`` and gates the
            # loopback /api/metrics/ endpoint. If absent (e.g. legacy
            # data dir predating init-time generation), /api/metrics/
            # simply returns 404 — generate one manually with
            # ``python3 -c 'import secrets; print(secrets.token_hex(32))' \
            # > $DATA_DIR/api_key && chmod 0600 $DATA_DIR/api_key``.
            api_key = None
            api_key_path = self.config.data_dir / "api_key"
            if api_key_path.exists():
                try:
                    api_key = api_key_path.read_text().strip() or None
                except OSError:
                    api_key = None

            self._observability = ObservabilityListener(
                heartbeat_path=self.config.data_dir / "heartbeat",
                port=self.config.observability_port,
                api_key=api_key,
                session_factory=self._session_factory,
                asyncio_loop=self.loop,
                rns_alive=_rns_alive,
                maintenance_fresh=_maintenance_fresh,
                stale_threshold_s=max(self.config.heartbeat_interval_s * 3, 30.0),
                rns_transport=RNS.Transport,
                daemon_start_time=self._start_time,
                mirror_manager=self._mirror_manager,
            )
            self._observability.start()
            self._services.register("observability", self._observability.stop)

    async def stop(self):
        """Graceful shutdown.

        Teardown is declarative: every subsystem registered itself with
        ``self._services`` in ``start()``. ``shutdown_all()`` walks them
        in reverse-registration order, wrapping each step in its own
        try/except so one failing subsystem can't block the rest.

        PID-file removal stays pinned to ``finally`` so it runs even
        when ``shutdown_all`` itself hits an unexpected failure mode.
        """
        logger.info("Stopping Hokora daemon...")
        self._running = False
        try:
            await self._services.shutdown_all()
        finally:
            self._pid_file.remove()
            logger.info("Hokora daemon stopped")

    def _write_argv_file(self) -> None:
        """Persist the daemon's argv + cwd + relevant env for dev-mode respawn.

        ``hokora seed apply --restart`` reads this sibling file after
        SIGTERM to re-exec the daemon with the same invocation when no
        supervisor (systemd, docker, runit) is managing the lifecycle.
        On supervised deployments the file is still written (cheap, 0o600)
        but the CLI prefers the supervisor's restart mechanism.

        Best-effort: a write failure logs a warning and the dev-respawn
        path becomes unavailable, but the daemon continues to run.
        """
        try:
            payload = {
                "argv": list(sys.argv),
                "cwd": os.getcwd(),
                "env": {
                    k: os.environ[k]
                    for k in ("HOKORA_CONFIG", "PYTHONPATH", "VIRTUAL_ENV")
                    if k in os.environ
                },
            }
            tmp = self._argv_file.with_suffix(".tmp")
            fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, json.dumps(payload).encode("utf-8"))
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(str(tmp), str(self._argv_file))
        except OSError as exc:
            logger.warning("Could not write argv file %s: %s", self._argv_file, exc)

    def _remove_argv_file(self) -> None:
        """Best-effort cleanup of the argv sibling file."""
        try:
            self._argv_file.unlink(missing_ok=True)
        except OSError:
            pass

    def _make_link_callback(self):
        """Create a link established callback that routes to LinkManager."""

        def callback(link):
            # Determine channel_id from the destination
            ch_id = self.channel_manager.get_channel_id_by_destination(link.destination.hash)
            if ch_id:
                self.link_manager.on_link_established(link, ch_id)

                # CDSP: start init timer for backward compat with pre-CDSP clients
                if self.cdsp_manager and self.loop:
                    identity = link.get_remote_identity()
                    if identity:
                        identity_hash = identity.hexhash
                        self.cdsp_manager.start_init_timer(
                            identity_hash,
                            lambda ih: self._create_default_cdsp_session(ih),
                            loop=self.loop,
                        )

        return callback

    def _create_default_cdsp_session(self, identity_hash: str):
        """Create a default FULL-profile session for a pre-CDSP client."""
        asyncio.run_coroutine_threadsafe(
            self._create_default_session_async(identity_hash),
            self.loop,
        )

    async def _create_default_session_async(self, identity_hash: str):
        """Async helper to create a default FULL session."""
        try:
            async with self._session_factory() as session:
                async with session.begin():
                    await self.cdsp_manager.handle_session_init(
                        session,
                        identity_hash,
                        {"cdsp_version": 1, "sync_profile": CDSP_PROFILE_FULL},
                    )
        except Exception:
            logger.exception("Failed to create default CDSP session")

    async def _handle_sync_request(
        self,
        action: int,
        nonce: bytes,
        payload: dict,
        channel_id: Optional[str] = None,
        requester_hash: Optional[str] = None,
        link=None,
    ) -> dict:
        """Async handler for sync requests from LinkManager."""
        async with self._session_factory() as session:
            async with session.begin():
                return await self.sync_handler.handle(
                    session,
                    action,
                    nonce,
                    payload,
                    channel_id,
                    requester_hash=requester_hash,
                    link=link,
                )

    async def _periodic_batch_flush(self):
        """Flush batched live push events every 30s (BATCHED profile window)."""
        from hokora.constants import CDSP_PROFILE_BATCHED, CDSP_PROFILE_LIMITS

        interval = CDSP_PROFILE_LIMITS[CDSP_PROFILE_BATCHED]["live_batch_window"]
        if not interval or interval <= 0:
            return
        while self._running:
            await asyncio.sleep(interval)
            if self._running and self.live_manager:
                self.live_manager.flush_batches(
                    lxmf_router=self.lxm_router,
                    cdsp_manager=self.cdsp_manager,
                )

    async def _periodic_announce(self):
        """Periodically announce channels and run maintenance.

        When ``announce_enabled`` is False the announce call is skipped, but
        maintenance (DB vacuum, key rotation, etc.) still runs on the same
        cadence so silent-mode nodes aren't starved of housekeeping.
        """
        while self._running:
            await asyncio.sleep(self.config.announce_interval)
            if self._running:
                if self.config.announce_enabled:
                    await self.channel_manager.announce_channels()
                await self._maintenance_scheduler.run_maintenance()
                # Record the last successful tick. Read by
                # HeartbeatWriter's invariant check + /health/ready so a
                # wedged maintenance loop surfaces within ~3 cycles
                # rather than failing silently.
                self._last_maintenance_run = time.time()

    def add_mirror(
        self,
        remote_hash: bytes,
        channel_id: str,
        initial_cursor: int = 0,
    ):
        """Add and start a channel mirror."""
        key = f"{remote_hash.hex()}:{channel_id}"
        if key in self._mirrors:
            logger.info(f"Mirror already exists: {key}")
            return

        peer_hash_hex = remote_hash.hex()

        def ingest(msg_data):
            asyncio.run_coroutine_threadsafe(
                self._mirror_ingestor.ingest(channel_id, msg_data, peer_hash_hex),
                self.loop,
            )

        mirror = ChannelMirror(
            remote_hash,
            channel_id,
            ingest_callback=ingest,
            initial_cursor=initial_cursor,
            cursor_callback=self._mirror_manager.make_cursor_callback(),
            attempt_callback=self._mirror_manager.make_attempt_callback(),
        )

        # Wire federation auth and handshake callbacks via the orchestrator.
        mirror._federation_auth = self.federation_auth
        mirror._handshake_callback = self._handshake_orchestrator.initiate
        mirror._handshake_response_callback = self._handshake_orchestrator.on_handshake_response
        mirror._push_ack_callback = self._handshake_orchestrator.on_push_ack

        mirror.start(self.reticulum)
        self._mirror_manager.mirrors[key] = mirror

        # Create a bidirectional pusher for this mirror
        node_hash = self.identity_manager.get_node_identity_hash()
        pusher = FederationPusher(
            peer_identity_hash=peer_hash_hex,
            channel_id=channel_id,
            node_identity_hash=node_hash,
            session_factory=self._session_factory,
            cursor_callback=self._mirror_manager.make_push_cursor_callback(),
            max_backoff=float(self.config.federation_push_max_backoff),
        )
        self._mirror_manager.federation_pushers[key] = pusher

        logger.info(f"Started mirror: {key} (cursor={initial_cursor})")

    def remove_mirror(self, remote_hash: bytes, channel_id: str):
        """Stop and remove a channel mirror."""
        key = f"{remote_hash.hex()}:{channel_id}"
        mirror = self._mirrors.pop(key, None)
        if mirror:
            mirror.stop()
            logger.info(f"Stopped mirror: {key}")
        if self._epoch_orchestrator is not None:
            self._epoch_orchestrator.teardown(key)

    def _install_live_defer_hook(self) -> None:
        """Wire the LiveSubscriptionManager's dead-link defer hook into the
        DeferredSyncItemRepo via the daemon's session factory.

        The hook is transport-agnostic — it fires whenever the push layer
        detects a dead Link, regardless of which transport dropped. It queues
        the event payload on the subscriber's CDSP session so the client
        replays it verbatim on next resume. When no active CDSP session
        exists for the identity (anonymous, expired, or never initiated),
        the event is dropped; the client's history-cursor sync on reconnect
        is the safety net for message-type events.

        Runs from RNS callback threads, so it marshals work into the
        daemon's event loop via run_coroutine_threadsafe.
        """
        import msgpack

        from hokora.constants import SYNC_LIVE_EVENT
        from hokora.db.queries import SessionRepo, DeferredSyncItemRepo

        def _hook(identity_hash: str, channel_id: str, event_type: str, data_dict: dict) -> None:
            if self.loop is None or self._session_factory is None:
                return

            # Wrap the event in msgpack → hex so bytes-typed fields
            # (lxmf_signature, sender_public_key, etc.) survive the JSON
            # payload column. On flush the session handler reverses this.
            try:
                envelope_bytes = msgpack.packb(
                    {"event": event_type, "data": data_dict},
                    use_bin_type=True,
                )
            except Exception:
                logger.exception("Failed to pack live-event envelope")
                return

            stored_payload = {"wire_hex": envelope_bytes.hex()}

            async def _do_defer():
                try:
                    async with self._session_factory() as session:
                        async with session.begin():
                            sess = await SessionRepo(session).get_active_session(identity_hash)
                            if not sess:
                                return
                            repo = DeferredSyncItemRepo(session)
                            limit = getattr(self.config, "cdsp_deferred_queue_limit", 1000)
                            count = await repo.count_for_session(sess.session_id)
                            if count >= limit:
                                await repo.evict_oldest(sess.session_id, limit - 1)
                            await repo.enqueue(
                                sess.session_id,
                                channel_id,
                                SYNC_LIVE_EVENT,
                                stored_payload,
                                ttl=sess.expires_at,
                            )
                except Exception:
                    logger.exception("Failed to defer live event")

            try:
                asyncio.run_coroutine_threadsafe(_do_defer(), self.loop)
            except Exception:
                logger.exception("Failed to schedule live-event defer")

        self.live_manager.set_defer_hook(_hook)

    async def _trigger_federation_push(self, channel_id: str):
        """Trigger federation pushers for a channel after a new local message."""
        for key, pusher in self._federation_pushers.items():
            if pusher.channel_id == channel_id:
                try:
                    await pusher.push_pending()
                except Exception:
                    logger.exception(f"Federation push failed for {key}")

    @property
    def uptime(self) -> float:
        """Return daemon uptime in seconds."""
        if self._start_time:
            return time.time() - self._start_time
        return 0.0

    def get_session(self):
        """Get an async session for external use (e.g., CLI)."""
        return self._session_factory()
