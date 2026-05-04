# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Peer discovery via Reticulum announces."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING, Callable, Optional

import RNS

from hokora.core.announce import AnnounceHandler

if TYPE_CHECKING:
    from hokora.core.mirror_manager import MirrorLifecycleManager

logger = logging.getLogger(__name__)

# Peers not seen in 24 hours are evicted
_PEER_TTL_SECONDS = 24 * 3600


class _AnnounceListener:
    """RNS announce-handler shim: ``aspect_filter = None`` receives every
    announce on the network. RNS calls ``received_announce(**kwargs)`` on
    this object whenever an announce arrives; we forward to a plain
    callback so callers can register a bound method.
    """

    def __init__(self, callback: Callable):
        self.aspect_filter = None
        self._callback = callback

    def received_announce(
        self,
        destination_hash=None,
        announced_identity=None,
        app_data=None,
    ):
        self._callback(destination_hash, announced_identity, app_data)


class PeerDiscovery:
    """Discovers peer nodes via RNS announces.

    Also routes ``type=key_rotation`` announces into the local DB so
    future federation signature verification uses the new identity
    hash. The rotation only applies when the announce's ``old_hash``
    matches our stored ``channel.identity_hash`` — prevents a hostile
    peer steering a channel we don't actually track from them.
    """

    def __init__(
        self,
        session_factory: Optional[Callable] = None,
        loop: Optional[asyncio.AbstractEventLoop] = None,
        mirror_manager: Optional["MirrorLifecycleManager"] = None,
    ):
        """``session_factory`` and ``loop`` are required for rotation
        write-back; ``mirror_manager`` enables the announce-driven
        cold-start wake-up — all three are optional in tests."""
        self._peers: dict[str, dict] = {}
        self._session_factory = session_factory
        self._loop = loop
        self._mirror_manager = mirror_manager
        self._rns_listener: Optional[_AnnounceListener] = None

    def register_with_rns_transport(self) -> bool:
        """Hook into RNS announce delivery; idempotent."""
        if self._rns_listener is not None:
            return True
        try:
            self._rns_listener = _AnnounceListener(self.handle_announce)
            RNS.Transport.register_announce_handler(self._rns_listener)
            logger.info("PeerDiscovery registered RNS announce handler")
            return True
        except Exception:
            logger.exception("Failed to register PeerDiscovery announce handler")
            self._rns_listener = None
            return False

    def handle_announce(self, destination_hash: bytes, announced_identity, app_data: bytes):
        """Process an incoming announce from a potential peer."""
        # Wake parked mirrors first — by the time we're here, recall is
        # guaranteed to succeed. Keyed on ``destination_hash`` because
        # that's what mirrors store (Peer.identity_hash is misleadingly named).
        if self._mirror_manager is not None and isinstance(destination_hash, bytes):
            try:
                self._mirror_manager.wake_for_hash(destination_hash)
            except Exception:
                logger.exception("Mirror wake-up failed during announce handling")

        # Drain any pending sealed-key distributions queued for this
        # announcer's identity. Keyed on ``announced_identity.hexhash``
        # because ``pending_sealed_distributions.identity_hash`` is the
        # recipient's *identity* hash (the value the operator passed to
        # ``hokora role assign``), not a destination_hash. Runs unconditionally
        # of app_data since LXMF/non-channel announces still resolve to a
        # peer identity that may have queued sealed-key grants.
        announcer_hexhash = (
            getattr(announced_identity, "hexhash", None) if announced_identity else None
        )
        if announcer_hexhash and self._session_factory is not None and self._loop is not None:
            fut = asyncio.run_coroutine_threadsafe(
                self._drain_pending_sealed_distributions(announcer_hexhash),
                self._loop,
            )
            fut.add_done_callback(_log_drain_future_exception)

        if not app_data:
            return

        parsed = AnnounceHandler.parse_announce(app_data)
        if not parsed:
            return

        announce_type = parsed.get("type")
        if announce_type == "channel":
            self._handle_channel_announce(destination_hash, announced_identity, parsed)
        elif announce_type == "key_rotation":
            self._handle_key_rotation_announce(app_data)

    def _handle_channel_announce(
        self,
        destination_hash: bytes,
        announced_identity,
        data: dict,
    ) -> None:
        # Evict stale peers not seen in 24h
        self._evict_stale_peers()

        peer_hash = RNS.hexrep(destination_hash, delimit=False)

        # Rotation-aware identity cross-check. If the announcing identity
        # is known AND the channel is in our DB, flag any mismatch that is
        # neither the current identity nor the (within-grace) pre-rotation
        # identity. Logged only; doesn't block peer-tracking because the
        # peer listing is purely informational. The real gates live at
        # transport (Link establishment uses the new destination hash
        # already recorded in channels.destination_hash).
        channel_id = data.get("channel_id")
        announcer_hash = (
            getattr(announced_identity, "hexhash", None) if announced_identity else None
        )
        if channel_id and announcer_hash and self._session_factory and self._loop:
            asyncio.run_coroutine_threadsafe(
                self._log_identity_mismatch(channel_id, announcer_hash),
                self._loop,
            )
        node_name = data.get("node", "Unknown")
        channel_name = data.get("name", "")

        if peer_hash not in self._peers:
            self._peers[peer_hash] = {
                "node_name": node_name,
                "channels": [],
                "first_seen": time.time(),
                "last_seen": time.time(),
            }
            logger.info(f"Discovered new peer: {node_name} ({peer_hash[:16]}...)")

        peer = self._peers[peer_hash]
        peer["last_seen"] = time.time()
        if channel_name and channel_name not in peer["channels"]:
            peer["channels"].append(channel_name)

    def _handle_key_rotation_announce(self, app_data: bytes) -> None:
        """Verify and apply a channel RNS key rotation announce."""
        payload = AnnounceHandler.parse_key_rotation_announce(app_data)
        if payload is None:
            logger.warning("Key rotation announce failed verification; ignoring")
            return

        if self._session_factory is None or self._loop is None:
            logger.debug(
                "Key rotation verified but no DB session; skipping apply (channel=%s)",
                payload.get("channel_id", "?"),
            )
            return

        # Hand off to the daemon loop — DB writes cannot run on the RNS
        # announce-handler thread.
        asyncio.run_coroutine_threadsafe(
            self._apply_rotation(payload),
            self._loop,
        )

    async def _log_identity_mismatch(
        self,
        channel_id: str,
        announcer_hash: str,
    ) -> None:
        """Log channel announces whose identity doesn't match our DB state.

        Rotation-aware: an announce from the pre-rotation identity is
        tolerated (logged at debug) while we're inside the grace window;
        anything else that disagrees with ``channel.identity_hash`` is
        logged at warning. No channel state is modified — peer tracking
        continues regardless. See channel_rotation_auth module docstring
        for why this check belongs here and not in mirror_ingestor.
        """
        from sqlalchemy import select
        from hokora.db.models import Channel
        from hokora.federation.channel_rotation_auth import (
            is_within_grace,
            matches_identity,
        )

        try:
            async with self._session_factory() as session:
                row = await session.execute(select(Channel).where(Channel.id == channel_id))
                channel = row.scalar_one_or_none()
                if channel is None or not channel.identity_hash:
                    return  # Nothing to compare against.
                if not matches_identity(
                    channel.identity_hash,
                    channel.rotation_old_hash,
                    channel.rotation_grace_end,
                    announcer_hash,
                ):
                    logger.warning(
                        "Channel announce identity mismatch for %s: "
                        "got %s, expected %s (grace active=%s)",
                        channel_id,
                        announcer_hash[:16],
                        (channel.identity_hash or "")[:16],
                        is_within_grace(channel.rotation_grace_end),
                    )
                elif channel.rotation_old_hash and announcer_hash == channel.rotation_old_hash:
                    logger.debug(
                        "Channel announce from pre-rotation identity for %s; "
                        "tolerated within grace window",
                        channel_id,
                    )
        except Exception:
            logger.exception("identity-mismatch log failed for %s", channel_id)

    async def _apply_rotation(self, payload: dict) -> None:
        """Apply a key rotation when the announce's ``old_hash`` matches our row.

        Guards: row exists; current identity_hash equals ``old_hash``;
        ``new_hash`` differs (replay reject); timestamp within a 30-day
        past + 5-min future drift window — same window as the mirror
        ingestor validation, kept aligned across both files.
        """
        from sqlalchemy import select
        from hokora.db.models import Channel

        channel_id = payload.get("channel_id")
        old_hash = payload.get("old_hash")
        new_hash = payload.get("new_hash")
        ts = payload.get("timestamp", 0)
        grace_period = int(payload.get("grace_period", 48 * 3600))
        now = time.time()

        if not channel_id or not old_hash or not new_hash:
            logger.warning("Key rotation payload missing required fields; ignoring")
            return
        if ts > now + 300 or ts < now - 30 * 86400:
            logger.warning("Key rotation timestamp out of window (ts=%s); ignoring", ts)
            return

        async with self._session_factory() as session:
            async with session.begin():
                row = await session.execute(select(Channel).where(Channel.id == channel_id))
                channel = row.scalar_one_or_none()
                if channel is None:
                    logger.debug(
                        "Key rotation for unknown channel %s; ignoring",
                        channel_id,
                    )
                    return
                if channel.identity_hash != old_hash:
                    logger.warning(
                        "Key rotation old_hash mismatch for %s: "
                        "have %s, announce claims %s — ignoring",
                        channel_id,
                        (channel.identity_hash or "")[:16],
                        old_hash[:16],
                    )
                    return
                if channel.identity_hash == new_hash:
                    logger.debug("Key rotation already applied for %s", channel_id)
                    return

                channel.rotation_old_hash = old_hash
                channel.rotation_grace_end = now + grace_period
                channel.identity_hash = new_hash
                logger.info(
                    "Applied key rotation for channel %s: %s → %s (grace ends %ds)",
                    channel_id,
                    old_hash[:16],
                    new_hash[:16],
                    grace_period,
                )

    async def _drain_pending_sealed_distributions(self, identity_hash: str) -> None:
        """Drain queued sealed-key distributions for an announcing peer.

        Each entry runs in its own transaction (so a single failure
        can't poison the queue). Entries whose role row has been revoked
        between enqueue and drain are evicted — authorisation lives on
        the role table, this queue is a delivery hint.
        """
        from sqlalchemy import select

        from hokora.constants import MAX_PENDING_DISTRIBUTION_RETRIES
        from hokora.db.models import RoleAssignment
        from hokora.db.queries import PendingSealedDistributionRepo
        from hokora.exceptions import SealedKeyDistributionDeferred
        from hokora.security.sealed import distribute_sealed_key_to_identity

        try:
            async with self._session_factory() as session:
                repo = PendingSealedDistributionRepo(session)
                entries = await repo.list_for_identity(identity_hash)
        except Exception:
            logger.exception("Pending sealed-distribution lookup failed for %s", identity_hash[:16])
            return

        for entry in entries:
            if entry.retry_count >= MAX_PENDING_DISTRIBUTION_RETRIES:
                # Stuck entries need operator inspection — never auto-evict.
                continue
            try:
                async with self._session_factory() as session:
                    async with session.begin():
                        # Revoke guard: confirm the role row still exists.
                        ra = (
                            await session.execute(
                                select(RoleAssignment)
                                .where(RoleAssignment.role_id == entry.role_id)
                                .where(RoleAssignment.identity_hash == identity_hash)
                                .where(RoleAssignment.channel_id == entry.channel_id)
                            )
                        ).scalar_one_or_none()
                        if ra is None:
                            logger.info(
                                "Pending sealed-key distribution for %s on %s skipped: "
                                "role assignment no longer present (likely revoked); evicting.",
                                identity_hash[:16],
                                entry.channel_id,
                            )
                            await PendingSealedDistributionRepo(session).evict(entry.id)
                            continue

                        await distribute_sealed_key_to_identity(
                            session, entry.channel_id, identity_hash
                        )
                        await PendingSealedDistributionRepo(session).evict(entry.id)
                logger.info(
                    "Drained pending sealed-key distribution for %s on channel %s "
                    "(prior retries=%d)",
                    identity_hash[:16],
                    entry.channel_id,
                    entry.retry_count,
                )
            except SealedKeyDistributionDeferred as exc:
                # Path cache lost the peer between announce and our recall;
                # bump retry count and try again on the next announce.
                try:
                    async with self._session_factory() as session:
                        async with session.begin():
                            await PendingSealedDistributionRepo(session).increment_retry(
                                entry.id, str(exc)
                            )
                except Exception:
                    logger.exception("Failed to record retry for pending distribution %s", entry.id)
                logger.debug(
                    "Pending sealed-key distribution still deferred for %s: %s",
                    identity_hash[:16],
                    exc,
                )
            except Exception as exc:
                try:
                    async with self._session_factory() as session:
                        async with session.begin():
                            await PendingSealedDistributionRepo(session).increment_retry(
                                entry.id, repr(exc)
                            )
                except Exception:
                    logger.exception("Failed to record retry for pending distribution %s", entry.id)
                logger.exception(
                    "Pending sealed-key distribution failed for %s on channel %s",
                    identity_hash[:16],
                    entry.channel_id,
                )

    def get_peers(self) -> dict[str, dict]:
        return dict(self._peers)

    def get_peer(self, peer_hash: str) -> Optional[dict]:
        return self._peers.get(peer_hash)

    def _evict_stale_peers(self):
        """Remove peers not seen within the TTL window."""
        now = time.time()
        stale = [h for h, p in self._peers.items() if now - p["last_seen"] > _PEER_TTL_SECONDS]
        for h in stale:
            del self._peers[h]
        if stale:
            logger.debug(f"Evicted {len(stale)} stale peers")


def _log_drain_future_exception(fut: "asyncio.Future") -> None:
    """Done-callback for ``run_coroutine_threadsafe`` futures.

    A discarded ``Future`` from ``run_coroutine_threadsafe`` silently
    swallows exceptions. Always attach this so failures surface in logs.
    """
    try:
        fut.result()
    except Exception:
        logger.exception("Pending sealed-distribution drain raised")
