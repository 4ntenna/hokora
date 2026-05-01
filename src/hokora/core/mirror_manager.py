# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Mirror lifecycle manager: loading, cursor persistence, push management."""

import asyncio
import logging
from collections import Counter
from typing import Optional

from hokora.federation.mirror import ChannelMirror, MirrorState
from hokora.federation.pusher import FederationPusher

logger = logging.getLogger(__name__)


class MirrorLifecycleManager:
    """Manages channel mirror lifecycle: loading from DB, cursor persistence, push cursors."""

    def __init__(self, session_factory, loop: Optional[asyncio.AbstractEventLoop] = None):
        self._session_factory = session_factory
        self.loop = loop
        self._mirrors: dict[str, ChannelMirror] = {}
        self._federation_pushers: dict[str, FederationPusher] = {}
        # Connect-attempt totals keyed on the mirror's reported result
        # ("success", "recall_none", "link_failed", "handshake_failed").
        # Read by the Prometheus exporter for the
        # ``hokora_mirror_connect_attempts_total`` counter family.
        self._connect_attempts: Counter[str] = Counter()

    @property
    def mirrors(self) -> dict[str, ChannelMirror]:
        return self._mirrors

    @property
    def federation_pushers(self) -> dict[str, FederationPusher]:
        return self._federation_pushers

    @property
    def connect_attempts(self) -> dict[str, int]:
        """Per-result connect-attempt totals. Cumulative since process start."""
        return dict(self._connect_attempts)

    def make_attempt_callback(self):
        """Build a thread-safe callback for ChannelMirror to report
        connect-attempt outcomes. The counter increments are atomic in
        CPython for ``Counter`` updates from a single attribute write,
        so no extra lock is needed for the call sites we have today.
        """

        def cb(result: str) -> None:
            self._connect_attempts[result] += 1

        return cb

    def state_summary(self) -> dict[str, int]:
        """Return a count of mirrors by state, e.g.
        ``{"linked": 3, "waiting_for_path": 1}``. Used by /api/node/status
        and the Prometheus exporter; states with zero mirrors are
        omitted (omit-rather-than-zero).
        """
        counts: Counter[str] = Counter()
        for mirror in self._mirrors.values():
            counts[mirror.state.value] += 1
        return dict(counts)

    def iter_mirror_states(self):
        """Yield ``(key, channel_id, peer_hash_hex, state_value)`` tuples
        for every registered mirror. Stable iteration order so the
        Prometheus exporter produces deterministic output across scrapes.
        """
        for key in sorted(self._mirrors.keys()):
            mirror = self._mirrors[key]
            yield key, mirror.channel_id, mirror.remote_hash.hex(), mirror.state.value

    def iter_parked(self) -> list[ChannelMirror]:
        """Mirrors currently waiting for a path or in the closed state.

        Both states are wake-eligible — see ``ChannelMirror.wake``.
        Returns a list snapshot so callers can iterate safely without
        holding any internal lock during ``wake()`` calls (which may
        re-enter via the timer or RNS callback).
        """
        out: list[ChannelMirror] = []
        for mirror in self._mirrors.values():
            if mirror.state in (MirrorState.WAITING_FOR_PATH, MirrorState.CLOSED):
                out.append(mirror)
        return out

    def wake_for_hash(self, remote_hash: bytes) -> int:
        """Wake any parked mirror keyed on ``remote_hash``.

        Called from ``PeerDiscovery.handle_announce`` whenever an
        announce arrives — by the time RNS dispatches to the listener,
        ``RNS.Identity.recall`` is guaranteed to succeed for this hash,
        so the mirror's next connect attempt won't trip the cold-start
        race.

        Returns the number of mirrors actually woken (zero if none of
        the registered mirrors are keyed on this hash, or if all of
        them are already linking / linked).
        """
        woken = 0
        for mirror in list(self._mirrors.values()):
            if mirror.remote_hash != remote_hash:
                continue
            if mirror.wake():
                woken += 1
        if woken:
            logger.info(
                "Announce wake-up: nudged %d parked mirror(s) for peer %s",
                woken,
                remote_hash.hex()[:16],
            )
        return woken

    async def load_configured_mirrors(self, add_mirror_fn):
        """Start channel mirrors from Peer table in DB.

        Args:
            add_mirror_fn: Callback to create and register a mirror (called with
                          remote_hash_bytes, channel_id, initial_cursor).
        """
        try:
            async with self._session_factory() as session:
                async with session.begin():
                    from hokora.db.models import Peer
                    from sqlalchemy import select

                    result = await session.execute(select(Peer))
                    peers = result.scalars().all()
                    for peer in peers:
                        for ch_id in peer.channels_mirrored or []:
                            key = f"{peer.identity_hash}:{ch_id}"
                            if key not in self._mirrors:
                                # Read persisted cursor
                                initial_cursor = (peer.sync_cursor or {}).get(ch_id, 0)
                                add_mirror_fn(
                                    bytes.fromhex(peer.identity_hash),
                                    ch_id,
                                    initial_cursor=initial_cursor,
                                )
                                # Restore push cursor from DB
                                push_cursor = (
                                    (peer.sync_cursor or {}).get("_push", {}).get(ch_id, 0)
                                )
                                pusher = self._federation_pushers.get(key)
                                if pusher:
                                    pusher.push_cursor = push_cursor
        except (KeyError, ValueError) as e:
            logger.warning(f"Failed to load configured mirrors: {e}")
        except Exception:
            logger.exception("Failed to load configured mirrors")

    async def persist_cursor(self, channel_id: str, cursor: int):
        """Write mirror cursor to Peer table."""
        from sqlalchemy.exc import SQLAlchemyError

        try:
            async with self._session_factory() as session:
                async with session.begin():
                    from hokora.db.models import Peer
                    from sqlalchemy import select

                    # Find the peer that mirrors this channel
                    result = await session.execute(select(Peer))
                    peers = result.scalars().all()
                    for peer in peers:
                        if channel_id in (peer.channels_mirrored or []):
                            cursors = dict(peer.sync_cursor or {})
                            cursors[channel_id] = cursor
                            peer.sync_cursor = cursors
                            break
        except (SQLAlchemyError, OSError):
            logger.exception("Failed to persist mirror cursor")

    async def persist_push_cursor(self, peer_hash: str, channel_id: str, cursor: int):
        """Write push cursor to Peer.sync_cursor['_push'][channel_id]."""
        from sqlalchemy.exc import SQLAlchemyError

        try:
            async with self._session_factory() as session:
                async with session.begin():
                    from hokora.db.models import Peer
                    from sqlalchemy import select

                    result = await session.execute(
                        select(Peer).where(Peer.identity_hash == peer_hash)
                    )
                    peer = result.scalar_one_or_none()
                    if peer:
                        cursors = dict(peer.sync_cursor or {})
                        push_cursors = dict(cursors.get("_push", {}))
                        push_cursors[channel_id] = cursor
                        cursors["_push"] = push_cursors
                        peer.sync_cursor = cursors
        except (SQLAlchemyError, OSError):
            logger.exception("Failed to persist push cursor")

    def make_cursor_callback(self):
        """Create a callback that persists mirror cursor to Peer.sync_cursor."""

        def callback(channel_id: str, cursor: int):
            asyncio.run_coroutine_threadsafe(
                self.persist_cursor(channel_id, cursor),
                self.loop,
            )

        return callback

    def make_push_cursor_callback(self):
        """Create a callback that persists push cursor to Peer.sync_cursor."""

        def callback(peer_hash: str, channel_id: str, cursor: int):
            asyncio.run_coroutine_threadsafe(
                self.persist_push_cursor(peer_hash, channel_id, cursor),
                self.loop,
            )

        return callback

    async def periodic_push_retry(self, running_fn, retry_interval: float):
        """Periodically retry pushing queued messages to federation peers."""
        while running_fn():
            await asyncio.sleep(retry_interval)
            if not running_fn():
                break
            for key, pusher in list(self._federation_pushers.items()):
                if pusher._should_retry():
                    try:
                        await pusher.push_pending()
                    except Exception:
                        logger.debug(f"Push retry failed for {key}")

    async def periodic_mirror_health(self, running_fn, retry_interval: float):
        """Bounded fallback to the announce-driven wake-up.

        Every ``retry_interval`` seconds, find any mirror parked in
        WAITING_FOR_PATH or CLOSED whose backoff timer has not yet
        fired (the timer is the primary recovery driver) and nudge
        it via ``wake()``. This is the safety net for the case where
        an announce gets lost or where the peer's announce cadence is
        much longer than ours.

        Idempotent under race with the timer + the announce listener
        — ``ChannelMirror.wake`` is no-op when the mirror is already
        connecting or linked.
        """
        while running_fn():
            await asyncio.sleep(retry_interval)
            if not running_fn():
                break
            try:
                parked = self.iter_parked()
                if not parked:
                    continue
                for mirror in parked:
                    mirror.wake()
            except Exception:
                logger.exception("periodic_mirror_health iteration failed")

    async def shutdown(self):
        """Persist push cursors and stop all mirrors."""
        for pusher in self._federation_pushers.values():
            await self.persist_push_cursor(
                pusher.peer_identity_hash, pusher.channel_id, pusher.push_cursor
            )

        for mirror in self._mirrors.values():
            mirror.stop()
        self._mirrors.clear()
        self._federation_pushers.clear()
