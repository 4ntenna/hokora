# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""CDSP Session Manager: lifecycle management for client-declared sync profiles."""

import asyncio
import logging
import os
import time

from hokora.config import NodeConfig
from hokora.constants import (
    CDSP_VERSION,
    CDSP_PROFILE_FULL,
    CDSP_PROFILE_LIMITS,
    CDSP_RESUME_TOKEN_SIZE,
    CDSP_STATE_ACTIVE,
    CDSP_STATE_CLOSED,
)
from hokora.db.queries import SessionRepo, DeferredSyncItemRepo

logger = logging.getLogger(__name__)

# Valid profile identifiers
_VALID_PROFILES = frozenset(CDSP_PROFILE_LIMITS.keys())


def _unwrap_deferred_item(item) -> dict:
    """Convert a DeferredSyncItem row into the shape clients expect.

    Live-event items are stored with payload == {"wire_hex": "..."} where
    the hex holds a msgpack-encoded {"event", "data"} envelope. Unwrap so
    bytes fields survive; other item kinds (profile-restriction deferrals)
    pass through unchanged.
    """
    payload = item.payload
    if isinstance(payload, dict) and "wire_hex" in payload:
        try:
            import msgpack

            decoded = msgpack.unpackb(bytes.fromhex(payload["wire_hex"]), raw=False)
            if isinstance(decoded, dict):
                payload = decoded
        except Exception:
            logger.warning(
                "Deferred item %s has corrupt wire_hex; forwarding as-is",
                getattr(item, "id", "?"),
            )
    return {
        "channel_id": item.channel_id,
        "sync_action": item.sync_action,
        "payload": payload,
    }


class CDSPSessionManager:
    """Core CDSP session lifecycle manager. Stateless service, delegates to DB repos."""

    def __init__(self, config: NodeConfig):
        self.config = config
        self._init_timers: dict[str, asyncio.TimerHandle] = {}
        # Runtime mapping: identity_hash -> lxmf_destination_hex (for BATCHED LXMF delivery)
        self._lxmf_destinations: dict[str, str] = {}

    async def handle_session_init(self, session, identity_hash, payload) -> dict:
        """Process Session Init, return Session Ack or Reject payload."""
        client_version = payload.get("cdsp_version", 1)
        sync_profile = payload.get("sync_profile", CDSP_PROFILE_FULL)
        resume_token = payload.get("resume_token")

        # Store LXMF destination for BATCHED delivery fallback
        lxmf_dest = payload.get("lxmf_destination")
        if lxmf_dest and identity_hash:
            self._lxmf_destinations[identity_hash] = lxmf_dest

        # Version check
        if client_version > CDSP_VERSION:
            return {
                "rejected": True,
                "error_code": 1,
                "cdsp_version": CDSP_VERSION,
            }

        # Validate profile
        if sync_profile not in _VALID_PROFILES:
            return {
                "rejected": True,
                "error_code": 2,
                "cdsp_version": CDSP_VERSION,
            }

        repo = SessionRepo(session)

        # Cancel init timer if any
        timer = self._init_timers.pop(identity_hash, None)
        if timer:
            timer.cancel()

        # Handle resume
        if resume_token:
            existing = await repo.get_active_session(identity_hash)
            if existing and existing.resume_token == resume_token:
                existing.sync_profile = sync_profile
                existing.last_activity = time.time()
                await session.flush()
                deferred_repo = DeferredSyncItemRepo(session)
                # Flush any events that accumulated while the client was
                # disconnected — live-push misses (transport drops) plus the
                # prior profile-restriction path share this queue. Items are
                # returned in FIFO order and removed from the DB.
                flushed = await deferred_repo.flush_for_session(existing.session_id, sync_profile)
                existing.deferred_count = 0
                flushed_items = [_unwrap_deferred_item(item) for item in flushed]
                return {
                    "rejected": False,
                    "session_id": existing.session_id,
                    "accepted_profile": sync_profile,
                    "cdsp_version": CDSP_VERSION,
                    "deferred_count": 0,
                    "flushed_count": len(flushed_items),
                    "flushed_items": flushed_items,
                    "resumed": True,
                }

        # Close any previous active session
        existing = await repo.get_active_session(identity_hash)
        if existing:
            await repo.update_state(existing.session_id, CDSP_STATE_CLOSED)

        # Create new session
        session_id = os.urandom(16).hex()
        new_resume_token = os.urandom(CDSP_RESUME_TOKEN_SIZE)
        expires_at = time.time() + self.config.cdsp_session_timeout

        await repo.create_session(
            session_id=session_id,
            identity_hash=identity_hash,
            sync_profile=sync_profile,
            cdsp_version=client_version,
            resume_token=new_resume_token,
            expires_at=expires_at,
        )

        return {
            "rejected": False,
            "session_id": session_id,
            "accepted_profile": sync_profile,
            "cdsp_version": CDSP_VERSION,
            "deferred_count": 0,
            "resume_token": new_resume_token,
        }

    def get_lxmf_destination(self, identity_hash: str) -> str | None:
        """Return the LXMF destination hex for a client, if registered."""
        return self._lxmf_destinations.get(identity_hash)

    async def handle_profile_update(self, session, session_id, new_profile) -> dict:
        """Process mid-session Profile Update, flush deferred items if upgrading."""
        if new_profile not in _VALID_PROFILES:
            return {"rejected": True, "error_code": 2}

        repo = SessionRepo(session)
        sess = await repo.get_session(session_id)
        if not sess or sess.state != CDSP_STATE_ACTIVE:
            return {"rejected": True, "error_code": 3}

        old_profile = sess.sync_profile
        await repo.update_profile(session_id, new_profile)

        flushed = []
        # If upgrading to a less restrictive profile, flush deferred items
        old_limits = CDSP_PROFILE_LIMITS.get(old_profile, {})
        new_limits = CDSP_PROFILE_LIMITS.get(new_profile, {})
        if new_limits.get("max_sync_limit", 0) > old_limits.get("max_sync_limit", 0):
            deferred_repo = DeferredSyncItemRepo(session)
            flushed = await deferred_repo.flush_for_session(session_id, new_profile)
            sess.deferred_count = 0

        return {
            "rejected": False,
            "session_id": session_id,
            "accepted_profile": new_profile,
            "cdsp_version": CDSP_VERSION,
            "deferred_count": sess.deferred_count,
            "flushed_count": len(flushed),
            "flushed_items": [
                {
                    "channel_id": item.channel_id,
                    "sync_action": item.sync_action,
                    "payload": item.payload,
                }
                for item in flushed
            ],
        }

    def start_init_timer(self, identity_hash: str, callback, loop=None):
        """Start timeout timer. If no Session Init in cdsp_init_timeout seconds,
        assign FULL profile (backward compat for pre-CDSP clients)."""
        if not self.config.cdsp_enabled:
            return

        target_loop = loop or asyncio.get_event_loop()

        def _timeout():
            self._init_timers.pop(identity_hash, None)
            logger.info(
                f"No CDSP Session Init from {identity_hash[:16]}... "
                f"— assigning default FULL profile"
            )
            callback(identity_hash)

        handle = target_loop.call_later(self.config.cdsp_init_timeout, _timeout)
        # Cancel any previous timer for this identity
        old = self._init_timers.pop(identity_hash, None)
        if old:
            old.cancel()
        self._init_timers[identity_hash] = handle

    def get_profile_limits(self, sync_profile: int) -> dict:
        """Return the limits dict for a given profile identifier."""
        return CDSP_PROFILE_LIMITS.get(sync_profile, CDSP_PROFILE_LIMITS[CDSP_PROFILE_FULL])

    async def cleanup_expired_sessions(self, session) -> int:
        """Called from maintenance loop. Expire old sessions, evict deferred items."""
        repo = SessionRepo(session)
        count = await repo.cleanup_expired(self.config.cdsp_session_timeout)
        deferred_repo = DeferredSyncItemRepo(session)
        await deferred_repo.cleanup_expired()
        return count
