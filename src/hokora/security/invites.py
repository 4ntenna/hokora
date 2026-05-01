# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Invite token management: creation, redemption, rate limiting."""

import asyncio
import hashlib
import logging
import os
import time
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from hokora.constants import (
    INVITE_TOKEN_SIZE,
    INVITE_DEFAULT_EXPIRY_HOURS,
    INVITE_DEFAULT_MAX_USES,
    INVITE_RATE_LIMIT_WINDOW,
    INVITE_RATE_LIMIT_MAX,
    INVITE_FAILURE_BLOCK_THRESHOLD,
    INVITE_FAILURE_BLOCK_DURATION,
    MAX_INVITE_RATE_ENTRIES,
)
from hokora.constants import ROLE_MEMBER
from hokora.db.models import Invite
from hokora.db.queries import RoleRepo, IdentityRepo
from hokora.exceptions import InviteError, PermissionDenied, RateLimitExceeded
from hokora.security.ban import check_not_blocked, record_ban_rejection

logger = logging.getLogger(__name__)


class InviteManager:
    """Manages invite tokens with rate-limited redemption."""

    def __init__(self):
        self._redemption_attempts: dict[str, list[float]] = {}
        self._failure_attempts: dict[str, list[float]] = {}
        self._blocked_until: dict[str, float] = {}
        self._redeem_lock = asyncio.Lock()

    async def create_invite(
        self,
        session: AsyncSession,
        created_by: str,
        channel_id: Optional[str] = None,
        max_uses: int = INVITE_DEFAULT_MAX_USES,
        expiry_hours: int = INVITE_DEFAULT_EXPIRY_HOURS,
        destination_hash: Optional[str] = None,
        destination_pubkey: Optional[str] = None,
    ) -> tuple[str, str]:
        """Create an invite token. Returns (raw_token, token_hash).

        Composite token formats (recipient parses left-to-right):
          ``token``                          — bare (no destination hints)
          ``token:dest_hash``                — 2-field legacy
          ``token:dest_hash:pubkey``         — 3-field with pubkey
        The CLI may further append ``:channel_id`` yielding a 3- or 4-field
        colon-separated string. Daemon validation only inspects the first
        field (token); all other fields are hints for the redeemer.
        """
        raw_token = os.urandom(INVITE_TOKEN_SIZE).hex()
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

        invite = Invite(
            token_hash=token_hash,
            channel_id=channel_id,
            created_by=created_by,
            max_uses=max_uses,
            expires_at=time.time() + (expiry_hours * 3600),
        )
        session.add(invite)
        await session.flush()

        logger.info(f"Created invite (hash={token_hash[:8]}...) by {created_by[:8]}...")

        composite = raw_token
        if destination_hash:
            composite = f"{composite}:{destination_hash}"
            if destination_pubkey:
                composite = f"{composite}:{destination_pubkey}"
        return composite, token_hash

    async def redeem_invite(
        self,
        session: AsyncSession,
        raw_token: str,
        identity_hash: str,
    ) -> Invite:
        """Redeem an invite token with rate limiting.

        Handles composite tokens in ``token:dest_hash`` format by splitting
        on ``:`` before hashing. Auto-assigns the ``member`` role on success.

        Uses an async lock to prevent concurrent redemptions from bypassing
        the max_uses check (TOCTOU race).
        """
        async with self._redeem_lock:
            # Persistent ban gate (Identity.blocked) runs before the
            # in-memory failure-block list so a banned identity sees a
            # consistent rejection regardless of failure-attempt history.
            try:
                await check_not_blocked(session, identity_hash)
            except PermissionDenied:
                record_ban_rejection("invite_redeem")
                raise

            # Transient redemption-failure block (in-memory rate limiter,
            # unrelated to persistent ban above).
            self._check_redeem_block(identity_hash)
            self._check_rate_limit(identity_hash)

            # Handle composite token format (token:dest_hash)
            bare_token = raw_token.split(":")[0] if ":" in raw_token else raw_token
            token_hash = hashlib.sha256(bare_token.encode()).hexdigest()

            result = await session.execute(select(Invite).where(Invite.token_hash == token_hash))
            invite = result.scalar_one_or_none()

            if not invite:
                self._record_failure(identity_hash)
                raise InviteError("Invalid invite token")

            if invite.revoked:
                self._record_failure(identity_hash)
                raise InviteError("Invite has been revoked")

            if invite.expires_at and invite.expires_at < time.time():
                self._record_failure(identity_hash)
                raise InviteError("Invite has expired")

            if invite.max_uses > 0 and invite.uses >= invite.max_uses:
                self._record_failure(identity_hash)
                raise InviteError("Invite has reached max uses")

            invite.uses += 1
            used_by = list(invite.used_by or [])
            used_by.append(identity_hash)
            invite.used_by = used_by
            used_at = list(invite.used_at or [])
            used_at.append(time.time())
            invite.used_at = used_at
            await session.flush()

            # Ensure identity record exists (FK requirement for role assignment)
            identity_repo = IdentityRepo(session)
            await identity_repo.upsert(identity_hash)

            # Auto-assign member role for access control
            role_repo = RoleRepo(session)
            member_role = await role_repo.get_by_name(ROLE_MEMBER)
            if member_role:
                # Check if already assigned (idempotent)
                existing = await role_repo.get_identity_roles(
                    identity_hash,
                    invite.channel_id,
                )
                already_has = any(r.id == member_role.id for r in existing)
                if not already_has:
                    await role_repo.assign_role(
                        member_role.id,
                        identity_hash,
                        channel_id=invite.channel_id,
                        assigned_by=invite.created_by,
                    )
                    scope = f"channel {invite.channel_id}" if invite.channel_id else "node"
                    logger.info(f"Assigned member role to {identity_hash[:8]}... (scope={scope})")

            logger.info(f"Invite redeemed by {identity_hash[:8]}...")
            return invite

    async def revoke_invite(self, session: AsyncSession, token_hash: str) -> bool:
        result = await session.execute(select(Invite).where(Invite.token_hash == token_hash))
        invite = result.scalar_one_or_none()
        if invite:
            invite.revoked = True
            await session.flush()
            return True
        return False

    async def list_invites(
        self,
        session: AsyncSession,
        channel_id: Optional[str] = None,
    ) -> list[Invite]:
        query = select(Invite)
        if channel_id:
            query = query.where(Invite.channel_id == channel_id)
        query = query.order_by(Invite.created_at.desc())
        result = await session.execute(query)
        return list(result.scalars().all())

    def _check_redeem_block(self, identity_hash: str):
        # In-memory transient block applied after repeated invite-redemption
        # failures. Distinct from ``Identity.blocked`` (persistent ban),
        # which is checked via ``security.ban.check_not_blocked`` earlier.
        blocked_until = self._blocked_until.get(identity_hash, 0)
        if time.time() < blocked_until:
            remaining = int(blocked_until - time.time())
            raise RateLimitExceeded(f"Blocked for {remaining}s due to too many failed attempts")

    def _check_rate_limit(self, identity_hash: str):
        now = time.time()
        attempts = self._redemption_attempts.get(identity_hash, [])
        # Clean old attempts
        attempts = [t for t in attempts if now - t < INVITE_RATE_LIMIT_WINDOW]
        self._redemption_attempts[identity_hash] = attempts

        if len(attempts) >= INVITE_RATE_LIMIT_MAX:
            raise RateLimitExceeded("Too many redemption attempts")

        # Cap total tracked identities (already inside _redeem_lock)
        if len(self._redemption_attempts) >= MAX_INVITE_RATE_ENTRIES:
            self._cleanup_stale_sync(600)
            if len(self._redemption_attempts) >= MAX_INVITE_RATE_ENTRIES:
                raise RateLimitExceeded("Too many tracked invite identities")

        attempts.append(now)

    def _cleanup_stale_sync(self, max_age: float = 3600):
        """Remove stale entries from rate-limit dicts (no lock — caller must hold it)."""
        now = time.time()
        stale_redemptions = [
            k
            for k, attempts in self._redemption_attempts.items()
            if not attempts or now - max(attempts) > max_age
        ]
        for k in stale_redemptions:
            del self._redemption_attempts[k]

        stale_failures = [
            k
            for k, attempts in self._failure_attempts.items()
            if not attempts or now - max(attempts) > max_age
        ]
        for k in stale_failures:
            del self._failure_attempts[k]

        stale_blocks = [k for k, until in self._blocked_until.items() if now > until]
        for k in stale_blocks:
            del self._blocked_until[k]

    async def cleanup_stale(self, max_age: float = 3600):
        """Remove stale in-memory rate limit tracking entries.

        Protected by _redeem_lock to avoid mutating dicts while
        redeem_invite() is iterating them.
        """
        async with self._redeem_lock:
            self._cleanup_stale_sync(max_age)

    def _record_failure(self, identity_hash: str):
        now = time.time()
        failures = self._failure_attempts.get(identity_hash, [])
        failures = [t for t in failures if now - t < INVITE_RATE_LIMIT_WINDOW]
        failures.append(now)

        # Cap total tracked failure identities (already inside _redeem_lock)
        if len(self._failure_attempts) >= MAX_INVITE_RATE_ENTRIES:
            self._cleanup_stale_sync(600)
        self._failure_attempts[identity_hash] = failures

        if len(failures) >= INVITE_FAILURE_BLOCK_THRESHOLD:
            self._blocked_until[identity_hash] = now + INVITE_FAILURE_BLOCK_DURATION
            logger.warning(
                f"Blocked {identity_hash[:8]}... for "
                f"{INVITE_FAILURE_BLOCK_DURATION}s due to failed invite attempts"
            )
