# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Ban enforcement chokepoint.

Read-side gate ``check_not_blocked`` is the single place every gated
surface routes through: local message ingest, sync read paths,
federation push receive, federation push send filter, and invite
redemption. Persistent state lives on ``Identity.blocked``;
``BanManager`` owns mutation.
"""

import time
from dataclasses import dataclass
from typing import Optional

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from hokora.db.models import (
    Channel,
    Identity,
    PendingSealedDistribution,
    RoleAssignment,
)
from hokora.db.queries import AuditLogRepo, IdentityRepo
from hokora.exceptions import HokoraError, PermissionDenied


class BanError(HokoraError):
    """Refused ban / unban operation (e.g. attempted ban of node owner)."""


# Surface-keyed rejection counts for the prometheus exporter. No
# ``lxmf_dm`` label: DMs are TUI-to-TUI peer-to-peer, never daemon-ingested.
_BAN_REJECTIONS: dict[str, int] = {}


def get_ban_rejection_counts() -> dict[str, int]:
    """Snapshot of ban-rejection counts (cheap, prometheus-render path)."""
    return dict(_BAN_REJECTIONS)


def record_ban_rejection(surface: str) -> None:
    """Increment the surface-label counter for an enforced ban rejection."""
    _BAN_REJECTIONS[surface] = _BAN_REJECTIONS.get(surface, 0) + 1


async def check_not_blocked(
    session: AsyncSession,
    identity_hash: str,
    *,
    identity_repo: IdentityRepo | None = None,
) -> None:
    """Raise ``PermissionDenied`` if ``identity_hash`` is currently banned."""
    if not identity_hash:
        return
    repo = identity_repo or IdentityRepo(session)
    if await repo.is_blocked(identity_hash):
        raise PermissionDenied(f"Identity {identity_hash[:8]}... is blocked")


async def is_blocked(
    session: AsyncSession,
    identity_hash: str,
    *,
    identity_repo: IdentityRepo | None = None,
) -> bool:
    """Boolean variant for non-raising call sites (e.g. pusher filter loop)."""
    if not identity_hash:
        return False
    repo = identity_repo or IdentityRepo(session)
    return await repo.is_blocked(identity_hash)


@dataclass(frozen=True)
class BanResult:
    """Outcome of ``BanManager.ban``; surfaces sealed channels needing key rotation."""

    target: str
    already_blocked: bool
    sealed_channels: list[tuple[str, str]]
    pending_dropped: int


@dataclass(frozen=True)
class UnbanResult:
    target: str
    was_blocked: bool


class BanManager:
    """Persistent ban surface: mutates Identity.blocked + writes the audit log.

    Refuses to ban the node-owner identity (the resolver short-circuits
    node-owner to PERM_ALL, so banning would leave inconsistent state).
    """

    def __init__(self, node_owner_hash: Optional[str] = None):
        self.node_owner_hash = node_owner_hash

    async def ban(
        self,
        session: AsyncSession,
        target: str,
        *,
        actor: str,
        reason: Optional[str] = None,
    ) -> BanResult:
        if not target:
            raise BanError("Target identity hash is required")
        if self.node_owner_hash and target == self.node_owner_hash:
            raise BanError("Refusing to ban the node-owner identity")

        ident_repo = IdentityRepo(session)
        ident = await ident_repo.get_by_hash(target)
        already_blocked = bool(ident and ident.blocked)

        # Upsert creates the row if missing — no separate "did the identity exist" branch.
        await ident_repo.upsert(
            target,
            blocked=True,
            blocked_at=time.time(),
            blocked_by=actor,
        )

        # Operator-driven rotation: surface sealed channels but never auto-rotate.
        sealed = await session.execute(
            select(Channel.id, Channel.name)
            .join(
                RoleAssignment,
                RoleAssignment.channel_id == Channel.id,
            )
            .where(RoleAssignment.identity_hash == target)
            .where(Channel.sealed.is_(True))
            .distinct()
        )
        sealed_channels = [(row[0], row[1]) for row in sealed.fetchall()]

        # Drop queued sealed-key distributions so a future announce can't
        # materialise a key envelope for the banned identity.
        pending_result = await session.execute(
            delete(PendingSealedDistribution).where(
                PendingSealedDistribution.identity_hash == target
            )
        )
        pending_dropped = int(pending_result.rowcount or 0)

        details: dict = {
            "reason": reason,
            "sealed_channels_at_ban": [cid for cid, _ in sealed_channels],
            "pending_dropped": pending_dropped,
        }
        await AuditLogRepo(session).log(
            actor=actor,
            action_type="identity_ban",
            target=target,
            details=details,
        )

        return BanResult(
            target=target,
            already_blocked=already_blocked,
            sealed_channels=sealed_channels,
            pending_dropped=pending_dropped,
        )

    async def unban(
        self,
        session: AsyncSession,
        target: str,
        *,
        actor: str,
        reason: Optional[str] = None,
    ) -> UnbanResult:
        if not target:
            raise BanError("Target identity hash is required")

        ident_repo = IdentityRepo(session)
        ident = await ident_repo.get_by_hash(target)
        was_blocked = bool(ident and ident.blocked)

        if ident is None:
            # No row to clear — return honest no-op rather than logging a misleading audit entry.
            return UnbanResult(target=target, was_blocked=False)

        ident.blocked = False
        ident.blocked_at = None
        ident.blocked_by = None
        await session.flush()

        await AuditLogRepo(session).log(
            actor=actor,
            action_type="identity_unban",
            target=target,
            details={"reason": reason, "was_blocked": was_blocked},
        )

        return UnbanResult(target=target, was_blocked=was_blocked)

    async def list_banned(self, session: AsyncSession) -> list[Identity]:
        """Return every identity currently flagged ``blocked=True``."""
        result = await session.execute(
            select(Identity).where(Identity.blocked.is_(True)).order_by(Identity.blocked_at.desc())
        )
        return list(result.scalars().all())
