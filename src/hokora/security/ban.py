# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Ban enforcement chokepoint.

Single helper that reads ``Identity.blocked`` and raises ``PermissionDenied``
when a banned identity attempts a gated action. Every surface that should
reject banned identities (local message ingest, sync read paths, federation
push receive, federation push send filter, invite redemption, LXMF DM
ingest) routes through ``check_not_blocked`` so the ban semantics are
defined in exactly one place.

The persistent ban state lives on the ``Identity`` row (``blocked``,
``blocked_at``, ``blocked_by``); ``BanManager`` owns mutation, this module
owns the read-side gate.
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


# Process-wide tally of ban-rejections at non-local surfaces, keyed on a
# coarse surface label (``federation_push`` / ``invite_redeem`` /
# ``sync_read``). Read by core.prometheus_exporter; reset by tests.
# Mirrors the binding-rejection counter pattern in federation.auth.
#
# DMs in Hokora are TUI-to-TUI peer-to-peer over LXMF transport; the
# daemon never ingests DMs, so there is no ``lxmf_dm`` surface label.
# Channel-message LXMF delivery is gated via the local-ingest chokepoint
# in ``core.message.MessageProcessor._check_permissions``.
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
    """Outcome of a ``BanManager.ban`` call.

    ``sealed_channels`` lists the (channel_id, channel_name) of every sealed
    channel the target was a member of at ban time; the operator should
    rotate keys on each via ``hokora channel rotate-key``. ``pending_dropped``
    is the count of ``pending_sealed_distributions`` rows removed.
    """

    target: str
    already_blocked: bool
    sealed_channels: list[tuple[str, str]]
    pending_dropped: int


@dataclass(frozen=True)
class UnbanResult:
    target: str
    was_blocked: bool


class BanManager:
    """Persistent ban surface: mutate ``Identity.blocked`` + audit log.

    Reads remain in ``check_not_blocked`` / ``is_blocked``; this class is
    the single write-side path. CLI (``hokora ban``) and any future
    protocol handler funnel here so audit-log writes and sealed-key
    rotation hints are produced uniformly.

    Refuses to ban the node-owner identity. The permission resolver
    short-circuits node-owner to ``PERM_ALL`` (see
    ``security.permissions.PermissionResolver.get_effective_permissions``);
    a banned-but-still-omnipotent owner row would leave the daemon in an
    inconsistent state, so the refusal lives at the mutation boundary.
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

        # Upsert sets blocked + provenance even if the row didn't exist
        # before. ``hokora.db.queries.IdentityRepo.upsert`` always touches
        # ``last_seen`` — that's expected for a row we are now writing.
        await ident_repo.upsert(
            target,
            blocked=True,
            blocked_at=time.time(),
            blocked_by=actor,
        )

        # Sealed-channel exposure surface: enumerate every sealed channel
        # the target was a channel-scoped role-assigned member of. The
        # operator runs ``hokora channel rotate-key`` per channel — we do
        # not auto-rotate (operator decision; mirrors how
        # ``hokora role revoke`` defers rotation to the operator).
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

        # Pending sealed-key distributions queued for the target are now
        # invalid. Mirrors the ``hokora role revoke`` cleanup at
        # ``cli/role.py::_revoke_role`` so banned identities cannot have a
        # key envelope materialised by their next announce.
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
            # No row to clear; recording the audit entry would mislead, so
            # report the no-op honestly to the caller.
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
