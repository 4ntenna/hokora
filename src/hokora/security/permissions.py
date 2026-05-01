# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Permission resolution: 5-level algorithm."""

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from hokora.constants import (
    ACCESS_WRITE_RESTRICTED,
    PERM_ALL,
    PERM_SEND_MESSAGES,
    PERM_SEND_MEDIA,
    ROLE_CHANNEL_OWNER,
    ROLE_EVERYONE,
)
from hokora.db.queries import RoleRepo
from hokora.db.models import Channel

logger = logging.getLogger(__name__)


class PermissionResolver:
    """Resolves permissions using 5-level hierarchy.

    Resolution order (highest priority first):
    1. Node owner -> all permissions
    2. Channel owner -> all channel permissions
    3. Per-channel role overrides (allow/deny)
    4. Role permissions (OR'd across all roles)
    5. Everyone baseline
    """

    def __init__(self, node_owner_hash: str):
        self.node_owner_hash = node_owner_hash

    async def _get_everyone_role(self, role_repo: RoleRepo):
        """Get @everyone role (always fresh query to reflect runtime changes)."""
        return await role_repo.get_by_name(ROLE_EVERYONE)

    async def resolve(
        self,
        session: AsyncSession,
        identity_hash: str,
        channel: Channel,
        required_permission: int,
    ) -> bool:
        """Check if an identity has a specific permission on a channel."""
        perms = await self.get_effective_permissions(session, identity_hash, channel)
        return bool(perms & required_permission)

    async def get_effective_permissions(
        self,
        session: AsyncSession,
        identity_hash: str,
        channel: Channel,
    ) -> int:
        """Compute the full effective permission bitfield for an identity on a channel."""
        if identity_hash == self.node_owner_hash:
            return PERM_ALL

        role_repo = RoleRepo(session)
        roles = await role_repo.get_identity_roles(identity_hash, channel.id)
        role_names = {r.name for r in roles}

        if ROLE_CHANNEL_OWNER in role_names:
            return PERM_ALL

        # Start with everyone baseline
        everyone_role = await self._get_everyone_role(role_repo)
        perms = everyone_role.permissions if everyone_role else 0

        # OR in role permissions
        for role in roles:
            perms |= role.permissions

        # Batch-fetch all channel overrides in a single query
        # Aggregate all allow/deny bits first, then apply once (order-independent)
        role_ids = [r.id for r in roles]
        overrides = await role_repo.get_all_channel_overrides(channel.id, role_ids)
        all_allow = 0
        all_deny = 0
        for role in roles:
            override = overrides.get(role.id)
            if override:
                all_allow |= override.allow
                all_deny |= override.deny
        perms = (perms | all_allow) & ~all_deny

        # Write-restricted channels: users without explicit roles get read-only access.
        # Only @everyone baseline contributes for role-less users, so strip write bits.
        if channel.access_mode == ACCESS_WRITE_RESTRICTED and not roles:
            perms &= ~(PERM_SEND_MESSAGES | PERM_SEND_MEDIA)

        return perms
