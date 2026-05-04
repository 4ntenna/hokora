# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Role management with hierarchy enforcement."""

import logging
import uuid
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from hokora.constants import (
    PERM_EVERYONE_DEFAULT,
    PERM_ALL,
    ROLE_NODE_OWNER,
    ROLE_CHANNEL_OWNER,
    ROLE_EVERYONE,
    ROLE_MEMBER,
)
from hokora.db.models import Channel, Role, RoleAssignment
from hokora.db.queries import RoleRepo
from hokora.exceptions import PermissionDenied

logger = logging.getLogger(__name__)

BUILTIN_ROLES = {
    ROLE_NODE_OWNER: {
        "permissions": PERM_ALL,
        "position": 1000,
        "is_builtin": True,
        "colour": "#FF0000",
        "mentionable": False,
    },
    ROLE_CHANNEL_OWNER: {
        "permissions": PERM_ALL,
        "position": 999,
        "is_builtin": True,
        "colour": "#FFA500",
        "mentionable": False,
    },
    ROLE_EVERYONE: {
        "permissions": PERM_EVERYONE_DEFAULT,
        "position": 0,
        "is_builtin": True,
        "colour": "#FFFFFF",
        "mentionable": False,
    },
    ROLE_MEMBER: {
        "permissions": PERM_EVERYONE_DEFAULT,
        "position": 1,
        "is_builtin": True,
        "colour": "#FFFFFF",
        "mentionable": False,
    },
}


class RoleManager:
    """Manages roles with hierarchy enforcement."""

    async def ensure_builtin_roles(self, session: AsyncSession):
        """Create or refresh built-in roles from code definitions."""
        repo = RoleRepo(session)
        for name, attrs in BUILTIN_ROLES.items():
            existing = await repo.get_by_name(name)
            if not existing:
                role = Role(
                    id=uuid.uuid4().hex[:16],
                    name=name,
                    **attrs,
                )
                await repo.create(role)
                logger.info(f"Created built-in role: {name}")
            elif existing.is_builtin:
                # Refresh permissions from code (propagates new flags on restart)
                if existing.permissions != attrs["permissions"]:
                    logger.info(
                        f"Refreshed built-in role {name}: "
                        f"perms 0x{existing.permissions:04x} -> 0x{attrs['permissions']:04x}"
                    )
                    existing.permissions = attrs["permissions"]
                    existing.position = attrs["position"]
                    await session.flush()

    async def create_role(
        self,
        session: AsyncSession,
        name: str,
        permissions: int = 0,
        position: int = 1,
        actor_hash: Optional[str] = None,
        actor_position: Optional[int] = None,
    ) -> Role:
        """Create a new role with hierarchy enforcement."""
        if name in BUILTIN_ROLES:
            raise PermissionDenied(f"Cannot create role with built-in name: {name}")

        # Hierarchy check: can't create role above own position
        if actor_position is not None and position >= actor_position:
            raise PermissionDenied("Cannot create role at or above your own position")

        repo = RoleRepo(session)
        role = Role(
            id=uuid.uuid4().hex[:16],
            name=name,
            permissions=permissions,
            position=position,
        )
        return await repo.create(role)

    async def assign_role(
        self,
        session: AsyncSession,
        role_id: str,
        identity_hash: str,
        channel_id: Optional[str] = None,
        assigned_by: Optional[str] = None,
        actor_position: Optional[int] = None,
    ) -> RoleAssignment:
        """Assign a role to an identity with hierarchy enforcement."""
        repo = RoleRepo(session)
        role = await repo.get_by_id(role_id)
        if not role:
            raise PermissionDenied(f"Role {role_id} not found")

        # Can't assign role above own position
        if actor_position is not None and role.position >= actor_position:
            raise PermissionDenied("Cannot assign role at or above your own position")

        return await repo.assign_role(role_id, identity_hash, channel_id, assigned_by)

    async def remove_role(
        self,
        session: AsyncSession,
        role_id: str,
        identity_hash: str,
        channel_id: Optional[str] = None,
        sealed_manager=None,
        lxmf_router=None,
        node_identity=None,
    ) -> bool:
        """Remove a role assignment. If the channel is sealed, trigger key rotation."""
        # Find and delete the assignment
        from sqlalchemy import and_

        conditions = [
            RoleAssignment.role_id == role_id,
            RoleAssignment.identity_hash == identity_hash,
        ]
        if channel_id:
            conditions.append(RoleAssignment.channel_id == channel_id)
        else:
            conditions.append(RoleAssignment.channel_id.is_(None))

        result = await session.execute(select(RoleAssignment).where(and_(*conditions)))
        assignment = result.scalar_one_or_none()
        if not assignment:
            return False

        await session.delete(assignment)
        await session.flush()

        # If this is a sealed channel, rotate the group key
        if channel_id and sealed_manager:
            ch_result = await session.execute(select(Channel).where(Channel.id == channel_id))
            channel = ch_result.scalar_one_or_none()
            if channel and channel.sealed:
                # Get remaining members
                remaining = await session.execute(
                    select(RoleAssignment.identity_hash)
                    .where(RoleAssignment.channel_id == channel_id)
                    .where(RoleAssignment.identity_hash != identity_hash)
                )
                remaining_hashes = [r[0] for r in remaining.fetchall()]

                if lxmf_router and node_identity:
                    sealed_manager.rotate_and_distribute(
                        channel_id,
                        remaining_hashes,
                        lxmf_router,
                        node_identity,
                    )
                else:
                    sealed_manager.rotate_key(channel_id)
                logger.info(
                    f"Rotated sealed key for channel {channel_id} after removing {identity_hash}"
                )

        return True

    async def get_identity_roles(
        self,
        session: AsyncSession,
        identity_hash: str,
        channel_id: Optional[str] = None,
    ) -> list[Role]:
        repo = RoleRepo(session)
        return await repo.get_identity_roles(identity_hash, channel_id)
