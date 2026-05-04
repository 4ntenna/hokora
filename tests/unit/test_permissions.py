# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Test permission resolution."""

import uuid


from hokora.constants import (
    PERM_SEND_MESSAGES,
    PERM_DELETE_OTHERS,
    PERM_SEND_MEDIA,
    PERM_PIN_MESSAGES,
    PERM_ALL,
    PERM_EVERYONE_DEFAULT,
)
from hokora.db.models import Channel, ChannelOverride, Identity, Role, RoleAssignment
from hokora.security.permissions import PermissionResolver
from hokora.security.roles import RoleManager


class TestPermissionResolver:
    async def test_node_owner_has_all(self, session):
        resolver = PermissionResolver(node_owner_hash="owner_hash_123")

        channel = Channel(id="permch1", name="test")
        session.add(channel)
        await session.flush()

        result = await resolver.resolve(
            session,
            "owner_hash_123",
            channel,
            PERM_DELETE_OTHERS,
        )
        assert result is True

    async def test_everyone_baseline(self, session):
        # Create everyone role with default perms
        mgr = RoleManager()
        await mgr.ensure_builtin_roles(session)

        resolver = PermissionResolver(node_owner_hash="not_this_user")

        channel = Channel(id="permch2", name="test2")
        session.add(channel)

        identity = Identity(hash="random_user_123")
        session.add(identity)
        await session.flush()

        # Everyone should have SEND_MESSAGES by default
        result = await resolver.resolve(
            session,
            "random_user_123",
            channel,
            PERM_SEND_MESSAGES,
        )
        assert result is True

        # Everyone should NOT have DELETE_OTHERS by default
        result = await resolver.resolve(
            session,
            "random_user_123",
            channel,
            PERM_DELETE_OTHERS,
        )
        assert result is False

    async def test_resolve_with_channel_overrides_batch(self, session):
        """Verify override allow/deny works correctly with batch query."""
        mgr = RoleManager()
        await mgr.ensure_builtin_roles(session)

        channel = Channel(id="permch_ovr", name="override_test")
        session.add(channel)

        identity = Identity(hash="override_user_1")
        session.add(identity)
        await session.flush()

        # Create a custom role with no special permissions
        role = Role(
            id=uuid.uuid4().hex[:16],
            name="custom_role",
            permissions=0,
            position=5,
        )
        session.add(role)
        await session.flush()

        # Assign the role to the identity
        assignment = RoleAssignment(
            role_id=role.id,
            identity_hash="override_user_1",
        )
        session.add(assignment)
        await session.flush()

        # Add channel override that allows PIN_MESSAGES but denies SEND_MEDIA
        override = ChannelOverride(
            channel_id="permch_ovr",
            role_id=role.id,
            allow=PERM_PIN_MESSAGES,
            deny=PERM_SEND_MEDIA,
        )
        session.add(override)
        await session.flush()

        resolver = PermissionResolver(node_owner_hash="not_this_user")

        # PIN_MESSAGES should be allowed via override
        result = await resolver.resolve(
            session,
            "override_user_1",
            channel,
            PERM_PIN_MESSAGES,
        )
        assert result is True

        # SEND_MEDIA should be denied via override (even though @everyone grants it)
        result = await resolver.resolve(
            session,
            "override_user_1",
            channel,
            PERM_SEND_MEDIA,
        )
        assert result is False

        # SEND_MESSAGES should still come through from @everyone baseline
        result = await resolver.resolve(
            session,
            "override_user_1",
            channel,
            PERM_SEND_MESSAGES,
        )
        assert result is True

    async def test_effective_permissions_single_call(self, session):
        """Verify get_effective_permissions returns correct bitmask in one call."""
        mgr = RoleManager()
        await mgr.ensure_builtin_roles(session)

        channel = Channel(id="permch_eff", name="effective_test")
        session.add(channel)

        identity = Identity(hash="eff_user_1")
        session.add(identity)
        await session.flush()

        resolver = PermissionResolver(node_owner_hash="not_this_user")

        # Node owner should get PERM_ALL
        perms = await resolver.get_effective_permissions(
            session,
            "not_this_user",
            channel,
        )
        assert perms == PERM_ALL

        # Regular user should get @everyone defaults
        perms = await resolver.get_effective_permissions(
            session,
            "eff_user_1",
            channel,
        )
        assert perms == PERM_EVERYONE_DEFAULT

        # Verify individual bit checks match resolve()
        assert bool(perms & PERM_SEND_MESSAGES) is True
        assert bool(perms & PERM_DELETE_OTHERS) is False

    async def test_everyone_role_fetched_fresh_each_call(self, session):
        """Verify @everyone role is always fetched fresh (no stale cache)."""
        mgr = RoleManager()
        await mgr.ensure_builtin_roles(session)

        channel = Channel(id="permch_cache", name="cache_test")
        session.add(channel)

        identity = Identity(hash="cache_user_1")
        session.add(identity)
        await session.flush()

        resolver = PermissionResolver(node_owner_hash="not_this_user")

        # Resolver should not have a _everyone_role cache attribute
        assert not hasattr(resolver, "_everyone_role")

        # Both calls should succeed (fetching fresh each time)
        result1 = await resolver.resolve(session, "cache_user_1", channel, PERM_SEND_MESSAGES)
        result2 = await resolver.resolve(session, "cache_user_1", channel, PERM_DELETE_OTHERS)
        assert isinstance(result1, bool)
        assert isinstance(result2, bool)
