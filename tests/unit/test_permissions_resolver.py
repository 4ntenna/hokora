# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Permission resolver tests: channel overrides, effective permissions, ingest checks."""

import time

import pytest

from hokora.constants import (
    PERM_MANAGE_MEMBERS,
    PERM_SEND_MESSAGES,
    PERM_SEND_MEDIA,
    PERM_USE_MENTIONS,
    PERM_ALL,
)
from hokora.core.message import MessageEnvelope, MessageProcessor
from hokora.core.sequencer import SequenceManager
from hokora.db.models import (
    Channel,
    Role,
    ChannelOverride,
)
from hokora.db.queries import (
    ChannelRepo,
    IdentityRepo,
    RoleRepo,
)
from hokora.exceptions import PermissionDenied
from hokora.security.permissions import PermissionResolver
from hokora.security.ratelimit import RateLimiter
from hokora.security.roles import RoleManager


class TestPermissionResolver:
    async def test_channel_override_deny_takes_precedence(self, session):
        """A channel override deny should block even if role has the perm."""
        ch_repo = ChannelRepo(session)
        channel = Channel(id="overch1", name="override_test", latest_seq=0)
        await ch_repo.create(channel)

        ident_repo = IdentityRepo(session)
        await ident_repo.upsert("overuser")

        role_repo = RoleRepo(session)
        role = Role(
            id="role_with_perm",
            name="role_with_perm_overch1",
            permissions=PERM_MANAGE_MEMBERS,
            position=1,
        )
        await role_repo.create(role)
        await role_repo.assign_role(role.id, "overuser", "overch1")

        # Add channel override that denies MANAGE_MEMBERS
        override = ChannelOverride(
            channel_id="overch1",
            role_id=role.id,
            allow=0,
            deny=PERM_MANAGE_MEMBERS,
        )
        session.add(override)
        await session.flush()

        resolver = PermissionResolver(node_owner_hash="someone_else")
        result = await resolver.resolve(session, "overuser", channel, PERM_MANAGE_MEMBERS)
        assert result is False

    async def test_channel_override_allow(self, session):
        """A channel override allow should grant perm even if role doesn't have it."""
        ch_repo = ChannelRepo(session)
        channel = Channel(id="allowch1", name="allow_test", latest_seq=0)
        await ch_repo.create(channel)

        ident_repo = IdentityRepo(session)
        await ident_repo.upsert("allowuser")

        role_repo = RoleRepo(session)
        role = Role(
            id="role_no_perm",
            name="role_no_perm_allowch1",
            permissions=0,
            position=1,
        )
        await role_repo.create(role)
        await role_repo.assign_role(role.id, "allowuser", "allowch1")

        # Override allows MANAGE_MEMBERS
        override = ChannelOverride(
            channel_id="allowch1",
            role_id=role.id,
            allow=PERM_MANAGE_MEMBERS,
            deny=0,
        )
        session.add(override)
        await session.flush()

        resolver = PermissionResolver(node_owner_hash="someone_else")
        result = await resolver.resolve(session, "allowuser", channel, PERM_MANAGE_MEMBERS)
        assert result is True

    async def test_get_effective_permissions(self, session):
        ch_repo = ChannelRepo(session)
        channel = Channel(id="effch1", name="eff_test", latest_seq=0)
        await ch_repo.create(channel)

        ident_repo = IdentityRepo(session)
        await ident_repo.upsert("effuser")

        role_repo = RoleRepo(session)
        role = Role(
            id="eff_role",
            name="eff_role_effch1",
            permissions=PERM_SEND_MESSAGES | PERM_MANAGE_MEMBERS,
            position=1,
        )
        await role_repo.create(role)
        await role_repo.assign_role(role.id, "effuser", "effch1")

        resolver = PermissionResolver(node_owner_hash="someone_else")
        perms = await resolver.get_effective_permissions(session, "effuser", channel)
        assert perms & PERM_SEND_MESSAGES
        assert perms & PERM_MANAGE_MEMBERS

    async def test_node_owner_gets_all_perms(self, session):
        ch_repo = ChannelRepo(session)
        channel = Channel(id="nownch1", name="nown_test", latest_seq=0)
        await ch_repo.create(channel)

        resolver = PermissionResolver(node_owner_hash="the_owner")
        perms = await resolver.get_effective_permissions(session, "the_owner", channel)
        assert perms == PERM_ALL

    async def test_identity_with_no_roles_denied(self, session):
        """Identity with no roles and no everyone role should be denied."""
        ch_repo = ChannelRepo(session)
        channel = Channel(id="norole1", name="norole_test", latest_seq=0)
        await ch_repo.create(channel)

        ident_repo = IdentityRepo(session)
        await ident_repo.upsert("noroleuser")

        # Do NOT create any builtin roles — ensure no everyone fallback
        resolver = PermissionResolver(node_owner_hash="someone_else")
        result = await resolver.resolve(
            session,
            "noroleuser",
            channel,
            PERM_MANAGE_MEMBERS,
        )
        assert result is False


# ============================================================================
# Ingest Permission Checks (from gap_remediation)
# ============================================================================


class TestIngestPermissionChecks:
    async def _setup(self, session, channel_id="permch_test"):
        """Helper to set up channel, roles, identity, and processor with perms."""
        ch_repo = ChannelRepo(session)
        channel = Channel(id=channel_id, name="perm_test", latest_seq=0)
        await ch_repo.create(channel)

        mgr = RoleManager()
        await mgr.ensure_builtin_roles(session)

        ident_repo = IdentityRepo(session)
        await ident_repo.upsert("allowed_user")
        await ident_repo.upsert("blocked_user", blocked=True, blocked_at=time.time())

        sequencer = SequenceManager()
        await sequencer.load_from_db(session, channel_id)

        resolver = PermissionResolver(node_owner_hash="node_owner_hash")
        rate_limiter = RateLimiter()

        processor = MessageProcessor(
            sequencer=sequencer,
            permission_resolver=resolver,
            rate_limiter=rate_limiter,
            identity_repo=ident_repo,
        )
        return processor

    async def test_ingest_blocked_user(self, session):
        processor = await self._setup(session, "blkch1")

        envelope = MessageEnvelope(
            channel_id="blkch1",
            sender_hash="blocked_user",
            timestamp=time.time(),
            body="Should fail",
        )

        with pytest.raises(PermissionDenied, match="blocked"):
            await processor.ingest(session, envelope)

    async def test_ingest_no_send_permission(self, session):
        """User without SEND_MESSAGES should be denied."""
        ch_repo = ChannelRepo(session)
        channel = Channel(id="nosendch", name="nosend", latest_seq=0)
        await ch_repo.create(channel)

        # Create a role with NO permissions and assign to user
        role_repo = RoleRepo(session)
        # Override everyone role to have 0 perms
        everyone = await role_repo.get_by_name("everyone")
        if everyone:
            everyone.permissions = 0
            await session.flush()

        ident_repo = IdentityRepo(session)
        await ident_repo.upsert("no_perm_user")

        sequencer = SequenceManager()
        await sequencer.load_from_db(session, "nosendch")

        resolver = PermissionResolver(node_owner_hash="node_owner_hash")
        processor = MessageProcessor(
            sequencer=sequencer,
            permission_resolver=resolver,
            identity_repo=ident_repo,
        )

        envelope = MessageEnvelope(
            channel_id="nosendch",
            sender_hash="no_perm_user",
            timestamp=time.time(),
            body="Should fail",
        )

        with pytest.raises(PermissionDenied, match="SEND_MESSAGES"):
            await processor.ingest(session, envelope)


# ============================================================================
# Mention Everyone Permission (from gap_remediation)
# ============================================================================


class TestMentionEveryone:
    async def test_mention_everyone_stripped(self, session):
        """@everyone should be stripped if user lacks PERM_MENTION_EVERYONE."""
        ch_repo = ChannelRepo(session)
        channel = Channel(id="mentch", name="ment_test", latest_seq=0)
        await ch_repo.create(channel)

        mgr = RoleManager()
        await mgr.ensure_builtin_roles(session)

        # Everyone role has send but NOT mention_everyone
        role_repo = RoleRepo(session)
        everyone = await role_repo.get_by_name("everyone")
        if everyone:
            everyone.permissions = PERM_SEND_MESSAGES | PERM_SEND_MEDIA | PERM_USE_MENTIONS
            await session.flush()

        ident_repo = IdentityRepo(session)
        await ident_repo.upsert("mention_user")

        sequencer = SequenceManager()
        await sequencer.load_from_db(session, "mentch")
        resolver = PermissionResolver(node_owner_hash="node_owner_hash")
        processor = MessageProcessor(
            sequencer=sequencer,
            permission_resolver=resolver,
            identity_repo=ident_repo,
        )

        envelope = MessageEnvelope(
            channel_id="mentch",
            sender_hash="mention_user",
            timestamp=time.time(),
            body="Hello @everyone",
            mentions=["user1", "@everyone"],
        )
        msg = await processor.ingest(session, envelope)
        # @everyone should have been stripped
        assert "@everyone" not in msg.mentions
        assert "user1" in msg.mentions
