# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for private channel access control and invite-based membership."""

import pytest
from unittest.mock import MagicMock

from hokora.constants import (
    ACCESS_PRIVATE,
    ACCESS_PUBLIC,
    ROLE_MEMBER,
    SYNC_REDEEM_INVITE,
)
from hokora.db.models import Channel, Identity
from hokora.db.queries import RoleRepo
from hokora.exceptions import PermissionDenied, SyncError
from hokora.protocol.sync import SyncHandler
from hokora.protocol.wire import generate_nonce
from hokora.security.invites import InviteManager
from hokora.security.permissions import PermissionResolver
from hokora.security.roles import RoleManager

from tests.conftest import make_identity_hash


NODE_OWNER_HASH = make_identity_hash(99)
MEMBER_HASH = make_identity_hash(1)
OUTSIDER_HASH = make_identity_hash(2)


async def _ensure_identity(session, identity_hash):
    """Insert an Identity row if it doesn't already exist."""
    from sqlalchemy import select

    result = await session.execute(select(Identity).where(Identity.hash == identity_hash))
    if not result.scalar_one_or_none():
        session.add(Identity(hash=identity_hash, display_name=identity_hash[:8]))
        await session.flush()


async def _ensure_channel_row(session, ch_id, access_mode=ACCESS_PRIVATE):
    """Insert a Channel row if it doesn't already exist."""
    from sqlalchemy import select

    result = await session.execute(select(Channel).where(Channel.id == ch_id))
    if not result.scalar_one_or_none():
        session.add(Channel(id=ch_id, name=ch_id, access_mode=access_mode))
        await session.flush()


def _make_mock_channel(ch_id, access_mode=ACCESS_PRIVATE, name="test"):
    """Mock channel object for ChannelManager (not DB)."""
    ch = MagicMock(spec=Channel)
    ch.id = ch_id
    ch.name = name
    ch.description = ""
    ch.access_mode = access_mode
    ch.category_id = None
    ch.position = 0
    ch.identity_hash = "deadbeef" * 4
    ch.latest_seq = 0
    ch.sealed = False
    ch.created_at = 0
    return ch


def _make_handler(channels):
    ch_mgr = MagicMock()
    ch_mgr.get_channel = lambda cid: {c.id: c for c in channels}.get(cid)
    ch_mgr.list_channels = lambda: channels
    return SyncHandler(
        ch_mgr,
        MagicMock(),
        node_name="test",
        permission_resolver=PermissionResolver(NODE_OWNER_HASH),
    )


class TestCheckChannelRead:
    """Test _check_channel_read access control helper."""

    async def test_public_channel_allows_anonymous(self, session):
        ch = _make_mock_channel("pub1", ACCESS_PUBLIC)
        handler = _make_handler([ch])
        result = await handler._check_channel_read(session, "pub1", requester_hash=None)
        assert result == ch

    async def test_private_channel_denies_anonymous(self, session):
        ch = _make_mock_channel("priv1", ACCESS_PRIVATE)
        handler = _make_handler([ch])
        with pytest.raises(PermissionDenied, match="Authentication required"):
            await handler._check_channel_read(session, "priv1", requester_hash=None)

    async def test_private_channel_allows_node_owner(self, session):
        ch = _make_mock_channel("priv1", ACCESS_PRIVATE)
        handler = _make_handler([ch])
        result = await handler._check_channel_read(
            session,
            "priv1",
            requester_hash=NODE_OWNER_HASH,
        )
        assert result == ch

    async def test_private_channel_allows_member(self, session):
        ch = _make_mock_channel("priv1", ACCESS_PRIVATE)
        handler = _make_handler([ch])

        # Create FK prerequisites
        await _ensure_identity(session, MEMBER_HASH)
        await _ensure_channel_row(session, "priv1", ACCESS_PRIVATE)

        role_mgr = RoleManager()
        await role_mgr.ensure_builtin_roles(session)
        role_repo = RoleRepo(session)
        member_role = await role_repo.get_by_name(ROLE_MEMBER)
        await role_repo.assign_role(member_role.id, MEMBER_HASH, channel_id="priv1")
        await session.flush()

        result = await handler._check_channel_read(
            session,
            "priv1",
            requester_hash=MEMBER_HASH,
        )
        assert result == ch

    async def test_private_channel_denies_non_member(self, session):
        ch = _make_mock_channel("priv1", ACCESS_PRIVATE)
        handler = _make_handler([ch])

        role_mgr = RoleManager()
        await role_mgr.ensure_builtin_roles(session)

        with pytest.raises(PermissionDenied, match="Not a member"):
            await handler._check_channel_read(
                session,
                "priv1",
                requester_hash=OUTSIDER_HASH,
            )

    async def test_unknown_channel_raises_sync_error(self, session):
        handler = _make_handler([])
        with pytest.raises(SyncError, match="not found"):
            await handler._check_channel_read(session, "nope", requester_hash=MEMBER_HASH)

    async def test_blocked_identity_denied_on_public_channel(self, session):
        # Ban gate runs before access-mode resolution; even a public
        # channel rejects a banned reader and increments the sync_read
        # surface counter on the prometheus exporter.
        from hokora.security import ban as ban_module
        from hokora.security.ban import get_ban_rejection_counts

        ban_module._BAN_REJECTIONS.clear()

        ch = _make_mock_channel("pub1", ACCESS_PUBLIC)
        handler = _make_handler([ch])
        await _ensure_identity(session, MEMBER_HASH)
        from hokora.db.queries import IdentityRepo

        await IdentityRepo(session).upsert(MEMBER_HASH, blocked=True)

        with pytest.raises(PermissionDenied, match="is blocked"):
            await handler._check_channel_read(session, "pub1", requester_hash=MEMBER_HASH)
        assert get_ban_rejection_counts()["sync_read"] == 1

    async def test_blocked_identity_denied_on_private_channel(self, session):
        ch = _make_mock_channel("priv1", ACCESS_PRIVATE)
        handler = _make_handler([ch])
        await _ensure_identity(session, MEMBER_HASH)
        from hokora.db.queries import IdentityRepo

        await IdentityRepo(session).upsert(MEMBER_HASH, blocked=True)

        # Ban check raises before the membership check, so the message
        # is "is blocked" not "Not a member" — uniform error surface.
        with pytest.raises(PermissionDenied, match="is blocked"):
            await handler._check_channel_read(session, "priv1", requester_hash=MEMBER_HASH)


class TestNodeMetaFiltering:
    """Test that _handle_node_meta hides private channels from non-members."""

    async def test_anonymous_sees_private_when_show_enabled(self, session):
        """With show_private_channels=True (default), all channels visible."""
        pub = _make_mock_channel("pub1", ACCESS_PUBLIC, name="public")
        priv = _make_mock_channel("priv1", ACCESS_PRIVATE, name="secret")
        handler = _make_handler([pub, priv])

        result = await handler._handle_node_meta(
            session,
            b"\x00" * 16,
            {},
            None,
            requester_hash=None,
        )
        channel_ids = [c["id"] for c in result["channels"]]
        assert "pub1" in channel_ids
        assert "priv1" in channel_ids

    async def test_node_owner_sees_all(self, session):
        pub = _make_mock_channel("pub1", ACCESS_PUBLIC)
        priv = _make_mock_channel("priv1", ACCESS_PRIVATE)
        handler = _make_handler([pub, priv])

        result = await handler._handle_node_meta(
            session,
            b"\x00" * 16,
            {},
            None,
            requester_hash=NODE_OWNER_HASH,
        )
        channel_ids = [c["id"] for c in result["channels"]]
        assert "pub1" in channel_ids
        assert "priv1" in channel_ids

    async def test_member_sees_their_private_channel(self, session):
        pub = _make_mock_channel("pub1", ACCESS_PUBLIC)
        priv = _make_mock_channel("priv1", ACCESS_PRIVATE)
        handler = _make_handler([pub, priv])

        # Create FK prerequisites
        await _ensure_identity(session, MEMBER_HASH)
        await _ensure_channel_row(session, "priv1", ACCESS_PRIVATE)

        role_mgr = RoleManager()
        await role_mgr.ensure_builtin_roles(session)
        role_repo = RoleRepo(session)
        member_role = await role_repo.get_by_name(ROLE_MEMBER)
        await role_repo.assign_role(member_role.id, MEMBER_HASH, channel_id="priv1")
        await session.flush()

        result = await handler._handle_node_meta(
            session,
            b"\x00" * 16,
            {},
            None,
            requester_hash=MEMBER_HASH,
        )
        channel_ids = [c["id"] for c in result["channels"]]
        assert "pub1" in channel_ids
        assert "priv1" in channel_ids


class TestInviteGrantsMembership:
    """Test that redeeming an invite auto-assigns the member role."""

    async def test_redeem_assigns_member_role_channel(self, session):
        await _ensure_identity(session, MEMBER_HASH)
        await _ensure_channel_row(session, "ch_priv", ACCESS_PRIVATE)

        role_mgr = RoleManager()
        await role_mgr.ensure_builtin_roles(session)

        mgr = InviteManager()
        raw_token, _ = await mgr.create_invite(
            session,
            "creator_hash",
            channel_id="ch_priv",
        )

        await mgr.redeem_invite(session, raw_token, MEMBER_HASH)

        role_repo = RoleRepo(session)
        roles = await role_repo.get_identity_roles(MEMBER_HASH, "ch_priv")
        role_names = [r.name for r in roles]
        assert ROLE_MEMBER in role_names

    async def test_redeem_node_invite_assigns_global_member(self, session):
        await _ensure_identity(session, MEMBER_HASH)

        role_mgr = RoleManager()
        await role_mgr.ensure_builtin_roles(session)

        mgr = InviteManager()
        raw_token, _ = await mgr.create_invite(
            session,
            "creator_hash",
            channel_id=None,
        )

        await mgr.redeem_invite(session, raw_token, MEMBER_HASH)

        role_repo = RoleRepo(session)
        roles = await role_repo.get_identity_roles(MEMBER_HASH)
        role_names = [r.name for r in roles]
        assert ROLE_MEMBER in role_names

    async def test_redeem_idempotent(self, session):
        await _ensure_identity(session, MEMBER_HASH)
        await _ensure_channel_row(session, "ch1", ACCESS_PRIVATE)

        role_mgr = RoleManager()
        await role_mgr.ensure_builtin_roles(session)

        mgr = InviteManager()
        raw1, _ = await mgr.create_invite(
            session,
            "creator_hash",
            channel_id="ch1",
            max_uses=2,
        )
        raw2, _ = await mgr.create_invite(
            session,
            "creator_hash",
            channel_id="ch1",
            max_uses=1,
        )

        await mgr.redeem_invite(session, raw1, MEMBER_HASH)
        await mgr.redeem_invite(session, raw2, MEMBER_HASH)

        role_repo = RoleRepo(session)
        roles = await role_repo.get_identity_roles(MEMBER_HASH, "ch1")
        member_roles = [r for r in roles if r.name == ROLE_MEMBER]
        assert len(member_roles) == 1  # Not duplicated


class TestCompositeToken:
    """Test composite token format (token:dest_hash)."""

    async def test_create_with_destination_hash(self, session):
        mgr = InviteManager()
        raw_token, _ = await mgr.create_invite(
            session,
            "creator_hash",
            destination_hash="abcd1234",
        )
        assert ":" in raw_token
        parts = raw_token.split(":")
        assert len(parts) == 2
        assert parts[1] == "abcd1234"

    async def test_create_without_destination_hash(self, session):
        mgr = InviteManager()
        raw_token, _ = await mgr.create_invite(session, "creator_hash")
        assert ":" not in raw_token

    async def test_redeem_composite_token(self, session):
        await _ensure_identity(session, MEMBER_HASH)

        role_mgr = RoleManager()
        await role_mgr.ensure_builtin_roles(session)

        mgr = InviteManager()
        raw_token, _ = await mgr.create_invite(
            session,
            "creator_hash",
            destination_hash="abcd1234",
        )

        invite = await mgr.redeem_invite(session, raw_token, MEMBER_HASH)
        assert invite.uses == 1

    async def test_redeem_plain_token_still_works(self, session):
        await _ensure_identity(session, MEMBER_HASH)

        role_mgr = RoleManager()
        await role_mgr.ensure_builtin_roles(session)

        mgr = InviteManager()
        raw_token, _ = await mgr.create_invite(session, "creator_hash")

        invite = await mgr.redeem_invite(session, raw_token, MEMBER_HASH)
        assert invite.uses == 1


class TestSyncRedeemInvite:
    """Test the SYNC_REDEEM_INVITE protocol action (Gap A)."""

    async def test_redeem_invite_via_sync(self, session):
        """Redeeming an invite over the sync protocol assigns the member role."""
        await _ensure_identity(session, MEMBER_HASH)
        await _ensure_channel_row(session, "priv_sync", ACCESS_PRIVATE)

        role_mgr = RoleManager()
        await role_mgr.ensure_builtin_roles(session)

        invite_mgr = InviteManager()
        raw_token, _ = await invite_mgr.create_invite(
            session,
            "creator_hash",
            channel_id="priv_sync",
            destination_hash="deadbeef1234",
        )

        priv = _make_mock_channel("priv_sync", ACCESS_PRIVATE)
        ch_mgr = MagicMock()
        ch_mgr.get_channel = lambda cid: {"priv_sync": priv}.get(cid)
        ch_mgr.list_channels = lambda: [priv]

        handler = SyncHandler(
            ch_mgr,
            MagicMock(),
            node_name="test",
            permission_resolver=PermissionResolver(NODE_OWNER_HASH),
            invite_manager=invite_mgr,
        )

        nonce = generate_nonce()
        result = await handler.handle(
            session,
            SYNC_REDEEM_INVITE,
            nonce,
            payload={"token": raw_token},
            requester_hash=MEMBER_HASH,
        )

        assert result["action"] == "invite_redeemed"
        assert result["channel_id"] == "priv_sync"
        assert result["identity_hash"] == MEMBER_HASH

        # Verify member role was assigned
        role_repo = RoleRepo(session)
        roles = await role_repo.get_identity_roles(MEMBER_HASH, "priv_sync")
        role_names = [r.name for r in roles]
        assert ROLE_MEMBER in role_names

    async def test_redeem_invite_requires_auth(self, session):
        """Anonymous users cannot redeem invites."""
        priv = _make_mock_channel("priv1", ACCESS_PRIVATE)
        handler = _make_handler([priv])

        nonce = generate_nonce()
        with pytest.raises(SyncError, match="Authentication required"):
            await handler.handle(
                session,
                SYNC_REDEEM_INVITE,
                nonce,
                payload={"token": "fake_token"},
                requester_hash=None,
            )

    async def test_redeem_invite_invalid_token(self, session):
        """Invalid tokens raise SyncError."""
        priv = _make_mock_channel("priv1", ACCESS_PRIVATE)
        handler = _make_handler([priv])

        nonce = generate_nonce()
        with pytest.raises(SyncError, match="Invite redemption failed"):
            await handler.handle(
                session,
                SYNC_REDEEM_INVITE,
                nonce,
                payload={"token": "totally_invalid_token"},
                requester_hash=MEMBER_HASH,
            )

    async def test_redeem_invite_no_token(self, session):
        """Missing token raises SyncError."""
        priv = _make_mock_channel("priv1", ACCESS_PRIVATE)
        handler = _make_handler([priv])

        nonce = generate_nonce()
        with pytest.raises(SyncError, match="No token"):
            await handler.handle(
                session,
                SYNC_REDEEM_INVITE,
                nonce,
                payload={},
                requester_hash=MEMBER_HASH,
            )
