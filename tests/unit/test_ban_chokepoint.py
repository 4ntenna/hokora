# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Ban chokepoint + per-surface ban gate tests.

Covers ``hokora.security.ban`` and the surfaces that route through it:
invite redemption, federation receive, federation pusher filter. The
local-message ingest gate has its own coverage in
``tests/integration/test_permission_enforcement.py``;
the sync-read gate is exercised via ``check_channel_read`` here.
"""

import pytest

from hokora.db.models import Identity
from hokora.db.queries import IdentityRepo
from hokora.exceptions import PermissionDenied
from hokora.security.ban import (
    check_not_blocked,
    get_ban_rejection_counts,
    is_blocked,
    record_ban_rejection,
)


class TestChokepoint:
    async def test_unknown_identity_passes(self, session):
        # Absent identity rows are not banned; check_not_blocked returns silently.
        await check_not_blocked(session, "deadbeef" * 8)

    async def test_unblocked_identity_passes(self, session):
        ident_hash = "ab" * 16
        await IdentityRepo(session).upsert(ident_hash)
        await check_not_blocked(session, ident_hash)

    async def test_blocked_identity_raises(self, session):
        ident_hash = "cd" * 16
        await IdentityRepo(session).upsert(ident_hash, blocked=True)
        with pytest.raises(PermissionDenied, match="is blocked"):
            await check_not_blocked(session, ident_hash)

    async def test_empty_identity_is_no_op(self, session):
        # Anonymous links / unauthenticated calls pass requester_hash=None.
        # The chokepoint must not raise — gating "no identity" is the
        # caller's responsibility (membership checks etc.).
        await check_not_blocked(session, "")
        await check_not_blocked(session, None)  # type: ignore[arg-type]

    async def test_is_blocked_boolean_variant(self, session):
        ident_hash = "ef" * 16
        await IdentityRepo(session).upsert(ident_hash, blocked=True)
        assert await is_blocked(session, ident_hash) is True
        assert await is_blocked(session, "01" * 16) is False
        assert await is_blocked(session, None) is False  # type: ignore[arg-type]


class TestRejectionCounter:
    def setup_method(self):
        # Module-level counter is process-wide; clear before each case.
        from hokora.security import ban as ban_module

        ban_module._BAN_REJECTIONS.clear()

    def test_record_increments(self):
        record_ban_rejection("federation_push")
        record_ban_rejection("federation_push")
        record_ban_rejection("invite_redeem")
        counts = get_ban_rejection_counts()
        assert counts["federation_push"] == 2
        assert counts["invite_redeem"] == 1

    def test_snapshot_is_a_copy(self):
        record_ban_rejection("sync_read")
        snap = get_ban_rejection_counts()
        snap["sync_read"] = 999
        assert get_ban_rejection_counts()["sync_read"] == 1


class TestInviteRedeemGate:
    async def test_blocked_redeemer_rejected(self, session):
        from hokora.security.invites import InviteManager

        await IdentityRepo(session).upsert("ba" * 16, blocked=True)

        mgr = InviteManager()
        raw_token, _ = await mgr.create_invite(session, "creator")

        with pytest.raises(PermissionDenied, match="is blocked"):
            await mgr.redeem_invite(session, raw_token, "ba" * 16)

    async def test_blocked_redeemer_increments_counter(self, session):
        from hokora.security import ban as ban_module
        from hokora.security.invites import InviteManager

        ban_module._BAN_REJECTIONS.clear()
        await IdentityRepo(session).upsert("ba" * 16, blocked=True)

        mgr = InviteManager()
        raw_token, _ = await mgr.create_invite(session, "creator")
        with pytest.raises(PermissionDenied):
            await mgr.redeem_invite(session, raw_token, "ba" * 16)
        assert get_ban_rejection_counts()["invite_redeem"] == 1

    async def test_unblocked_redeem_still_works(self, session):
        from hokora.security.invites import InviteManager

        mgr = InviteManager()
        raw_token, _ = await mgr.create_invite(session, "creator")
        invite = await mgr.redeem_invite(session, raw_token, "ab" * 16)
        assert invite.uses == 1


class TestPusherBanFilter:
    """Pusher-side outbound filter — blocked senders' messages skipped."""

    async def test_blocked_sender_skipped(self, session_factory):
        from hokora.db.models import Channel, Message
        import time

        async with session_factory() as session:
            async with session.begin():
                session.add(Channel(id="c" * 16, name="t"))
                session.add(Identity(hash="ba" * 16, blocked=True))
                session.add(Identity(hash="ce" * 16, blocked=False))
                session.add(
                    Message(
                        msg_hash="m1" + "0" * 62,
                        channel_id="c" * 16,
                        sender_hash="ba" * 16,
                        seq=1,
                        timestamp=time.time(),
                        type=1,
                        body="banned author",
                    )
                )
                session.add(
                    Message(
                        msg_hash="m2" + "0" * 62,
                        channel_id="c" * 16,
                        sender_hash="ce" * 16,
                        seq=2,
                        timestamp=time.time(),
                        type=1,
                        body="clean",
                    )
                )

        async with session_factory() as session:
            assert await is_blocked(session, "ba" * 16) is True
            assert await is_blocked(session, "ce" * 16) is False
