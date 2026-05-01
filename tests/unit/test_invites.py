# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Test invite token management."""

import asyncio

import pytest

from hokora.security.invites import InviteManager
from hokora.exceptions import InviteError


class TestInviteManager:
    async def test_create_and_redeem(self, session):
        mgr = InviteManager()
        raw_token, token_hash = await mgr.create_invite(
            session,
            "creator_hash",
            max_uses=1,
        )

        assert len(raw_token) == 32  # 16 bytes hex
        invite = await mgr.redeem_invite(session, raw_token, "redeemer_hash")
        assert invite.uses == 1

    async def test_composite_with_destination_hash(self, session):
        """destination_hash alone yields token:dest (2-field)."""
        mgr = InviteManager()
        composite, _ = await mgr.create_invite(
            session,
            "creator",
            destination_hash="deadbeef" * 4,
        )
        parts = composite.split(":")
        assert len(parts) == 2
        assert len(parts[0]) == 32
        assert parts[1] == "deadbeef" * 4

    async def test_composite_with_destination_pubkey(self, session):
        """destination_hash + destination_pubkey yields token:dest:pubkey."""
        mgr = InviteManager()
        pubkey_hex = "ab" * 64  # 128 hex chars
        composite, _ = await mgr.create_invite(
            session,
            "creator",
            destination_hash="deadbeef" * 4,
            destination_pubkey=pubkey_hex,
        )
        parts = composite.split(":")
        assert len(parts) == 3
        assert parts[1] == "deadbeef" * 4
        assert parts[2] == pubkey_hex

    async def test_pubkey_without_destination_hash_omitted(self, session):
        """Pubkey is ignored when destination_hash is missing (unreachable target)."""
        mgr = InviteManager()
        composite, _ = await mgr.create_invite(
            session,
            "creator",
            destination_pubkey="ab" * 64,
        )
        assert ":" not in composite  # bare token only

    async def test_redeem_works_on_4_field_composite(self, session):
        """Daemon redeem splits on ':' and uses only the first field regardless of extras."""
        mgr = InviteManager()
        raw_token, _ = await mgr.create_invite(
            session,
            "creator",
            destination_hash="deadbeef" * 4,
            destination_pubkey="ab" * 64,
        )
        # Append a channel_id to simulate the 4-field token the CLI emits
        composite4 = f"{raw_token}:chan0000deadbeef"
        invite = await mgr.redeem_invite(session, composite4, "user")
        assert invite.uses == 1

    async def test_invalid_token(self, session):
        mgr = InviteManager()
        with pytest.raises(InviteError, match="Invalid"):
            await mgr.redeem_invite(session, "bad_token_value", "user_hash")

    async def test_max_uses_exceeded(self, session):
        mgr = InviteManager()
        raw_token, _ = await mgr.create_invite(
            session,
            "creator",
            max_uses=1,
        )

        await mgr.redeem_invite(session, raw_token, "user1")
        with pytest.raises(InviteError, match="max uses"):
            await mgr.redeem_invite(session, raw_token, "user2")

    async def test_revoke(self, session):
        mgr = InviteManager()
        raw_token, token_hash = await mgr.create_invite(session, "creator")
        assert await mgr.revoke_invite(session, token_hash) is True

        with pytest.raises(InviteError, match="revoked"):
            await mgr.redeem_invite(session, raw_token, "user")

    async def test_concurrent_redeem_respects_max_uses(self, session):
        """Async lock prevents TOCTOU race on max_uses check."""
        mgr = InviteManager()
        raw_token, _ = await mgr.create_invite(
            session,
            "creator",
            max_uses=1,
        )

        results = await asyncio.gather(
            mgr.redeem_invite(session, raw_token, "user_a"),
            mgr.redeem_invite(session, raw_token, "user_b"),
            return_exceptions=True,
        )

        successes = [r for r in results if not isinstance(r, Exception)]
        failures = [r for r in results if isinstance(r, InviteError)]
        assert len(successes) == 1
        assert len(failures) == 1

    async def test_redeem_lock_exists(self, session):
        """InviteManager has an async lock for redemption."""
        mgr = InviteManager()
        assert isinstance(mgr._redeem_lock, asyncio.Lock)

    async def test_concurrent_redeem_and_cleanup(self, session):
        """Concurrent redeem + cleanup_stale must not raise RuntimeError."""
        mgr = InviteManager()
        raw_token, _ = await mgr.create_invite(
            session,
            "creator",
            max_uses=10,
        )

        # Pre-populate some rate limit entries that cleanup will process
        mgr._redemption_attempts["stale_user"] = [0.0]
        mgr._failure_attempts["stale_user"] = [0.0]
        mgr._blocked_until["stale_user"] = 0.0

        async def do_redeem():
            await mgr.redeem_invite(session, raw_token, "user_conc")

        async def do_cleanup():
            await mgr.cleanup_stale(max_age=1)

        results = await asyncio.gather(
            do_redeem(),
            do_cleanup(),
            return_exceptions=True,
        )
        runtime_errors = [r for r in results if isinstance(r, RuntimeError)]
        assert len(runtime_errors) == 0

    async def test_cleanup_stale_is_async(self, session):
        """cleanup_stale must be a coroutine."""
        import inspect

        mgr = InviteManager()
        assert inspect.iscoroutinefunction(mgr.cleanup_stale)
