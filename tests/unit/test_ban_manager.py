# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""BanManager and ``hokora ban`` CLI smoke tests."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner

from hokora.cli.ban import ban_group
from hokora.db.engine import create_db_engine, init_db
from hokora.db.models import (
    Channel,
    Identity,
    PendingSealedDistribution,
    Role,
    RoleAssignment,
)
from hokora.db.queries import AuditLogRepo, IdentityRepo
from hokora.security.ban import BanError, BanManager, is_blocked


NODE_OWNER = "ff" * 16
ACTOR = "aa" * 16
TARGET = "bb" * 16


class TestBanManager:
    async def test_ban_sets_blocked_and_provenance(self, session):
        mgr = BanManager(node_owner_hash=NODE_OWNER)
        await mgr.ban(session, TARGET, actor=ACTOR, reason="spam")

        ident = await IdentityRepo(session).get_by_hash(TARGET)
        assert ident is not None
        assert ident.blocked is True
        assert ident.blocked_by == ACTOR
        assert ident.blocked_at is not None and ident.blocked_at > 0

    async def test_ban_writes_audit_entry(self, session):
        mgr = BanManager(node_owner_hash=NODE_OWNER)
        await mgr.ban(session, TARGET, actor=ACTOR, reason="abuse")

        rows = await AuditLogRepo(session).get_recent(limit=10)
        ban_rows = [r for r in rows if r.action_type == "identity_ban"]
        assert len(ban_rows) == 1
        assert ban_rows[0].actor == ACTOR
        assert ban_rows[0].target == TARGET
        assert ban_rows[0].details.get("reason") == "abuse"

    async def test_ban_refuses_node_owner(self, session):
        mgr = BanManager(node_owner_hash=NODE_OWNER)
        with pytest.raises(BanError, match="node-owner"):
            await mgr.ban(session, NODE_OWNER, actor=ACTOR)

    async def test_ban_requires_target(self, session):
        mgr = BanManager(node_owner_hash=NODE_OWNER)
        with pytest.raises(BanError, match="required"):
            await mgr.ban(session, "", actor=ACTOR)

    async def test_ban_idempotent_already_blocked_flag(self, session):
        mgr = BanManager(node_owner_hash=NODE_OWNER)
        await IdentityRepo(session).upsert(TARGET, blocked=True, blocked_at=time.time())

        result = await mgr.ban(session, TARGET, actor=ACTOR)
        assert result.already_blocked is True

    async def test_ban_drops_pending_sealed_distributions(self, session):
        # Channel + role plumbing required by FKs on the pending row
        session.add(Channel(id="c" * 16, name="sealed-ops", sealed=True))
        session.add(Role(id="r" * 16, name="member-test", permissions=0))
        await session.flush()
        session.add(
            PendingSealedDistribution(
                channel_id="c" * 16,
                identity_hash=TARGET,
                role_id="r" * 16,
                queued_at=time.time(),
            )
        )
        await session.flush()

        mgr = BanManager(node_owner_hash=NODE_OWNER)
        result = await mgr.ban(session, TARGET, actor=ACTOR)
        assert result.pending_dropped == 1

    async def test_ban_lists_sealed_channel_membership(self, session):
        session.add(Channel(id="s" * 16, name="ops", sealed=True))
        session.add(Channel(id="p" * 16, name="public", sealed=False))
        session.add(Role(id="m" * 16, name="member-x", permissions=0))
        session.add(Identity(hash=TARGET))
        await session.flush()
        # Channel-scoped role assignments — the membership signal we test on
        session.add(
            RoleAssignment(
                role_id="m" * 16,
                identity_hash=TARGET,
                channel_id="s" * 16,
            )
        )
        session.add(
            RoleAssignment(
                role_id="m" * 16,
                identity_hash=TARGET,
                channel_id="p" * 16,
            )
        )
        await session.flush()

        mgr = BanManager(node_owner_hash=NODE_OWNER)
        result = await mgr.ban(session, TARGET, actor=ACTOR)
        sealed_ids = {cid for cid, _ in result.sealed_channels}
        assert sealed_ids == {"s" * 16}

    async def test_ban_takes_effect_at_chokepoint(self, session):
        mgr = BanManager(node_owner_hash=NODE_OWNER)
        assert await is_blocked(session, TARGET) is False
        await mgr.ban(session, TARGET, actor=ACTOR)
        assert await is_blocked(session, TARGET) is True

    async def test_unban_clears_state_and_audits(self, session):
        mgr = BanManager(node_owner_hash=NODE_OWNER)
        await mgr.ban(session, TARGET, actor=ACTOR)

        result = await mgr.unban(session, TARGET, actor=ACTOR, reason="reformed")
        assert result.was_blocked is True

        ident = await IdentityRepo(session).get_by_hash(TARGET)
        assert ident.blocked is False
        assert ident.blocked_at is None
        assert ident.blocked_by is None

        rows = await AuditLogRepo(session).get_recent(limit=10)
        unban_rows = [r for r in rows if r.action_type == "identity_unban"]
        assert len(unban_rows) == 1
        assert unban_rows[0].details.get("reason") == "reformed"

    async def test_unban_unknown_identity_no_op(self, session):
        mgr = BanManager(node_owner_hash=NODE_OWNER)
        result = await mgr.unban(session, "f0" * 16, actor=ACTOR)
        assert result.was_blocked is False
        # Audit log should not record a non-existent unban
        rows = await AuditLogRepo(session).get_recent(limit=10)
        assert all(r.action_type != "identity_unban" for r in rows)

    async def test_list_banned_returns_only_blocked(self, session):
        await IdentityRepo(session).upsert("11" * 16, blocked=True, blocked_at=time.time())
        await IdentityRepo(session).upsert("22" * 16, blocked=False)
        await IdentityRepo(session).upsert("33" * 16, blocked=True, blocked_at=time.time() + 1)

        mgr = BanManager()
        rows = await mgr.list_banned(session)
        hashes = {r.hash for r in rows}
        assert hashes == {"11" * 16, "33" * 16}


# --- CLI smoke tests ---


@pytest.fixture
def cli_setup(tmp_path: Path, monkeypatch):
    """Build a fresh DB + temp hokora.toml the way ``test_cli_seed.py``
    does it: HOKORA_CONFIG env override is the supported config-path
    mechanism and bypasses every from-import patching trap. ``RNS.Identity
    .from_file`` is the only true external dep we still substitute, since
    we don't write a real RNS identity file."""
    import os

    identity_dir = tmp_path / "identities"
    identity_dir.mkdir(parents=True, exist_ok=True)
    (identity_dir / "node_identity").write_bytes(b"")

    toml = tmp_path / "hokora.toml"
    toml.write_text(
        f'node_name = "ban-cli-test"\n'
        f'data_dir = "{tmp_path}"\n'
        f'db_path = "{tmp_path / "test.db"}"\n'
        f'identity_dir = "{identity_dir}"\n'
        f"db_encrypt = false\n"
    )
    os.chmod(toml, 0o600)
    monkeypatch.setenv("HOKORA_CONFIG", str(toml))

    asyncio.run(_init_db(tmp_path / "test.db"))

    fake_identity = MagicMock()
    fake_identity.hexhash = NODE_OWNER

    import RNS

    monkeypatch.setattr(RNS.Identity, "from_file", staticmethod(lambda path: fake_identity))

    return tmp_path


async def _init_db(db_path: Path):
    engine = create_db_engine(db_path, encrypt=False)
    await init_db(engine)
    await engine.dispose()


def test_cli_ban_add_then_list(cli_setup):
    runner = CliRunner()
    result = runner.invoke(ban_group, ["add", TARGET])
    assert result.exit_code == 0, result.output
    assert "Banned" in result.output

    listed = runner.invoke(ban_group, ["list"])
    assert listed.exit_code == 0
    assert TARGET in listed.output


def test_cli_ban_remove(cli_setup):
    runner = CliRunner()
    runner.invoke(ban_group, ["add", TARGET])
    result = runner.invoke(ban_group, ["remove", TARGET])
    assert result.exit_code == 0, result.output
    assert "Unbanned" in result.output

    listed = runner.invoke(ban_group, ["list"])
    assert "no banned identities" in listed.output


def test_cli_ban_refuses_node_owner(cli_setup):
    runner = CliRunner()
    result = runner.invoke(ban_group, ["add", NODE_OWNER])
    assert result.exit_code == 1
    assert "Refused" in result.output
    assert "node-owner" in result.output


def test_cli_ban_list_empty(cli_setup):
    runner = CliRunner()
    result = runner.invoke(ban_group, ["list"])
    assert result.exit_code == 0
    assert "no banned identities" in result.output
