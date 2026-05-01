# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Functional tests for CLI commands using Click CliRunner."""

import asyncio

import pytest
from click.testing import CliRunner

from hokora.cli.audit import audit_group
from hokora.cli.channel import channel_group
from hokora.cli.role import role_group
from hokora.cli.invite import invite_group
from hokora.cli.db import db_group
from hokora.cli.mirror import mirror_group
from hokora.config import NodeConfig
from hokora.db.engine import create_db_engine, create_session_factory, init_db
from hokora.security.roles import RoleManager


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def cli_config(tmp_dir, monkeypatch):
    """Set up a temporary config and DB for CLI tests."""
    db_path = tmp_dir / "hokora.db"
    (tmp_dir / "identities").mkdir(parents=True, exist_ok=True)
    (tmp_dir / "media").mkdir(parents=True, exist_ok=True)

    # Write a config file that load_config() will pick up
    config_path = tmp_dir / "hokora.toml"
    config_path.write_text(
        f'node_name = "CLI Test Node"\ndata_dir = "{tmp_dir}"\ndb_encrypt = false\n'
    )
    monkeypatch.setenv("HOKORA_CONFIG", str(config_path))

    config = NodeConfig(
        node_name="CLI Test Node",
        data_dir=tmp_dir,
        db_encrypt=False,
    )

    # Initialize DB at the default path (data_dir/hokora.db)
    async def _init():
        engine = create_db_engine(db_path)
        await init_db(engine)
        sf = create_session_factory(engine)
        async with sf() as session:
            async with session.begin():
                mgr = RoleManager()
                await mgr.ensure_builtin_roles(session)
        await engine.dispose()

    asyncio.run(_init())
    return config


class TestChannelCLI:
    def test_create_channel(self, runner, cli_config):
        result = runner.invoke(channel_group, ["create", "test-channel"])
        assert result.exit_code == 0
        assert "Created channel #test-channel" in result.output

    def test_list_channels(self, runner, cli_config):
        runner.invoke(channel_group, ["create", "ch1"])
        result = runner.invoke(channel_group, ["list"])
        assert result.exit_code == 0
        assert "#ch1" in result.output

    def test_list_empty(self, runner, cli_config):
        result = runner.invoke(channel_group, ["list"])
        assert result.exit_code == 0
        assert "No channels" in result.output

    def test_create_and_info(self, runner, cli_config):
        result = runner.invoke(channel_group, ["create", "info-test"])
        assert result.exit_code == 0
        # Extract channel ID from output
        ch_id = result.output.split("(")[1].split(")")[0]

        result = runner.invoke(channel_group, ["info", ch_id])
        assert result.exit_code == 0
        assert "#info-test" in result.output
        assert "public" in result.output

    def test_create_private_channel(self, runner, cli_config):
        result = runner.invoke(channel_group, ["create", "secret", "--access", "private"])
        assert result.exit_code == 0
        assert "[private]" in result.output

    def test_edit_channel(self, runner, cli_config):
        result = runner.invoke(channel_group, ["create", "edit-me"])
        ch_id = result.output.split("(")[1].split(")")[0]

        result = runner.invoke(channel_group, ["edit", ch_id, "--name", "edited"])
        assert result.exit_code == 0
        assert "Updated channel #edited" in result.output

    def test_delete_channel(self, runner, cli_config):
        result = runner.invoke(channel_group, ["create", "delete-me"])
        ch_id = result.output.split("(")[1].split(")")[0]

        result = runner.invoke(channel_group, ["delete", ch_id], input="y\n")
        assert result.exit_code == 0
        assert "Deleted" in result.output

    def test_info_not_found(self, runner, cli_config):
        result = runner.invoke(channel_group, ["info", "nonexistent"])
        assert result.exit_code == 0
        assert "not found" in result.output


class TestRotateRnsKeyCLI:
    """``hokora channel rotate-rns-key`` CLI behaviour.

    The command creates a new RNS identity, emits a dual-signed rotation
    announce via the OLD destination, swaps the on-disk identity file, and
    updates the channels row with the new identity hash + destination hash +
    rotation grace state. RNS itself is mocked at the module boundary so the
    test exercises the pure CLI/DB/file-swap orchestration.
    """

    def test_rotate_rns_key_updates_db_and_swaps_identity_file(
        self, runner, cli_config, tmp_dir, monkeypatch
    ):
        import asyncio
        from pathlib import Path
        from unittest.mock import MagicMock, patch

        from hokora.db.models import Channel
        from hokora.db.engine import create_db_engine, create_session_factory
        from sqlalchemy import select

        # Seed a channel row directly — avoids the RNS-touching create path.
        db_path = Path(tmp_dir) / "hokora.db"

        async def _seed():
            engine = create_db_engine(db_path)
            sf = create_session_factory(engine)
            async with sf() as session:
                async with session.begin():
                    session.add(
                        Channel(
                            id="rot01",
                            name="rotatable",
                            identity_hash="a" * 64,
                            destination_hash="b" * 32,
                        )
                    )
            await engine.dispose()

        asyncio.run(_seed())

        identity_dir = Path(tmp_dir) / "identities"
        identity_dir.mkdir(parents=True, exist_ok=True)
        id_path = identity_dir / "channel_rot01"
        id_path.write_bytes(b"OLD-IDENTITY-BYTES")

        old_identity = MagicMock()
        old_identity.hexhash = "a" * 64
        old_identity.sign = MagicMock(return_value=b"\x01" * 64)

        new_identity = MagicMock()
        new_identity.hexhash = "c" * 64
        new_identity.sign = MagicMock(return_value=b"\x02" * 64)

        old_destination = MagicMock()
        old_destination.announce = MagicMock()
        new_destination = MagicMock()
        new_destination.hash = b"\xcc" * 16

        # Ordered factory: first Destination call returns the old dest, second returns new.
        dest_sequence = [old_destination, new_destination]

        def dest_factory(*args, **kwargs):
            return dest_sequence.pop(0)

        # The CLI does `import RNS` at call time; patching the module object
        # so attribute access inside the CLI resolves to our mocks. Single
        # RNS replacement sidesteps the module-vs-class ambiguity on
        # RNS.Identity (submodule AND re-exported class share the name).
        fake_rns = MagicMock()
        fake_rns.Identity.from_file = MagicMock(return_value=old_identity)
        fake_rns.Identity.side_effect = None
        fake_rns.Identity.return_value = new_identity
        # RNS.Destination(...) returns mocks in order; Destination.IN / .SINGLE
        # need to be plain ints so msgpack doesn't trip on them during the
        # announce payload construction inside KeyRotationManager.
        fake_rns.Destination = MagicMock(side_effect=dest_factory)
        fake_rns.Destination.IN = 0
        fake_rns.Destination.SINGLE = 0
        # write_identity_secure is imported by the CLI at function scope from
        # hokora.security.fs, so patching its source module binding is
        # picked up by the next import at call time.
        with (
            patch.dict("sys.modules", {"RNS": fake_rns}),
            patch(
                "hokora.security.fs.write_identity_secure",
                side_effect=lambda ident, p: Path(p).write_bytes(b"NEW-IDENTITY-BYTES"),
            ),
        ):
            result = runner.invoke(
                channel_group,
                ["rotate-rns-key", "rot01", "--yes"],
            )

        assert result.exit_code == 0, result.output
        assert "Rotated RNS identity for #rotatable" in result.output

        # Dual-signed announce fired via OLD destination exactly once.
        old_destination.announce.assert_called_once()
        old_identity.sign.assert_called_once()
        new_identity.sign.assert_called_once()

        # Identity file now holds the new bytes, old file backed up.
        assert id_path.read_bytes() == b"NEW-IDENTITY-BYTES"
        backups = list(identity_dir.glob("channel_rot01.pre-rotation-*"))
        assert len(backups) == 1
        assert backups[0].read_bytes() == b"OLD-IDENTITY-BYTES"

        async def _verify_db():
            engine = create_db_engine(db_path)
            sf = create_session_factory(engine)
            async with sf() as session:
                row = await session.execute(select(Channel).where(Channel.id == "rot01"))
                ch = row.scalar_one()
            await engine.dispose()
            return ch

        ch = asyncio.run(_verify_db())
        assert ch.identity_hash == "c" * 64
        assert ch.destination_hash == ("cc" * 16)
        assert ch.rotation_old_hash == "a" * 64
        assert ch.rotation_grace_end is not None
        assert ch.rotation_grace_end > 0

    def test_rotate_rns_key_missing_channel(self, runner, cli_config, tmp_dir):
        from pathlib import Path
        from unittest.mock import patch

        identity_dir = Path(tmp_dir) / "identities"
        identity_dir.mkdir(parents=True, exist_ok=True)
        (identity_dir / "channel_ghost").write_bytes(b"DUMMY")

        with patch("RNS.Reticulum"):
            result = runner.invoke(
                channel_group,
                ["rotate-rns-key", "ghost", "--yes"],
            )

        assert result.exit_code == 0
        assert "not found" in result.output

    def test_rotate_rns_key_missing_identity_file(self, runner, cli_config, tmp_dir):
        # DB lookup resolves the channel ref before checking the
        # identity-file path. An unknown channel surfaces the DB
        # message, which is more accurate — you can't have an identity
        # file for a channel that doesn't exist as a row.
        result = runner.invoke(
            channel_group,
            ["rotate-rns-key", "absent", "--yes"],
        )
        assert result.exit_code == 0
        assert "not found in DB" in result.output


class TestRoleCLI:
    def test_list_builtin_roles(self, runner, cli_config):
        result = runner.invoke(role_group, ["list"])
        assert result.exit_code == 0
        assert "node_owner" in result.output
        assert "[builtin]" in result.output

    def test_create_role(self, runner, cli_config):
        result = runner.invoke(role_group, ["create", "moderator", "-p", "255"])
        assert result.exit_code == 0
        assert "moderator" in result.output

    def test_create_role_with_colour(self, runner, cli_config):
        result = runner.invoke(
            role_group,
            ["create", "vip", "-p", "7", "--colour", "#FF0000", "--mentionable"],
        )
        assert result.exit_code == 0
        assert "vip" in result.output
        assert "#FF0000" in result.output


class TestInviteCLI:
    def test_list_empty(self, runner, cli_config):
        result = runner.invoke(invite_group, ["list"])
        assert result.exit_code == 0
        assert "No invites" in result.output


class TestMirrorCLI:
    def test_list_empty(self, runner, cli_config):
        result = runner.invoke(mirror_group, ["list"])
        assert result.exit_code == 0
        assert "No mirrors" in result.output

    def test_add_mirror(self, runner, cli_config):
        fake_hash = "a" * 32
        result = runner.invoke(mirror_group, ["add", fake_hash, "general"])
        assert result.exit_code == 0
        assert "Added mirror" in result.output

    def test_add_then_list(self, runner, cli_config):
        fake_hash = "b" * 32
        runner.invoke(mirror_group, ["add", fake_hash, "test-ch"])
        result = runner.invoke(mirror_group, ["list"])
        assert result.exit_code == 0
        assert "test-ch" in result.output

    def test_remove_mirror(self, runner, cli_config):
        fake_hash = "c" * 32
        runner.invoke(mirror_group, ["add", fake_hash, "rm-ch"])
        result = runner.invoke(mirror_group, ["remove", fake_hash, "rm-ch"])
        assert result.exit_code == 0
        assert "Removed" in result.output


class TestDbCLI:
    def test_help(self, runner):
        result = runner.invoke(db_group, ["--help"])
        assert result.exit_code == 0
        assert "upgrade" in result.output


class TestAuditCLI:
    def test_list_empty(self, runner, cli_config):
        result = runner.invoke(audit_group, ["list"])
        assert result.exit_code == 0
        assert "No audit log entries." in result.output

    def test_list_with_entries(self, runner, cli_config, tmp_dir):
        import asyncio

        from hokora.db.engine import create_db_engine, create_session_factory
        from hokora.db.queries import AuditLogRepo

        async def _seed():
            engine = create_db_engine(tmp_dir / "hokora.db")
            sf = create_session_factory(engine)
            async with sf() as session:
                async with session.begin():
                    repo = AuditLogRepo(session)
                    await repo.log(
                        actor="alice",
                        action_type="channel_create",
                        target="general",
                        channel_id="abc123",
                    )
            await engine.dispose()

        asyncio.run(_seed())

        result = runner.invoke(audit_group, ["list"])
        assert result.exit_code == 0, result.output
        assert "alice" in result.output
        assert "channel_create" in result.output

    def test_list_json(self, runner, cli_config, tmp_dir):
        import asyncio
        import json

        from hokora.db.engine import create_db_engine, create_session_factory
        from hokora.db.queries import AuditLogRepo

        async def _seed():
            engine = create_db_engine(tmp_dir / "hokora.db")
            sf = create_session_factory(engine)
            async with sf() as session:
                async with session.begin():
                    repo = AuditLogRepo(session)
                    await repo.log(actor="bob", action_type="role_assign")
            await engine.dispose()

        asyncio.run(_seed())

        result = runner.invoke(audit_group, ["list", "--json"])
        assert result.exit_code == 0, result.output
        rows = json.loads(result.output)
        assert isinstance(rows, list)
        assert any(r["actor"] == "bob" for r in rows)

    def test_list_invalid_limit(self, runner, cli_config):
        result = runner.invoke(audit_group, ["list", "--limit", "0"])
        assert result.exit_code != 0
        assert "limit" in result.output.lower()
