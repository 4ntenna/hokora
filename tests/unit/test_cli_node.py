# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Smoke tests for ``hokora node`` (status / config / peers).

The CLI reads directly from the daemon's DB (no IPC), so these can run
without a daemon process. Pin the read-path against fresh + populated
DBs and the no-secrets-leaked invariant on ``node config``.
"""

import time

import pytest
from click.testing import CliRunner

from hokora.cli.node import node_group
from hokora.config import NodeConfig
from hokora.db.engine import create_db_engine, create_session_factory, init_db
from hokora.db.models import Channel, Message, Peer


@pytest.fixture
def runner():
    return CliRunner()


async def _seed_db(cfg: NodeConfig, *, channels=0, messages=0, peers=()):
    engine = create_db_engine(cfg.db_path, encrypt=False)
    await init_db(engine)
    factory = create_session_factory(engine)
    async with factory() as session:
        async with session.begin():
            for i in range(channels):
                session.add(Channel(id=f"c{i:063d}", name=f"ch{i}", latest_seq=0))
            for i in range(messages):
                session.add(
                    Message(
                        msg_hash=f"m{i:063d}",
                        channel_id=f"c0{'0' * 62}",
                        sender_hash="a" * 64,
                        seq=i + 1,
                        timestamp=time.time(),
                        type=1,
                        body="x",
                    )
                )
            for p in peers:
                session.add(p)
    await engine.dispose()


def _make_config(tmp_path):
    return NodeConfig(
        node_name="node-cli-test",
        data_dir=tmp_path,
        db_path=tmp_path / "test.db",
        identity_dir=tmp_path / "identities",
        db_encrypt=False,
    )


def test_status_reports_zero_channels_on_fresh_db(runner, tmp_path, monkeypatch):
    """``node status`` itself drives ``asyncio.run()``; tests that call
    it must stay sync so we don't end up running asyncio.run inside a
    pytest-asyncio loop."""
    import asyncio

    cfg = _make_config(tmp_path)
    asyncio.run(_seed_db(cfg))
    monkeypatch.setattr("hokora.cli.node.load_config", lambda: cfg)

    result = runner.invoke(node_group, ["status"])
    assert result.exit_code == 0
    assert "Node: node-cli-test" in result.output
    assert "Channels: 0" in result.output
    assert "Messages: 0" in result.output
    assert "Identity: not created" in result.output


def test_status_reports_seeded_counts(runner, tmp_path, monkeypatch):
    import asyncio

    cfg = _make_config(tmp_path)
    asyncio.run(_seed_db(cfg, channels=2, messages=5))
    monkeypatch.setattr("hokora.cli.node.load_config", lambda: cfg)

    result = runner.invoke(node_group, ["status"])
    assert result.exit_code == 0
    assert "Channels: 2" in result.output
    assert "Messages: 5" in result.output


def test_config_redacts_db_key(runner, tmp_path, monkeypatch):
    """``node config`` must NOT print the master DB key in clear."""
    cfg = NodeConfig(
        node_name="redact-test",
        data_dir=tmp_path,
        db_path=tmp_path / "test.db",
        db_encrypt=True,
        db_key="a" * 64,
    )
    monkeypatch.setattr("hokora.cli.node.load_config", lambda: cfg)

    result = runner.invoke(node_group, ["config"])
    assert result.exit_code == 0
    assert "node_name: redact-test" in result.output
    assert "db_key: ***" in result.output
    # Hard rule: the literal key must not appear anywhere in output.
    assert "a" * 64 not in result.output


def test_peers_empty(runner, tmp_path, monkeypatch):
    cfg = _make_config(tmp_path)
    import asyncio

    asyncio.run(_seed_db(cfg))
    monkeypatch.setattr("hokora.cli.node.load_config", lambda: cfg)

    result = runner.invoke(node_group, ["peers"])
    assert result.exit_code == 0
    assert "No peers discovered" in result.output


def test_peers_lists_seen(runner, tmp_path, monkeypatch):
    cfg = _make_config(tmp_path)
    import asyncio

    asyncio.run(
        _seed_db(
            cfg,
            peers=(
                Peer(
                    identity_hash="d" * 64,
                    node_name="seed-vps",
                    federation_trusted=True,
                    last_seen=time.time(),
                ),
                Peer(
                    identity_hash="e" * 64,
                    node_name="random-peer",
                    federation_trusted=False,
                    last_seen=time.time() - 60,
                ),
            ),
        )
    )
    monkeypatch.setattr("hokora.cli.node.load_config", lambda: cfg)

    result = runner.invoke(node_group, ["peers"])
    assert result.exit_code == 0
    # Trust marker present for trusted peer.
    assert "[TRUSTED]" in result.output
    assert "[untrusted]" in result.output
    # First 16 hex chars of each identity.
    assert "d" * 16 in result.output
    assert "e" * 16 in result.output
    assert "seed-vps" in result.output
