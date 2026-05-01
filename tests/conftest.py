# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Shared test fixtures: temp data dir, NodeConfig, async DB engine + session, FTS manager."""

import asyncio
import tempfile
from pathlib import Path

import pytest
import pytest_asyncio

from hokora.config import NodeConfig
from hokora.db.engine import create_db_engine, create_session_factory, init_db
from hokora.db.fts import FTSManager


@pytest.fixture
def tmp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.fixture
def config(tmp_dir):
    return NodeConfig(
        node_name="Test Node",
        data_dir=tmp_dir,
        db_path=tmp_dir / "test.db",
        media_dir=tmp_dir / "media",
        identity_dir=tmp_dir / "identities",
        db_encrypt=False,
    )


@pytest_asyncio.fixture
async def engine(config):
    eng = create_db_engine(config.db_path)
    await init_db(eng)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def session_factory(engine):
    return create_session_factory(engine)


@pytest_asyncio.fixture
async def session(session_factory):
    async with session_factory() as sess:
        async with sess.begin():
            yield sess


@pytest_asyncio.fixture
async def fts_manager(engine):
    fts = FTSManager(engine)
    await fts.init_fts()
    return fts


@pytest.fixture
def isolated_event_loop():
    """One-shot event loop for sync tests that need to drive a coroutine.

    Cleans up the thread-local loop policy on teardown so a leaked loop
    cannot poison the next pytest-asyncio test (auto-mode owns its own
    loop per function — leaving an attached loop here breaks that
    invariant). Use this in preference to manual ``asyncio.new_event_loop``
    / ``asyncio.run`` from inside test bodies.
    """
    loop = asyncio.new_event_loop()
    try:
        yield loop
    finally:
        loop.close()
        asyncio.set_event_loop(None)


# --- Identity / channel ID factories (string-only helpers) ---


def make_identity_hash(n: int = 0) -> str:
    return f"{n:032x}"


def make_channel_id(n: int = 0) -> str:
    return f"ch{n:014x}"
