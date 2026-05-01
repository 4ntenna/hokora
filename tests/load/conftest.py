# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Load test fixtures: temp data dir + DB session factory.

Mesh-condition simulation fixtures were removed alongside
``test_mesh_conditions.py`` — they exercised only the in-test
``MeshConditionProxy`` stub, never any Hokora code, and gave a false
sense of mesh-resilience coverage. Real mesh testing lives in
``tests/multinode/`` (RNS over TCP localhost) and on hardware.
"""

import tempfile
from pathlib import Path

import pytest
import pytest_asyncio

from hokora.config import NodeConfig
from hokora.db.engine import create_db_engine, create_session_factory, init_db


@pytest.fixture
def load_tmp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.fixture
def load_config(load_tmp_dir):
    return NodeConfig(
        node_name="Load Test Node",
        data_dir=load_tmp_dir,
        db_path=load_tmp_dir / "load.db",
        media_dir=load_tmp_dir / "media",
        identity_dir=load_tmp_dir / "identities",
        db_encrypt=False,
        require_signed_federation=False,
    )


@pytest_asyncio.fixture
async def load_engine(load_config):
    eng = create_db_engine(load_config.db_path)
    await init_db(eng)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def load_session_factory(load_engine):
    return create_session_factory(load_engine)
