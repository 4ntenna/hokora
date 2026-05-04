# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for check_alembic_revision in db/engine.py."""

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text

from hokora.db.engine import check_alembic_revision, init_db


@pytest.fixture
async def tmp_engine():
    """Create a temporary SQLite engine with tables."""
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "test.db"
        engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
        await init_db(engine)
        yield engine
        await engine.dispose()


class TestCheckAlembicRevision:
    async def test_fresh_db_stamps_to_head(self, tmp_engine):
        """Fresh DB (no alembic_version table) should be stamped to head."""
        await check_alembic_revision(tmp_engine)

        async with tmp_engine.connect() as conn:
            result = await conn.execute(text("SELECT version_num FROM alembic_version"))
            rows = result.fetchall()
            assert len(rows) == 1
            assert rows[0][0] is not None

    async def test_db_at_head_passes(self, tmp_engine):
        """DB already at head should pass without error on second call."""
        await check_alembic_revision(tmp_engine)
        await check_alembic_revision(tmp_engine)

    async def test_db_at_old_revision_raises(self, tmp_engine):
        """DB at a different revision should raise RuntimeError."""
        await check_alembic_revision(tmp_engine)

        async with tmp_engine.connect() as conn:
            await conn.execute(text("UPDATE alembic_version SET version_num = 'old_rev_123'"))
            await conn.commit()

        with pytest.raises(RuntimeError, match=r"Run `hokora db upgrade`"):
            await check_alembic_revision(tmp_engine)

    async def test_missing_alembic_dir_skips(self, tmp_engine):
        """Missing alembic directory should log warning and skip gracefully."""
        # Patch __file__ in the engine module to point somewhere with no alembic/ dir
        with patch("hokora.db.engine.__file__", "/tmp/nonexistent/engine.py"):
            # Should not raise — just log warning and return
            await check_alembic_revision(tmp_engine)
