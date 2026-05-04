# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Verify the squashed v0.1.0 migration produces a schema byte-equivalent to ``Base.metadata``.

The squash collapsed dev migrations 001-015 into a single
``001_initial_schema``. This test guards the equivalence: running the
squashed migration against a fresh DB must produce the same
``sqlite_master`` rows (tables, indexes, FKs, constraints) as
``Base.metadata.create_all()`` against the same DB. Drift here means
fresh installs and code-driven schema would diverge.
"""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy.ext.asyncio import create_async_engine

from hokora.db.models import Base

REPO_ROOT = Path(__file__).resolve().parents[2]
ALEMBIC_INI = REPO_ROOT / "alembic.ini"
ALEMBIC_DIR = REPO_ROOT / "alembic"


def _dump_master(db_path: Path) -> list[tuple]:
    conn = sqlite3.connect(str(db_path))
    try:
        rows = conn.execute(
            """
            SELECT type, name, tbl_name, sql
            FROM sqlite_master
            WHERE name NOT LIKE 'sqlite_%'
              AND name != 'alembic_version'
            ORDER BY type, name
            """
        ).fetchall()
    finally:
        conn.close()
    return rows


def test_squashed_migration_matches_metadata(tmp_path: Path) -> None:
    squashed_db = tmp_path / "squashed.db"
    cfg = Config(str(ALEMBIC_INI))
    cfg.set_main_option("sqlalchemy.url", f"sqlite+aiosqlite:///{squashed_db}")
    cfg.set_main_option("script_location", str(ALEMBIC_DIR))
    command.upgrade(cfg, "head")

    metadata_db = tmp_path / "metadata.db"

    async def _build_metadata() -> None:
        eng = create_async_engine(f"sqlite+aiosqlite:///{metadata_db}")
        async with eng.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        await eng.dispose()

    asyncio.run(_build_metadata())

    squashed_rows = _dump_master(squashed_db)
    metadata_rows = _dump_master(metadata_db)

    assert squashed_rows == metadata_rows, (
        "Squashed migration drift detected. Either the migration or the ORM models "
        "changed without the other being updated. Diff sqlite_master rows manually."
    )


def test_alembic_head_is_initial() -> None:
    """v0.1.0 ships exactly one revision; existing deploys stamp at this rev."""
    from alembic.script import ScriptDirectory

    cfg = Config(str(ALEMBIC_INI))
    cfg.set_main_option("script_location", str(ALEMBIC_DIR))
    script = ScriptDirectory.from_config(cfg)
    heads = list(script.get_revisions("heads"))
    assert len(heads) == 1
    assert heads[0].revision == "001_initial"
