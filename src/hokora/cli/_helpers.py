# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""CLI helper utilities."""

from contextlib import asynccontextmanager

from hokora.config import load_config
from hokora.db.engine import (
    check_alembic_revision,
    create_db_engine,
    create_session_factory,
)
from hokora.security.fs import (  # noqa: F401 — re-exported for existing CLI callers
    secure_identity_dir,
    write_identity_secure,
    write_secure,
)


@asynccontextmanager
async def db_session():
    """Async context manager yielding a transactional DB session.

    Handles config loading, engine creation, session lifecycle, and cleanup.

    Calls ``check_alembic_revision`` before yielding so CLI commands
    on an out-of-date DB raise a clear
    ``RuntimeError: ... Run 'hokora db upgrade' ...`` message instead
    of a raw ``sqlite3.OperationalError: no such column: ...`` stack
    trace.

    ``hokora db upgrade|downgrade|current|history`` do NOT go through this
    helper — they use Alembic's own connection path — so operators can
    still fix a down-rev DB when this guard would otherwise block them.
    """
    config = load_config()
    engine = create_db_engine(
        config.db_path, encrypt=config.db_encrypt, db_key=config.resolve_db_key()
    )
    try:
        await check_alembic_revision(engine)
        sf = create_session_factory(engine)
        async with sf() as session:
            async with session.begin():
                yield session
    finally:
        await engine.dispose()
