# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Runtime SQLCipher tests: encrypted-DB round-trip, wrong-key rejection,
plain-SQLite-cannot-decrypt, key validation. Exercises the actual
encrypted path end-to-end (no ``db_encrypt=False`` shortcut).
"""

import secrets
import sqlite3
from pathlib import Path

import pytest
import sqlcipher3

from hokora.db.engine import create_db_engine, create_session_factory, init_db
from hokora.db.models import Channel


def _bare_open_with(db_path: Path, *, pragma_key: str | None):
    """Open the DB via sqlcipher3 directly, with or without a PRAGMA key."""
    conn = sqlcipher3.connect(str(db_path))
    if pragma_key is not None:
        conn.execute(f"PRAGMA key=\"x'{pragma_key}'\"")
    try:
        cur = conn.execute("SELECT count(*) FROM sqlite_master")
        return cur.fetchone()[0]
    finally:
        conn.close()


async def _create_encrypted_db(db: Path, key: str) -> None:
    """Create + initialise an encrypted DB, then dispose the engine."""
    engine = create_db_engine(db, encrypt=True, db_key=key)
    await init_db(engine)
    await engine.dispose()


async def test_encrypted_db_round_trip(tmp_path):
    """Create encrypted DB, write, close, reopen with correct key."""
    db = tmp_path / "enc.db"
    key = secrets.token_hex(32)

    engine = create_db_engine(db, encrypt=True, db_key=key)
    await init_db(engine)
    sf = create_session_factory(engine)
    async with sf() as session:
        async with session.begin():
            session.add(Channel(id="ch-round-trip", name="rt"))
    await engine.dispose()

    engine2 = create_db_engine(db, encrypt=True, db_key=key)
    sf2 = create_session_factory(engine2)
    async with sf2() as session:
        from sqlalchemy import select

        r = await session.execute(select(Channel).where(Channel.id == "ch-round-trip"))
        assert r.scalar_one().name == "rt"
    await engine2.dispose()


async def test_plain_sqlite_cannot_read_encrypted_db(tmp_path):
    """Plain sqlite3 must fail on an encrypted DB — proves PRAGMA key took effect."""
    db = tmp_path / "enc.db"
    await _create_encrypted_db(db, secrets.token_hex(32))

    conn = sqlite3.connect(str(db))
    with pytest.raises(sqlite3.DatabaseError):
        conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
    conn.close()


async def test_wrong_key_rejected(tmp_path):
    """Wrong key must fail to decrypt."""
    db = tmp_path / "enc.db"
    await _create_encrypted_db(db, secrets.token_hex(32))

    with pytest.raises(sqlcipher3.DatabaseError):
        _bare_open_with(db, pragma_key=secrets.token_hex(32))


async def test_no_key_rejected(tmp_path):
    """No PRAGMA key at all must fail."""
    db = tmp_path / "enc.db"
    await _create_encrypted_db(db, secrets.token_hex(32))

    with pytest.raises(sqlcipher3.DatabaseError):
        _bare_open_with(db, pragma_key=None)


def test_short_key_rejected_by_engine_factory(tmp_path):
    """create_db_engine validates key length/charset."""
    db = tmp_path / "enc.db"
    with pytest.raises(ValueError, match="64 hex"):
        create_db_engine(db, encrypt=True, db_key="tooshort")
    with pytest.raises(ValueError, match="64 hex"):
        create_db_engine(db, encrypt=True, db_key="G" * 64)


async def test_plain_db_uses_magic_bytes(tmp_path):
    """Sanity: encrypt=False produces a normal SQLite file."""
    db = tmp_path / "plain.db"
    engine = create_db_engine(db, encrypt=False)
    await init_db(engine)
    await engine.dispose()

    magic = db.read_bytes()[:16]
    assert magic.startswith(b"SQLite format 3"), (
        f"plain DB should start with SQLite magic, got {magic!r}"
    )
