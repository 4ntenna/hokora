# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""SQLCipher connection helper for the TUI client cache.

Single chokepoint for opening an encrypted ``tui.db``. Mirrors the
daemon's pattern at ``hokora.db.engine`` — same pragma form
(``PRAGMA key="x'<hex>'"`` literal, structurally injection-immune),
same WAL/foreign_keys/busy_timeout post-key pragmas — but synchronous
because the TUI does not use aiosqlite.
"""

from __future__ import annotations

import logging
import sqlcipher3

from hokora.security.db_key import validate_db_key_hex

logger = logging.getLogger(__name__)


def open_encrypted(db_path: str, key_hex: str) -> sqlcipher3.Connection:
    """Open ``db_path`` as an encrypted SQLCipher database.

    ``key_hex`` is validated as 64 hex chars before use; the literal-form
    PRAGMA accepts ``[0-9a-fA-F]`` only and is therefore not vulnerable
    to PRAGMA-statement injection. Caller owns the returned connection.
    """
    validate_db_key_hex(key_hex, source="client db_key")
    conn = sqlcipher3.connect(str(db_path), check_same_thread=False)
    cursor = conn.cursor()
    try:
        cursor.execute("PRAGMA key=\"x'" + key_hex + "'\"")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA busy_timeout=5000")
    finally:
        cursor.close()
    return conn


def is_plaintext_sqlite(db_path: str) -> bool:
    """Return True if ``db_path`` is a readable plaintext SQLite file.

    Used by the migration helper to decide whether an existing ``tui.db``
    needs to be re-encrypted. Probes by attempting an unencrypted open
    and reading the schema; a successful read means the file is NOT
    SQLCipher-encrypted (SQLCipher headers are indistinguishable from
    random bytes without the key).

    Returns False for: missing file, encrypted file, corrupted file,
    or any other read error. The migration only acts on a clean True.
    """
    import sqlite3
    from pathlib import Path

    p = Path(db_path)
    if not p.is_file():
        return False
    try:
        conn = sqlite3.connect(str(p))
        try:
            conn.execute("SELECT name FROM sqlite_master LIMIT 1").fetchone()
            return True
        finally:
            conn.close()
    except sqlite3.DatabaseError:
        return False
    except Exception:
        logger.debug("plaintext probe failed on %s", p, exc_info=True)
        return False
