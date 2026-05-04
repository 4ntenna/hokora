# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""One-time plaintext → SQLCipher migration for the TUI client cache.

Triggered from ``ClientDB.__init__`` when an existing ``tui.db`` is
detected as plaintext. Steps (all-or-nothing):

1. Copy the plaintext source to ``tui.db.pre-encryption.bak`` (preserved
   for the operator).
2. Open the source plaintext, ``ATTACH DATABASE`` an encrypted sibling
   ``tui.db.encrypted`` with the configured key, ``SELECT
   sqlcipher_export('encrypted')``, then DETACH and close the source.
3. ``os.replace`` the encrypted sibling over the original — atomic
   filename swap on POSIX so an interrupted run never leaves a
   half-written ``tui.db``.

Failure at any step raises and aborts TUI startup. The plaintext file
is preserved as ``.bak`` so no data is lost; the operator can retry or
roll back. **Never silently degrades to plaintext** — that would defeat
the whole purpose of adding encryption.
"""

from __future__ import annotations

import logging
import os
import shutil
import sqlite3
from pathlib import Path
from typing import Callable, Optional

from hokora.security.db_key import validate_db_key_hex

logger = logging.getLogger(__name__)


class ClientDBMigrationError(RuntimeError):
    """Raised when the plaintext→encrypted migration cannot complete."""


def migrate_to_encrypted(
    db_path: Path,
    key_hex: str,
    *,
    notice: Optional[Callable[[str], None]] = None,
) -> Path:
    """Convert plaintext ``db_path`` to a SQLCipher-encrypted database in place.

    ``key_hex`` is validated up-front. ``notice`` is an optional
    user-facing status callback (the TUI passes its status-area emitter
    so the operator sees the migration happening). Returns the path of
    the preserved plaintext backup so the caller can log or surface it.

    Raises ``ClientDBMigrationError`` on any failure; the original
    plaintext file is preserved at ``<db_path>.pre-encryption.bak``
    if the copy step succeeded.
    """
    validate_db_key_hex(key_hex, source="client db_key")
    db_path = Path(db_path)
    if not db_path.is_file():
        raise ClientDBMigrationError(f"Cannot migrate {db_path}: file does not exist")

    bak_path = db_path.with_suffix(db_path.suffix + ".pre-encryption.bak")
    enc_path = db_path.with_suffix(db_path.suffix + ".encrypted")

    if notice is not None:
        notice("Encrypting local cache (one-time migration)...")

    # 1. Backup. shutil.copy2 preserves mode + mtime; the source is
    #    already 0o600 in nominal cases, and we re-tighten via fs hardening
    #    later regardless.
    try:
        shutil.copy2(str(db_path), str(bak_path))
    except OSError as exc:
        raise ClientDBMigrationError(
            f"Could not back up plaintext DB to {bak_path}: {exc}"
        ) from exc

    # 2. ATTACH + sqlcipher_export. We use stdlib sqlite3 to OPEN the
    #    plaintext source and ATTACH the encrypted sibling — sqlcipher3 can
    #    do this too, but going through sqlite3 makes the source-is-plaintext
    #    contract explicit. The ATTACH DATABASE call REQUIRES sqlcipher3 on
    #    the same process, so we patch via sqlcipher_export from the
    #    sqlcipher3 side to be safe.
    if enc_path.exists():
        try:
            enc_path.unlink()
        except OSError as exc:
            raise ClientDBMigrationError(f"Could not remove stale {enc_path}: {exc}") from exc

    try:
        import sqlcipher3

        # Open plaintext source via sqlcipher3 with no key set — sqlcipher3
        # treats an unkeyed connection as plain SQLite, which is exactly
        # what we need to ATTACH an encrypted sibling and export.
        src = sqlcipher3.connect(str(db_path))
        try:
            cursor = src.cursor()
            try:
                cursor.execute(
                    "ATTACH DATABASE ? AS encrypted KEY \"x'" + key_hex + "'\"",
                    (str(enc_path),),
                )
                cursor.execute("SELECT sqlcipher_export('encrypted')")
                cursor.execute("DETACH DATABASE encrypted")
                src.commit()
            finally:
                cursor.close()
        finally:
            src.close()
    except (sqlite3.DatabaseError, Exception) as exc:
        # Clean up the half-written encrypted file before re-raising.
        if enc_path.exists():
            try:
                enc_path.unlink()
            except OSError:
                pass
        raise ClientDBMigrationError(f"sqlcipher_export failed for {db_path}: {exc}") from exc

    # 3. Atomic swap. os.replace is POSIX-atomic when source + target
    #    are on the same filesystem (always true here — same parent dir).
    try:
        os.replace(str(enc_path), str(db_path))
    except OSError as exc:
        raise ClientDBMigrationError(
            f"Could not swap encrypted DB into place at {db_path}: {exc}"
        ) from exc

    # Tighten the new file's mode immediately — umask on the encrypted
    # sibling create may have left it 0o644 on hosts with default umask.
    try:
        os.chmod(str(db_path), 0o600)
    except OSError as exc:
        logger.warning("Could not chmod %s to 0o600 post-migration: %s", db_path, exc)

    if notice is not None:
        notice(f"Local cache encrypted; backup retained at {bak_path.name}")
    logger.info("Migrated client DB to SQLCipher: %s (backup at %s)", db_path, bak_path)
    return bak_path
