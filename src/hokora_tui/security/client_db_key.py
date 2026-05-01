# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""TUI client cache SQLCipher master-key resolution.

Greenfield wrapper around ``hokora.security.db_key`` for the TUI side.
No inline-key path: the TUI has no config file and no back-compat
ladder, so the keyfile at ``<client_dir>/db_key`` is the sole source.
First launch generates the key via ``ensure_db_key`` (atomic 0o600
write through ``write_secure``); subsequent launches read + validate.
"""

from __future__ import annotations

from pathlib import Path

from hokora.security.db_key import ensure_db_key

CLIENT_DB_KEYFILE_NAME = "db_key"


def client_db_keyfile_path(client_dir: Path) -> Path:
    """Resolve the keyfile path inside ``client_dir``."""
    return Path(client_dir) / CLIENT_DB_KEYFILE_NAME


def resolve_client_db_key(client_dir: Path) -> str:
    """Return the SQLCipher master key for the TUI cache.

    Generates a fresh 64-hex key on first call (atomic 0o600 write);
    reads + validates the existing keyfile on subsequent calls.
    Raises ``ValueError`` on a corrupted keyfile and ``RuntimeError``
    on read failure — never silently degrades to plaintext.
    """
    return ensure_db_key(client_db_keyfile_path(client_dir))
