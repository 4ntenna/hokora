# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""SQLCipher master-key chokepoint: validation, keyfile read, first-run generation.

Daemon (``NodeConfig.resolve_db_key``) and TUI delegate here so the
on-disk contract (64 hex chars, 0o600, atomic write) is enforced once.
"""

from __future__ import annotations

import logging
import re
import secrets
from pathlib import Path

from hokora.security.fs import write_secure

logger = logging.getLogger(__name__)

# 64 hex chars == 32 raw bytes — SQLCipher AES-256 key length.
DB_KEY_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")
DB_KEY_BYTES = 32


def validate_db_key_hex(value: str, *, source: str = "db_key") -> str:
    """Validate 64-hex-char key shape; ``source`` disambiguates inline / keyfile / CLI."""
    if not DB_KEY_PATTERN.match(value):
        raise ValueError(
            f"{source} must be exactly 64 hexadecimal characters "
            f"(32 raw bytes). Generate one with: openssl rand -hex 32"
        )
    return value


def resolve_db_key_from_path(path: Path) -> str:
    """Read + validate a SQLCipher key. Strips whitespace; warns on mode > 0o600.

    Raises ``FileNotFoundError`` (missing), ``RuntimeError`` (read fails),
    or ``ValueError`` (not 64 hex chars).
    """
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(
            f"db_keyfile points at {path} but no file exists there. "
            "Create it (0o600, 64 hex chars), update the keyfile setting, or "
            "fall back to inline db_key in hokora.toml."
        )

    try:
        mode = path.stat().st_mode & 0o777
    except OSError:
        mode = None
    if mode is not None and mode & 0o077:
        logger.warning(
            "db_keyfile %s has loose permissions %o — should be 0o600",
            path,
            mode,
        )

    try:
        contents = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise RuntimeError(f"Could not read db_keyfile {path}: {exc}") from exc

    if not DB_KEY_PATTERN.match(contents):
        raise ValueError(
            f"db_keyfile {path} does not contain exactly 64 hex characters. "
            f"Regenerate with: openssl rand -hex 32 > {path}"
        )

    return contents


def ensure_db_key(path: Path) -> str:
    """Read existing key or generate-and-persist on first run; idempotent."""
    path = Path(path)
    if not path.is_file():
        new_key = secrets.token_hex(DB_KEY_BYTES)
        write_secure(path, new_key + "\n", mode=0o600)
        logger.info("Generated new db_keyfile at %s (0o600)", path)
        return new_key
    return resolve_db_key_from_path(path)
