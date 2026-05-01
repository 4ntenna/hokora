# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Shared SQLCipher master-key handling for daemon and TUI.

Single chokepoint for the at-rest encryption key lifecycle: validation,
keyfile read, keyfile mode-loose warn, and first-run generation. Both
``NodeConfig.resolve_db_key`` (daemon) and the TUI's
``client_db_key.resolve_client_db_key`` delegate here so the on-disk
contract — 64 hex chars, 0o600, atomic write — is enforced in one place.
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
    """Return ``value`` if it matches ``DB_KEY_PATTERN``; raise ValueError otherwise.

    ``source`` is used in the error message to disambiguate inline vs
    keyfile vs CLI-provided keys.
    """
    if not DB_KEY_PATTERN.match(value):
        raise ValueError(
            f"{source} must be exactly 64 hexadecimal characters "
            f"(32 raw bytes). Generate one with: openssl rand -hex 32"
        )
    return value


def resolve_db_key_from_path(path: Path) -> str:
    """Read a SQLCipher key from ``path``, validate it, return as hex string.

    Logs a warning if file mode is looser than 0o600. Raises
    ``FileNotFoundError`` if the file is missing, ``RuntimeError`` if the
    file can't be read, and ``ValueError`` if contents are not 64 hex chars.
    Trailing whitespace (including a newline) is stripped before validation.
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
    """Return the key at ``path`` if it exists; otherwise generate + persist.

    First-run: produces a fresh ``secrets.token_hex(32)`` and writes it
    via ``write_secure`` (atomic, mode 0o600). Idempotent — subsequent
    calls just delegate to ``resolve_db_key_from_path``.

    Used by callers that own the key lifecycle end-to-end (e.g., the TUI
    on first launch). Daemon ``hokora init`` writes the keyfile itself
    via ``write_secure`` and never calls this helper at runtime.
    """
    path = Path(path)
    if not path.is_file():
        new_key = secrets.token_hex(DB_KEY_BYTES)
        write_secure(path, new_key + "\n", mode=0o600)
        logger.info("Generated new db_keyfile at %s (0o600)", path)
        return new_key
    return resolve_db_key_from_path(path)
