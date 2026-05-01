# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Filesystem security helpers: atomic writes with strict modes.

Used by both CLI bootstrap paths and the core identity manager. Lives under
security/ rather than cli/ so core/ can depend on it without a layering
inversion.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import RNS

logger = logging.getLogger(__name__)


def write_secure(path: Path, content: str, mode: int = 0o600) -> None:
    """Atomically write text content to path with the given mode.

    Creates a same-directory temp file at ``mode``, writes, fsyncs, and
    renames over the target. No window where another uid can read content
    at a looser permission than requested.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.write(fd, content.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(str(tmp), str(path))


def write_identity_secure(identity: "RNS.Identity", path: Path) -> None:
    """Write an RNS.Identity to path with 0o600 permissions.

    RNS.Identity.to_file opens the file itself, so we cannot control the
    creation mode directly. We write to a same-directory tmp path, chmod
    it to 0o600 *before* the atomic rename, so the final path never exists
    at a looser mode than 0o600.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    if tmp.exists():
        tmp.unlink()
    identity.to_file(str(tmp))
    os.chmod(str(tmp), 0o600)
    os.replace(str(tmp), str(path))


def secure_identity_dir(path: Path) -> None:
    """Ensure identity_dir is 0o700 and every contained regular file is 0o600.

    Idempotent migration helper — safe to call on every daemon start. Files
    that already have the correct mode are untouched. Symlinks are skipped.
    """
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(str(path), 0o700)
    except OSError as exc:
        logger.warning("Could not chmod identity_dir %s to 0o700: %s", path, exc)
    if not path.is_dir():
        return
    for entry in path.iterdir():
        if not entry.is_file() or entry.is_symlink():
            continue
        try:
            mode = entry.stat().st_mode & 0o777
            if mode != 0o600:
                os.chmod(str(entry), 0o600)
                logger.info("Migrated identity file perms to 0o600: %s", entry)
        except OSError as exc:
            logger.warning("Could not chmod identity file %s: %s", entry, exc)


def secure_existing_file(path: Path, mode: int = 0o600) -> None:
    """Chmod an existing file to ``mode``. Idempotent, tolerates missing files."""
    try:
        if path.is_file() and not path.is_symlink():
            os.chmod(str(path), mode)
    except OSError as exc:
        logger.warning("Could not chmod %s to %o: %s", path, mode, exc)


def secure_client_dir(path: Path, recursive: bool = False) -> None:
    """Tighten a client-data directory to 0o700/0o600 throughout.

    Sibling of ``secure_identity_dir`` covering the broader TUI cache
    surface (``~/.hokora-client/``): the directory itself, the SQLCipher
    DB, the keyfile, log files, and (recursively) the LXMF spool.

    With ``recursive=False`` only the directory and its direct children
    are touched. With ``recursive=True`` the entire subtree is walked
    (subdirs → 0o700, regular files → 0o600). Symlinks are skipped to
    avoid following operator-placed pointers into other parts of the
    filesystem.

    Idempotent — files/dirs already at the target mode are unchanged.
    Tolerant of permission errors (logs at warning, continues) so a
    partially-recoverable startup doesn't trip the whole TUI.
    """
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(str(path), 0o700)
    except OSError as exc:
        logger.warning("Could not chmod client_dir %s to 0o700: %s", path, exc)
    if not path.is_dir():
        return

    if recursive:
        for root, dirs, files in os.walk(str(path)):
            for d in dirs:
                entry = Path(root) / d
                if entry.is_symlink():
                    continue
                try:
                    if (entry.stat().st_mode & 0o777) != 0o700:
                        os.chmod(str(entry), 0o700)
                except OSError as exc:
                    logger.warning("Could not chmod %s to 0o700: %s", entry, exc)
            for f in files:
                entry = Path(root) / f
                if entry.is_symlink():
                    continue
                try:
                    if (entry.stat().st_mode & 0o777) != 0o600:
                        os.chmod(str(entry), 0o600)
                except OSError as exc:
                    logger.warning("Could not chmod %s to 0o600: %s", entry, exc)
        return

    for entry in path.iterdir():
        if entry.is_symlink():
            continue
        try:
            if entry.is_file():
                if (entry.stat().st_mode & 0o777) != 0o600:
                    os.chmod(str(entry), 0o600)
            elif entry.is_dir():
                if (entry.stat().st_mode & 0o777) != 0o700:
                    os.chmod(str(entry), 0o700)
        except OSError as exc:
            logger.warning("Could not chmod %s: %s", entry, exc)
