# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""PidFile: atomic PID file for daemon auto-discovery."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class PidFile:
    """Atomic PID file with 0o600 perms.

    Used by sibling tools (TUI auto-discovery, ``hokora daemon status``,
    external monitors) to identify a running daemon regardless of how it
    was launched. Write is atomic via tmp + ``os.replace``.
    """

    def __init__(self, path: Path) -> None:
        self._path = Path(path)

    @property
    def path(self) -> Path:
        return self._path

    def write(self, pid: Optional[int] = None) -> None:
        """Atomically write ``pid`` (default: ``os.getpid()``) to the file."""
        pid_value = os.getpid() if pid is None else pid
        tmp = self._path.with_suffix(".tmp")
        try:
            fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, str(pid_value).encode("utf-8"))
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(str(tmp), str(self._path))
        except OSError as exc:
            logger.warning(f"Could not write PID file {self._path}: {exc}")

    def remove(self) -> None:
        """Best-effort cleanup. Idempotent."""
        try:
            self._path.unlink(missing_ok=True)
        except OSError:
            pass

    def read(self) -> Optional[int]:
        """Read the stored PID, or None if file missing or contents invalid."""
        try:
            text = self._path.read_text().strip()
        except OSError:
            return None
        try:
            return int(text)
        except ValueError:
            return None

    def is_stale(self) -> bool:
        """True if the file is missing OR the recorded PID is not alive.

        Uses ``os.kill(pid, 0)`` as a liveness probe — doesn't signal, just
        checks whether the process exists and is accessible.
        """
        pid = self.read()
        if pid is None:
            return True
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            # Process exists but we can't signal it — still alive.
            return False
        except OSError:
            return True
        return False
