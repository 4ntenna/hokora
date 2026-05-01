# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Sync subsystems for the Hokora TUI client.

Subsystems share a ``SyncState`` dataclass and are composed by the
``SyncEngine`` facade in ``hokora_tui.sync_engine``. Callers normally
go through that facade; direct subsystem use is for tests.
"""

from hokora_tui.sync.state import SyncState

__all__ = ["SyncState"]
