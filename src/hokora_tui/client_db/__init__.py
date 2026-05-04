# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Client-side SQLite cache for the TUI.

The ``ClientDB`` facade exposes a flat public API for backward
compatibility; direct sub-store access (``db.messages``,
``db.channels``, ...) is also available for code that wants
namespacing. Internally the facade delegates to eight
single-responsibility stores.
"""

from hokora_tui.client_db.facade import ClientDB

__all__ = ["ClientDB"]
