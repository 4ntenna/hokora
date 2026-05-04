# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Shared helpers for the command subsystem.

Holds ``ensure_sync_engine`` — the engine init + callback-wiring helper
that commands (/local, /connect) + views (discovery_view) call to make
sure the engine exists and its callbacks are wired before driving it.

Callback bodies live in ``sync_callbacks.py``; event-type dispatch
lives in ``event_dispatcher.py``. This module is just the wiring
point.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from hokora_tui.commands import sync_callbacks as cb
from hokora_tui.commands.event_dispatcher import dispatch_event

if TYPE_CHECKING:
    from hokora_tui.app import HokoraTUI

logger = logging.getLogger(__name__)


def ensure_sync_engine(app: "HokoraTUI") -> None:
    """Lazy-create SyncEngine and (re)wire its callbacks; idempotent.

    Engine creation requires the main thread because LXMF installs
    signal handlers in its constructor — off-thread construction
    blows up there. Callback bodies are module-level functions taking
    ``app`` as their first arg, wrapped in app-binding lambdas before
    being handed to the engine; each marshals urwid mutations back
    to the main thread via ``loop.set_alarm_in(0, ...)``.
    """
    if app.sync_engine is None:
        # Try creating it now (only works on main thread)
        app._init_sync_engine()
        if app.sync_engine is None:
            return

    engine = app.sync_engine
    engine.set_display_name(app.state.display_name)

    # Load persisted cursors so reconnects fetch only new messages.
    # Always refresh from DB (not just when empty) to prevent cursor
    # race where register_channel fires before cursors are loaded.
    if app.db is not None:
        try:
            saved = app.db.get_all_cursors()
            if saved:
                engine.update_cursors(saved)
        except Exception:
            logger.debug("sync cursor restore failed in ensure_sync_engine", exc_info=True)

    engine.set_message_callback(
        lambda channel_id, messages, latest_seq: cb.on_messages(
            app, channel_id, messages, latest_seq
        )
    )
    engine.set_event_callback(lambda event_type, data: dispatch_event(app, event_type, data))
    engine.set_thread_callback(lambda data: cb.on_thread_data(app, data))
    engine.set_search_callback(lambda data: cb.on_search_results(app, data))
    engine.set_pins_callback(lambda data: cb.on_pins_data(app, data))
    engine.set_member_list_callback(lambda data: cb.on_member_list(app, data))
    engine.set_invite_callback(lambda data: cb.on_invite_result(app, data))

    app._wire_dm_callback()
