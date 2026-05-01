# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Event-type → handler dispatch for sync-engine events.

A single dict lookup picks the ``_handle_*`` function for each
sync-engine event type, plus a small escape hatch for the ``message``
event (which re-enters ``on_messages`` AND may trigger a thread-reply
push, so it carries its own micro-logic rather than a flat handler
lookup).

Keeping the dispatch table in a dedicated module makes it trivial to:
  * grep all event types we care about — ``EVENT_HANDLERS.keys()``.
  * add a new handler — one import + one dict entry, no need to edit
    the callback-wiring code in ``helpers.py``.
  * unit-test the dispatch independent of the callback bodies.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from hokora_tui.commands import sync_callbacks as cb
from hokora_tui.sync._verify import verify_message_signature

if TYPE_CHECKING:
    from hokora_tui.app import HokoraTUI

logger = logging.getLogger(__name__)


# event_type → handler(app, data). ``message`` is not in this table
# because it needs to recurse into on_messages + conditionally trigger
# the thread-reply push path — see ``dispatch_event`` below.
EVENT_HANDLERS = {
    "node_meta": cb.handle_node_meta,
    "message_updated": cb.handle_message_updated,
    "connection_recovering": cb.handle_connection_recovering,
    "invite_redeemed": lambda app, _data: cb.handle_invite_redeemed(app),
    "media_downloaded": cb.handle_media_downloaded,
    "thread_messages": cb.handle_thread_messages,
    "connection_lost": lambda app, _data: cb.handle_connection_lost(app),
    # CDSP acks are fully processed inside sync_engine.py's CdspClient
    # (session state + deferred-event replay happen there). They are
    # re-fired through this dispatcher as an observability hook for any
    # future UI component that wants to react to profile/session state
    # changes. Registering explicit no-op handlers documents the intent
    # and silences the "Unhandled sync event" log noise.
    "cdsp_session_ack": lambda _app, _data: None,
    "cdsp_profile_ack": lambda _app, _data: None,
}


def dispatch_event(app: "HokoraTUI", event_type: str, data) -> None:
    """Route a sync-engine event to its handler.

    Handles three special cases inline because they don't fit the clean
    ``(app, data) -> None`` shape every other handler uses:

    * ``message`` — a live-push for a new channel message. Recurses into
      ``on_messages`` for the dedup + cache path, then optionally forwards
      to the thread-reply handler if the message carries ``reply_to`` +
      ``thread_seq``.
    * ``batch`` — BATCHED-profile flush carrying nested events; each
      inner event is a raw bytes payload that the sync engine
      demultiplexes via ``dispatch_batch_packet``.

    Everything else goes through the ``EVENT_HANDLERS`` dict.
    """
    logger.info(
        "Sync event: %s, data keys: %s",
        event_type,
        list(data.keys()) if isinstance(data, dict) else type(data),
    )

    if event_type == "message":
        msg = data
        channel_id = msg.get("channel_id")
        if channel_id:
            # TUI-side Ed25519 verification on the live path. Same chokepoint
            # used by HistoryClient.handle_history — consistent TOFU MITM
            # detection across both paths. Three-state result:
            #   True  → store verified=1 (cryptographic check passed).
            #   False → store verified=0 (failed sig OR TOFU mismatch).
            #   None  → no sig material on the wire; leave the field unset
            #           and the MessageStore stores verified=0 so the row
            #           honestly renders [UNVERIFIED].
            engine = getattr(app, "sync_engine", None)
            if engine is not None:
                verified = verify_message_signature(msg, engine.identity_keys)
                if verified is not None:
                    msg["verified"] = verified
            cb.on_messages(app, channel_id, [msg], msg.get("seq", 0))
            if msg.get("reply_to") and msg.get("thread_seq") is not None:
                cb.handle_thread_reply_push(app, msg, channel_id)
        return

    if event_type == "batch":
        events = data.get("events", [])
        logger.info("Received batch: %d events", len(events))
        if app.sync_engine is not None:
            for event_data in events:
                if isinstance(event_data, bytes):
                    app.sync_engine.dispatch_batch_packet(event_data)
        return

    handler = EVENT_HANDLERS.get(event_type)
    if handler is None:
        logger.info("Unhandled sync event: %s", event_type)
        return
    handler(app, data)
