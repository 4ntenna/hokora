# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Event-type → handler dispatch for sync-engine events.

A single dict lookup picks each ``_handle_*`` function; ``message``
and ``batch`` need bespoke logic and are dispatched inline.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from hokora_tui.commands import sync_callbacks as cb
from hokora_tui.sync._verify import verify_message_signature

if TYPE_CHECKING:
    from hokora_tui.app import HokoraTUI

logger = logging.getLogger(__name__)


# event_type → handler(app, data). ``message`` is dispatched inline below.
EVENT_HANDLERS = {
    "node_meta": cb.handle_node_meta,
    "message_updated": cb.handle_message_updated,
    "connection_recovering": cb.handle_connection_recovering,
    "invite_redeemed": lambda app, _data: cb.handle_invite_redeemed(app),
    "media_downloaded": cb.handle_media_downloaded,
    "thread_messages": cb.handle_thread_messages,
    "connection_lost": lambda app, _data: cb.handle_connection_lost(app),
    # CDSP acks are processed in CdspClient; explicit no-ops here
    # silence the "Unhandled event" log noise.
    "cdsp_session_ack": lambda _app, _data: None,
    "cdsp_profile_ack": lambda _app, _data: None,
}


def dispatch_event(app: "HokoraTUI", event_type: str, data) -> None:
    """Route a sync-engine event; ``message`` and ``batch`` are inline-dispatched."""
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
