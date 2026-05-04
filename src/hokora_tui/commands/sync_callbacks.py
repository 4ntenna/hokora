# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Sync-engine callback bodies.

Each top-level function here is a sync-engine callback body, and each
``_handle_*`` is an event-type handler that the router in
``commands/event_dispatcher.py`` dispatches to.

All functions take ``app`` as their first argument instead of closing
over it. ``ensure_sync_engine`` (in ``helpers.py``) binds ``app``
into small closures that hand these functions to the engine's
``set_*_callback`` methods.

No callback here runs its own urwid mutation — they all marshal state
changes onto the main loop via ``app.loop.set_alarm_in(0, ...)``. That
is the TUI's thread-safety invariant: any mutation from a non-loop
thread must round-trip through the alarm scheduler.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hokora_tui.app import HokoraTUI

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────
# Top-level callbacks wired onto the engine
# ─────────────────────────────────────────────────────────────────────


def on_messages(app: "HokoraTUI", channel_id: str, messages: list, latest_seq) -> None:
    """Handle incoming messages from sync (with deduplication)."""
    logger.info(
        "on_messages: channel=%s, count=%d, latest_seq=%s",
        channel_id,
        len(messages),
        latest_seq,
    )
    if channel_id not in app.state.messages:
        app.state.messages[channel_id] = []

    # Deduplicate: only add messages whose msg_hash is not already present.
    # Also update existing messages if sync provides a body (sealed decrypt).
    existing_by_hash = {
        m.get("msg_hash"): m for m in app.state.messages[channel_id] if m.get("msg_hash")
    }
    new_messages = []
    updated_messages = []
    for m in messages:
        h = m.get("msg_hash")
        if not h:
            continue
        existing = existing_by_hash.get(h)
        if existing is None:
            new_messages.append(m)
        elif not existing.get("body") and m.get("body"):
            # Sync provided decrypted body — update cached message
            existing.update(m)
            updated_messages.append(existing)
        elif m.get("has_thread") and not existing.get("has_thread"):
            # Update thread info selectively — never overwrite good body
            existing["has_thread"] = True
            if m.get("reply_count"):
                existing["reply_count"] = m["reply_count"]
            if m.get("edited") and not existing.get("edited"):
                existing["edited"] = True
            # Only update body if existing is blank and daemon has content
            if m.get("body") and not existing.get("body"):
                existing["body"] = m["body"]
            updated_messages.append(existing)
    logger.info(
        "on_messages: %d new after dedup (was %d), %d updated",
        len(new_messages),
        len(messages),
        len(updated_messages),
    )
    # DB store is thread-safe (skip thread replies — seq=None)
    storable = [m for m in new_messages if m.get("seq") is not None]
    storable_updated = [m for m in updated_messages if m.get("seq") is not None]
    if app.db is not None and (storable or storable_updated):
        if storable:
            app.db.store_messages(storable)
        if storable_updated:
            app.db.store_messages(storable_updated)
        if latest_seq:
            app.db.set_cursor(channel_id, latest_seq)

    if not new_messages:
        return

    # Separate channel messages from thread replies
    channel_msgs = [m for m in new_messages if m.get("seq") is not None]
    # Thread replies handled by the live push thread_reply handler

    # Schedule ALL state + UI updates on main thread
    def _on_msgs(_loop=None, _data=None):
        if channel_msgs:
            app.state.messages[channel_id].extend(channel_msgs)
        if channel_id == app.state.current_channel_id:
            if app.messages_view is not None:
                for msg in channel_msgs:
                    app.messages_view.append_message(msg)
        else:
            count = app.state.unread_counts.get(channel_id, 0) + len(channel_msgs)
            app.state.unread_counts[channel_id] = count
        app._schedule_redraw()

    if app.loop:
        app.loop.set_alarm_in(0, _on_msgs)
        app._wake_loop()
    else:
        _on_msgs()


def on_thread_data(app: "HokoraTUI", data) -> None:
    """Handle thread messages from daemon."""
    messages = data.get("messages", data) if isinstance(data, dict) else data

    def _on_thread(_loop=None, _data=None):
        if hasattr(app, "channels_view") and app.channels_view:
            tv = getattr(app.channels_view, "_thread_view", None)
            if tv and hasattr(tv, "_on_thread_data"):
                tv._on_thread_data(messages)

    if app.loop:
        app.loop.set_alarm_in(0, _on_thread)
        app._wake_loop()


def on_search_results(app: "HokoraTUI", data) -> None:
    """Handle search results from daemon."""
    results = data.get("results", data) if isinstance(data, dict) else data

    def _on_search(_loop=None, _data=None):
        if hasattr(app, "channels_view") and app.channels_view:
            sv = getattr(app.channels_view, "_search_view", None)
            if sv and hasattr(sv, "_on_search_results"):
                sv._on_search_results(results)

    if app.loop:
        app.loop.set_alarm_in(0, _on_search)
        app._wake_loop()


def on_pins_data(app: "HokoraTUI", data) -> None:
    """Handle pinned messages from daemon."""
    pins = data.get("messages", data) if isinstance(data, dict) else data
    logger.info(
        "Received %s pinned messages",
        len(pins) if isinstance(pins, list) else "?",
    )


def on_member_list(app: "HokoraTUI", data) -> None:
    """Handle member list from daemon."""
    members = data.get("members", data) if isinstance(data, dict) else data
    logger.info(
        "Received member list: %s members",
        len(members) if isinstance(members, list) else "?",
    )

    def _show_members(_loop=None, _data=None):
        if isinstance(members, list) and members:
            names = []
            for m in members[:20]:
                h = m.get("identity_hash", m.get("hash", "?"))[:8]
                name = m.get("display_name") or h
                names.append(f"{name} ({h})")
            app.status.set_context(f"Members ({len(members)}): {', '.join(names)}")
        else:
            app.status.set_context("No members found")
        app._schedule_redraw()

    if app.loop:
        app.loop.set_alarm_in(0, _show_members)
        app._wake_loop()


def on_invite_result(app: "HokoraTUI", data) -> None:
    """Handle invite creation/listing results from daemon."""
    action = data.get("action", "")

    def _show_invite(_loop=None, _data=None):
        from hokora.constants import MSG_SYSTEM

        ch_id = app.state.current_channel_id
        if action == "invite_created":
            token = data.get("token", "")
            max_uses = data.get("max_uses", 1)
            hours = data.get("expiry_hours", 72)
            msg = {
                "type": MSG_SYSTEM,
                "body": f"Invite created: {token} (uses: 0/{max_uses}, expires: {hours}h)",
                "timestamp": time.time(),
                "msg_hash": "",
                "channel_id": ch_id or "",
            }
            if hasattr(app, "messages_view") and app.messages_view:
                app.messages_view.append_message(msg)
            app.status.set_context("Invite created successfully")

        elif action == "invite_list":
            invites = data.get("invites", [])
            if not invites:
                app.status.set_context("No active invites")
            else:
                for inv in invites:
                    h = inv.get("token_hash", "?")
                    uses = f"{inv.get('uses', 0)}/{inv.get('max_uses', '?')}"
                    status = "revoked" if inv.get("revoked") else "active"
                    msg = {
                        "type": MSG_SYSTEM,
                        "body": f"Invite {h}: {uses} uses, {status}",
                        "timestamp": time.time(),
                        "msg_hash": "",
                        "channel_id": ch_id or "",
                    }
                    if hasattr(app, "messages_view") and app.messages_view:
                        app.messages_view.append_message(msg)
                app.status.set_context(f"{len(invites)} invite(s) found")

        app._schedule_redraw()

    if app.loop:
        app.loop.set_alarm_in(0, _show_invite)
        app._wake_loop()


# ─────────────────────────────────────────────────────────────────────
# Internal event-type handlers — dispatched by event_dispatcher
# ─────────────────────────────────────────────────────────────────────


def handle_node_meta(app: "HokoraTUI", data: dict) -> None:
    """Extract + normalize channels, store in DB, update state, register links."""
    # Extract channels — handle both flat and nested formats
    channels = data.get("channels", [])
    if not channels and isinstance(data.get("data"), dict):
        channels = data["data"].get("channels", [])

    # Node identity hash from daemon. Older daemons may omit this —
    # channels simply stay untagged in that case.
    node_identity_hash = data.get("node_identity_hash")
    if node_identity_hash is None and isinstance(data.get("data"), dict):
        node_identity_hash = data["data"].get("node_identity_hash")

    # Normalize channel dicts and tag each with the source node identity.
    normalized = []
    for ch in channels:
        if isinstance(ch, dict) and ch.get("id"):
            if node_identity_hash and not ch.get("node_identity_hash"):
                ch = {**ch, "node_identity_hash": node_identity_hash}
            normalized.append(ch)

    node_name = data.get("node_name") or data.get("node", "Remote")
    if not node_name and isinstance(data.get("data"), dict):
        node_name = data["data"].get("node_name", "Remote")

    logger.info("node_meta: %s, %d channels", node_name, len(normalized))

    if app.db is not None:
        app.db.store_channels(normalized)

    # Build channel_dests (pure data)
    channel_dests = {}
    for ch in normalized:
        ch_id = ch.get("id", "")
        dest_hash = ch.get("destination_hash") or ch.get("identity_hash", "")
        if ch_id and dest_hash:
            channel_dests[ch_id] = dest_hash

    node_key = node_name
    existing = app.state.discovered_nodes.get(node_key, {})
    node_dict = {
        "hash": node_key,
        "node_name": node_name,
        "channel_count": len(normalized),
        "last_seen": time.time(),
        "channels": [ch.get("name", "") for ch in normalized],
        "channel_dests": channel_dests,
        "primary_dest": next(iter(channel_dests.values()), None) if channel_dests else None,
        "bookmarked": existing.get("bookmarked", False),
    }

    def _on_meta(_loop=None, _data=None):
        app.state.channels = normalized
        app.state.connected_node_name = node_name
        for ch in normalized:
            ch_id = ch.get("id", "")
            if ch_id:
                app.state.unread_counts[ch_id] = 0
        app.state.discovered_nodes[node_key] = node_dict

        # Load cached messages from client DB so history shows immediately
        if app.db:
            for ch in normalized:
                ch_id = ch.get("id")
                if ch_id:
                    try:
                        cached = app.db.get_messages(ch_id, limit=50)
                        if cached:
                            existing = app.state.messages.get(ch_id, [])
                            existing_hashes = {
                                m.get("msg_hash") for m in existing if m.get("msg_hash")
                            }
                            merged = list(existing)
                            for m in cached:
                                if m.get("msg_hash") and m["msg_hash"] not in existing_hashes:
                                    merged.append(m)
                            merged.sort(key=lambda m: m.get("seq", 0))
                            app.state.messages[ch_id] = merged
                    except Exception:
                        logger.debug("failed to merge cached messages for %s", ch_id, exc_info=True)

        # Register all channels on the existing link.
        engine = app.sync_engine
        if engine:
            for ch in normalized:
                ch_id = ch.get("id")
                dh = ch.get("destination_hash")
                pub_key = ch.get("identity_public_key")
                if ch_id and not engine.has_link(ch_id):
                    try:
                        dest_bytes = bytes.fromhex(dh) if dh else None
                        engine.register_channel(
                            ch_id,
                            destination_hash=dest_bytes,
                            identity_public_key=pub_key,
                        )
                    except Exception:
                        logger.debug("register_channel failed for %s", ch_id, exc_info=True)

        app.state.connection_status = "connected"
        app.state.connected_node_name = node_name
        app.state.emit("channels_updated")
        app.state.emit("nodes_updated")
        app.status.set_connection("connected", node_name)
        app.status.set_context(f"Connected to {node_name} ({len(normalized)} channels)")

        # Auto-redeem pending node invite
        if engine:
            pending_token = engine.pop_pending_redeem("__node__")
            if pending_token and normalized:
                first_ch = normalized[0].get("id")
                if first_ch:
                    engine.redeem_invite(first_ch, pending_token)
                    app.status.set_context(f"Redeeming invite on {node_name}...")

        app.nav.switch_to(3)
        if normalized:
            first_ch = normalized[0].get("id")
            if first_ch and hasattr(app, "channels_view"):
                app.channels_view.select_channel(first_ch)
        app._schedule_redraw()

    if app.loop:
        app.loop.set_alarm_in(0, _on_meta)
        app._wake_loop()
    else:
        _on_meta()


def handle_thread_reply_push(app: "HokoraTUI", msg: dict, channel_id: str) -> None:
    """Live-push for a thread reply: append to open thread view + mark root."""
    root_hash = msg.get("reply_to")

    def _handler(_loop=None, _data=None):
        # Append to open thread view if matching
        if hasattr(app, "channels_view") and app.channels_view:
            tv = getattr(app.channels_view, "_thread_view", None)
            if tv and tv._root_hash == root_hash:
                from hokora_tui.widgets.message_widget import MessageWidget

                sealed_keys = getattr(app.db, "sealed_keys", None) if app.db else None
                w = MessageWidget(msg, sealed_keys=sealed_keys)
                tv._replies_walker.append(w)
                if tv._replies_walker:
                    tv._replies_walker.set_focus(len(tv._replies_walker) - 1)
        # Mark root message as having a thread + persist
        if channel_id in app.state.messages:
            for m in app.state.messages[channel_id]:
                if m.get("msg_hash") == root_hash:
                    m["has_thread"] = True
                    if app.db:
                        app.db.store_messages([m])
                    break
            # Refresh display to show thread indicator
            if channel_id == app.state.current_channel_id and app.messages_view:
                app.messages_view.set_messages(app.state.messages.get(channel_id, []))
        app._schedule_redraw()

    if app.loop:
        app.loop.set_alarm_in(0, _handler)
        app._wake_loop()


def handle_message_updated(app: "HokoraTUI", msg: dict) -> None:
    """Mutation (edit/delete/reaction/pin): update in-place + rebuild display."""
    channel_id = msg.get("channel_id")
    msg_hash = msg.get("msg_hash")

    def _update(_loop=None, _data=None):
        if channel_id and msg_hash and channel_id in app.state.messages:
            for i, existing in enumerate(app.state.messages[channel_id]):
                if existing.get("msg_hash") == msg_hash:
                    app.state.messages[channel_id][i] = msg
                    break
            if (
                hasattr(app, "messages_view")
                and app.messages_view
                and app.state.current_channel_id == channel_id
            ):
                app.messages_view.set_messages(app.state.messages.get(channel_id, []))
            if app.db:
                app.db.store_messages([msg])
            app._schedule_redraw()

    if app.loop:
        app.loop.set_alarm_in(0, _update)
        app._wake_loop()


def handle_connection_lost(app: "HokoraTUI") -> None:
    def _on_disc(_loop=None, _data=None):
        app.state.connection_status = "disconnected"
        app.status.set_connection("disconnected")
        app.status.set_context("Connection lost")
        app._schedule_redraw()

    if app.loop:
        app.loop.set_alarm_in(0, _on_disc)
        app._wake_loop()


def handle_connection_recovering(app: "HokoraTUI", data: dict) -> None:
    """Transient Link drop — sync engine is retrying. UI shows "Reconnecting...""" ""
    attempt = data.get("attempt", 1)
    delay = data.get("next_retry_in", 0)

    def _on_rec(_loop=None, _data=None, _a=attempt, _d=delay):
        app.state.connection_status = "recovering"
        app.status.set_connection("recovering")
        app.status.set_context(f"Reconnecting (attempt {_a}, retry in {_d:.0f}s)...")
        app._schedule_redraw()

    if app.loop:
        app.loop.set_alarm_in(0, _on_rec)
        app._wake_loop()


def handle_invite_redeemed(app: "HokoraTUI") -> None:
    """Auto-bookmark the node + show status."""
    node_name = app.state.connected_node_name
    if node_name and app.db:
        try:
            for n in app.db.get_discovered_nodes():
                if n.get("node_name") == node_name and not n.get("bookmarked"):
                    app.db.toggle_node_bookmark(n["hash"])
                    break
        except Exception:
            logger.debug("auto-bookmark after invite redeem failed", exc_info=True)

    def _on_r(_loop=None, _data=None):
        app.status.set_context(f"Invite redeemed - connected to {node_name or 'node'}")
        app._schedule_redraw()

    if app.loop:
        app.loop.set_alarm_in(0, _on_r)
        app._wake_loop()


def handle_media_downloaded(app: "HokoraTUI", data: dict) -> None:
    path = data.get("path", "")
    size = data.get("size", 0)

    def _on_dl(_loop=None, _data=None):
        app.status.set_context(f"Downloaded: {path} ({size} bytes)")
        app._schedule_redraw()

    if app.loop:
        app.loop.set_alarm_in(0, _on_dl)
        app._wake_loop()


def handle_thread_messages(app: "HokoraTUI", data: dict) -> None:
    messages = data.get("messages", data) if isinstance(data, dict) else data

    def _on_t(_loop=None, _data=None):
        if hasattr(app, "channels_view") and app.channels_view:
            tv = getattr(app.channels_view, "_thread_view", None)
            if tv and hasattr(tv, "_on_thread_data"):
                tv._on_thread_data(messages)

    if app.loop:
        app.loop.set_alarm_in(0, _on_t)
        app._wake_loop()
