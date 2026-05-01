# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Client-side sync engine for the Hokora TUI.

Thin facade over the ``hokora_tui.sync`` subsystem package. Each subsystem
owns one coherent responsibility:

- ``ChannelLinkManager`` — RNS.Link lifecycle per channel
- ``ReconnectScheduler`` — exponential-backoff reconnect on transport drop
- ``DmRouter`` — LXMF direct messaging (owns the LXMRouter)
- ``CdspClient`` — CDSP session init/resume + profile updates
- ``HistoryClient`` — packet parse, sync_history, subscribe/unsubscribe,
  signature verify, sequence integrity, identity-key cache
- ``QueryClient`` — search, threads, pins, member list
- ``InviteClient`` — create/list/redeem invites
- ``RichMessageClient`` — send_message + reaction/edit/delete/pin/thread
- ``MediaClient`` — media upload + download (resource-concluded routing)

State is shared via ``SyncState`` (a dataclass) so subsystems stay
loosely coupled. SyncEngine wires the subsystems together, owns the
public API surface for callers, and routes responses to the right
``handle_*`` method via ``_handle_response``.
"""

import logging
from pathlib import Path
from typing import Optional, Callable

import LXMF  # noqa: F401 — re-exported as ``hokora_tui.sync_engine.LXMF`` for tests that patch it
import RNS

from hokora.security.verification import VerificationService
from hokora_tui.sync.cdsp_client import CdspClient
from hokora_tui.sync.dm_router import DmRouter
from hokora_tui.sync.history_client import HistoryClient
from hokora_tui.sync.invite_client import InviteClient
from hokora_tui.sync.link_manager import (
    LINK_ESTABLISHMENT_TIMEOUT_PER_HOP,  # noqa: F401 — re-exported for callers
    ChannelLinkManager,
)
from hokora_tui.sync.media_client import MediaClient
from hokora_tui.sync.query_client import QueryClient
from hokora_tui.sync.reconnect_scheduler import ReconnectScheduler
from hokora_tui.sync.rich_message_client import RichMessageClient
from hokora_tui.sync.state import SyncState

logger = logging.getLogger(__name__)

# Stale nonce cleanup interval
_NONCE_CLEANUP_INTERVAL = 30.0
_NONCE_MAX_AGE = 60.0

# Re-exported for backward compatibility — tests import these from
# ``hokora_tui.sync_engine``. They live on ReconnectScheduler now.
RECONNECT_BACKOFF_SCHEDULE = ReconnectScheduler.BACKOFF_SCHEDULE
RECONNECT_BACKOFF_JITTER = ReconnectScheduler.BACKOFF_JITTER


class SyncEngine:
    """Client-side sync engine managing connections to Hokora nodes.

    Extended v2 engine with support for search, threads, pins, member lists,
    reactions, edits, deletes, thread replies, unsubscribe, and direct messages.
    """

    def __init__(
        self,
        reticulum: RNS.Reticulum,
        identity: Optional[RNS.Identity] = None,
        data_dir: Optional[Path] = None,
    ):
        self.reticulum = reticulum
        self.identity = identity
        # Cross-cutting mutable state shared across subsystems.
        self._state = SyncState()
        # Link lifecycle + reconnect.
        self._link_manager = ChannelLinkManager(reticulum, identity, self._state)
        self._reconnect = ReconnectScheduler(self._link_manager)
        # Message / event callbacks.
        self._message_callback: Optional[Callable] = None
        self._event_callback: Optional[Callable] = None
        self._verifier = VerificationService()
        # Link-connected callback: fires inside _on_link_established so the
        # UI can transition "Resolving path..." → "Connected" regardless of
        # which path (immediate, announce-driven retry, or pubkey-seeded)
        # eventually establishes the link.
        self._connected_callback: Optional[Callable] = None
        # Sealed-key persistence callback: signature
        #   on_sealed_key(channel_id: str, key: bytes, epoch: int)
        # App registers this to wire daemon-served sealed keys into the
        # TUI's SealedKeyStore for at-rest envelope encryption.
        self._on_sealed_key: Optional[Callable[[str, bytes, int], None]] = None
        # DM + CDSP subsystems.
        self._dm_router = DmRouter(identity, data_dir, self._state)
        self._cdsp = CdspClient(self._link_manager, self._dm_router, self._state)
        # History, query, invite, rich message, and media subsystems —
        # see module docstring for the responsibility split.
        self._history = HistoryClient(
            self._link_manager,
            self._state,
            self._verifier,
            response_dispatcher=self._handle_response,
            event_callback_getter=lambda: self._event_callback,
        )
        self._queries = QueryClient(self._link_manager, self._state)
        self._invites = InviteClient(self._link_manager, self._state)
        self._messages = RichMessageClient(
            self._link_manager, self._dm_router, self._state, identity
        )
        self._media = MediaClient(
            self._link_manager,
            self._dm_router,
            self._state,
            identity,
            packet_dispatcher=self._history._on_packet,
            event_callback_getter=lambda: self._event_callback,
        )
        # Wire ChannelLinkManager callbacks now that subsystems exist:
        # link establishment runs the identify/CDSP/history/subscribe chain;
        # link closed decides between reconnect and terminal connection_lost;
        # packet dispatch goes to HistoryClient (which routes responses back
        # via _handle_response); resource conclusion goes to MediaClient
        # (which decides between save-to-disk and packet-redispatch). LXMF
        # batch deliveries fan into the same packet dispatch.
        self._link_manager.set_on_established(self._on_link_established)
        self._link_manager.set_on_closed(self._on_link_closed)
        self._link_manager.set_on_packet(self._history._on_packet)
        self._link_manager.set_on_resource_concluded(self._media.on_resource_concluded)
        self._dm_router.register_batch_dispatch(self._history._on_packet)
        # DmRouter starts AFTER the batch dispatch is wired — its
        # start() may register the LXMF delivery callback that invokes
        # batch dispatch on first inbound packet.
        self._dm_router.start()

    def set_message_callback(self, callback: Callable):
        """Set callback for received messages: callback(channel_id, messages)."""
        self._message_callback = callback

    def set_event_callback(self, callback: Callable):
        """Set callback for live events: callback(event_type, data)."""
        self._event_callback = callback

    def set_search_callback(self, callback: Callable):
        """Set callback for search results — forwarded to QueryClient since Step C."""
        self._queries.set_on_search(callback)

    def set_thread_callback(self, callback: Callable):
        """Set callback for thread messages — forwarded to QueryClient."""
        self._queries.set_on_thread(callback)

    def set_pins_callback(self, callback: Callable):
        """Set callback for pinned messages — forwarded to QueryClient."""
        self._queries.set_on_pins(callback)

    def set_member_list_callback(self, callback: Callable):
        """Set callback for member list — forwarded to QueryClient."""
        self._queries.set_on_member_list(callback)

    def set_invite_callback(self, callback: Callable):
        """Set callback for invite results — forwarded to InviteClient."""
        self._invites.set_on_result(callback)

    def set_dm_callback(self, callback: Callable):
        """Register callback for incoming direct messages.

        callback(sender_hash, display_name, body, timestamp)
        """
        self._dm_router.set_on_delivery(callback)

    def set_sealed_key_callback(self, callback: Callable[[str, bytes, int], None]) -> None:
        """Register the sealed-key persistence callback.

        Fired after the daemon serves a sealed key envelope and SyncEngine
        has decrypted it with the TUI's RNS identity. Callback is invoked
        on the RNS packet thread — handler must hop to the urwid loop if
        UI updates are required.
        """
        self._on_sealed_key = callback

    def set_connected_callback(self, callback: Callable):
        """Register a callback fired when an RNS link is established.

        Signature: callback(channel_id: str, destination_hash: bytes).
        Called from the RNS thread — handler MUST route to the urwid loop
        via loop.set_alarm_in() for thread safety.
        """
        self._connected_callback = callback

    # ── Public accessors for UI / commands / announcer ──────────────────

    # Display name (DM sender label).
    def set_display_name(self, name: Optional[str]) -> None:
        self._state.display_name = name

    def get_display_name(self) -> Optional[str]:
        return self._state.display_name

    # Cursors (sync history position).
    def update_cursors(self, cursors: dict[str, int]) -> None:
        """Bulk-update cursors (e.g. from persisted client DB on startup)."""
        self._state.cursors.update(cursors)

    def clear_cursors(self) -> None:
        """Drop all sync cursors — used on disconnect or manual reset."""
        self._state.cursors.clear()

    # Link state queries.
    def has_link(self, channel_id: str) -> bool:
        """True if a Link object exists for this channel (any status)."""
        return self._link_manager.get_link(channel_id) is not None

    def is_connected(self, channel_id: str) -> bool:
        """True if the channel's Link is ACTIVE."""
        return self._link_manager.is_connected(channel_id)

    def link_count(self) -> int:
        """Number of channels with a Link object (any status)."""
        return self._link_manager.link_count()

    def first_connected_channel_id(self) -> Optional[str]:
        """Return the channel_id of any channel currently linked. Used by
        invite-redeem when the user hasn't selected a channel — we just
        need *some* link to send the redeem request through."""
        snap = self._link_manager.links_snapshot()
        return next(iter(snap)) if snap else None

    # Pending-state queries.
    def has_pending_connects(self) -> bool:
        """True if any channel is awaiting RNS path resolution."""
        return bool(self._state.pending_connects)

    def pop_pending_redeem(self, key: str) -> Optional[str]:
        """Pop and return a pending invite token by key (e.g. ``"__node__"``)."""
        return self._state.pending_redeems.pop(key, None)

    def set_pending_redeem(self, key: str, token: str) -> None:
        """Stash an invite token for redemption after the next link establishes."""
        self._state.pending_redeems[key] = token

    def set_pending_pubkey(self, dest_hex: str, pubkey_bytes: bytes) -> None:
        """Stash a public key (from a 4-field invite) so connect_channel can
        construct an RNS.Identity without waiting for an announce."""
        self._state.pending_pubkeys[dest_hex] = pubkey_bytes

    # Batch dispatch — used when an LXMF batch delivery arrives and each
    # contained event must be replayed as if it came from a packet.
    def dispatch_batch_packet(self, data: bytes) -> None:
        """Inject a single event-bytes payload into the packet pipeline."""
        self._history._on_packet(data, None)

    # LXMF announce.
    def announce_lxmf_destination(self) -> bool:
        """Announce our LXMF delivery destination so peers can route DMs to us.

        Returns True if announce was sent, False if no source destination
        is registered (e.g. running anonymous without identity).
        """
        src = self._dm_router.lxmf_source
        if src is None or not hasattr(src, "announce"):
            return False
        try:
            src.announce()
            return True
        except Exception:
            logger.exception("LXMF announce failed")
            return False

    def cache_identity_key(self, identity_hash: str, public_key_bytes: bytes):
        """Cache a sender's public key for signature verification."""
        self._history.cache_identity_key(identity_hash, public_key_bytes)

    @property
    def identity_keys(self) -> dict[str, bytes]:
        """Live TOFU pubkey cache (shared with the history-sync verifier).

        Returned dict is the underlying ``SyncState.identity_keys`` —
        mutations propagate. Used by the live-event verify hook in
        ``commands.event_dispatcher`` so the live path shares the same
        TOFU MITM detection as ``HistoryClient.handle_history``.
        """
        return self._state.identity_keys

    def get_seq_warnings(self, channel_id: str) -> list[str]:
        """Return sequence gap warnings for a channel."""
        return self._history.get_seq_warnings(channel_id)

    def connect_channel(self, destination_hash: bytes, channel_id: str):
        """Establish a link to a channel's destination.

        Identity resolution priority is documented on
        ``ChannelLinkManager.connect_channel``. This facade additionally
        registers the target with the reconnect scheduler so the link is
        restored automatically after a transport drop.
        """
        # New user-initiated connect clears any lingering user-disconnect
        # state so the scheduler becomes eligible again.
        self._reconnect.reset_user_disconnected()
        self._reconnect.add_target(channel_id, destination_hash)
        self._link_manager.connect_channel(destination_hash, channel_id)

    def register_channel(
        self,
        channel_id: str,
        destination_hash: bytes = None,
        identity_public_key: bytes = None,
    ):
        """Register an additional channel on the existing active link.

        After registration, kicks off history sync + subscribe for the
        new channel.
        """
        self._link_manager.register_channel(channel_id, destination_hash, identity_public_key)
        if self._link_manager.is_connected(channel_id):
            cursor = self._state.cursors.get(channel_id, 0)
            # Ask for the sealed-channel key envelope before history sync
            # so the persisted ciphertext rows can be rendered. Daemon
            # rejects with PermissionDenied for non-sealed channels; the
            # response is dropped silently.
            self.request_sealed_key(channel_id)
            self.sync_history(channel_id, since_seq=cursor)
            self.subscribe_live(channel_id)

    def retry_pending_connects(self):
        """Retry connections for channels whose paths weren't resolved yet."""
        self._link_manager.retry_pending_connects()

    def disconnect_channel(self, channel_id: str):
        # User-initiated disconnect on this channel: stop auto-reconnecting it.
        self._reconnect.remove_target(channel_id)
        if not self._reconnect.targets_snapshot():
            # No more channels to keep alive — stop any pending reconnect loop.
            self._reconnect.stop()
        self._link_manager.disconnect_channel(channel_id)

    def sync_history(self, channel_id: str, since_seq: int = 0, limit: int = 50):
        """Delegates to HistoryClient."""
        self._history.sync_history(channel_id, since_seq, limit)

    def request_node_meta(self, channel_id: str):
        """Delegates to HistoryClient."""
        self._history.request_node_meta(channel_id)

    def subscribe_live(self, channel_id: str):
        """Delegates to HistoryClient."""
        self._history.subscribe_live(channel_id)

    def request_sealed_key(self, channel_id: str):
        """Delegates to HistoryClient. Used by sealed-channel at-rest
        access — the response is dispatched through ``_handle_sealed_key_response``
        and persisted into the SealedKeyStore."""
        self._history.request_sealed_key(channel_id)

    def unsubscribe(self, channel_id: str | None = None):
        """Delegates to HistoryClient."""
        self._history.unsubscribe(channel_id)

    def redeem_invite(self, channel_id: str, token: str):
        """Delegates to InviteClient."""
        self._invites.redeem_invite(channel_id, token)

    def send_message(self, channel_id: str, message_data: dict):
        """Delegates to RichMessageClient."""
        return self._messages.send_message(channel_id, message_data)

    def send_media(self, channel_id: str, filepath: str) -> bool:
        """Delegates to MediaClient."""
        return self._media.send_media(channel_id, filepath)

    # --- Read-side queries + invite management (delegated) ---

    def search(self, channel_id: str, query: str, limit: int = 20):
        """Delegates to QueryClient."""
        self._queries.search(channel_id, query, limit)

    def create_invite(self, channel_id: str, max_uses: int = 1, expiry_hours: int = 72):
        """Delegates to InviteClient."""
        self._invites.create_invite(channel_id, max_uses, expiry_hours)

    def list_invites(self, channel_id: str | None = None):
        """Delegates to InviteClient."""
        self._invites.list_invites(channel_id)

    def get_thread(self, root_hash: str, limit: int = 50):
        """Delegates to QueryClient."""
        self._queries.get_thread(root_hash, limit)

    def get_pins(self, channel_id: str):
        """Delegates to QueryClient."""
        self._queries.get_pins(channel_id)

    def get_member_list(self, channel_id: str, limit: int = 50, offset: int = 0):
        """Delegates to QueryClient."""
        self._queries.get_member_list(channel_id, limit, offset)

    # --- LXMF message types (delegated to RichMessageClient since Step C) ---

    def send_reaction(self, channel_id: str, msg_hash: str, emoji: str) -> bool:
        return self._messages.send_reaction(channel_id, msg_hash, emoji)

    def send_edit(self, channel_id: str, msg_hash: str, new_body: str) -> bool:
        return self._messages.send_edit(channel_id, msg_hash, new_body)

    def send_delete(self, channel_id: str, msg_hash: str) -> bool:
        return self._messages.send_delete(channel_id, msg_hash)

    def send_pin(self, channel_id: str, msg_hash: str) -> bool:
        return self._messages.send_pin(channel_id, msg_hash)

    def send_thread_reply(self, channel_id: str, root_hash: str, body: str) -> bool:
        return self._messages.send_thread_reply(channel_id, root_hash, body)

    # --- Direct messaging (delegated to DmRouter) ---

    def send_dm(self, peer_identity_hash: str, body: str) -> bool:
        """Send a direct LXMF message via DmRouter."""
        return self._dm_router.send_dm(peer_identity_hash, body)

    # --- CDSP methods (delegated to CdspClient) ---

    def set_sync_profile(self, profile: int):
        """Set the sync profile for new connections."""
        self._cdsp.set_profile(profile)

    def update_sync_profile(self, new_profile: int):
        """Update profile and notify daemon for all active channel links."""
        self._cdsp.update_profile_all(new_profile)

    def send_cdsp_session_init(self, channel_id: str):
        """Send a CDSP Session Init to establish sync profile."""
        self._cdsp.init_session(channel_id)

    def send_cdsp_profile_update(self, channel_id: str, new_profile: int):
        """Send a CDSP Profile Update to change sync profile mid-session."""
        self._cdsp.update_profile(channel_id, new_profile)

    def request_media_download(self, channel_id: str, media_path: str, save_path: str = None):
        """Delegates to MediaClient."""
        self._media.request_media_download(channel_id, media_path, save_path)

    # --- Link callbacks (fire from ChannelLinkManager on RNS threads) ---

    def _on_link_established(self, channel_id: str, link: RNS.Link) -> None:
        """Invoked by ChannelLinkManager after a link is up + keepalive set.

        Runs the full post-connect chain: user callback notification,
        identify to daemon, LXMF path request, pending-invite redemption,
        CDSP init, history sync, live subscribe, node_meta fetch.
        """
        # Reset reconnect backoff and stop any pending loop — we're back.
        self._reconnect.reset_attempt()

        # Notify UI (RNS thread — handler must hop to urwid loop).
        if self._connected_callback:
            try:
                dest_hash = getattr(link.destination, "hash", None)
                self._connected_callback(channel_id, dest_hash)
            except Exception:
                logger.exception("connected_callback raised")

        # Send identity proof to the daemon (async, non-blocking).
        if self.identity:
            link.identify(self.identity)

        # Ensure LXMF delivery path is known.
        self._ensure_lxmf_path(link)

        # Check if this is a pending invite redemption.
        pending_token = self._state.pending_redeems.pop(channel_id, None)
        if pending_token:
            self.redeem_invite(channel_id, pending_token)
            return

        # CDSP session init (may race with identify — non-critical if it fails).
        self.send_cdsp_session_init(channel_id)

        # Ask for our sealed-channel key envelope. The daemon only
        # responds for channel-scoped members, so non-sealed channels
        # produce a SyncError on the daemon side which we ignore here —
        # easier than tracking sealed-or-not in TUI state at link time.
        # Successful response flows through ``_handle_sealed_key_response``.
        self.request_sealed_key(channel_id)

        # Sync history from cursor.
        cursor = self._state.cursors.get(channel_id, 0)
        self.sync_history(channel_id, since_seq=cursor)

        # Subscribe to live updates for real-time messages.
        self.subscribe_live(channel_id)

        # Request node metadata to discover all channels on this node.
        self.request_node_meta(channel_id)

    def _ensure_lxmf_path(self, link: RNS.Link):
        """Request path to the daemon's LXMF delivery destination.

        The sync link uses 'hokora/channel_id' aspects, but LXMF
        targets 'lxmf/delivery' — a different destination hash.
        We need the path in the routing table for LXMF DIRECT delivery.
        """
        try:
            dest_identity = link.destination.identity
            if not dest_identity:
                return
            lxmf_dest = RNS.Destination(
                dest_identity,
                RNS.Destination.OUT,
                RNS.Destination.SINGLE,
                "lxmf",
                "delivery",
            )
            if not RNS.Transport.has_path(lxmf_dest.hash):
                RNS.Transport.request_path(lxmf_dest.hash)
                logger.debug(
                    f"Requested path to LXMF destination {RNS.prettyhexrep(lxmf_dest.hash)}"
                )
        except Exception:
            logger.debug("Could not request LXMF path", exc_info=True)

    def _on_link_closed(self, channel_id: str, link: RNS.Link) -> None:
        """Invoked by ChannelLinkManager after a link is removed from its map.

        Integration logic: if there are still reconnect targets and the user
        didn't explicitly disconnect, kick the backoff scheduler; otherwise
        emit terminal connection_lost.
        """
        # If there are any other active links left, this was a partial drop —
        # no need to start the reconnect manager. If every link is dead, we
        # must choose between transient recovery and terminal connection_lost.
        still_any_active = self._link_manager.any_active()
        if not still_any_active:
            if self._reconnect.targets_snapshot() and not self._reconnect.is_user_disconnected():
                logger.warning(
                    "All links closed — starting reconnect loop (%d targets)",
                    len(self._reconnect.targets_snapshot()),
                )
                self._start_reconnect_loop()
            else:
                logger.warning("All links closed — connection lost")
                if self._event_callback:
                    self._event_callback("connection_lost", {})

    def _start_reconnect_loop(self) -> None:
        """Facade method kept so tests can patch it. Delegates to scheduler.

        Behavior: idempotent — triggers the scheduler's backoff thread if
        targets remain and the user didn't explicitly disconnect. Exposes a
        ``connection_recovering`` event via the event callback on each
        backoff tick.
        """
        self._reconnect.set_on_recovering(self._emit_reconnect_recovering)
        self._reconnect.trigger()

    def _emit_reconnect_recovering(self, data: dict) -> None:
        """Forward the scheduler's on_recovering hook to the
        ``connection_recovering`` event the views subscribe to."""
        if self._event_callback:
            try:
                self._event_callback("connection_recovering", data)
            except Exception:
                logger.exception("connection_recovering callback raised")

    def _on_resource_concluded(self, resource):
        """Delegates to MediaClient."""
        self._media.on_resource_concluded(resource)

    def _handle_response(self, data: dict):
        """Per-action response dispatcher.

        Dispatches each response action to the owning client's handle_*
        method. SyncEngine owns the callback registry (message_callback,
        event_callback) and passes the relevant callback through to each
        handler so the existing public API (set_message_callback etc.)
        keeps working.
        """
        action = data.get("action")

        if action == "history":
            self._history.handle_history(data, message_callback=self._message_callback)

        elif action == "node_meta":
            self._history.handle_node_meta(data, event_callback=self._event_callback)

        elif action == "invite_redeemed":
            self._invites.handle_invite_redeemed(data, event_callback=self._event_callback)

        elif action == "cdsp_session_ack":
            # CdspClient extracts session state + returns flushed_items.
            # Replay is orchestrated here because it funnels through the
            # engine's event_callback registry.
            flushed = self._cdsp.handle_session_ack(data)
            if flushed:
                logger.info(
                    "CDSP resume: replaying %d deferred live event(s)",
                    len(flushed),
                )
                for item in flushed:
                    payload = item.get("payload") or {}
                    ev = payload.get("event")
                    ev_data = payload.get("data") or {}
                    if ev and self._event_callback:
                        try:
                            self._event_callback(ev, ev_data)
                        except Exception:
                            logger.exception("Error replaying deferred event %s", ev)
            if self._event_callback:
                self._event_callback("cdsp_session_ack", data)

        elif action == "cdsp_profile_ack":
            self._cdsp.handle_profile_ack(data)
            if self._event_callback:
                self._event_callback("cdsp_profile_ack", data)

        elif action == "cdsp_session_reject":
            self._cdsp.handle_session_reject(data)
            if self._event_callback:
                self._event_callback("cdsp_session_reject", data)

        elif action in ("search", "search_results"):
            self._queries.handle_search(data, event_callback=self._event_callback)

        elif action in ("thread", "thread_messages"):
            self._queries.handle_thread(data, event_callback=self._event_callback)

        elif action in ("pins", "pinned_messages"):
            self._queries.handle_pins(data, event_callback=self._event_callback)

        elif action == "member_list":
            self._queries.handle_member_list(data, event_callback=self._event_callback)

        elif action == "invite_created":
            self._invites.handle_invite_created(data, event_callback=self._event_callback)

        elif action == "invite_list":
            self._invites.handle_invite_list(data, event_callback=self._event_callback)

        elif action == "sealed_key":
            self._handle_sealed_key_response(data)

    def _handle_sealed_key_response(self, data: dict) -> None:
        """Decrypt the daemon-served sealed-key envelope and persist.

        The envelope is encrypted with this TUI's RNS public key
        (see ``security.sealed.distribute_sealed_key_to_identity``).
        We decrypt with our RNS private key, then hand the raw symmetric
        key to the app-registered ``_on_sealed_key`` callback for
        persistence in the SealedKeyStore.
        """
        channel_id = data.get("channel_id")
        epoch = data.get("epoch")
        blob = data.get("encrypted_key_blob")
        # Daemon emits empty blob + null epoch for non-sealed channels — the
        # TUI requests for every channel on link establishment, this is the
        # quiet "no key needed here" response. Drop without warning.
        if not channel_id:
            return
        if epoch is None or not blob:
            logger.debug("sealed_key response empty for %s — channel not sealed", channel_id)
            return
        if not self.identity:
            logger.warning("sealed_key response received but no TUI identity loaded")
            return
        try:
            key = self.identity.decrypt(bytes(blob))
        except Exception:
            logger.exception("Failed to decrypt sealed-key envelope for %s", channel_id)
            return
        if not key or len(key) != 32:
            logger.warning(
                "sealed-key decrypt produced unexpected length: %s",
                len(key) if key else None,
            )
            return
        if self._on_sealed_key is not None:
            try:
                self._on_sealed_key(channel_id, key, int(epoch))
            except Exception:
                logger.exception("on_sealed_key callback raised")

    def get_cursor(self, channel_id: str) -> int:
        return self._state.cursors.get(channel_id, 0)

    def set_cursor(self, channel_id: str, seq: int):
        self._state.cursors[channel_id] = seq

    def disconnect_all(self) -> None:
        """Tear down all channel links but keep the engine alive.

        The LXMRouter and identity remain intact so the engine can be
        reused for reconnection without hitting RNS duplicate-destination
        errors.
        """
        self._link_manager.disconnect_all()
        self._state.cursors.clear()
        self._state.pending_nonces.clear()
        # Explicit teardown: suppress auto-reconnect and signal the backoff
        # loop to exit so a lingering thread doesn't race with app shutdown.
        self._reconnect.mark_user_disconnected()
        self._reconnect.clear_targets()
        self._reconnect.stop()
        logger.info("SyncEngine: all links torn down (engine still alive)")

    def get_link(self, channel_id: str) -> Optional[RNS.Link]:
        """Public accessor for channel links."""
        return self._link_manager.get_link(channel_id)
