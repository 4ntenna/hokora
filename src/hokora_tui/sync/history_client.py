# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""HistoryClient — history sync, live subscribe, and packet dispatch.

Owns:

- ``_on_packet`` — the RNS packet callback registered on every link via
  ``ChannelLinkManager.set_on_packet``. Parses incoming packets into
  either push events (event_callback) or sync responses (routed back to
  the SyncEngine-provided response_dispatcher for per-action dispatch).
- Sync request senders: ``sync_history``, ``subscribe_live``,
  ``unsubscribe``, ``request_node_meta``.
- Cursor + sequence-integrity + identity-key-cache side of history
  response processing.

Why the response_dispatcher is passed in rather than hardcoded: the
SyncEngine facade owns per-action routing (tests call
``engine._handle_response(...)`` directly). HistoryClient invokes the
dispatcher with the parsed response payload; the facade fans out to the
owning client's ``handle_*`` method. Inversion of control without a
circular import.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Callable, Optional

import msgpack
import RNS

from hokora.constants import (
    SYNC_HISTORY,
    SYNC_NODE_META,
    SYNC_REQUEST_SEALED_KEY,
    SYNC_SUBSCRIBE_LIVE,
    SYNC_UNSUBSCRIBE,
)
from hokora.exceptions import SyncError as WireSyncError
from hokora.protocol.wire import (
    _strip_length_header,
    encode_sync_request,
    generate_nonce,
)
from hokora.security.verification import VerificationService
from hokora_tui.sync._verify import verify_message_signature

if TYPE_CHECKING:
    from hokora_tui.sync.link_manager import ChannelLinkManager
    from hokora_tui.sync.state import SyncState

logger = logging.getLogger(__name__)


class HistoryClient:
    """History sync + live subscribe + packet parsing dispatcher."""

    def __init__(
        self,
        link_manager: "ChannelLinkManager",
        state: "SyncState",
        verifier: VerificationService,
        response_dispatcher: Callable[[dict], None],
        event_callback_getter: Callable[[], Optional[Callable]],
    ) -> None:
        self._link_manager = link_manager
        self._state = state
        self._verifier = verifier
        # Called with the parsed response ``data`` dict for non-push payloads.
        # Bound to ``SyncEngine._handle_response`` so facade owns routing.
        self._dispatch = response_dispatcher
        # Callable that returns the currently-registered event_callback on
        # SyncEngine. Called lazily so late-set callbacks are honored.
        self._event_cb = event_callback_getter

    # ── Sync requests ─────────────────────────────────────────────────

    def sync_history(self, channel_id: str, since_seq: int = 0, limit: int = 50) -> None:
        """Request message history for a channel."""
        link = self._link_manager.get_link(channel_id)
        if not link or link.status != RNS.Link.ACTIVE:
            logger.warning("No active link for channel %s", channel_id)
            return
        self._state.cleanup_stale_nonces()
        nonce = generate_nonce()
        self._state.pending_nonces[nonce] = time.time()
        request = encode_sync_request(
            SYNC_HISTORY,
            nonce,
            {
                "channel_id": channel_id,
                "since_seq": since_seq,
                "limit": limit,
                # This TUI persists ciphertext at rest and decrypts at
                # render-time. Daemon emits ciphertext fields for
                # sealed-channel rows when this flag is set.
                "supports_sealed_at_rest": True,
            },
        )
        RNS.Packet(link, request).send()

    def request_node_meta(self, channel_id: str) -> None:
        """Request node metadata via a channel link."""
        link = self._link_manager.get_link(channel_id)
        if not link or link.status != RNS.Link.ACTIVE:
            return
        nonce = generate_nonce()
        self._state.pending_nonces[nonce] = time.time()
        request = encode_sync_request(SYNC_NODE_META, nonce)
        RNS.Packet(link, request).send()

    def subscribe_live(self, channel_id: str) -> None:
        """Subscribe to live updates for a channel."""
        link = self._link_manager.get_link(channel_id)
        if not link or link.status != RNS.Link.ACTIVE:
            return
        nonce = generate_nonce()
        self._state.pending_nonces[nonce] = time.time()
        request = encode_sync_request(
            SYNC_SUBSCRIBE_LIVE,
            nonce,
            {
                "channel_id": channel_id,
                # Receive ciphertext on the wire for sealed channels;
                # decrypt on render via SealedKeyStore.
                "supports_sealed_at_rest": True,
            },
        )
        RNS.Packet(link, request).send()

    def request_sealed_key(self, channel_id: str) -> None:
        """Ask the daemon for our sealed-channel key envelope.

        The daemon serves an envelope-encrypted blob (encrypted with our
        RNS public key); the response handler decrypts it with our
        identity's private key and persists into the sealed_keys store.
        """
        link = self._link_manager.get_link(channel_id)
        if not link or link.status != RNS.Link.ACTIVE:
            return
        nonce = generate_nonce()
        self._state.pending_nonces[nonce] = time.time()
        request = encode_sync_request(
            SYNC_REQUEST_SEALED_KEY,
            nonce,
            {"channel_id": channel_id},
        )
        RNS.Packet(link, request).send()

    def unsubscribe(self, channel_id: Optional[str] = None) -> None:
        """Send SYNC_UNSUBSCRIBE. If channel_id is None, unsub from all."""
        if channel_id:
            link = self._link_manager.get_link(channel_id)
        else:
            link = self._link_manager.find_active_link()
        if not link or link.status != RNS.Link.ACTIVE:
            logger.warning("No active link for unsubscribe")
            return
        nonce = generate_nonce()
        self._state.pending_nonces[nonce] = time.time()
        payload = {"channel_id": channel_id} if channel_id else None
        request = encode_sync_request(SYNC_UNSUBSCRIBE, nonce, payload)
        RNS.Packet(link, request).send()

    # ── Cursor + warnings + identity-key cache ────────────────────────

    def get_cursor(self, channel_id: str) -> int:
        return self._state.cursors.get(channel_id, 0)

    def set_cursor(self, channel_id: str, seq: int) -> None:
        self._state.cursors[channel_id] = seq

    def get_seq_warnings(self, channel_id: str) -> list[str]:
        return self._state.seq_warnings.get(channel_id, [])

    def cache_identity_key(self, identity_hash: str, public_key_bytes: bytes) -> None:
        self._state.identity_keys[identity_hash] = public_key_bytes

    # ── Response handlers ────────────────────────────────────────────

    def handle_history(self, data: dict, message_callback: Optional[Callable]) -> None:
        """Verify signatures, check sequence integrity, update cursor, fire
        the message_callback."""
        channel_id = data.get("channel_id")
        if not channel_id:
            return
        messages = data.get("messages", [])

        # Verify signatures [MANDATORY] — single chokepoint shared with the
        # live-event path (commands.event_dispatcher). Three-state return:
        # True / False / None (no opinion when sig material is missing).
        # Persist absent-as-False here for the legacy history wire shape;
        # the live path treats None as "no opinion" and lets the storage
        # default apply.
        for msg in messages:
            verified = verify_message_signature(msg, self._state.identity_keys)
            msg["verified"] = bool(verified)

        # Sequence integrity check [MANDATORY]
        current_cursor = self._state.cursors.get(channel_id, 0)
        if messages:
            sorted_msgs = sorted(messages, key=lambda m: m.get("seq", 0))
            for msg in sorted_msgs:
                seq = msg.get("seq", 0)
                if seq and current_cursor > 0:
                    ok, warning = VerificationService.check_sequence_integrity(current_cursor, seq)
                    if warning:
                        if channel_id not in self._state.seq_warnings:
                            self._state.seq_warnings[channel_id] = []
                        self._state.seq_warnings[channel_id].append(warning)
                if seq and seq > current_cursor:
                    current_cursor = seq

        # Update cursor
        if messages:
            max_seq = max(m.get("seq", 0) for m in messages)
            self._state.cursors[channel_id] = max(self._state.cursors.get(channel_id, 0), max_seq)

        if message_callback and channel_id:
            latest_seq = self._state.cursors.get(channel_id, 0)
            message_callback(channel_id, messages, latest_seq)

    def handle_node_meta(self, data: dict, event_callback: Optional[Callable]) -> None:
        """Pre-request LXMF paths for discovered channels + fire event_callback."""
        for ch in data.get("channels", []):
            ch_id = ch.get("id")
            lxmf_dh = ch.get("lxmf_destination_hash")
            dest_dh = ch.get("destination_hash")
            if ch_id and dest_dh:
                self._state.channel_dest_hashes[ch_id] = bytes.fromhex(dest_dh)
            if lxmf_dh:
                try:
                    lxmf_bytes = bytes.fromhex(lxmf_dh)
                    if not RNS.Transport.has_path(lxmf_bytes):
                        RNS.Transport.request_path(lxmf_bytes)
                except Exception:
                    logger.debug("LXMF path request failed for node_meta", exc_info=True)
        if event_callback:
            event_callback("node_meta", data)

    # ── Internal — RNS packet entry ───────────────────────────────────

    def _on_packet(self, message: bytes, packet) -> None:
        """Handle incoming response or push event.

        Registered on every link by SyncEngine via
        ``ChannelLinkManager.set_on_packet(history._on_packet)``.
        """
        try:
            # Strip 2-byte length header if present
            try:
                message = _strip_length_header(message)
            except WireSyncError:
                pass  # no valid length header — try raw msgpack

            data = msgpack.unpackb(message, raw=False)

            # Push event path
            if "event" in data:
                cb = self._event_cb()
                if cb:
                    cb(data["event"], data.get("data", {}))
                return

            # Sync response — verify nonce matches one we sent
            nonce = data.get("nonce")
            if nonce and nonce in self._state.pending_nonces:
                del self._state.pending_nonces[nonce]

                # Verify node time
                node_time = data.get("node_time")
                if node_time:
                    try:
                        self._verifier.verify_node_time(node_time)
                    except Exception as e:
                        logger.warning("Node time verification: %s", e)

                response_data = data.get("data", {})
                self._dispatch(response_data)
            else:
                logger.warning("Response with unknown nonce, discarding")

        except Exception:
            logger.exception("Error handling packet")
