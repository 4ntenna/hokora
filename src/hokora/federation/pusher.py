# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Federation pusher: push local messages to remote peers."""

import logging
import random
import time
from typing import Callable, Optional

import RNS

from hokora.constants import SYNC_PUSH_MESSAGES
from hokora.protocol.wire import encode_sync_request, generate_nonce

logger = logging.getLogger(__name__)

# Max messages per push batch (avoid 65KB frame limit)
PUSH_BATCH_SIZE = 15


class FederationPusher:
    """Pushes local messages to a federated peer."""

    def __init__(
        self,
        peer_identity_hash: str,
        channel_id: str,
        node_identity_hash: str,
        link: Optional[RNS.Link] = None,
        session_factory=None,
        cursor_callback: Optional[Callable] = None,
        max_backoff: float = 600.0,
    ):
        self.peer_identity_hash = peer_identity_hash
        self.channel_id = channel_id
        self.node_identity_hash = node_identity_hash
        self._link = link
        self._session_factory = session_factory
        self._push_cursor: int = 0
        self._epoch_manager = None  # Set by daemon for forward secrecy
        self._cursor_callback = cursor_callback

        # Backoff state for retry logic
        self._consecutive_failures: int = 0
        self._last_attempt: float = 0.0
        self._backoff_base: float = 30.0
        self._max_backoff: float = max_backoff

    @property
    def push_cursor(self) -> int:
        return self._push_cursor

    @push_cursor.setter
    def push_cursor(self, value: int):
        self._push_cursor = value

    def set_link(self, link: RNS.Link):
        self._link = link

    def _should_retry(self) -> bool:
        """Check if enough time has elapsed since last failure for a retry."""
        if self._consecutive_failures == 0:
            return True
        delay = min(
            self._backoff_base * (2 ** (self._consecutive_failures - 1)),
            self._max_backoff,
        )
        # Add ±25% jitter
        delay *= 0.75 + random.random() * 0.5
        elapsed = time.monotonic() - self._last_attempt
        return elapsed >= delay

    async def push_pending(self) -> bool:
        """Query and push local messages with seq > push_cursor.

        Returns True if successful or nothing to push, False on failure.
        """
        if not self._link or not self._session_factory:
            self._consecutive_failures += 1
            self._last_attempt = time.monotonic()
            return False

        from hokora.db.queries import MessageRepo
        from hokora.protocol.wire import encode_message_for_sync
        from hokora.security.ban import is_blocked

        try:
            async with self._session_factory() as session:
                async with session.begin():
                    repo = MessageRepo(session)
                    messages = await repo.get_history(
                        self.channel_id,
                        since_seq=self._push_cursor,
                        limit=PUSH_BATCH_SIZE,
                    )

                    # Filter out messages that originated from the target peer
                    # (loop prevention) and messages whose sender is banned
                    # locally — banning is a node-local decision and we do
                    # not propagate banned-author content outbound.
                    to_push = []
                    max_seq = self._push_cursor
                    for msg in messages:
                        if msg.seq > max_seq:
                            max_seq = msg.seq
                        if msg.origin_node == self.peer_identity_hash:
                            continue
                        if msg.sender_hash and await is_blocked(session, msg.sender_hash):
                            continue
                        to_push.append(msg)

                    if not to_push:
                        # Advance cursor past filtered messages (stale cursor handling)
                        if messages and max_seq > self._push_cursor:
                            self._push_cursor = max_seq
                            if self._cursor_callback:
                                self._cursor_callback(
                                    self.peer_identity_hash, self.channel_id, max_seq
                                )
                        self._consecutive_failures = 0
                        return True

                    encoded = [encode_message_for_sync(m) for m in to_push]

                    # Attach the authoring identity's full RNS pubkey
                    # (X25519||Ed25519) so the receiver can structurally bind
                    # sender_hash to its pubkey via truncated_hash equality —
                    # no TOFU, no path-cache fallback. Recall hits whenever
                    # this daemon has seen the author's announce; on a miss
                    # we leave both fields None and the receiver rejects when
                    # ``require_signed_federation`` is True (default). Same
                    # mechanism as security.sealed.load_peer_rns_identity.
                    for d in encoded:
                        d["origin_node"] = self.node_identity_hash
                        sh = d.get("sender_hash")
                        if not sh:
                            continue
                        try:
                            ident = RNS.Identity.recall(bytes.fromhex(sh), from_identity_hash=True)
                        except (ValueError, TypeError):
                            ident = None
                        if ident is None:
                            continue
                        rns_pk = ident.get_public_key()
                        if rns_pk and len(rns_pk) == 64:
                            d["sender_rns_public_key"] = bytes(rns_pk)
                            d["sender_public_key"] = bytes(rns_pk)[32:]

                    nonce = generate_nonce()
                    request = encode_sync_request(
                        SYNC_PUSH_MESSAGES,
                        nonce,
                        {
                            "channel_id": self.channel_id,
                            "messages": encoded,
                            "node_identity": self.node_identity_hash,
                        },
                    )

                    # Encrypt with forward secrecy if active
                    if self._epoch_manager and self._epoch_manager.is_active:
                        request = self._epoch_manager.encrypt(request)

                    RNS.Packet(self._link, request).send()
                    logger.info(
                        f"Pushed {len(encoded)} messages to {self.peer_identity_hash[:16]} "
                        f"for channel {self.channel_id}"
                    )
                    self._consecutive_failures = 0
                    return True
        except Exception:
            logger.exception("Failed to push messages")
            self._consecutive_failures += 1
            self._last_attempt = time.monotonic()
            return False

    def handle_push_ack(self, data: dict):
        """Handle push acknowledgment from the remote peer."""
        received = data.get("received", [])
        if received:
            max_seq = max(received)
            if max_seq > self._push_cursor:
                self._push_cursor = max_seq
                logger.info(
                    f"Push cursor for {self.peer_identity_hash[:16]}/"
                    f"{self.channel_id} advanced to {self._push_cursor}"
                )
                if self._cursor_callback:
                    self._cursor_callback(self.peer_identity_hash, self.channel_id, max_seq)
