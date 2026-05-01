# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""LxmfMessageIngestor: LXMF → MessageProcessor pipeline."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Awaitable, Callable, Optional

from hokora.core.message import MessageEnvelope

if TYPE_CHECKING:
    from hokora.core.message import MessageProcessor
    from hokora.media.storage import MediaStorage
    from hokora.protocol.live import LiveSubscriptionManager
    from hokora.security.sealed import SealedChannelManager

logger = logging.getLogger(__name__)


class LxmfMessageIngestor:
    """Bridge LXMF delivery callbacks into the async ingestion pipeline.

    ``on_lxmf_delivery`` is the RNS-thread entry point wired into
    LXMFBridge; it marshals into the daemon's event loop via
    ``run_coroutine_threadsafe``. ``ingest`` does the work: extract
    embedded media bytes, dispatch to MessageProcessor, push to live
    subscribers (with EDIT/DELETE/REACTION/PIN mapped to
    ``message_updated``), trigger federation push.
    """

    def __init__(
        self,
        loop: asyncio.AbstractEventLoop,
        session_factory,
        message_processor: "MessageProcessor",
        live_manager: Optional["LiveSubscriptionManager"],
        media_storage: Optional["MediaStorage"],
        federation_trigger: Callable[[str], Awaitable[None]],
        sealed_manager: Optional["SealedChannelManager"] = None,
    ) -> None:
        self._loop = loop
        self._session_factory = session_factory
        self._message_processor = message_processor
        self._live_manager = live_manager
        self._media_storage = media_storage
        self._federation_trigger = federation_trigger
        # Needed for server-side decrypt of sealed rows before emitting
        # ``message_updated`` events (edits/deletes/pins/reactions). The
        # at-rest row has ``body=None`` for sealed channels; subscribers
        # receive plaintext on their already-authenticated Link. Injected
        # rather than pulled off ``live_manager`` so the dependency is
        # explicit and testable.
        self._sealed_manager = sealed_manager

    def on_lxmf_delivery(self, envelope: MessageEnvelope) -> None:
        """RNS-thread entry; schedules ingest() on the event loop."""
        future = asyncio.run_coroutine_threadsafe(self.ingest(envelope), self._loop)
        future.add_done_callback(self._log_ingest_error)

    @staticmethod
    def _log_ingest_error(future) -> None:
        try:
            future.result()
        except Exception:
            logger.exception("LXMF message ingestion failed")

    async def ingest(self, envelope: MessageEnvelope) -> None:
        """Store embedded media (if any), dispatch, push to live, federate."""
        if envelope.media_path and envelope.media_bytes and self._media_storage:
            try:
                ext = Path(envelope.media_path).suffix.lstrip(".") or "bin"
                fname = Path(envelope.media_path).stem
                stored = self._media_storage.store(
                    channel_id=envelope.channel_id,
                    msg_hash=fname,
                    data=envelope.media_bytes,
                    extension=ext,
                )
                envelope.media_path = stored
                envelope.media_bytes = None
                logger.info(f"Stored uploaded media as {stored}")
            except Exception:
                logger.exception("Failed to store uploaded media")

        async with self._session_factory() as session:
            async with session.begin():
                message = await self._message_processor.ingest(session, envelope)

                if self._live_manager:
                    from hokora.constants import (
                        MSG_DELETE,
                        MSG_EDIT,
                        MSG_PIN,
                        MSG_REACTION,
                    )

                    if envelope.type in (MSG_EDIT, MSG_DELETE, MSG_REACTION, MSG_PIN):
                        target_hash = envelope.reply_to
                        if target_hash:
                            from hokora.db.queries import MessageRepo
                            from hokora.protocol.sync_utils import (
                                encode_message_for_wire,
                            )

                            original = await MessageRepo(session).get_by_hash(target_hash)
                            if original:
                                # Sealed-aware encoding: the at-rest row has
                                # body=None for sealed channels, so we must
                                # decrypt server-side before emitting the
                                # message_updated event. Subscribers are
                                # already authenticated channel members via
                                # the subscribe-live membership gate.
                                self._live_manager.push_event(
                                    envelope.channel_id,
                                    "message_updated",
                                    encode_message_for_wire(
                                        original, sealed_manager=self._sealed_manager
                                    ),
                                )
                    else:
                        # ``push_message`` decrypts sealed rows internally
                        # via its own sealed_manager reference. No local
                        # temp-restore hack needed — the at-rest row stays
                        # clean (body=None for sealed channels), and the
                        # subscriber gets plaintext on the wire.
                        self._live_manager.push_message(
                            envelope.channel_id,
                            message,
                            sender_public_key=envelope.sender_public_key,
                        )

                await self._federation_trigger(envelope.channel_id)
