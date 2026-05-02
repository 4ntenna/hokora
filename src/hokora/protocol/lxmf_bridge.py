# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""LXMF reception -> signature verify -> MessageProcessor pipeline.

Creates one LXMRouter per channel so every channel receives direct
LXMF store-and-forward delivery (the LXMF library limits each router
to a single delivery identity).
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Optional

import LXMF
import RNS

from hokora.constants import MSG_TEXT
from hokora.core.message import MessageEnvelope
from hokora.security.lxmf_inbound import (
    reconstruct_lxmf_signed_part,
    verify_lxmf_inbound,
)

if TYPE_CHECKING:
    from hokora.config import NodeConfig

logger = logging.getLogger(__name__)


class LXMFBridge:
    """Bridges LXMF reception to the message-processing pipeline.

    Owns one LXMRouter per channel (the LXMF library caps each router to
    a single delivery identity). Inbound messages run through
    ``security.lxmf_inbound.verify_lxmf_inbound`` before envelope
    construction so an attacker-claimed ``source_hash`` cannot bypass
    the role/permission gates downstream.
    """

    def __init__(
        self,
        base_storagepath: str,
        ingest_callback: Optional[Callable[[MessageEnvelope], Awaitable[None]]] = None,
        node_lxm_router: Optional[LXMF.LXMRouter] = None,
        loop: Optional[asyncio.AbstractEventLoop] = None,
        config: Optional["NodeConfig"] = None,
    ):
        self._base_storagepath = base_storagepath
        self.ingest_callback = ingest_callback
        self._node_lxm_router = node_lxm_router
        self._loop = loop
        self._config = config
        self._routers: dict[str, LXMF.LXMRouter] = {}
        self._registered_destinations: dict[str, Any] = {}

    def register_channel(
        self, channel_id: str, identity: RNS.Identity, destination: RNS.Destination
    ):
        """Register a channel for LXMF delivery with its own LXMRouter."""
        if channel_id in self._routers:
            logger.debug(f"Channel {channel_id} already registered with LXMF")
            return

        channel_storage = os.path.join(self._base_storagepath, channel_id)
        os.makedirs(channel_storage, exist_ok=True)

        router = LXMF.LXMRouter(identity=identity, storagepath=channel_storage)
        router.register_delivery_identity(identity, display_name=channel_id)
        router.register_delivery_callback(self._on_lxmf_delivery)

        self._routers[channel_id] = router
        self._registered_destinations[channel_id] = {
            "identity": identity,
            "destination": destination,
        }

        logger.info(f"Registered LXMF delivery for channel {channel_id}")

    def get_router(self, channel_id: str) -> Optional[LXMF.LXMRouter]:
        """Get the LXMRouter for a specific channel (for outbound LXMF)."""
        return self._routers.get(channel_id)

    def get_any_router(self) -> Optional[LXMF.LXMRouter]:
        """Get any available router for node-level LXMF operations.

        Prefers the node-level router if available, otherwise returns the
        first channel router. Used for non-channel-specific outbound like
        key exchange.
        """
        if self._node_lxm_router:
            return self._node_lxm_router
        if self._routers:
            return next(iter(self._routers.values()))
        return None

    def _on_lxmf_delivery(self, message: LXMF.LXMessage) -> None:
        """RNS-thread entry: hop onto the asyncio loop for verify+dispatch.

        Production always supplies a loop. The fallback covers tests that
        drive the bridge directly: when a running loop is already present
        (pytest-asyncio), schedule onto it; otherwise spin a one-shot
        ``asyncio.run`` to drive the coroutine to completion.
        """
        if self._loop is not None:
            future = asyncio.run_coroutine_threadsafe(
                self._validate_and_dispatch(message), self._loop
            )
            future.add_done_callback(self._log_dispatch_error)
            return

        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None

        if running is not None:
            task = running.create_task(self._validate_and_dispatch(message))
            task.add_done_callback(self._log_dispatch_error)
            return

        try:
            asyncio.run(self._validate_and_dispatch(message))
        except Exception:
            logger.exception("Error processing LXMF message")

    @staticmethod
    def _log_dispatch_error(future: Any) -> None:
        try:
            future.result()
        except Exception:
            logger.exception("LXMF dispatch failed")

    async def _validate_and_dispatch(self, message: LXMF.LXMessage) -> None:
        """On-loop verify + envelope build + ingest dispatch."""
        require_signed = bool(getattr(self._config, "require_signed_lxmf", True))
        path_wait = float(getattr(self._config, "lxmf_path_wait_seconds", 5.0))

        ok, reason, identity = await verify_lxmf_inbound(
            message,
            require_signed=require_signed,
            path_wait_seconds=path_wait,
        )
        if not ok:
            src = getattr(message, "source_hash", b"")
            src_hex = RNS.hexrep(src, delimit=False) if isinstance(src, (bytes, bytearray)) else "?"
            logger.warning(f"LXMF inbound rejected ({reason}) from {src_hex}")
            return

        sender_public_key: Optional[bytes] = None
        if identity is not None:
            pk = getattr(identity, "sig_pub_bytes", None)
            if pk is None:
                full = identity.get_public_key()
                pk = full[32:] if full and len(full) == 64 else None
            if isinstance(pk, (bytes, bytearray)) and len(pk) == 32:
                sender_public_key = bytes(pk)
            else:
                logger.warning("Recovered identity yielded no usable Ed25519 key")

        lxmf_signed_part = reconstruct_lxmf_signed_part(message)

        channel_id = self._find_channel_for_destination(message.destination_hash)
        content = self._decode_content(message)

        if not channel_id:
            content_channel = content.get("channel_id")
            if content_channel and content_channel in self._routers:
                channel_id = content_channel
                logger.info(f"Matched channel from content: {channel_id}")
            else:
                logger.warning(f"No channel for destination {message.destination_hash}")
                return

        if identity is not None and hasattr(identity, "hexhash"):
            sender_hash = identity.hexhash
        elif message.source and getattr(message.source, "identity", None):
            sender_hash = message.source.identity.hexhash
        else:
            sender_hash = RNS.hexrep(message.source_hash, delimit=False)

        envelope = MessageEnvelope(
            channel_id=channel_id,
            sender_hash=sender_hash,
            timestamp=message.timestamp if hasattr(message, "timestamp") else time.time(),
            type=content.get("type", MSG_TEXT),
            body=content.get("body"),
            media_path=content.get("media_path"),
            media_bytes=content.get("media_bytes"),
            reply_to=content.get("reply_to"),
            ttl=content.get("ttl"),
            lxmf_signature=message.signature if hasattr(message, "signature") else None,
            lxmf_signed_part=lxmf_signed_part,
            sender_public_key=sender_public_key,
            display_name=content.get("display_name"),
            mentions=content.get("mentions", []),
        )

        if self.ingest_callback is None:
            return

        result = self.ingest_callback(envelope)
        if asyncio.iscoroutine(result):
            await result

    def _find_channel_for_destination(self, dest_hash) -> Optional[str]:
        """Find which channel a destination hash belongs to."""
        for channel_id, info in self._registered_destinations.items():
            dest = info["destination"]
            if dest.hash == dest_hash:
                return channel_id
        return None

    def _decode_content(self, message: LXMF.LXMessage) -> dict:
        """Decode LXMF message content."""
        import msgpack

        content_bytes = message.content
        if not content_bytes:
            return {"body": "", "type": MSG_TEXT}

        try:
            return msgpack.unpackb(content_bytes, raw=False)
        except Exception:
            try:
                text = content_bytes.decode("utf-8")
                return {"body": text, "type": MSG_TEXT}
            except UnicodeDecodeError:
                return {"body": "", "type": MSG_TEXT}
