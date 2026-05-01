# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""MediaClient — media upload (LXMF-embedded) + download (SYNC_FETCH_MEDIA).

Owns:

- ``send_media`` — upload bytes via LXMF MSG_MEDIA (daemon stores them
  via MediaStorage; other users see a `[file: name]` message).
- ``request_media_download`` — issue SYNC_FETCH_MEDIA; daemon serves the
  bytes via RNS.Resource which arrives at our resource_concluded handler.
- ``on_resource_concluded`` — registered on ChannelLinkManager via
  SyncEngine; routes media (raw file bytes) to ``_save_media_download``
  and falls back to packet handler (large sync responses) otherwise.
- ``_save_media_download`` — writes to disk, fires ``media_downloaded``
  event through the SyncEngine event_callback.

State (``state.pending_media_path`` / ``state.pending_media_save_path``)
disambiguates media vs sync-response branches in on_resource_concluded.

Uses ``link_manager.resolve_channel_identity`` for LXMF destination
construction; uses ``dm_router.lxm_router`` + ``lxmf_source`` for
outbound.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Optional

import LXMF
import msgpack
import RNS

from hokora.constants import MSG_MEDIA, SYNC_FETCH_MEDIA
from hokora.protocol.wire import encode_sync_request, generate_nonce

if TYPE_CHECKING:
    from hokora_tui.sync.dm_router import DmRouter
    from hokora_tui.sync.link_manager import ChannelLinkManager
    from hokora_tui.sync.state import SyncState

logger = logging.getLogger(__name__)


class MediaClient:
    """Media upload + download subsystem."""

    def __init__(
        self,
        link_manager: "ChannelLinkManager",
        dm_router: "DmRouter",
        state: "SyncState",
        identity: Optional[RNS.Identity],
        packet_dispatcher: Callable[[bytes, Optional[object]], None],
        event_callback_getter: Callable[[], Optional[Callable]],
    ) -> None:
        self._link_manager = link_manager
        self._dm_router = dm_router
        self._state = state
        self.identity = identity
        # Called when a resource turns out to be a sync response (msgpack)
        # instead of media bytes. Bound to HistoryClient._on_packet.
        self._dispatch_packet = packet_dispatcher
        self._event_cb = event_callback_getter

    # ── Public API ────────────────────────────────────────────────────

    def send_media(self, channel_id: str, filepath: str) -> bool:
        """Send a media file to a channel.

        File bytes are embedded in the LXMF MSG_MEDIA content; LXMF
        handles chunked delivery via RNS.Resource internally for large
        content.
        """
        link = self._link_manager.get_link(channel_id)
        if not link or link.status != RNS.Link.ACTIVE:
            logger.warning("No active link for channel %s, cannot send media", channel_id)
            return False
        if not self._dm_router.lxm_router or not self.identity:
            logger.error("No LXMRouter or identity — cannot send media")
            return False

        try:
            file_path = Path(filepath)
            if not file_path.exists():
                logger.error("File not found: %s", filepath)
                return False

            file_data = file_path.read_bytes()
            filename = file_path.name

            content = msgpack.packb(
                {
                    "type": MSG_MEDIA,
                    "body": f"[file: {filename}]",
                    "media_path": filename,
                    "media_bytes": file_data,
                    "media_meta": {
                        "filename": filename,
                        "size": len(file_data),
                    },
                    "channel_id": channel_id,
                    "display_name": self._state.display_name,
                },
                use_bin_type=True,
            )

            dest_identity = self._link_manager.resolve_channel_identity(channel_id, link)
            if not dest_identity:
                logger.warning("No identity for channel %s", channel_id)
                return False

            destination = RNS.Destination(
                dest_identity,
                RNS.Destination.OUT,
                RNS.Destination.SINGLE,
                "lxmf",
                "delivery",
            )
            if not RNS.Transport.has_path(destination.hash):
                RNS.Transport.request_path(destination.hash)

            lxm = LXMF.LXMessage(
                destination,
                self._dm_router.lxmf_source,
                content,
                desired_method=LXMF.LXMessage.DIRECT,
            )
            lxm.try_propagation_on_fail = True
            self._dm_router.lxm_router.handle_outbound(lxm)
            logger.info("Sent media %s to channel %s", filename, channel_id)
            return True
        except Exception:
            logger.exception("Media send failed")
            return False

    def request_media_download(
        self,
        channel_id: str,
        media_path: str,
        save_path: Optional[str] = None,
    ) -> None:
        """Request a media file from the daemon via SYNC_FETCH_MEDIA.

        Records ``state.pending_media_path`` so the next inbound resource
        is routed to ``_save_media_download`` instead of the packet
        dispatcher.
        """
        link = self._link_manager.get_link(channel_id)
        if not link or link.status != RNS.Link.ACTIVE:
            logger.warning("No active link for channel %s", channel_id)
            return
        self._state.cleanup_stale_nonces()
        nonce = generate_nonce()
        self._state.pending_nonces[nonce] = time.time()
        request = encode_sync_request(
            SYNC_FETCH_MEDIA,
            nonce,
            {"channel_id": channel_id, "path": media_path},
        )
        self._state.pending_media_path = media_path
        self._state.pending_media_save_path = save_path
        RNS.Packet(link, request).send()
        logger.info("Requested media download: %s", media_path)

    def on_resource_concluded(self, resource) -> None:
        """Handle a completed resource transfer.

        Routes:
        - raw file bytes (no msgpack header) when ``pending_media_path``
          is set → ``_save_media_download``
        - everything else → ``packet_dispatcher`` (large sync response).
        """
        try:
            if resource.status != RNS.Resource.COMPLETE:
                logger.warning("Resource transfer failed with status %s", resource.status)
                return

            data = resource.data
            if hasattr(data, "read"):
                data = data.read()
            if not isinstance(data, bytes):
                logger.warning("Resource data is unexpected type: %s", type(data))
                return

            if self._state.pending_media_path:
                if not self._is_msgpack_payload(data):
                    self._save_media_download(
                        data,
                        self._state.pending_media_path,
                        save_path=self._state.pending_media_save_path,
                    )
                    self._state.pending_media_path = None
                    self._state.pending_media_save_path = None
                    return

            self._dispatch_packet(data, None)
        except Exception:
            logger.exception("Error handling resource")

    # ── Internal ──────────────────────────────────────────────────────

    @staticmethod
    def _is_msgpack_payload(data: bytes) -> bool:
        """Heuristic — msgpack maps start with 0x80-0x8F or 0xDE/0xDF."""
        return len(data) > 0 and ((0x80 <= data[0] <= 0x8F) or data[0] in (0xDE, 0xDF))

    def _save_media_download(
        self,
        data: bytes,
        media_path: str,
        save_path: Optional[str] = None,
    ) -> None:
        """Save downloaded media file to disk and fire media_downloaded event."""
        try:
            filename = Path(media_path).name
            if save_path:
                dest = Path(save_path)
                if dest.is_dir():
                    dest = dest / filename
                dest.parent.mkdir(parents=True, exist_ok=True)
            else:
                download_dir = Path.home() / ".hokora-client" / "downloads"
                download_dir.mkdir(parents=True, exist_ok=True)
                dest = download_dir / filename
            dest.write_bytes(data)
            logger.info("Media saved: %s (%d bytes)", dest, len(data))
            cb = self._event_cb()
            if cb:
                cb(
                    "media_downloaded",
                    {
                        "path": str(dest),
                        "size": len(data),
                        "filename": filename,
                    },
                )
        except Exception:
            logger.exception("Failed to save media download")
