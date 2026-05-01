# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Media transfer via RNS.Resource for chunked delivery."""

import logging
from typing import Optional, Callable

import RNS

from hokora.media.storage import MediaStorage

logger = logging.getLogger(__name__)


class MediaTransfer:
    """Handles fetch_media requests via RNS.Resource."""

    def __init__(self, storage: MediaStorage):
        self.storage = storage

    def serve_media(
        self,
        link: RNS.Link,
        relative_path: str,
        progress_callback: Optional[Callable] = None,
    ) -> bool:
        """Serve a media file to a requester via RNS.Resource."""
        data = self.storage.get(relative_path)
        if not data:
            logger.warning(f"Media not found: {relative_path}")
            return False

        RNS.Resource(data, link, callback=progress_callback)
        logger.info(f"Serving media: {relative_path} ({len(data)} bytes)")
        return True

    def request_media(
        self,
        link: RNS.Link,
        relative_path: str,
        channel_id: str = "",
        callback: Optional[Callable] = None,
    ):
        """Request a media file from a remote node via SYNC_FETCH_MEDIA.

        Sends the fetch request as a sync action. The remote node responds
        by serving the file as an RNS.Resource, which is received via the
        resource_started callback on the link.
        """
        from hokora.constants import SYNC_FETCH_MEDIA
        from hokora.protocol.wire import encode_sync_request, generate_nonce

        logger.info(f"Requesting media: {relative_path}")

        nonce = generate_nonce()
        request = encode_sync_request(
            SYNC_FETCH_MEDIA,
            nonce,
            {
                "channel_id": channel_id,
                "path": relative_path,
            },
        )

        # Register resource callback to receive the file data
        if callback:

            def _resource_started(resource):
                resource.callback = lambda r: callback(r.data.read())

            # Use ACCEPT_APP with a size filter instead of ACCEPT_ALL to prevent
            # a malicious peer from sending arbitrarily large resources
            max_size = self.storage.max_upload_bytes

            def _resource_filter(resource):
                if resource.data_size is not None and resource.data_size > max_size:
                    logger.warning(
                        f"Rejecting media resource: size {resource.data_size} > {max_size}"
                    )
                    return False
                return True

            # Two-call pattern: ``set_resource_strategy(callback=...)`` was
            # removed in current RNS — strategy and filter callback are now
            # configured separately. Mirrors ``protocol/link_manager.py:77-78``.
            link.set_resource_strategy(RNS.Link.ACCEPT_APP)
            link.set_resource_callback(_resource_filter)
            link.set_resource_started_callback(_resource_started)

        RNS.Packet(link, request).send()
        return True
