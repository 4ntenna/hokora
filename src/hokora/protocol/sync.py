# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Sync handler: thin router dispatching sync actions to grouped handlers."""

import asyncio
import logging
import time
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from hokora.constants import (
    SYNC_HISTORY,
    SYNC_NODE_META,
    SYNC_GET_PINS,
    SYNC_SEARCH,
    SYNC_THREAD,
    SYNC_SUBSCRIBE_LIVE,
    SYNC_UNSUBSCRIBE,
    SYNC_GET_MEMBER_LIST,
    SYNC_FETCH_MEDIA,
    SYNC_REDEEM_INVITE,
    SYNC_FEDERATION_HANDSHAKE,
    SYNC_PUSH_MESSAGES,
    SYNC_REQUEST_SEALED_KEY,
    SYNC_CDSP_SESSION_INIT,
    SYNC_CDSP_PROFILE_UPDATE,
    SYNC_CREATE_INVITE,
    SYNC_LIST_INVITES,
    SYNC_LIST_SEEDS,
)
from hokora.core.channel import ChannelManager
from hokora.core.sequencer import SequenceManager
from hokora.db.fts import FTSManager
from hokora.exceptions import SyncError
from hokora.security.invites import InviteManager
from hokora.protocol.sync_utils import SyncContext
from hokora.protocol.handlers.history import handle_history, handle_search
from hokora.protocol.handlers.metadata import (
    handle_node_meta,
    handle_get_pins,
    handle_thread,
    handle_member_list,
)
from hokora.protocol.handlers.live import (
    handle_subscribe_live,
    handle_unsubscribe,
    handle_fetch_media,
)
from hokora.protocol.handlers.federation import (
    handle_federation_handshake,
    handle_push_messages,
)
from hokora.protocol.handlers.session import (
    handle_redeem_invite,
    handle_request_sealed_key,
    handle_cdsp_session_init,
    handle_cdsp_profile_update,
    handle_create_invite,
    handle_list_invites,
)
from hokora.protocol.handlers.transport import handle_list_seeds

logger = logging.getLogger(__name__)


class SyncHandler:
    """Thin router dispatching sync actions to grouped handler modules."""

    def __init__(
        self,
        channel_manager: ChannelManager,
        sequencer: SequenceManager,
        fts_manager: Optional[FTSManager] = None,
        node_name: str = "",
        node_description: str = "",
        node_identity: str = "",
        live_manager=None,
        media_transfer=None,
        permission_resolver=None,
        invite_manager: Optional[InviteManager] = None,
        federation_auth=None,
        sealed_manager=None,
        config=None,
        node_rns_identity=None,
        rate_limiter=None,
        cdsp_manager=None,
    ):
        self.invite_manager = invite_manager or InviteManager()

        # Shared context for all handler modules
        self._ctx = SyncContext(
            channel_manager=channel_manager,
            sequencer=sequencer,
            fts_manager=fts_manager,
            node_name=node_name,
            node_description=node_description,
            node_identity=node_identity,
            live_manager=live_manager,
            media_transfer=media_transfer,
            permission_resolver=permission_resolver,
            invite_manager=self.invite_manager,
            federation_auth=federation_auth,
            sealed_manager=sealed_manager,
            config=config,
            node_rns_identity=node_rns_identity,
            rate_limiter=rate_limiter,
            cdsp_manager=cdsp_manager,
        )

        # Federation handshake state
        self._pending_counter_challenges: dict[str, tuple[bytes, float]] = {}
        self._challenges_lock = asyncio.Lock()

        # Action -> handler dispatch table
        self._action_handlers = {
            SYNC_HISTORY: self._route_history,
            SYNC_NODE_META: self._route_node_meta,
            SYNC_GET_PINS: self._route_get_pins,
            SYNC_SEARCH: self._route_search,
            SYNC_THREAD: self._route_thread,
            SYNC_GET_MEMBER_LIST: self._route_member_list,
            SYNC_SUBSCRIBE_LIVE: self._route_subscribe_live,
            SYNC_UNSUBSCRIBE: self._route_unsubscribe,
            SYNC_FETCH_MEDIA: self._route_fetch_media,
            SYNC_REDEEM_INVITE: self._route_redeem_invite,
            SYNC_FEDERATION_HANDSHAKE: self._route_federation_handshake,
            SYNC_PUSH_MESSAGES: self._route_push_messages,
            SYNC_REQUEST_SEALED_KEY: self._route_request_sealed_key,
            SYNC_CDSP_SESSION_INIT: self._route_cdsp_session_init,
            SYNC_CDSP_PROFILE_UPDATE: self._route_cdsp_profile_update,
            SYNC_CREATE_INVITE: self._route_create_invite,
            SYNC_LIST_INVITES: self._route_list_invites,
            SYNC_LIST_SEEDS: self._route_list_seeds,
        }

    async def handle(
        self,
        session: AsyncSession,
        action: int,
        nonce: bytes,
        payload: Optional[dict] = None,
        channel_id: Optional[str] = None,
        requester_hash: Optional[str] = None,
        link=None,
    ) -> dict:
        """Dispatch a sync action and return response data."""
        # Nonce replay protection
        self._ctx.verifier.check_nonce_replay(nonce)

        handler = self._action_handlers.get(action)
        if not handler:
            raise SyncError(f"Unknown sync action: {action:#x}")

        return await handler(
            session,
            nonce,
            payload or {},
            channel_id,
            requester_hash=requester_hash,
            link=link,
        )

    # --- Route methods (thin wrappers passing ctx to handler functions) ---

    async def _route_history(self, session, nonce, payload, channel_id, **kw):
        return await handle_history(self._ctx, session, nonce, payload, channel_id, **kw)

    async def _route_node_meta(self, session, nonce, payload, channel_id, **kw):
        return await handle_node_meta(self._ctx, session, nonce, payload, channel_id, **kw)

    async def _route_get_pins(self, session, nonce, payload, channel_id, **kw):
        return await handle_get_pins(self._ctx, session, nonce, payload, channel_id, **kw)

    async def _route_search(self, session, nonce, payload, channel_id, **kw):
        return await handle_search(self._ctx, session, nonce, payload, channel_id, **kw)

    async def _route_thread(self, session, nonce, payload, channel_id, **kw):
        return await handle_thread(self._ctx, session, nonce, payload, channel_id, **kw)

    async def _route_member_list(self, session, nonce, payload, channel_id, **kw):
        return await handle_member_list(self._ctx, session, nonce, payload, channel_id, **kw)

    async def _route_subscribe_live(self, session, nonce, payload, channel_id, **kw):
        return await handle_subscribe_live(self._ctx, session, nonce, payload, channel_id, **kw)

    async def _route_unsubscribe(self, session, nonce, payload, channel_id, **kw):
        return await handle_unsubscribe(self._ctx, session, nonce, payload, channel_id, **kw)

    async def _route_fetch_media(self, session, nonce, payload, channel_id, **kw):
        return await handle_fetch_media(self._ctx, session, nonce, payload, channel_id, **kw)

    async def _route_redeem_invite(self, session, nonce, payload, channel_id, **kw):
        return await handle_redeem_invite(self._ctx, session, nonce, payload, channel_id, **kw)

    async def _route_federation_handshake(self, session, nonce, payload, channel_id, **kw):
        return await handle_federation_handshake(
            self._ctx,
            session,
            nonce,
            payload,
            channel_id,
            pending_counter_challenges=self._pending_counter_challenges,
            challenges_lock=self._challenges_lock,
            **kw,
        )

    async def _route_push_messages(self, session, nonce, payload, channel_id, **kw):
        return await handle_push_messages(self._ctx, session, nonce, payload, channel_id, **kw)

    async def _route_request_sealed_key(self, session, nonce, payload, channel_id, **kw):
        return await handle_request_sealed_key(self._ctx, session, nonce, payload, channel_id, **kw)

    async def _route_cdsp_session_init(self, session, nonce, payload, channel_id, **kw):
        return await handle_cdsp_session_init(self._ctx, session, nonce, payload, channel_id, **kw)

    async def _route_cdsp_profile_update(self, session, nonce, payload, channel_id, **kw):
        return await handle_cdsp_profile_update(
            self._ctx, session, nonce, payload, channel_id, **kw
        )

    async def _route_create_invite(self, session, nonce, payload, channel_id, **kw):
        return await handle_create_invite(self._ctx, session, nonce, payload, channel_id, **kw)

    async def _route_list_invites(self, session, nonce, payload, channel_id, **kw):
        return await handle_list_invites(self._ctx, session, nonce, payload, channel_id, **kw)

    async def _route_list_seeds(self, session, nonce, payload, channel_id, **kw):
        return await handle_list_seeds(self._ctx, session, nonce, payload, channel_id, **kw)

    async def cleanup_stale_challenges(self, max_age: float = 300):
        """Remove pending counter-challenges older than max_age seconds."""
        async with self._challenges_lock:
            now = time.time()
            stale = [
                peer
                for peer, (_, created_at) in self._pending_counter_challenges.items()
                if now - created_at > max_age
            ]
            for peer in stale:
                del self._pending_counter_challenges[peer]
            if stale:
                logger.info(f"Cleaned up {len(stale)} stale pending challenges")

    # --- Backward compatibility: private method delegates for tests ---

    async def _get_session_profile(self, session, requester_hash):
        from hokora.protocol.sync_utils import get_session_profile

        return await get_session_profile(self._ctx, session, requester_hash)

    async def _check_channel_read(self, session, ch_id, requester_hash=None):
        from hokora.protocol.sync_utils import check_channel_read

        return await check_channel_read(self._ctx, session, ch_id, requester_hash)

    async def _handle_history(self, session, nonce, payload, channel_id, **kw):
        return await self._route_history(session, nonce, payload, channel_id, **kw)

    async def _handle_search(self, session, nonce, payload, channel_id, **kw):
        return await self._route_search(session, nonce, payload, channel_id, **kw)

    async def _handle_node_meta(self, session, nonce, payload, channel_id, **kw):
        return await self._route_node_meta(session, nonce, payload, channel_id, **kw)

    async def _handle_get_pins(self, session, nonce, payload, channel_id, **kw):
        return await self._route_get_pins(session, nonce, payload, channel_id, **kw)

    async def _handle_thread(self, session, nonce, payload, channel_id, **kw):
        return await self._route_thread(session, nonce, payload, channel_id, **kw)

    async def _handle_member_list(self, session, nonce, payload, channel_id, **kw):
        return await self._route_member_list(session, nonce, payload, channel_id, **kw)

    async def _handle_subscribe_live(self, session, nonce, payload, channel_id, **kw):
        return await self._route_subscribe_live(session, nonce, payload, channel_id, **kw)

    async def _handle_unsubscribe(self, session, nonce, payload, channel_id, **kw):
        return await self._route_unsubscribe(session, nonce, payload, channel_id, **kw)

    async def _handle_fetch_media(self, session, nonce, payload, channel_id, **kw):
        return await self._route_fetch_media(session, nonce, payload, channel_id, **kw)

    async def _handle_redeem_invite(self, session, nonce, payload, channel_id, **kw):
        return await self._route_redeem_invite(session, nonce, payload, channel_id, **kw)

    async def _handle_federation_handshake(self, session, nonce, payload, channel_id, **kw):
        return await self._route_federation_handshake(session, nonce, payload, channel_id, **kw)

    async def _handle_push_messages(self, session, nonce, payload, channel_id, **kw):
        return await self._route_push_messages(session, nonce, payload, channel_id, **kw)

    async def _handle_request_sealed_key(self, session, nonce, payload, channel_id, **kw):
        return await self._route_request_sealed_key(session, nonce, payload, channel_id, **kw)

    async def _handle_cdsp_session_init(self, session, nonce, payload, channel_id, **kw):
        return await self._route_cdsp_session_init(session, nonce, payload, channel_id, **kw)

    async def _handle_cdsp_profile_update(self, session, nonce, payload, channel_id, **kw):
        return await self._route_cdsp_profile_update(session, nonce, payload, channel_id, **kw)

    # --- Backward compatibility: expose shared state attributes ---

    @property
    def channel_manager(self):
        return self._ctx.channel_manager

    @property
    def sequencer(self):
        return self._ctx.sequencer

    @property
    def fts_manager(self):
        return self._ctx.fts_manager

    @property
    def node_name(self):
        return self._ctx.node_name

    @property
    def node_description(self):
        return self._ctx.node_description

    @property
    def node_identity(self):
        return self._ctx.node_identity

    @property
    def live_manager(self):
        return self._ctx.live_manager

    @property
    def media_transfer(self):
        return self._ctx.media_transfer

    @property
    def permission_resolver(self):
        return self._ctx.permission_resolver

    @property
    def federation_auth(self):
        return self._ctx.federation_auth

    @property
    def sealed_manager(self):
        return self._ctx.sealed_manager

    @property
    def config(self):
        return self._ctx.config

    @property
    def node_rns_identity(self):
        return self._ctx.node_rns_identity

    @property
    def rate_limiter(self):
        return self._ctx.rate_limiter
