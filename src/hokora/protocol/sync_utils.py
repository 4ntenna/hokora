# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Shared context and helpers for sync handlers.

The concrete ``SyncContext`` dataclass below carries every collaborator
any sync handler might touch (16 fields). To stop handlers drifting
into using whatever happens to be on the bag, each handler group
annotates its ``ctx`` argument with a narrow ``typing.Protocol`` that
enumerates **only** the attributes it reads. ``SyncContext`` structurally
satisfies all five Protocols — callers pass the same concrete object
to every handler, but each handler's signature documents its
dependencies and mypy will flag drift.

The five contexts mirror the ``protocol/handlers/`` package layout:

* ``LiveContext``        — ``handlers/live.py``        (2 fields)
* ``HistoryContext``     — ``handlers/history.py``     (3 fields)
* ``MetadataContext``    — ``handlers/metadata.py``    (8 fields)
* ``SessionContext``     — ``handlers/session.py``     (7 fields)
* ``FederationContext``  — ``handlers/federation.py``  (7 fields)

Generic call sites using ``ctx: SyncContext`` keep working; new
handlers pick the narrow Protocol that matches their reads.
"""

import logging
from dataclasses import dataclass, field
from typing import Optional, Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from hokora.constants import (
    ACCESS_PRIVATE,
    CDSP_PROFILE_FULL,
    CDSP_PROFILE_LIMITS,
)
from hokora.db.models import Message
from hokora.db.queries import (
    RoleRepo,
    IdentityRepo,
    SessionRepo,
    DeferredSyncItemRepo,
)
from hokora.exceptions import SyncError, PermissionDenied
from hokora.protocol.wire import encode_message_for_sync
from hokora.security.ban import check_not_blocked, record_ban_rejection
from hokora.security.verification import VerificationService

logger = logging.getLogger(__name__)


def populate_sender_pubkey(d: dict, sender_public_key: Optional[bytes]) -> None:
    """Fill ``d["sender_public_key"]`` from a known 32-byte Ed25519 key.

    Single chokepoint for "the sender's signing pubkey on a sync/live wire
    dict." ``encode_message_for_sync`` always returns the field set to None;
    the bulk sync-response encoder and the live push manager both call this
    after encoding so the TUI can re-verify Ed25519 signatures end-to-end.

    No-op when ``sender_public_key`` is None — keeps the wire-dict shape
    backwards-compatible for callers that don't have the pubkey at hand.
    """
    if sender_public_key:
        d["sender_public_key"] = sender_public_key


def encode_message_for_wire(
    msg,
    sealed_manager=None,
    *,
    subscriber_supports_sealed_at_rest: bool = False,
) -> dict:
    """Serialise a Message ORM row for a sync/live-push wire payload.

    Single source of truth for "ORM row → wire dict" that respects the
    sealed-channel invariant.

    Two output shapes for sealed-channel rows depending on the subscriber:

    * **Legacy clients (default)** — ``sealed_manager`` provided + row
      carries ciphertext → plaintext is resolved server-side and placed
      in ``d["body"]`` so the wire payload is renderable. Daemon-side
      at-rest invariant is preserved, but the TUI persists plaintext.

    * **R1-capable clients** (``subscriber_supports_sealed_at_rest=True``)
      → ciphertext fields are emitted on the wire (``encrypted_body`` /
      ``encryption_nonce`` / ``encryption_epoch``), ``body`` is empty.
      The TUI persists ciphertext at rest and decrypts at render-time
      via its own sealed-key store. Full at-rest parity.

    ``sealed_manager=None`` degrades to the legacy ``encode_message_for_sync``
    behaviour (wire dict carries whatever ``msg.body`` happens to be).
    That's used by non-daemon callers that don't hold a sealed_manager —
    they never have sealed rows anyway.

    Security notes:
      * Membership is gated upstream by ``check_channel_read`` +
        ``handle_subscribe_live``. Only authenticated channel members can
        receive a live push, regardless of subscriber capability.
      * Wire transport (RNS.Link) is separately encrypted end-to-end
        between daemon and subscriber — neither plaintext nor ciphertext
        on the wire is visible to network observers.
      * On legacy-path decrypt failure the body is replaced with a
        stable marker so the wire dict is still well-formed.
    """
    d = encode_message_for_sync(msg)
    has_ciphertext = (
        sealed_manager is not None
        and getattr(msg, "encrypted_body", None)
        and getattr(msg, "encryption_nonce", None)
    )
    if has_ciphertext and subscriber_supports_sealed_at_rest:
        # R1: emit ciphertext fields, empty body. TUI decrypts on render.
        d["body"] = ""
        d["encrypted_body"] = msg.encrypted_body
        d["encryption_nonce"] = msg.encryption_nonce
        d["encryption_epoch"] = getattr(msg, "encryption_epoch", None)
        return d
    if has_ciphertext:
        try:
            plaintext = sealed_manager.decrypt(
                msg.channel_id,
                msg.encryption_nonce,
                msg.encrypted_body,
                getattr(msg, "encryption_epoch", None),
            )
            d["body"] = plaintext.decode("utf-8")
        except Exception:
            logger.warning(
                "Failed to decrypt sealed msg seq=%s ch=%s",
                getattr(msg, "seq", None),
                getattr(msg, "channel_id", None),
                exc_info=True,
            )
            d["body"] = "[encrypted - key unavailable]"
    return d


class _ChannelReadCtx(Protocol):
    """Fields read by ``check_channel_read``."""

    channel_manager: object
    permission_resolver: object


class _SessionProfileCtx(Protocol):
    """Fields read by ``get_session_profile``."""

    cdsp_manager: object


class _DeferItemCtx(Protocol):
    """Fields read by ``defer_sync_item``."""

    config: object


class LiveContext(Protocol):
    """Fields read directly or transitively by ``protocol/handlers/live.py``.

    Direct: ``live_manager``, ``media_transfer``. Transitive via
    ``check_channel_read`` / ``get_session_profile`` / ``defer_sync_item``:
    ``channel_manager``, ``permission_resolver``, ``cdsp_manager``, ``config``.
    """

    live_manager: object
    media_transfer: object
    channel_manager: object
    permission_resolver: object
    cdsp_manager: object
    config: object


class HistoryContext(Protocol):
    """Fields read directly or transitively by ``protocol/handlers/history.py``.

    Direct: ``fts_manager``, ``sealed_manager``, ``sequencer``. Transitive:
    ``channel_manager``, ``permission_resolver``, ``cdsp_manager``, ``config``.
    """

    fts_manager: object
    sealed_manager: object
    sequencer: object
    channel_manager: object
    permission_resolver: object
    cdsp_manager: object
    config: object


class MetadataContext(Protocol):
    """Fields read directly or transitively by ``protocol/handlers/metadata.py``.

    Direct: 8 fields (listed). Transitive via ``get_session_profile``:
    ``cdsp_manager``.
    """

    channel_manager: object
    config: object
    node_description: str
    node_identity: str
    node_name: str
    node_rns_identity: object
    permission_resolver: object
    sealed_manager: object
    cdsp_manager: object


class SessionContext(Protocol):
    """Fields read by ``protocol/handlers/session.py``. No sync_utils
    helpers called, so the list is purely direct reads."""

    cdsp_manager: object
    channel_manager: object
    invite_manager: object
    node_identity: str
    permission_resolver: object
    rate_limiter: object
    sealed_manager: object


class FederationContext(Protocol):
    """Fields read by ``protocol/handlers/federation.py``. No sync_utils
    helpers called, so the list is purely direct reads."""

    config: object
    live_manager: object
    node_identity: str
    node_name: str
    node_rns_identity: object
    rate_limiter: object
    sequencer: object


@dataclass
class SyncContext:
    """Shared state for all sync handlers.

    Concrete dataclass carrying every collaborator. Structurally satisfies
    the five per-handler Protocols above — handlers that annotate their
    ``ctx`` parameter with a narrow Protocol still accept this dataclass
    at runtime; mypy enforces that the handler only reads declared fields.
    """

    channel_manager: object
    sequencer: object
    fts_manager: object = None
    node_name: str = ""
    node_description: str = ""
    node_identity: str = ""
    live_manager: object = None
    media_transfer: object = None
    permission_resolver: object = None
    invite_manager: object = None
    federation_auth: object = None
    sealed_manager: object = None
    config: object = None
    node_rns_identity: object = None
    rate_limiter: object = None
    cdsp_manager: object = None
    verifier: VerificationService = field(default_factory=VerificationService)


async def encode_messages_with_keys(
    session: AsyncSession,
    messages: list[Message],
    sealed_manager=None,
    *,
    subscriber_supports_sealed_at_rest: bool = False,
) -> list[dict]:
    """Encode messages for sync and attach sender public keys.

    If sealed_manager is provided, encrypted messages are decrypted
    server-side so sync responses contain plaintext for authorized
    members (legacy default).

    With ``subscriber_supports_sealed_at_rest=True`` the sealed rows
    are emitted as ciphertext fields instead, so the requesting client
    can persist ciphertext at rest and decrypt at render-time.
    """
    sender_hashes = {m.sender_hash for m in messages if m.sender_hash}
    identity_repo = IdentityRepo(session)
    identities = {ident.hash: ident for ident in await identity_repo.get_batch(sender_hashes)}

    # Batch-lookup thread reply counts for messages that are thread roots
    from hokora.db.models import Thread
    from sqlalchemy import select

    msg_hashes = [m.msg_hash for m in messages if m.msg_hash]
    thread_counts = {}
    if msg_hashes:
        result = await session.execute(
            select(Thread.root_msg_hash, Thread.reply_count).where(
                Thread.root_msg_hash.in_(msg_hashes)
            )
        )
        thread_counts = {row[0]: row[1] for row in result}

    encoded = []
    for m in messages:
        d = encode_message_for_wire(
            m,
            sealed_manager=sealed_manager,
            subscriber_supports_sealed_at_rest=subscriber_supports_sealed_at_rest,
        )
        # Add thread reply count if this message is a thread root
        rc = thread_counts.get(m.msg_hash, 0)
        if rc > 0:
            d["has_thread"] = True
            d["reply_count"] = rc
        ident = identities.get(m.sender_hash)
        populate_sender_pubkey(d, ident.public_key if ident else None)
        encoded.append(d)
    return encoded


async def check_channel_read(
    ctx: _ChannelReadCtx,
    session: AsyncSession,
    ch_id: str,
    requester_hash: Optional[str] = None,
):
    """Verify requester can read from a channel. Returns the Channel.

    Public/write_restricted channels: anyone can read.
    Private channels: require node_owner OR any role on the channel.
    Banned identities are rejected on every access mode before the
    membership check — local enforcement of ``Identity.blocked``.
    """
    channel = ctx.channel_manager.get_channel(ch_id)
    if not channel:
        raise SyncError(f"Channel {ch_id} not found")

    # Ban gate runs before access-mode check so banned identities are
    # rejected uniformly across public, write_restricted, and private
    # channels via the single ``hokora.security.ban`` chokepoint.
    if requester_hash:
        try:
            await check_not_blocked(session, requester_hash)
        except PermissionDenied:
            record_ban_rejection("sync_read")
            raise

    if channel.access_mode == ACCESS_PRIVATE:
        # Node owner always has access
        if (
            ctx.permission_resolver
            and requester_hash
            and requester_hash == ctx.permission_resolver.node_owner_hash
        ):
            return channel

        # Must have a role on this channel
        if not requester_hash:
            raise PermissionDenied("Authentication required for private channel")

        role_repo = RoleRepo(session)
        roles = await role_repo.get_identity_roles(requester_hash, ch_id, strict_channel_scope=True)
        if not roles:
            raise PermissionDenied("Not a member of this private channel")

    return channel


async def get_session_profile(ctx: _SessionProfileCtx, session, requester_hash) -> dict:
    """Look up the active CDSP profile limits for this requester.
    Returns FULL profile limits if no CDSP session exists (backward compat)."""
    if not ctx.cdsp_manager:
        return CDSP_PROFILE_LIMITS[CDSP_PROFILE_FULL]
    sess = await SessionRepo(session).get_active_session(requester_hash)
    if not sess:
        return CDSP_PROFILE_LIMITS[CDSP_PROFILE_FULL]
    return CDSP_PROFILE_LIMITS.get(sess.sync_profile, CDSP_PROFILE_LIMITS[CDSP_PROFILE_FULL])


async def defer_sync_item(ctx: _DeferItemCtx, session, requester_hash, channel_id, action, payload):
    """Enqueue a deferred sync item for the requester's session."""
    sess = await SessionRepo(session).get_active_session(requester_hash)
    if not sess:
        return
    repo = DeferredSyncItemRepo(session)
    count = await repo.count_for_session(sess.session_id)
    limit = ctx.config.cdsp_deferred_queue_limit if ctx.config else 1000
    if count >= limit:
        await repo.evict_oldest(sess.session_id, limit - 1)
    await repo.enqueue(sess.session_id, channel_id, action, payload, ttl=sess.expires_at)
    sess.deferred_count = await repo.count_for_session(sess.session_id)
