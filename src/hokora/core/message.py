# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Message processing: ingestion pipeline and MessageEnvelope dataclass."""

import asyncio
import hashlib
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from hokora.constants import (
    MSG_TEXT,
    MSG_MEDIA,
    MSG_SYSTEM,
    MSG_THREAD_REPLY,
    MSG_REACTION,
    MSG_DELETE,
    MSG_PIN,
    MSG_EDIT,
    MAX_MESSAGE_BODY_SIZE,
    PERM_SEND_MESSAGES,
    PERM_SEND_MEDIA,
    PERM_CREATE_THREADS,
    PERM_ADD_REACTIONS,
    PERM_PIN_MESSAGES,
    PERM_DELETE_OWN,
    PERM_DELETE_OTHERS,
    PERM_EDIT_OWN,
    PERM_USE_MENTIONS,
    PERM_MENTION_EVERYONE,
    MAX_REACTIONS_PER_MESSAGE,
    MAX_LOCK_ENTRIES,
    MAX_DISPLAY_NAME_LENGTH,
)
from hokora.core.sequencer import SequenceManager
from hokora.db.models import Message, Thread
from hokora.constants import ACCESS_PRIVATE
from hokora.db.queries import MessageRepo, ChannelRepo, AuditLogRepo, IdentityRepo, RoleRepo
from hokora.exceptions import MessageError, PermissionDenied
from hokora.security.ban import check_not_blocked

logger = logging.getLogger(__name__)


@dataclass
class MessageEnvelope:
    """Represents an incoming message before storage."""

    channel_id: str
    sender_hash: str
    timestamp: float
    type: int = MSG_TEXT
    body: Optional[str] = None
    media_path: Optional[str] = None
    media_bytes: Optional[bytes] = None
    media_meta: Optional[dict] = None
    reply_to: Optional[str] = None
    ttl: Optional[int] = None
    lxmf_signature: Optional[bytes] = None
    lxmf_signed_part: Optional[bytes] = None
    sender_public_key: Optional[bytes] = None
    display_name: Optional[str] = None
    mentions: list[str] = field(default_factory=list)
    reactions: dict = field(default_factory=dict)

    def compute_hash(self) -> str:
        """Compute deterministic message hash."""
        data = (
            f"{self.channel_id}:{self.sender_hash}:{self.timestamp}:"
            f"{self.type}:{self.body or ''}:{self.reply_to or ''}"
        ).encode("utf-8")
        return hashlib.sha256(data).hexdigest()


class MessageProcessor:
    """Processes incoming messages through the ingestion pipeline."""

    def __init__(
        self,
        sequencer: SequenceManager,
        permission_resolver=None,
        rate_limiter=None,
        identity_repo=None,
        node_identity_hash: Optional[str] = None,
        sealed_manager=None,
    ):
        self.sequencer = sequencer
        self.permission_resolver = permission_resolver
        self.rate_limiter = rate_limiter
        self.identity_repo = identity_repo
        self.node_identity_hash = node_identity_hash
        self.sealed_manager = sealed_manager
        self._thread_locks: dict[str, asyncio.Lock] = {}

    def _seal_body_for_insert(
        self,
        channel,
        plaintext: Optional[str],
    ) -> tuple[Optional[str], Optional[bytes], Optional[bytes], Optional[int]]:
        """Origin-side sealed chokepoint — see ``security.sealed_invariant``."""
        from hokora.security.sealed_invariant import seal_for_origin

        return seal_for_origin(channel, plaintext, self.sealed_manager)

    async def _check_permissions(self, session, envelope, channel):
        """Enforce permission checks before message storage."""
        if not self.permission_resolver:
            return

        sender = envelope.sender_hash

        # 1. Check if identity is blocked
        identity_repo = self.identity_repo or IdentityRepo(session)
        await check_not_blocked(session, sender, identity_repo=identity_repo)

        # 2. Rate limiting
        if self.rate_limiter:
            self.rate_limiter.check_rate_limit(sender)
            self.rate_limiter.check_slowmode(sender, channel.id, channel.slowmode)

        # 3. Sealed/private channel membership check — STRICT channel scope.
        # Node-wide role grants don't satisfy private/sealed membership; only
        # an explicit per-channel role assignment (or node-owner bypass) does.
        if channel.access_mode == ACCESS_PRIVATE or getattr(channel, "sealed", False):
            if sender != self.node_identity_hash:
                role_repo = RoleRepo(session)
                roles = await role_repo.get_identity_roles(
                    sender, channel.id, strict_channel_scope=True
                )
                if not roles:
                    raise PermissionDenied("Not a member of this channel")

        # 4. Get full permission bitmask once (eliminates N+1 queries)
        perms = await self.permission_resolver.get_effective_permissions(
            session,
            sender,
            channel,
        )

        # 4. Type-based permission checks against the bitmask
        msg_type = envelope.type
        if msg_type in (MSG_TEXT, MSG_MEDIA):
            if not (perms & PERM_SEND_MESSAGES):
                raise PermissionDenied("Missing SEND_MESSAGES permission")
            if msg_type == MSG_MEDIA and not (perms & PERM_SEND_MEDIA):
                raise PermissionDenied("Missing SEND_MEDIA permission")

        elif msg_type == MSG_THREAD_REPLY:
            if not (perms & PERM_CREATE_THREADS):
                raise PermissionDenied("Missing CREATE_THREADS permission")

        elif msg_type == MSG_REACTION:
            if not (perms & PERM_ADD_REACTIONS):
                raise PermissionDenied("Missing ADD_REACTIONS permission")

        elif msg_type == MSG_PIN:
            if not (perms & PERM_PIN_MESSAGES):
                raise PermissionDenied("Missing PIN_MESSAGES permission")

        elif msg_type == MSG_DELETE:
            # Check permission based on ownership
            target_hash = envelope.reply_to
            if target_hash:
                msg_repo = MessageRepo(session)
                target = await msg_repo.get_by_hash(target_hash)
                if target:
                    if target.sender_hash == sender:
                        if not (perms & PERM_DELETE_OWN):
                            raise PermissionDenied("Missing DELETE_OWN permission")
                    else:
                        if not (perms & PERM_DELETE_OTHERS):
                            raise PermissionDenied("Missing DELETE_OTHERS permission")

        elif msg_type == MSG_EDIT:
            # Check PERM_EDIT_OWN first, then verify author-only
            if not (perms & PERM_EDIT_OWN):
                raise PermissionDenied("Missing EDIT_OWN permission")
            target_hash = envelope.reply_to
            if target_hash:
                msg_repo = MessageRepo(session)
                target = await msg_repo.get_by_hash(target_hash)
                if target and target.sender_hash != sender:
                    raise PermissionDenied("Only the author can edit a message")

        # 5. Strip mentions if no permission
        if envelope.mentions:
            if not (perms & PERM_USE_MENTIONS):
                envelope.mentions = []
            elif "@everyone" in envelope.mentions:
                if not (perms & PERM_MENTION_EVERYONE):
                    envelope.mentions = [m for m in envelope.mentions if m != "@everyone"]

    async def ingest(
        self,
        session: AsyncSession,
        envelope: MessageEnvelope,
    ) -> Message:
        """Ingest a message: validate, check perms, dedup, assign seq, store.

        Returns the stored Message ORM object.
        """
        # Validate channel exists
        channel_repo = ChannelRepo(session)
        channel = await channel_repo.get_by_id(envelope.channel_id)
        if not channel:
            raise MessageError(f"Channel {envelope.channel_id} not found")

        # Validate body size
        if envelope.body and len(envelope.body.encode("utf-8")) > MAX_MESSAGE_BODY_SIZE:
            raise MessageError("Message body exceeds maximum size")

        # Truncate display name to schema limit (defensive — remote peers control this field)
        if envelope.display_name and len(envelope.display_name) > MAX_DISPLAY_NAME_LENGTH:
            envelope.display_name = envelope.display_name[:MAX_DISPLAY_NAME_LENGTH]

        await self._check_permissions(session, envelope, channel)

        # Route to specialized handlers for non-standard types
        if envelope.type == MSG_EDIT:
            return await self.process_edit(session, envelope)
        if envelope.type == MSG_DELETE:
            return await self.process_delete(session, envelope)
        if envelope.type == MSG_PIN:
            return await self.process_pin(session, envelope, channel)
        if envelope.type == MSG_REACTION:
            return await self.process_reaction(session, envelope)

        # Compute hash and dedup
        msg_hash = envelope.compute_hash()
        msg_repo = MessageRepo(session)
        existing = await msg_repo.get_by_hash(msg_hash)
        if existing:
            logger.debug(f"Duplicate message {msg_hash}, skipping")
            return existing

        # Thread replies get thread_seq instead of main seq
        thread_seq = None
        if envelope.type == MSG_THREAD_REPLY and envelope.reply_to:
            seq = None  # thread replies don't appear in main timeline
            thread_seq = await self.sequencer.next_thread_seq(
                session, envelope.reply_to, envelope.channel_id
            )
            await self._update_thread_metadata(session, envelope)
        else:
            # Assign main sequence number
            seq = await self.sequencer.next_seq(session, envelope.channel_id)

        # Sealed channel invariant enforced via single choke-point helper.
        body_for_insert, encrypted_body, encryption_nonce, encryption_epoch = (
            self._seal_body_for_insert(channel, envelope.body)
        )

        # Build ORM message
        message = Message(
            msg_hash=msg_hash,
            channel_id=envelope.channel_id,
            sender_hash=envelope.sender_hash,
            seq=seq,
            thread_seq=thread_seq,
            timestamp=envelope.timestamp,
            type=envelope.type,
            body=body_for_insert,
            encrypted_body=encrypted_body,
            encryption_nonce=encryption_nonce,
            encryption_epoch=encryption_epoch,
            media_path=envelope.media_path,
            media_meta=envelope.media_meta,
            reply_to=envelope.reply_to,
            ttl=envelope.ttl,
            received_at=time.time(),
            lxmf_signature=envelope.lxmf_signature,
            lxmf_signed_part=envelope.lxmf_signed_part,
            display_name=envelope.display_name,
            mentions=envelope.mentions,
            reactions=envelope.reactions,
            origin_node=self.node_identity_hash,
        )

        await msg_repo.insert(message)

        # Upsert sender identity with public key for sync verification
        if envelope.sender_public_key:
            identity_repo = IdentityRepo(session)
            await identity_repo.upsert(
                envelope.sender_hash,
                public_key=envelope.sender_public_key,
            )

        logger.info(
            f"Ingested message {msg_hash} in channel {envelope.channel_id} "
            f"seq={seq} thread_seq={thread_seq}"
        )
        return message

    def _get_thread_lock(self, reply_to: str) -> asyncio.Lock:
        """Get or create an asyncio.Lock for a specific thread root hash."""
        if reply_to not in self._thread_locks:
            # Evict oldest unlocked entries to prevent unbounded growth
            if len(self._thread_locks) >= MAX_LOCK_ENTRIES:
                for old_key in list(self._thread_locks)[:100]:
                    lock = self._thread_locks[old_key]
                    if not lock.locked():
                        del self._thread_locks[old_key]
            self._thread_locks[reply_to] = asyncio.Lock()
        return self._thread_locks[reply_to]

    async def _update_thread_metadata(self, session, envelope):
        """Create or update Thread metadata for a thread reply.

        Uses a per-thread asyncio.Lock to serialize concurrent updates
        to participant_hashes (read-modify-write).
        """
        from sqlalchemy import select, update as sa_update

        lock = self._get_thread_lock(envelope.reply_to)
        async with lock:
            result = await session.execute(
                select(Thread).where(Thread.root_msg_hash == envelope.reply_to)
            )
            thread = result.scalar_one_or_none()
            if thread:
                # Use SQL expression for atomic increment (avoids lost updates)
                await session.execute(
                    sa_update(Thread)
                    .where(Thread.root_msg_hash == envelope.reply_to)
                    .values(reply_count=Thread.reply_count + 1, last_activity=time.time())
                )
                await session.refresh(thread)
                participants = list(thread.participant_hashes or [])
                if envelope.sender_hash not in participants:
                    participants.append(envelope.sender_hash)
                    thread.participant_hashes = participants
            else:
                thread = Thread(
                    root_msg_hash=envelope.reply_to,
                    channel_id=envelope.channel_id,
                    reply_count=1,
                    latest_thread_seq=0,
                    last_activity=time.time(),
                    participant_hashes=[envelope.sender_hash],
                )
                session.add(thread)
            await session.flush()

    async def process_edit(self, session: AsyncSession, envelope: MessageEnvelope) -> Message:
        """Process an edit — author-only, store new msg, update edit_chain."""
        target_hash = envelope.reply_to
        if not target_hash:
            raise MessageError("Edit requires reply_to (target message hash)")

        msg_repo = MessageRepo(session)
        original = await msg_repo.get_by_hash(target_hash)
        if not original:
            raise MessageError(f"Target message {target_hash} not found")
        if original.channel_id != envelope.channel_id:
            raise MessageError("Target message does not belong to this channel")

        if original.sender_hash != envelope.sender_hash:
            raise PermissionDenied("Only the author can edit a message")

        # Resolve channel once — needed for sealed invariant enforcement on
        # both the edit message row and the original's body update.
        channel = await ChannelRepo(session).get_by_id(envelope.channel_id)
        if not channel:
            raise MessageError(f"Channel {envelope.channel_id} not found")

        # Compute hash for the edit message
        msg_hash = envelope.compute_hash()

        # Sealed invariant: encrypt edit body before storing the edit row
        # AND before updating the original's visible body. A sealed channel
        # without a key is a hard failure — no plaintext fallback.
        body_for_insert, enc_body, enc_nonce, enc_epoch = self._seal_body_for_insert(
            channel, envelope.body
        )

        # Store the edit as a new message (no main timeline seq)
        edit_msg = Message(
            msg_hash=msg_hash,
            channel_id=envelope.channel_id,
            sender_hash=envelope.sender_hash,
            seq=None,
            timestamp=envelope.timestamp,
            type=envelope.type,
            body=body_for_insert,
            encrypted_body=enc_body,
            encryption_nonce=enc_nonce,
            encryption_epoch=enc_epoch,
            reply_to=target_hash,
            received_at=time.time(),
            origin_node=self.node_identity_hash,
        )
        await msg_repo.insert(edit_msg)

        # Append to original's edit chain
        from hokora.constants import MAX_EDIT_CHAIN_LENGTH

        chain = list(original.edit_chain or [])
        if len(chain) >= MAX_EDIT_CHAIN_LENGTH:
            raise MessageError(f"Edit chain limit ({MAX_EDIT_CHAIN_LENGTH}) reached")
        chain.append(msg_hash)
        original.edit_chain = chain
        # Update visible body to latest edit — same sealed handling applied.
        original.body = body_for_insert
        original.encrypted_body = enc_body
        original.encryption_nonce = enc_nonce
        original.encryption_epoch = enc_epoch
        await session.flush()

        logger.info(f"Processed edit {msg_hash} for original {target_hash}")
        return edit_msg

    async def process_delete(self, session: AsyncSession, envelope: MessageEnvelope) -> Message:
        """Process a delete — author or PERM_DELETE_OTHERS."""
        target_hash = envelope.reply_to
        if not target_hash:
            raise MessageError("Delete requires reply_to (target message hash)")

        msg_repo = MessageRepo(session)
        original = await msg_repo.get_by_hash(target_hash)
        if not original:
            raise MessageError(f"Target message {target_hash} not found")
        if original.channel_id != envelope.channel_id:
            raise MessageError("Target message does not belong to this channel")

        # Permission already checked in _check_permissions
        result = await msg_repo.soft_delete(target_hash, envelope.sender_hash)

        # Write audit log
        audit_repo = AuditLogRepo(session)
        await audit_repo.log(
            actor=envelope.sender_hash,
            action_type="message_delete",
            target=target_hash,
            channel_id=envelope.channel_id,
        )

        logger.info(f"Deleted message {target_hash} by {envelope.sender_hash[:8]}...")
        return result

    async def process_pin(
        self,
        session: AsyncSession,
        envelope: MessageEnvelope,
        channel=None,
    ) -> Message:
        """Process a pin toggle — requires PERM_PIN_MESSAGES."""
        target_hash = envelope.reply_to
        if not target_hash:
            raise MessageError("Pin requires reply_to (target message hash)")

        msg_repo = MessageRepo(session)
        original = await msg_repo.get_by_hash(target_hash)
        if not original:
            raise MessageError(f"Target message {target_hash} not found")

        # Toggle pin state
        new_pinned = not original.pinned
        await msg_repo.set_pinned(target_hash, new_pinned)

        # Create system message about the pin/unpin. Sealed channels
        # encrypt the system body too — it names the actor and reveals
        # a pin/unpin action, so leaking it at rest breaks the sealed
        # guarantee. Resolve channel via ``channel`` arg when caller
        # supplied it to avoid a second lookup.
        action = "pinned" if new_pinned else "unpinned"
        sys_data = f"{envelope.channel_id}:pin_system:{envelope.sender_hash}:{time.time()}".encode()
        sys_hash = hashlib.sha256(sys_data).hexdigest()
        sys_seq = await self.sequencer.next_seq(session, envelope.channel_id)
        if channel is None:
            channel = await ChannelRepo(session).get_by_id(envelope.channel_id)
            if not channel:
                raise MessageError(f"Channel {envelope.channel_id} not found")
        sys_body_plain = f"{envelope.sender_hash[:8]} {action} a message"
        body_for_insert, enc_body, enc_nonce, enc_epoch = self._seal_body_for_insert(
            channel, sys_body_plain
        )
        sys_msg = Message(
            msg_hash=sys_hash,
            channel_id=envelope.channel_id,
            sender_hash=envelope.sender_hash,
            seq=sys_seq,
            timestamp=time.time(),
            type=MSG_SYSTEM,
            body=body_for_insert,
            encrypted_body=enc_body,
            encryption_nonce=enc_nonce,
            encryption_epoch=enc_epoch,
            received_at=time.time(),
            origin_node=self.node_identity_hash,
        )
        await msg_repo.insert(sys_msg)

        logger.info(f"Pin toggled for {target_hash}: pinned={new_pinned}")
        return sys_msg

    async def process_reaction(self, session: AsyncSession, envelope: MessageEnvelope) -> Message:
        """Process a reaction — dedup, aggregate into target message."""
        target_hash = envelope.reply_to
        if not target_hash:
            raise MessageError("Reaction requires reply_to (target message hash)")

        msg_repo = MessageRepo(session)
        original = await msg_repo.get_by_hash(target_hash)
        if not original:
            raise MessageError(f"Target message {target_hash} not found")
        if original.channel_id != envelope.channel_id:
            raise MessageError("Target message does not belong to this channel")

        emoji = envelope.body
        if not emoji:
            raise MessageError("Reaction requires emoji in body")
        if len(emoji) > 32:
            raise MessageError("Reaction emoji too long (max 32 characters)")

        # Aggregate into target's reactions JSON
        reactions = dict(original.reactions or {})
        if emoji not in reactions:
            reactions[emoji] = {"count": 0, "identities": []}

        entry = reactions[emoji]
        # Dedup: one per emoji per identity per message
        if envelope.sender_hash in entry["identities"]:
            logger.debug(f"Duplicate reaction {emoji} from {envelope.sender_hash[:8]}...")
            return original

        entry["identities"].append(envelope.sender_hash)
        # Track the true count before truncating the identity list for storage
        entry["count"] = entry.get("count", 0) + 1
        # Truncate stored identities list to limit storage, but keep true count
        if len(entry["identities"]) > MAX_REACTIONS_PER_MESSAGE:
            entry["identities"] = entry["identities"][:MAX_REACTIONS_PER_MESSAGE]
        reactions[emoji] = entry
        original.reactions = reactions
        await session.flush()

        logger.info(f"Reaction {emoji} added to {target_hash}")
        return original
