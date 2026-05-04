# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Repository pattern for database operations."""

import time
from typing import Optional

from sqlalchemy import select, update, delete, func, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from hokora.db.models import (
    Channel,
    Category,
    Message,
    Identity,
    Role,
    RoleAssignment,
    ChannelOverride,
    AuditLog,
    Session,
    DeferredSyncItem,
    FederationEpochState,
    PendingSealedDistribution,
)


class MessageRepo:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def insert(self, message: Message) -> Message:
        self.session.add(message)
        await self.session.flush()
        return message

    async def get_by_hash(self, msg_hash: str) -> Optional[Message]:
        result = await self.session.execute(select(Message).where(Message.msg_hash == msg_hash))
        return result.scalar_one_or_none()

    async def get_history(
        self,
        channel_id: str,
        since_seq: int = 0,
        limit: int = 50,
        direction: str = "forward",
        before_seq: Optional[int] = None,
    ) -> list[Message]:
        query = select(Message).where(Message.channel_id == channel_id)

        if direction == "forward":
            query = query.where(Message.seq > since_seq)
            if before_seq is not None:
                query = query.where(Message.seq < before_seq)
            query = query.order_by(Message.seq.asc())
        else:
            if before_seq is not None:
                query = query.where(Message.seq < before_seq)
            else:
                query = query.where(Message.seq < since_seq)
            query = query.order_by(Message.seq.desc())

        query = query.limit(limit)
        result = await self.session.execute(query)
        rows = list(result.scalars().all())
        if direction == "backward":
            rows.reverse()
        return rows

    async def get_latest_seq(self, channel_id: str) -> int:
        result = await self.session.execute(
            select(func.max(Message.seq)).where(Message.channel_id == channel_id)
        )
        return result.scalar() or 0

    async def get_pinned(self, channel_id: str) -> list[Message]:
        result = await self.session.execute(
            select(Message)
            .where(and_(Message.channel_id == channel_id, Message.pinned.is_(True)))
            .order_by(Message.pinned_at.desc())
        )
        return list(result.scalars().all())

    @staticmethod
    def _escape_like(value: str) -> str:
        """Escape LIKE special characters: %, _, and backslash."""
        return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

    async def search(self, channel_id: str, query: str, limit: int = 20) -> list[Message]:
        # FTS5 search is handled by FTSManager; this is a fallback LIKE search
        escaped = self._escape_like(query)
        result = await self.session.execute(
            select(Message)
            .where(
                and_(
                    Message.channel_id == channel_id,
                    Message.body.ilike(f"%{escaped}%", escape="\\"),
                    Message.deleted.is_(False),
                )
            )
            .order_by(Message.seq.desc())
            .limit(limit)
        )
        return list(result.scalars().all())

    async def soft_delete(self, msg_hash: str, deleted_by: str) -> Optional[Message]:
        msg = await self.get_by_hash(msg_hash)
        if msg:
            msg.deleted = True
            msg.deleted_by = deleted_by
            msg.body = None
            msg.media_path = None
            await self.session.flush()
        return msg

    async def set_pinned(self, msg_hash: str, pinned: bool) -> Optional[Message]:
        msg = await self.get_by_hash(msg_hash)
        if msg:
            msg.pinned = pinned
            msg.pinned_at = time.time() if pinned else None
            await self.session.flush()
        return msg

    async def get_thread_messages(self, root_hash: str, limit: int = 50) -> list[Message]:
        result = await self.session.execute(
            select(Message)
            .where(
                or_(
                    Message.msg_hash == root_hash,
                    Message.reply_to == root_hash,
                )
            )
            .order_by(Message.thread_seq.asc().nulls_first(), Message.seq.asc())
            .limit(limit)
        )
        return list(result.scalars().all())


class ChannelRepo:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, channel: Channel) -> Channel:
        self.session.add(channel)
        await self.session.flush()
        return channel

    async def get_by_id(self, channel_id: str) -> Optional[Channel]:
        result = await self.session.execute(select(Channel).where(Channel.id == channel_id))
        return result.scalar_one_or_none()

    async def list_all(
        self,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> list[Channel]:
        query = select(Channel).order_by(Channel.position.asc())
        if offset is not None:
            query = query.offset(offset)
        if limit is not None:
            query = query.limit(limit)
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def increment_seq(self, channel_id: str) -> int:
        result = await self.session.execute(
            update(Channel)
            .where(Channel.id == channel_id)
            .values(latest_seq=Channel.latest_seq + 1)
            .returning(Channel.latest_seq)
        )
        seq = result.scalar_one()
        await self.session.flush()
        return seq

    # Fields allowed to be updated via update_channel
    _ALLOWED_UPDATE_FIELDS = {
        "name",
        "description",
        "topic",
        "position",
        "access_mode",
        "slowmode",
        "category_id",
        "sealed",
        "max_messages",
    }

    async def update_channel(self, channel_id: str, **kwargs) -> Optional[Channel]:
        ch = await self.get_by_id(channel_id)
        if ch:
            for k, v in kwargs.items():
                if k not in self._ALLOWED_UPDATE_FIELDS:
                    raise ValueError(f"Field '{k}' is not allowed in update_channel")
                setattr(ch, k, v)
            await self.session.flush()
        return ch

    async def delete_channel(self, channel_id: str) -> bool:
        ch = await self.get_by_id(channel_id)
        if ch:
            await self.session.delete(ch)
            await self.session.flush()
            return True
        return False


class CategoryRepo:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, category: Category) -> Category:
        self.session.add(category)
        await self.session.flush()
        return category

    async def get_by_id(self, category_id: str) -> Optional[Category]:
        result = await self.session.execute(select(Category).where(Category.id == category_id))
        return result.scalar_one_or_none()

    async def list_all(self) -> list[Category]:
        result = await self.session.execute(select(Category).order_by(Category.position.asc()))
        return list(result.scalars().all())


class IdentityRepo:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def upsert(self, identity_hash: str, **kwargs) -> Identity:
        existing = await self.session.execute(
            select(Identity).where(Identity.hash == identity_hash)
        )
        ident = existing.scalar_one_or_none()
        if ident:
            for k, v in kwargs.items():
                setattr(ident, k, v)
            ident.last_seen = time.time()
        else:
            ident = Identity(hash=identity_hash, **kwargs)
            self.session.add(ident)
        await self.session.flush()
        return ident

    async def get_by_hash(self, identity_hash: str) -> Optional[Identity]:
        result = await self.session.execute(select(Identity).where(Identity.hash == identity_hash))
        return result.scalar_one_or_none()

    async def get_batch(self, hashes: set[str]) -> list[Identity]:
        if not hashes:
            return []
        result = await self.session.execute(select(Identity).where(Identity.hash.in_(hashes)))
        return list(result.scalars().all())

    async def is_blocked(self, identity_hash: str) -> bool:
        ident = await self.get_by_hash(identity_hash)
        return ident.blocked if ident else False


class RoleRepo:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, role: Role) -> Role:
        self.session.add(role)
        await self.session.flush()
        return role

    async def get_by_id(self, role_id: str) -> Optional[Role]:
        result = await self.session.execute(select(Role).where(Role.id == role_id))
        return result.scalar_one_or_none()

    async def get_by_name(self, name: str) -> Optional[Role]:
        result = await self.session.execute(select(Role).where(Role.name == name))
        return result.scalar_one_or_none()

    async def list_all(
        self,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> list[Role]:
        query = select(Role).order_by(Role.position.desc())
        if offset is not None:
            query = query.offset(offset)
        if limit is not None:
            query = query.limit(limit)
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def assign_role(
        self,
        role_id: str,
        identity_hash: str,
        channel_id: Optional[str] = None,
        assigned_by: Optional[str] = None,
    ) -> RoleAssignment:
        # Explicit duplicate check — SQLite UNIQUE constraints don't prevent
        # duplicate NULLs, so we must guard global (channel_id=None) assignments.
        if channel_id is None:
            result = await self.session.execute(
                select(RoleAssignment).where(
                    RoleAssignment.role_id == role_id,
                    RoleAssignment.identity_hash == identity_hash,
                    RoleAssignment.channel_id.is_(None),
                )
            )
            existing = result.scalar_one_or_none()
            if existing:
                return existing
        assignment = RoleAssignment(
            role_id=role_id,
            identity_hash=identity_hash,
            channel_id=channel_id,
            assigned_by=assigned_by,
        )
        self.session.add(assignment)
        await self.session.flush()
        return assignment

    async def get_identity_roles(
        self,
        identity_hash: str,
        channel_id: Optional[str] = None,
        strict_channel_scope: bool = False,
    ) -> list[Role]:
        """Return roles assigned to ``identity_hash``.

        ``channel_id`` + ``strict_channel_scope=False`` (default): return the
        union of node-scoped (channel_id IS NULL) and channel-scoped rows.
        Used by the permission bitmask resolver so node_owner's node-wide
        role still applies globally.

        ``channel_id`` + ``strict_channel_scope=True``: return only rows where
        ``RoleAssignment.channel_id == channel_id``. Node-scoped rows are
        excluded. Used by private/sealed channel *membership* gates where
        access must be explicitly granted per-channel.
        """
        query = (
            select(Role)
            .join(RoleAssignment, Role.id == RoleAssignment.role_id)
            .where(RoleAssignment.identity_hash == identity_hash)
        )
        if channel_id:
            if strict_channel_scope:
                query = query.where(RoleAssignment.channel_id == channel_id)
            else:
                query = query.where(
                    or_(
                        RoleAssignment.channel_id == channel_id,
                        RoleAssignment.channel_id.is_(None),
                    )
                )
        else:
            query = query.where(RoleAssignment.channel_id.is_(None))
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_channel_overrides(
        self,
        channel_id: str,
        role_id: str,
    ) -> Optional[ChannelOverride]:
        result = await self.session.execute(
            select(ChannelOverride).where(
                and_(
                    ChannelOverride.channel_id == channel_id,
                    ChannelOverride.role_id == role_id,
                )
            )
        )
        return result.scalar_one_or_none()

    async def get_all_channel_overrides(
        self,
        channel_id: str,
        role_ids: list[str],
    ) -> dict[str, ChannelOverride]:
        """Batch-fetch overrides for a channel and multiple roles. Returns {role_id: override}."""
        if not role_ids:
            return {}
        result = await self.session.execute(
            select(ChannelOverride).where(
                and_(
                    ChannelOverride.channel_id == channel_id,
                    ChannelOverride.role_id.in_(role_ids),
                )
            )
        )
        return {o.role_id: o for o in result.scalars().all()}

    async def get_channel_member_hashes(self, channel_id: str) -> list[str]:
        """Return all identity hashes with a role assigned on a channel."""
        result = await self.session.execute(
            select(RoleAssignment.identity_hash)
            .where(RoleAssignment.channel_id == channel_id)
            .distinct()
        )
        return [r[0] for r in result.fetchall()]


class AuditLogRepo:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def log(
        self,
        actor: str,
        action_type: str,
        target: Optional[str] = None,
        channel_id: Optional[str] = None,
        details: Optional[dict] = None,
    ) -> AuditLog:
        entry = AuditLog(
            actor=actor,
            action_type=action_type,
            target=target,
            channel_id=channel_id,
            details=details or {},
        )
        self.session.add(entry)
        await self.session.flush()
        return entry

    async def get_recent(
        self,
        limit: int = 50,
        channel_id: Optional[str] = None,
        offset: Optional[int] = None,
    ) -> list[AuditLog]:
        query = select(AuditLog)
        if channel_id:
            query = query.where(AuditLog.channel_id == channel_id)
        query = query.order_by(AuditLog.timestamp.desc())
        if offset is not None:
            query = query.offset(offset)
        query = query.limit(limit)
        result = await self.session.execute(query)
        return list(result.scalars().all())


class SessionRepo:
    """Repository for CDSP session records."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_session(
        self,
        session_id: str,
        identity_hash: str,
        sync_profile: int,
        cdsp_version: int = 1,
        resume_token: Optional[bytes] = None,
        expires_at: Optional[float] = None,
    ) -> Session:
        sess = Session(
            session_id=session_id,
            identity_hash=identity_hash,
            sync_profile=sync_profile,
            cdsp_version=cdsp_version,
            state="active",
            resume_token=resume_token,
            expires_at=expires_at,
        )
        self.session.add(sess)
        await self.session.flush()
        return sess

    async def get_session(self, session_id: str) -> Optional[Session]:
        result = await self.session.execute(select(Session).where(Session.session_id == session_id))
        return result.scalar_one_or_none()

    async def get_active_session(self, identity_hash: str) -> Optional[Session]:
        result = await self.session.execute(
            select(Session)
            .where(
                and_(
                    Session.identity_hash == identity_hash,
                    Session.state == "active",
                )
            )
            .order_by(Session.last_activity.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def update_profile(self, session_id: str, sync_profile: int) -> Optional[Session]:
        sess = await self.get_session(session_id)
        if sess:
            sess.sync_profile = sync_profile
            sess.last_activity = time.time()
            await self.session.flush()
        return sess

    async def update_state(self, session_id: str, state: str) -> Optional[Session]:
        sess = await self.get_session(session_id)
        if sess:
            sess.state = state
            sess.last_activity = time.time()
            await self.session.flush()
        return sess

    async def touch(self, session_id: str):
        await self.session.execute(
            update(Session)
            .where(Session.session_id == session_id)
            .values(last_activity=time.time())
        )

    async def cleanup_expired(self, max_age: float) -> int:
        cutoff = time.time() - max_age
        result = await self.session.execute(
            delete(Session).where(
                or_(
                    Session.last_activity < cutoff,
                    and_(Session.expires_at.isnot(None), Session.expires_at < time.time()),
                )
            )
        )
        await self.session.flush()
        return result.rowcount


class DeferredSyncItemRepo:
    """Repository for deferred sync items."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def enqueue(
        self,
        session_id: str,
        channel_id: Optional[str],
        sync_action: int,
        payload: Optional[dict] = None,
        priority: int = 0,
        ttl: Optional[float] = None,
    ) -> DeferredSyncItem:
        item = DeferredSyncItem(
            session_id=session_id,
            channel_id=channel_id,
            sync_action=sync_action,
            payload=payload,
            priority=priority,
            expires_at=ttl,
        )
        self.session.add(item)
        await self.session.flush()
        return item

    async def flush_for_session(self, session_id: str, new_profile: int) -> list[DeferredSyncItem]:
        """Return deferred items now within scope of the new profile, then delete them."""
        result = await self.session.execute(
            select(DeferredSyncItem)
            .where(DeferredSyncItem.session_id == session_id)
            .order_by(DeferredSyncItem.priority.desc(), DeferredSyncItem.created_at.asc())
        )
        items = list(result.scalars().all())

        flushed = []
        for item in items:
            flushed.append(item)
            await self.session.delete(item)

        await self.session.flush()
        return flushed

    async def count_for_session(self, session_id: str) -> int:
        result = await self.session.execute(
            select(func.count())
            .select_from(DeferredSyncItem)
            .where(DeferredSyncItem.session_id == session_id)
        )
        return result.scalar() or 0

    async def evict_oldest(self, session_id: str, keep_limit: int) -> int:
        keep_q = (
            select(DeferredSyncItem.id)
            .where(DeferredSyncItem.session_id == session_id)
            .order_by(DeferredSyncItem.created_at.desc())
            .limit(keep_limit)
        )
        keep_result = await self.session.execute(keep_q)
        keep_ids = {row[0] for row in keep_result.all()}

        if not keep_ids:
            return 0

        all_q = await self.session.execute(
            select(DeferredSyncItem).where(
                and_(
                    DeferredSyncItem.session_id == session_id,
                    ~DeferredSyncItem.id.in_(keep_ids),
                )
            )
        )
        to_delete = list(all_q.scalars().all())
        for item in to_delete:
            await self.session.delete(item)
        await self.session.flush()
        return len(to_delete)

    async def cleanup_expired(self) -> int:
        now = time.time()
        result = await self.session.execute(
            delete(DeferredSyncItem).where(
                and_(
                    DeferredSyncItem.expires_at.isnot(None),
                    DeferredSyncItem.expires_at < now,
                )
            )
        )
        await self.session.flush()
        return result.rowcount


class EpochStateRepo:
    """Repository for forward secrecy epoch state."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def get(self, peer_hash: str) -> Optional[FederationEpochState]:
        result = await self.session.execute(
            select(FederationEpochState).where(FederationEpochState.peer_identity_hash == peer_hash)
        )
        return result.scalar_one_or_none()

    async def upsert(self, peer_hash: str, **kwargs) -> FederationEpochState:
        existing = await self.get(peer_hash)
        if existing:
            for k, v in kwargs.items():
                setattr(existing, k, v)
            existing.updated_at = time.time()
            await self.session.flush()
            return existing
        else:
            state = FederationEpochState(peer_identity_hash=peer_hash, **kwargs)
            state.updated_at = time.time()
            self.session.add(state)
            await self.session.flush()
            return state

    async def delete(self, peer_hash: str) -> None:
        await self.session.execute(
            delete(FederationEpochState).where(FederationEpochState.peer_identity_hash == peer_hash)
        )
        await self.session.flush()


class PendingSealedDistributionRepo:
    """Repository for the deferred sealed-key distribution queue.

    See ``security.sealed.distribute_sealed_key_to_identity`` for the
    distribution chokepoint and ``federation.peering.PeerDiscovery`` for
    the announce-driven drain hook.
    """

    def __init__(self, session: AsyncSession):
        self.session = session

    async def enqueue(
        self,
        channel_id: str,
        identity_hash: str,
        role_id: str,
    ) -> PendingSealedDistribution:
        """Insert a queue entry. Idempotent on the
        ``(channel_id, identity_hash, role_id)`` triple — duplicate
        enqueues raise via the UNIQUE constraint and are caught here so
        the operator-side CLI never sees a confusing IntegrityError when
        re-running an assign while the peer is still offline.
        """
        existing = (
            await self.session.execute(
                select(PendingSealedDistribution)
                .where(PendingSealedDistribution.channel_id == channel_id)
                .where(PendingSealedDistribution.identity_hash == identity_hash)
                .where(PendingSealedDistribution.role_id == role_id)
            )
        ).scalar_one_or_none()
        if existing is not None:
            return existing

        entry = PendingSealedDistribution(
            channel_id=channel_id,
            identity_hash=identity_hash,
            role_id=role_id,
            queued_at=time.time(),
            retry_count=0,
        )
        self.session.add(entry)
        await self.session.flush()
        return entry

    async def list_for_identity(self, identity_hash: str) -> list[PendingSealedDistribution]:
        result = await self.session.execute(
            select(PendingSealedDistribution).where(
                PendingSealedDistribution.identity_hash == identity_hash
            )
        )
        return list(result.scalars().all())

    async def list_all(self, channel_id: Optional[str] = None) -> list[PendingSealedDistribution]:
        stmt = select(PendingSealedDistribution).order_by(PendingSealedDistribution.queued_at.asc())
        if channel_id is not None:
            stmt = stmt.where(PendingSealedDistribution.channel_id == channel_id)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def evict(self, entry_id: int) -> None:
        await self.session.execute(
            delete(PendingSealedDistribution).where(PendingSealedDistribution.id == entry_id)
        )
        await self.session.flush()

    async def increment_retry(self, entry_id: int, error: str) -> None:
        await self.session.execute(
            update(PendingSealedDistribution)
            .where(PendingSealedDistribution.id == entry_id)
            .values(
                retry_count=PendingSealedDistribution.retry_count + 1,
                last_attempt_at=time.time(),
                last_error=error,
            )
        )
        await self.session.flush()
