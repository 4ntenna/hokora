# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""SealedKeyBootstrap: idempotent startup tasks enforcing the sealed invariant."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from sqlalchemy import delete, select, text, update

from hokora.db.models import Channel, Message, SealedKey

if TYPE_CHECKING:
    from hokora.core.identity import IdentityManager
    from hokora.security.sealed import SealedChannelManager

logger = logging.getLogger(__name__)


class SealedKeyBootstrap:
    """One-shot startup tasks that enforce the sealed-channel invariant.

    Pure function of (session_factory, sealed_manager, identity_manager) —
    no daemon coupling. All three phases are idempotent; on clean deploys
    ``bootstrap_missing_keys`` and ``purge_plaintext_from_sealed_channels``
    are no-ops.
    """

    def __init__(
        self,
        session_factory,
        sealed_manager: "SealedChannelManager",
        identity_manager: "IdentityManager",
    ) -> None:
        self._session_factory = session_factory
        self._sealed_manager = sealed_manager
        self._identity_manager = identity_manager

    async def load_existing_keys(self) -> int:
        """Load persisted sealed keys from DB into the in-memory manager.

        Returns the number of keys successfully loaded.
        """
        if not self._sealed_manager:
            return 0
        loaded = 0
        try:
            async with self._session_factory() as session:
                async with session.begin():
                    result = await session.execute(select(Channel).where(Channel.sealed.is_(True)))
                    sealed_channels = result.scalars().all()

                    node_hash = self._identity_manager.get_node_identity_hash()
                    for ch in sealed_channels:
                        key_result = await session.execute(
                            select(SealedKey)
                            .where(SealedKey.channel_id == ch.id)
                            .where(SealedKey.identity_hash == node_hash)
                            .order_by(SealedKey.epoch.desc())
                            .limit(1)
                        )
                        sk = key_result.scalar_one_or_none()
                        if sk:
                            try:
                                node_identity = self._identity_manager.get_node_identity()
                                if node_identity:
                                    group_key = node_identity.decrypt(sk.encrypted_key_blob)
                                    with self._sealed_manager._lock:
                                        self._sealed_manager._keys[ch.id] = {
                                            "key": group_key,
                                            "epoch": sk.epoch,
                                        }
                                    loaded += 1
                                    logger.info(
                                        f"Loaded sealed key for channel {ch.id} epoch={sk.epoch}"
                                    )
                            except Exception:
                                logger.warning(f"Failed to decrypt sealed key for channel {ch.id}")
        except Exception:
            logger.exception("Failed to load sealed keys")
        return loaded

    async def bootstrap_missing_keys(self) -> list[str]:
        """Generate a node-owner SealedKey for every sealed channel missing one.

        Covers channels sealed before the invariant landed, channels created
        without immediate key generation, and first-time deployment.

        Returns the list of channel_ids that received a new key.
        """
        bootstrapped: list[str] = []
        if not self._sealed_manager:
            return bootstrapped
        try:
            async with self._session_factory() as session:
                async with session.begin():
                    result = await session.execute(select(Channel).where(Channel.sealed.is_(True)))
                    sealed_channels = result.scalars().all()

                    node_identity = self._identity_manager.get_node_identity()
                    if not node_identity:
                        logger.warning("Cannot bootstrap sealed keys: node identity unavailable")
                        return bootstrapped

                    for ch in sealed_channels:
                        if self._sealed_manager.get_key(ch.id) is None:
                            self._sealed_manager.generate_key(ch.id)
                            await self._sealed_manager.persist_key(session, ch.id, node_identity)
                            bootstrapped.append(ch.id)
                            logger.info(
                                f"Bootstrapped initial sealed key for channel {ch.name} ({ch.id})"
                            )
        except Exception:
            logger.exception("Failed to initialize missing sealed keys")
        return bootstrapped

    async def purge_plaintext_from_sealed_channels(self) -> int:
        """Enforce the sealed invariant retroactively.

        Two phases:

        1. **Delete** rows where ``encrypted_body IS NULL`` — pre-invariant
           rows with only plaintext at rest. These were never valid under
           the sealed model; deletion is the safe default.
        2. **Nullify plaintext** on rows where both ``body`` and
           ``encrypted_body`` are populated — legacy rows produced by
           mutation paths that did not route through the sealed helper.
           We keep the ciphertext and strip the plaintext column, then
           prune the matching FTS5 row so the plaintext is not
           searchable either.

        The FTS5 ``messages_au`` update trigger fires only when
        ``new.body IS NOT NULL``, so setting ``body = NULL`` does not
        propagate to the FTS index — we issue explicit per-row deletes
        against ``messages_fts`` using the saved rowid/body snapshot.

        Returns the total row count affected (deletes + nullifies).
        """
        total = 0
        try:
            async with self._session_factory() as session:
                async with session.begin():
                    sealed_ids_q = select(Channel.id).where(Channel.sealed.is_(True))
                    sealed_ids = list((await session.execute(sealed_ids_q)).scalars().all())
                    if not sealed_ids:
                        return 0

                    # Step 1 — delete rows with no ciphertext at all.
                    del_result = await session.execute(
                        delete(Message)
                        .where(Message.channel_id.in_(sealed_ids))
                        .where(Message.encrypted_body.is_(None))
                    )
                    deleted = del_result.rowcount or 0
                    total += deleted

                    # Step 2 — snapshot + nullify + FTS purge for rows that
                    # have both plaintext body AND ciphertext. Snapshot must
                    # happen BEFORE the UPDATE — after, the FTS DELETE
                    # synthetic row needs the old body string to match the
                    # FTS entry. rowid is the implicit SQLite rowid on the
                    # messages table (aliased in the FTS trigger).
                    snap = await session.execute(
                        select(
                            Message.__table__.c.rowid
                            if hasattr(Message.__table__.c, "rowid")
                            else text("rowid"),
                            Message.msg_hash,
                            Message.channel_id,
                            Message.body,
                        )
                        .where(Message.channel_id.in_(sealed_ids))
                        .where(Message.encrypted_body.isnot(None))
                        .where(Message.body.isnot(None))
                    )
                    leaked_rows = snap.fetchall()

                    if leaked_rows:
                        # Strip plaintext body (and any media_path, which
                        # would leak filename metadata for sealed media).
                        # The FTS ``messages_au`` trigger does not fire on
                        # ``new.body IS NULL``, so we handle FTS manually.
                        await session.execute(
                            update(Message)
                            .where(Message.channel_id.in_(sealed_ids))
                            .where(Message.encrypted_body.isnot(None))
                            .where(Message.body.isnot(None))
                            .values(body=None, media_path=None)
                        )

                        for rowid, msg_hash, channel_id, old_body in leaked_rows:
                            await session.execute(
                                text(
                                    "INSERT INTO messages_fts"
                                    "(messages_fts, rowid, msg_hash, channel_id, body) "
                                    "VALUES ('delete', :rowid, :msg_hash, :channel_id, :body)"
                                ),
                                {
                                    "rowid": rowid,
                                    "msg_hash": msg_hash,
                                    "channel_id": channel_id,
                                    "body": old_body,
                                },
                            )
                        total += len(leaked_rows)

                    if total:
                        logger.warning(
                            f"Sealed invariant purge: deleted={deleted} "
                            f"plaintext_nullified={len(leaked_rows) if leaked_rows else 0}"
                        )
                    return total
        except Exception:
            logger.exception("Failed to purge plaintext from sealed channels")
            return 0

    async def run_all(self) -> None:
        """Convenience: run all three phases in order (load → bootstrap → purge)."""
        await self.load_existing_keys()
        await self.bootstrap_missing_keys()
        await self.purge_plaintext_from_sealed_channels()
