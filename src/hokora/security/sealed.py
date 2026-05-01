# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Sealed channel encryption: AES-256-GCM group key management."""

from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
from typing import TYPE_CHECKING, Optional

import msgpack
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from hokora.exceptions import SealedChannelError, SealedKeyDistributionDeferred

if TYPE_CHECKING:
    import RNS  # noqa: F401

logger = logging.getLogger(__name__)

# Cap on retained prior-epoch keys per channel. Bounded memory + bounded
# DB-load fan-out at startup; ciphertext older than this many rotations
# cannot be decrypted on this node.
_MAX_PREVIOUS_KEYS = 5


async def load_peer_rns_identity(identity_hash: str) -> "RNS.Identity":
    """Resolve a peer ``identity_hash`` to a fully-populated RNS.Identity.

    This is the **single chokepoint** for getting a peer's full RNS public
    key (X25519 encryption key + Ed25519 signing key) when we need to
    envelope-encrypt to them — currently used only by sealed-key
    distribution (``security.sealed.distribute_sealed_key_to_identity``).

    Why not use ``identities.public_key`` from the database? Migration
    014 chopped that column to 32 bytes (Ed25519 only), because the
    X25519 half was never used for anything else and storing the full
    64-byte blob breaks ``verify_ed25519_signature`` (which strictly
    requires a 32-byte Ed25519 key). The X25519 half is therefore not
    in our database. RNS's ``known_destinations`` cache **is** the
    canonical source — it is populated by every announce we've ever
    received and persisted to disk via ``Transport.persist_data()``.
    No reason to duplicate it.

    Behaviour:

    - If RNS has the identity in its cache, return a fresh
      ``RNS.Identity`` ready for ``encrypt(plaintext)``.
    - If not, issue a ``Transport.request_path(identity_hash)`` (cheap,
      non-blocking — the response comes back asynchronously via the next
      announce) and raise :class:`SealedKeyDistributionDeferred`. The
      caller should report this clearly so the operator can retry once
      the peer has announced (typically: peer connects via TUI).

    The path-request side-effect means a transient cache miss usually
    resolves itself within a few seconds; a permanent miss means the peer
    has never announced (which is a real operational problem, not
    something we can paper over).

    Async: the 3 s polling loop yields via ``asyncio.sleep`` so callers
    inside the daemon's event loop (e.g. the announce-driven drain at
    ``federation/peering.py``) don't block other coroutines while
    waiting for the path response.
    """
    import RNS

    try:
        target = bytes.fromhex(identity_hash)
    except ValueError as exc:
        raise SealedKeyDistributionDeferred(
            f"Invalid identity_hash {identity_hash!r}: {exc}"
        ) from exc

    ident = RNS.Identity.recall(target, from_identity_hash=True)
    if ident is not None:
        return ident

    # Cache miss on first try. Issue a path request — when running as a
    # shared-instance client of a live daemon, the request forwards to
    # the daemon, which answers from its in-memory path cache and
    # populates this process's ``known_destinations`` via the response.
    # Then poll for up to ~3 s before declaring deferred.
    try:
        RNS.Transport.request_path(target)
    except Exception:
        logger.debug("request_path for %s raised; ignoring", identity_hash[:16])

    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        await asyncio.sleep(0.25)
        ident = RNS.Identity.recall(target, from_identity_hash=True)
        if ident is not None:
            return ident

    raise SealedKeyDistributionDeferred(
        f"Peer {identity_hash[:16]} not in RNS path cache after path request "
        f"(3 s wait). Cannot envelope-encrypt sealed key. Retry the role "
        f"assign / invite redeem after the peer has announced (typically: "
        f"peer connects once via TUI)."
    )


async def distribute_sealed_key_to_identity(
    session,
    channel_id: str,
    identity_hash: str,
    node_identity: Optional["RNS.Identity"] = None,
) -> None:
    """Envelope-encrypt the channel group key for ``identity_hash`` and persist a SealedKey row.

    Single chokepoint for sealed-key distribution. Used by:

    - CLI ``role assign`` (operator-driven grant; ``node_identity=None`` so the
      helper loads it from disk).
    - Daemon announce-driven drainer for ``pending_sealed_distributions``
      (``node_identity`` passed in so we don't re-read the identity
      file on every announce).

    Preconditions:

    1. A node-owner SealedKey row exists at the latest epoch (channel has a
       provisioned group key).
    2. The recipient is in RNS's path cache; ``load_peer_rns_identity`` is
       the chokepoint and raises :class:`SealedKeyDistributionDeferred` if not.

    Raises:
        RuntimeError: when the channel has no provisioned group key.
        SealedKeyDistributionDeferred: when the recipient is not in RNS's
            path cache.
    """
    import RNS
    from sqlalchemy import select

    from hokora.config import load_config
    from hokora.db.models import SealedKey

    if node_identity is None:
        cfg = load_config()
        id_path = cfg.identity_dir / "node_identity"
        node_identity = RNS.Identity.from_file(str(id_path))

    owner_key = (
        await session.execute(
            select(SealedKey)
            .where(SealedKey.channel_id == channel_id)
            .where(SealedKey.identity_hash == node_identity.hexhash)
            .order_by(SealedKey.epoch.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if owner_key is None:
        raise RuntimeError("No node-owner SealedKey — channel has no provisioned group key")
    group_key = node_identity.decrypt(owner_key.encrypted_key_blob)

    peer_identity = await load_peer_rns_identity(identity_hash)
    encrypted_blob = peer_identity.encrypt(group_key)

    session.add(
        SealedKey(
            channel_id=channel_id,
            epoch=owner_key.epoch,
            encrypted_key_blob=encrypted_blob,
            identity_hash=identity_hash,
            created_at=time.time(),
        )
    )


class SealedChannelManager:
    """Manages AES-256-GCM group symmetric keys for sealed (private) channels."""

    def __init__(self):
        # channel_id -> {epoch, key}
        self._keys: dict[str, dict] = {}
        # channel_id -> [{epoch, key}, ...] in ascending-epoch order;
        # newest at the end, capped at _MAX_PREVIOUS_KEYS. Consulted by
        # decrypt() when the caller supplies a non-current epoch (e.g.
        # ciphertext stored before the most recent rotation).
        self._previous_keys: dict[str, list[dict]] = {}
        # threading.Lock (not asyncio.Lock): accessed from both async handlers
        # and synchronous LXMF/RNS callbacks (e.g., key distribution).
        self._lock = threading.Lock()

    def generate_key(self, channel_id: str, session=None) -> tuple[bytes, int]:
        """Generate a new AES-256-GCM key for a channel. Returns (key, epoch)."""
        key = AESGCM.generate_key(bit_length=256)
        with self._lock:
            current = self._keys.get(channel_id, {})
            epoch = current.get("epoch", 0) + 1
            self._keys[channel_id] = {"key": key, "epoch": epoch}
        logger.info(f"Generated sealed key for channel {channel_id} epoch={epoch}")
        return key, epoch

    def encrypt(self, channel_id: str, plaintext: bytes) -> tuple[bytes, bytes, int]:
        """Encrypt data for a sealed channel. Returns (nonce, ciphertext, epoch)."""
        with self._lock:
            key_info = self._keys.get(channel_id)
            if not key_info:
                raise SealedChannelError(f"No key for channel {channel_id}")
            key = key_info["key"]
            epoch = key_info["epoch"]

        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, channel_id.encode("utf-8"))
        return nonce, ciphertext, epoch

    def decrypt(
        self,
        channel_id: str,
        nonce: bytes,
        ciphertext: bytes,
        epoch: Optional[int] = None,
    ) -> bytes:
        """Decrypt data from a sealed channel.

        When ``epoch`` is None or matches the current epoch, the active
        key is used. When it names an older epoch, the matching entry is
        looked up in ``_previous_keys`` so messages encrypted before a
        rotation remain decryptable. Raises ``SealedChannelError`` if
        the requested epoch is older than the retained window.
        """
        with self._lock:
            key_info = self._keys.get(channel_id)
            if not key_info:
                raise SealedChannelError(f"No key for channel {channel_id}")
            if epoch is None or epoch == key_info["epoch"]:
                key = key_info["key"]
            else:
                match = next(
                    (p for p in self._previous_keys.get(channel_id, []) if p["epoch"] == epoch),
                    None,
                )
                if match is None:
                    raise SealedChannelError(
                        f"Key epoch {epoch} unavailable for channel {channel_id}: "
                        f"current={key_info['epoch']}, "
                        f"retained={[p['epoch'] for p in self._previous_keys.get(channel_id, [])]}"
                    )
                key = match["key"]

        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, channel_id.encode("utf-8"))

    def get_key(self, channel_id: str) -> Optional[bytes]:
        with self._lock:
            info = self._keys.get(channel_id)
            return info["key"] if info else None

    def get_epoch(self, channel_id: str) -> int:
        with self._lock:
            info = self._keys.get(channel_id)
            return info["epoch"] if info else 0

    def rotate_key(self, channel_id: str, session=None) -> tuple[bytes, int]:
        """Rotate the key for a sealed channel (e.g., on member removal).

        The outgoing key is appended to ``_previous_keys[channel_id]``
        (newest at the end, capped at ``_MAX_PREVIOUS_KEYS``) so
        ``decrypt`` can still serve ciphertext encrypted under the prior
        epoch.
        """
        with self._lock:
            old_info = self._keys.get(channel_id)
            if old_info:
                history = self._previous_keys.setdefault(channel_id, [])
                history.append(dict(old_info))
                if len(history) > _MAX_PREVIOUS_KEYS:
                    self._previous_keys[channel_id] = history[-_MAX_PREVIOUS_KEYS:]
                logger.info(f"Preserved old key for channel {channel_id} epoch={old_info['epoch']}")

        return self.generate_key(channel_id, session=session)

    async def persist_key(self, session, channel_id: str, node_identity) -> None:
        """Encrypt current key with node identity and write to SealedKey table."""
        from hokora.db.models import SealedKey

        with self._lock:
            key_info = self._keys.get(channel_id)
            if not key_info:
                raise SealedChannelError(f"No key for channel {channel_id}")
            key = key_info["key"]
            epoch = key_info["epoch"]

        # Encrypt the group key with the node's identity
        encrypted_blob = node_identity.encrypt(key)
        node_hash = node_identity.hexhash

        sealed_key = SealedKey(
            channel_id=channel_id,
            epoch=epoch,
            encrypted_key_blob=encrypted_blob,
            identity_hash=node_hash,
            created_at=time.time(),
        )
        session.add(sealed_key)
        logger.info(
            f"Persisted sealed key for channel {channel_id} epoch={epoch} identity={node_hash[:16]}"
        )

    async def load_keys(self, session, node_identity) -> None:
        """Load and decrypt sealed keys from DB into ``_keys`` and ``_previous_keys``.

        Hydrates the latest epoch as the active key plus up to
        ``_MAX_PREVIOUS_KEYS`` prior epochs, so ciphertext encrypted
        before a rotation remains decryptable across daemon restarts.
        """
        from hokora.db.models import SealedKey, Channel
        from sqlalchemy import select

        node_hash = node_identity.hexhash

        result = await session.execute(select(Channel).where(Channel.sealed.is_(True)))
        sealed_channels = result.scalars().all()

        for ch in sealed_channels:
            key_result = await session.execute(
                select(SealedKey)
                .where(SealedKey.channel_id == ch.id)
                .where(SealedKey.identity_hash == node_hash)
                .order_by(SealedKey.epoch.desc())
                .limit(_MAX_PREVIOUS_KEYS + 1)
            )
            rows = key_result.scalars().all()
            if not rows:
                continue
            try:
                current_key = node_identity.decrypt(rows[0].encrypted_key_blob)
            except Exception:
                logger.warning(f"Failed to decrypt sealed key for channel {ch.id}")
                continue
            with self._lock:
                self._keys[ch.id] = {"key": current_key, "epoch": rows[0].epoch}
            logger.info(f"Loaded sealed key for channel {ch.id} epoch={rows[0].epoch}")
            # Hydrate retained prior epochs, oldest-first to match the
            # in-memory rotate_key append order.
            history: list[dict] = []
            for older in reversed(rows[1:]):
                try:
                    k = node_identity.decrypt(older.encrypted_key_blob)
                    history.append({"key": k, "epoch": older.epoch})
                except Exception:
                    logger.warning(
                        f"Failed to decrypt historical sealed key for channel {ch.id} "
                        f"epoch={older.epoch}"
                    )
            if history:
                with self._lock:
                    self._previous_keys[ch.id] = history

    def distribute_key(
        self,
        channel_id: str,
        member_hashes: list[str],
        lxmf_router,
        node_identity,
    ) -> list[dict]:
        """Distribute the group key to members via LXMF.

        Encrypts the group key individually for each member using their
        Reticulum identity's public key, then sends via LXMF.

        Returns list of {identity_hash, success} dicts.
        """
        import RNS
        import LXMF

        with self._lock:
            key_info = self._keys.get(channel_id)
            if not key_info:
                raise SealedChannelError(f"No key for channel {channel_id}")
            group_key = key_info["key"]
            epoch = key_info["epoch"]

        results = []

        for member_hash in member_hashes:
            try:
                # Recall the member's identity for encryption
                member_identity = RNS.Identity.recall(bytes.fromhex(member_hash))
                if not member_identity:
                    logger.warning(
                        f"Cannot recall identity for {member_hash}, skipping key distribution"
                    )
                    results.append({"identity_hash": member_hash, "success": False})
                    continue

                # Encrypt group key with member's public key
                encrypted_key = member_identity.encrypt(group_key)

                # Build LXMF message with sealed key payload
                payload = msgpack.packb(
                    {
                        "type": "sealed_key",
                        "channel_id": channel_id,
                        "epoch": epoch,
                        "encrypted_key": encrypted_key,
                    },
                    use_bin_type=True,
                )

                # Create LXMF destination for the member
                member_dest = RNS.Destination(
                    member_identity,
                    RNS.Destination.OUT,
                    RNS.Destination.SINGLE,
                    "hokora",
                    "key_exchange",
                )

                # LXMRouter.get_delivery_destination() was removed in LXMF
                # 0.9; construct the sender-side delivery destination
                # explicitly from the node identity. Matches the manual-
                # destination pattern already used elsewhere in the
                # codebase (see protocol/lxmf_bridge.py and cli/channel.py).
                sender_delivery = RNS.Destination(
                    node_identity,
                    RNS.Destination.IN,
                    RNS.Destination.SINGLE,
                    "lxmf",
                    "delivery",
                )

                lxm = LXMF.LXMessage(
                    member_dest,
                    sender_delivery,
                    payload,
                    desired_method=LXMF.LXMessage.DIRECT,
                )
                lxmf_router.handle_outbound(lxm)

                logger.info(f"Distributed sealed key to {member_hash} (epoch={epoch})")
                results.append({"identity_hash": member_hash, "success": True})

            except Exception:
                logger.exception(f"Failed to distribute key to {member_hash}")
                results.append({"identity_hash": member_hash, "success": False})

        return results

    def rotate_and_distribute(
        self,
        channel_id: str,
        member_hashes: list[str],
        lxmf_router,
        node_identity,
    ) -> tuple[bytes, int, list[dict]]:
        """Rotate key and distribute to all remaining members.

        Used when a member is removed from a sealed channel.
        """
        key, epoch = self.rotate_key(channel_id)
        results = self.distribute_key(channel_id, member_hashes, lxmf_router, node_identity)
        return key, epoch, results
