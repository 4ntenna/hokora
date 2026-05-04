# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Stateful epoch lifecycle manager for forward secrecy."""

import asyncio
import logging
import struct
import time
from typing import Optional, Callable

from hokora.constants import (
    EPOCH_NONCE_OVERFLOW,
    EPOCH_MAX_RETRIES,
    EPOCH_INITIAL_BACKOFF,
    EPOCH_ROTATE_TIMEOUT,
)
from hokora.exceptions import EpochError
from hokora.federation.epoch_crypto import (
    generate_x25519_keypair,
    derive_epoch_keys,
    compute_chain_hash,
    generate_nonce_prefix,
    build_nonce,
    encrypt_payload,
    decrypt_payload,
    secure_erase,
    derive_kek,
    wrap_key,
    unwrap_key,
)
from hokora.federation.epoch_wire import (
    encode_epoch_rotate,
    decode_epoch_rotate,
    encode_epoch_rotate_ack,
    decode_epoch_rotate_ack,
    encode_epoch_data,
    decode_epoch_data,
)

logger = logging.getLogger(__name__)


class EpochManager:
    """Manages forward secrecy epoch lifecycle for a single federation link."""

    def __init__(
        self,
        peer_identity_hash: str,
        is_initiator: bool,
        local_rns_identity,
        epoch_duration: int = 3600,
        on_send: Optional[Callable[[bytes], None]] = None,
        session_factory=None,
        peer_rns_identity=None,
    ):
        self.peer_identity_hash = peer_identity_hash
        self.is_initiator = is_initiator
        self._local_identity = local_rns_identity
        self._peer_identity = peer_rns_identity
        self.epoch_duration = epoch_duration
        self._on_send = on_send
        self._session_factory = session_factory

        # Current epoch state
        self._current_epoch_id: int = 0
        self._send_key: Optional[bytearray] = None
        self._recv_key: Optional[bytearray] = None
        self._prev_recv_key: Optional[bytearray] = None
        self._prev_epoch_id: int = 0
        self._nonce_prefix: bytes = b""
        self._message_counter: int = 0
        self._last_chain_hash: bytes = b"\x00" * 32
        self._epoch_start_time: float = 0.0

        # Pending handshake state
        self._pending_private_key = None
        self._pending_public_key: bytes = b""

        # Rotation scheduler
        self._rotation_task: Optional[asyncio.Task] = None
        self._torn_down = False

    @property
    def is_active(self) -> bool:
        """True if epoch keys are set and ready for encrypt/decrypt."""
        return self._send_key is not None and self._recv_key is not None

    def create_epoch_rotate(self) -> bytes:
        """Step 5: initiator creates an EpochRotate frame."""
        new_epoch_id = self._current_epoch_id + 1

        private_key, public_bytes = generate_x25519_keypair()
        self._pending_private_key = private_key
        self._pending_public_key = public_bytes

        # Sign the frame content for authentication
        sign_data = (
            struct.pack(">Q", new_epoch_id)
            + struct.pack(">I", self.epoch_duration)
            + public_bytes
            + self._last_chain_hash
        )
        signature = self._local_identity.sign(sign_data)

        return encode_epoch_rotate(
            new_epoch_id,
            self.epoch_duration,
            public_bytes,
            self._last_chain_hash,
            signature,
        )

    def handle_epoch_rotate(self, data: bytes) -> bytes:
        """Step 5 (responder): process EpochRotate, return EpochRotateAck."""
        parsed = decode_epoch_rotate(data)
        new_epoch_id = parsed["epoch_id"]
        remote_pubkey = parsed["eph_pubkey"]
        prev_hash = parsed["prev_epoch_hash"]
        signature = parsed["signature"]

        # Verify the initiator's signature before trusting the frame
        if self._peer_identity is None:
            raise EpochError("Cannot verify EpochRotate: no peer identity available")
        sign_data = (
            struct.pack(">Q", new_epoch_id)
            + struct.pack(">I", parsed["epoch_duration"])
            + remote_pubkey
            + prev_hash
        )
        if not self._peer_identity.validate(signature, sign_data):
            raise EpochError("EpochRotate signature verification failed — possible MITM")

        # Validate epoch progression
        if new_epoch_id <= self._current_epoch_id:
            raise EpochError(f"Epoch ID regression: {new_epoch_id} <= {self._current_epoch_id}")

        # Validate chain hash continuity
        if prev_hash != self._last_chain_hash:
            raise EpochError("Chain hash mismatch in EpochRotate")

        # Generate our ephemeral keypair
        private_key, public_bytes = generate_x25519_keypair()

        # Derive keys
        i2r_key, r2i_key = derive_epoch_keys(
            private_key, remote_pubkey, new_epoch_id, is_initiator=False
        )

        # Responder: recv = i2r (initiator sends with i2r), send = r2i
        self._activate_epoch(
            new_epoch_id, send_key=r2i_key, recv_key=i2r_key, i2r_key_bytes=bytes(i2r_key)
        )

        # Sign our ack
        sign_data = struct.pack(">Q", new_epoch_id) + public_bytes + self._last_chain_hash
        signature = self._local_identity.sign(sign_data)

        return encode_epoch_rotate_ack(
            new_epoch_id,
            public_bytes,
            self._last_chain_hash,
            signature,
        )

    def handle_epoch_rotate_ack(self, data: bytes) -> None:
        """Step 6: initiator completes epoch setup from Ack."""
        parsed = decode_epoch_rotate_ack(data)
        new_epoch_id = parsed["epoch_id"]
        remote_pubkey = parsed["eph_pubkey"]
        signature = parsed["signature"]

        # Verify the responder's signature before trusting the ack
        if self._peer_identity is None:
            raise EpochError("Cannot verify EpochRotateAck: no peer identity available")
        sign_data = struct.pack(">Q", new_epoch_id) + remote_pubkey + parsed["prev_epoch_hash"]
        if not self._peer_identity.validate(signature, sign_data):
            raise EpochError("EpochRotateAck signature verification failed — possible MITM")

        if self._pending_private_key is None:
            raise EpochError("No pending key exchange for EpochRotateAck")

        # Derive keys
        i2r_key, r2i_key = derive_epoch_keys(
            self._pending_private_key, remote_pubkey, new_epoch_id, is_initiator=True
        )

        # Initiator: send = i2r, recv = r2i
        self._activate_epoch(
            new_epoch_id, send_key=i2r_key, recv_key=r2i_key, i2r_key_bytes=bytes(i2r_key)
        )

        # Clear pending handshake state — extract raw bytes for best-effort erasure
        if self._pending_private_key is not None:
            try:
                raw = bytearray(self._pending_private_key.private_bytes_raw())
                secure_erase(raw)
            except Exception:
                pass  # Best effort; GC will eventually reclaim
        self._pending_private_key = None
        self._pending_public_key = b""

    def _activate_epoch(
        self,
        epoch_id: int,
        send_key: bytearray,
        recv_key: bytearray,
        i2r_key_bytes: bytes = b"",
    ) -> None:
        """Transition to a new epoch, retaining previous recv key briefly.

        Args:
            i2r_key_bytes: The initiator-to-responder key bytes, used to compute
                a deterministic chain hash that both sides agree on.
        """
        # Move current recv key to prev for transition window
        if self._prev_recv_key is not None:
            secure_erase(self._prev_recv_key)
        self._prev_recv_key = self._recv_key
        self._prev_epoch_id = self._current_epoch_id

        # Erase old send key
        if self._send_key is not None:
            secure_erase(self._send_key)

        self._current_epoch_id = epoch_id
        self._send_key = send_key
        self._recv_key = recv_key
        self._nonce_prefix = generate_nonce_prefix()
        self._message_counter = 0
        # Chain hash uses i2r key so both sides compute the same value
        self._last_chain_hash = compute_chain_hash(i2r_key_bytes or bytes(send_key))
        self._epoch_start_time = time.time()

        logger.info(
            f"Epoch {epoch_id} activated for peer {self.peer_identity_hash[:16]} "
            f"(initiator={self.is_initiator})"
        )

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt plaintext and wrap in an EpochData frame."""
        if not self.is_active:
            raise EpochError("Cannot encrypt: no active epoch")

        if self._message_counter >= EPOCH_NONCE_OVERFLOW:
            raise EpochError("Nonce counter overflow — emergency rotation required")

        nonce = build_nonce(self._nonce_prefix, self._message_counter)
        self._message_counter += 1

        aad = struct.pack(">Q", self._current_epoch_id)
        ciphertext = encrypt_payload(bytes(self._send_key), nonce, plaintext, aad)

        return encode_epoch_data(self._current_epoch_id, nonce, ciphertext)

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt an EpochData frame."""
        parsed = decode_epoch_data(data)
        epoch_id = parsed["epoch_id"]
        nonce = parsed["nonce"]
        ciphertext = parsed["ciphertext"]

        aad = struct.pack(">Q", epoch_id)

        # Try current key first
        if epoch_id == self._current_epoch_id and self._recv_key:
            result = decrypt_payload(bytes(self._recv_key), nonce, ciphertext, aad)
            # First successful decrypt under new key: erase prev
            if self._prev_recv_key is not None:
                secure_erase(self._prev_recv_key)
                self._prev_recv_key = None
            return result

        # Try previous key during transition window
        if epoch_id == self._prev_epoch_id and self._prev_recv_key:
            return decrypt_payload(bytes(self._prev_recv_key), nonce, ciphertext, aad)

        raise EpochError(f"No key for epoch {epoch_id}")

    def start_rotation_scheduler(self, loop: asyncio.AbstractEventLoop) -> None:
        """Start the async rotation timer."""
        if self.is_initiator and not self._torn_down:
            self._rotation_task = loop.create_task(self._rotation_loop())

    async def _rotation_loop(self) -> None:
        """Periodic rotation: sleep for epoch_duration, then rotate."""
        while not self._torn_down:
            try:
                await asyncio.sleep(self.epoch_duration)
                if self._torn_down:
                    break
                await self._do_rotation()
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Rotation loop error")

    async def _do_rotation(self) -> None:
        """Perform one rotation with retry/backoff."""
        for attempt in range(EPOCH_MAX_RETRIES):
            try:
                expected_epoch = self._current_epoch_id + 1
                frame = self.create_epoch_rotate()
                if self._on_send:
                    self._on_send(frame)

                # Wait for ack (handled externally via handle_epoch_rotate_ack)
                deadline = time.time() + EPOCH_ROTATE_TIMEOUT
                while time.time() < deadline:
                    if self._current_epoch_id >= expected_epoch:
                        # Ack was processed — epoch has advanced
                        logger.info(f"Rotation to epoch {expected_epoch} confirmed")
                        return
                    await asyncio.sleep(1)

                # Timeout waiting for ack
                logger.warning(f"Rotation to epoch {expected_epoch} timed out waiting for ack")
                continue  # Retry
            except Exception as e:
                backoff = EPOCH_INITIAL_BACKOFF * (2**attempt)
                logger.warning(
                    f"Rotation attempt {attempt + 1}/{EPOCH_MAX_RETRIES} failed: {e}. "
                    f"Retrying in {backoff}s"
                )
                await asyncio.sleep(backoff)

        logger.error(f"Rotation failed after {EPOCH_MAX_RETRIES} attempts")

    def _get_kek(self) -> bytes | None:
        """Derive a KEK from the local node identity for wrapping epoch keys at rest."""
        if self._local_identity is None:
            logger.warning(
                "KEK unavailable: no local identity — epoch keys will persist unencrypted"
            )
            return None
        try:
            identity_bytes = self._local_identity.get_public_key()
            return derive_kek(identity_bytes)
        except Exception:
            logger.warning("KEK derivation failed — epoch keys will persist unencrypted")
            return None

    async def persist_state(self) -> None:
        """Save current epoch state to the database."""
        if not self._session_factory:
            return
        try:
            from hokora.db.queries import EpochStateRepo

            kek = self._get_kek()

            # Wrap keys before storage
            wrapped_send = None
            wrapped_recv = None
            if self._send_key:
                raw = bytes(self._send_key)
                wrapped_send = wrap_key(kek, raw) if kek else raw
            if self._recv_key:
                raw = bytes(self._recv_key)
                wrapped_recv = wrap_key(kek, raw) if kek else raw

            async with self._session_factory() as session:
                async with session.begin():
                    repo = EpochStateRepo(session)
                    await repo.upsert(
                        self.peer_identity_hash,
                        current_epoch_id=self._current_epoch_id,
                        epoch_duration=self.epoch_duration,
                        is_initiator=self.is_initiator,
                        epoch_start_time=self._epoch_start_time,
                        current_key_send=wrapped_send,
                        current_key_recv=wrapped_recv,
                        nonce_prefix=self._nonce_prefix or None,
                        message_counter=self._message_counter,
                        last_chain_hash=self._last_chain_hash,
                    )
        except Exception:
            logger.exception("Failed to persist epoch state")

    async def load_state(self) -> None:
        """Restore epoch state from the database."""
        if not self._session_factory:
            return
        try:
            from hokora.db.queries import EpochStateRepo

            kek = self._get_kek()

            async with self._session_factory() as session:
                async with session.begin():
                    repo = EpochStateRepo(session)
                    state = await repo.get(self.peer_identity_hash)
                    if not state:
                        return

                    self._current_epoch_id = state.current_epoch_id
                    self.epoch_duration = state.epoch_duration
                    self.is_initiator = state.is_initiator
                    self._epoch_start_time = state.epoch_start_time or 0.0

                    # Unwrap keys from storage
                    if state.current_key_send:
                        try:
                            raw = (
                                unwrap_key(kek, state.current_key_send)
                                if kek
                                else state.current_key_send
                            )
                            self._send_key = bytearray(raw)
                        except Exception:
                            logger.warning(
                                "Failed to unwrap send key — epoch requires re-negotiation"
                            )
                            self._send_key = None
                    if state.current_key_recv:
                        try:
                            raw = (
                                unwrap_key(kek, state.current_key_recv)
                                if kek
                                else state.current_key_recv
                            )
                            self._recv_key = bytearray(raw)
                        except Exception:
                            logger.warning(
                                "Failed to unwrap recv key — epoch requires re-negotiation"
                            )
                            self._recv_key = None

                    self._nonce_prefix = state.nonce_prefix or b""
                    self._message_counter = state.message_counter
                    self._last_chain_hash = state.last_chain_hash or b"\x00" * 32

                    logger.info(
                        f"Loaded epoch state for {self.peer_identity_hash[:16]}: "
                        f"epoch={self._current_epoch_id}"
                    )
        except Exception:
            logger.exception("Failed to load epoch state")

    def teardown(self) -> None:
        """Cancel timers and erase all key material."""
        self._torn_down = True
        if self._rotation_task:
            self._rotation_task.cancel()
            self._rotation_task = None

        for key in (self._send_key, self._recv_key, self._prev_recv_key):
            if key is not None:
                secure_erase(key)

        self._send_key = None
        self._recv_key = None
        self._prev_recv_key = None
        self._pending_private_key = None

        logger.info(f"Epoch manager torn down for {self.peer_identity_hash[:16]}")
