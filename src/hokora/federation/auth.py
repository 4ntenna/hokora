# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Federation peer authentication via Ed25519 challenge-response handshake."""

import logging
import os
import time
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from hokora.exceptions import FederationError

logger = logging.getLogger(__name__)

CHALLENGE_SIZE = 32
ED25519_PUBLIC_KEY_SIZE = 32
RNS_PUBLIC_KEY_SIZE = 64
IDENTITY_HASH_HEX_LENGTH = 32

# Process-wide tally of sender-binding rejections, keyed on a coarse reason
# label (``binding_mismatch`` / ``missing_pubkey`` / ``bad_signature`` /
# ``malformed``). Read by core.prometheus_exporter; reset by tests.
_BINDING_REJECTIONS: dict[str, int] = {}


def get_binding_rejection_counts() -> dict[str, int]:
    """Snapshot of binding-rejection counts (cheap, prometheus-render path)."""
    return dict(_BINDING_REJECTIONS)


def _record_binding_rejection(label: str) -> None:
    _BINDING_REJECTIONS[label] = _BINDING_REJECTIONS.get(label, 0) + 1


def derive_identity_hash_hex(rns_public_key: bytes) -> str:
    """Derive the RNS identity hash (32 hex chars) from a 64-byte RNS pubkey blob.

    RNS computes ``Identity.hash`` as ``truncated_hash(X25519_pub || Ed25519_pub)``
    where ``truncated_hash`` is SHA-256 truncated to ``TRUNCATED_HASHLENGTH``
    (128 bits = 16 bytes = 32 hex chars). Mirroring that derivation lets us
    structurally verify that a wire-claimed ``sender_hash`` is bound to the
    accompanying public key — no TOFU, no path-cache lookup, just hash equality.
    """
    if not isinstance(rns_public_key, (bytes, bytearray)):
        raise FederationError(f"rns_public_key must be bytes, got {type(rns_public_key).__name__}")
    if len(rns_public_key) != RNS_PUBLIC_KEY_SIZE:
        raise FederationError(
            f"rns_public_key must be {RNS_PUBLIC_KEY_SIZE} bytes "
            f"(X25519||Ed25519); got {len(rns_public_key)}"
        )
    import RNS

    return RNS.hexrep(RNS.Identity.truncated_hash(bytes(rns_public_key)), delimit=False)


def verify_sender_binding(
    sender_hash: Optional[str],
    sender_rns_public_key: Optional[bytes],
    lxmf_signed_part: Optional[bytes],
    lxmf_signature: Optional[bytes],
    require_signed: bool,
) -> tuple[bool, Optional[str]]:
    """Single chokepoint: bind wire ``sender_hash`` to its pubkey, verify sig.

    Federation-receive write paths (``handle_push_messages``,
    ``MirrorMessageIngestor.ingest``) MUST call this before assigning a
    sequence number. A trusted-but-malicious peer can otherwise push a
    record with their own ``sender_public_key`` and a victim's
    ``sender_hash``; the signature verifies but the row lands under the
    victim's identity. The structural fix is to require the full 64-byte
    RNS pubkey on the wire, recompute the identity hash from it, and
    reject any mismatch — no TOFU surface, fail-closed before seq assign.

    Returns ``(ok, reject_reason)``. On ``ok=False`` the caller MUST drop
    the message (no seq advance).

    Args:
        sender_hash: hex identity hash claimed on the wire.
        sender_rns_public_key: 64-byte ``X25519||Ed25519`` blob the
            pusher attached. ``None`` is accepted only when
            ``require_signed`` is False (legacy unsigned mode).
        lxmf_signed_part: bytes the LXMF sender signed.
        lxmf_signature: detached Ed25519 signature.
        require_signed: when True, missing pubkey or missing signature
            both reject. Mirrors ``NodeConfig.require_signed_federation``.
    """
    if not sender_hash or not isinstance(sender_hash, str):
        _record_binding_rejection("malformed")
        return False, "missing sender_hash"
    if len(sender_hash) != IDENTITY_HASH_HEX_LENGTH:
        _record_binding_rejection("malformed")
        return False, (
            f"malformed sender_hash length ({len(sender_hash)}; "
            f"expected {IDENTITY_HASH_HEX_LENGTH})"
        )

    if not sender_rns_public_key:
        if require_signed:
            _record_binding_rejection("missing_pubkey")
            return False, "missing sender_rns_public_key"
        return True, None

    try:
        expected_hash = derive_identity_hash_hex(sender_rns_public_key)
    except FederationError as e:
        _record_binding_rejection("malformed")
        return False, f"malformed sender_rns_public_key: {e}"

    if expected_hash != sender_hash:
        _record_binding_rejection("binding_mismatch")
        return False, (
            f"sender_hash binding violation: claimed {sender_hash} "
            f"does not match pubkey-derived {expected_hash}"
        )

    if lxmf_signed_part and lxmf_signature:
        from hokora.security.verification import VerificationService

        ed25519_pk = bytes(sender_rns_public_key)[ED25519_PUBLIC_KEY_SIZE:]
        if not VerificationService.verify_ed25519_signature(
            ed25519_pk, lxmf_signed_part, lxmf_signature
        ):
            _record_binding_rejection("bad_signature")
            return False, "Ed25519 signature verification failed"
    elif require_signed:
        _record_binding_rejection("missing_signature")
        return False, "missing signature"

    return True, None


def signing_public_key(identity: Any) -> bytes:
    """Extract the 32-byte Ed25519 signing public key from an RNS.Identity.

    RNS.Identity.get_public_key() returns a 64-byte concatenation:
    32 bytes X25519 (encryption) + 32 bytes Ed25519 (signing). The
    federation handshake only needs the Ed25519 portion for signature
    verification, so callers must use this helper rather than the raw
    get_public_key() to avoid a wire-format mismatch with verifiers that
    expect a bare 32-byte Ed25519 key.

    Single source of truth: any path that puts a peer_public_key onto
    the federation wire MUST go through this function.
    """
    pk = getattr(identity, "sig_pub_bytes", None)
    if not isinstance(pk, (bytes, bytearray)) or len(pk) != ED25519_PUBLIC_KEY_SIZE:
        raise FederationError(
            f"Invalid Ed25519 sig_pub_bytes on identity: expected "
            f"{ED25519_PUBLIC_KEY_SIZE} bytes, got "
            f"{0 if pk is None else len(pk)}"
        )
    return bytes(pk)


class PeerKeyStore:
    """Tracks peer public keys for TOFU (Trust On First Use) key-change detection."""

    def __init__(self, reject_key_change: bool = True):
        # identity_hash -> public_key_bytes
        self._known_keys: dict[str, bytes] = {}
        self._reject_key_change = reject_key_change

    def check_and_store(self, identity_hash: str, public_key_bytes: bytes) -> bool:
        """Store a peer's key on first contact; reject if key changes.

        Returns True if the key is new or unchanged.
        Returns False (and refuses the peer) if the key has changed,
        unless reject_key_change is False.

        Raises FederationError if reject_key_change is True and key changed.
        """
        existing = self._known_keys.get(identity_hash)
        if existing is None:
            self._known_keys[identity_hash] = public_key_bytes
            logger.info(f"Stored TOFU key for peer {identity_hash[:16]}")
            return True

        if existing != public_key_bytes:
            logger.warning(
                f"SECURITY: Peer {identity_hash[:16]} public key has CHANGED. "
                "Possible impersonation or key rotation. Manual verification recommended."
            )
            if self._reject_key_change:
                raise FederationError(
                    f"Peer {identity_hash[:16]} public key changed. "
                    "Connection rejected — use update_key() after manual verification "
                    "to trust the new key."
                )
            return False

        return True

    def update_key(self, identity_hash: str, public_key_bytes: bytes) -> None:
        """Explicitly update a peer's key (after manual verification)."""
        self._known_keys[identity_hash] = public_key_bytes
        logger.info(f"Updated TOFU key for peer {identity_hash[:16]}")

    def get_key(self, identity_hash: str) -> Optional[bytes]:
        return self._known_keys.get(identity_hash)


class FederationAuth:
    """Handles Ed25519 challenge-response authentication for federation peers."""

    @staticmethod
    def create_challenge() -> bytes:
        """Create a 32-byte random challenge."""
        return os.urandom(CHALLENGE_SIZE)

    @staticmethod
    def create_response(challenge: bytes, private_key: Ed25519PrivateKey) -> bytes:
        """Sign a challenge with the node's Ed25519 private key."""
        if len(challenge) != CHALLENGE_SIZE:
            raise FederationError(
                f"Invalid challenge size: {len(challenge)}, expected {CHALLENGE_SIZE}"
            )
        return private_key.sign(challenge)

    @staticmethod
    def verify_response(
        challenge: bytes,
        response: bytes,
        public_key_bytes: bytes,
    ) -> bool:
        """Verify a signed challenge response with the peer's public key.

        Distinguishes structural failures (wrong key length, wrong type) from
        cryptographic failures (invalid signature). Both return False, but the
        log line names the failure mode so operators can tell a wire-format
        bug apart from a forged signature.
        """
        if not isinstance(public_key_bytes, (bytes, bytearray)):
            logger.warning(
                "Federation handshake verification failed: peer_public_key not bytes "
                f"(got {type(public_key_bytes).__name__})"
            )
            return False
        if len(public_key_bytes) != ED25519_PUBLIC_KEY_SIZE:
            logger.warning(
                "Federation handshake verification failed: invalid Ed25519 pk length "
                f"({len(public_key_bytes)} bytes; expected {ED25519_PUBLIC_KEY_SIZE}). "
                "Likely wire-format mismatch — peer may be on a stale build."
            )
            return False
        try:
            public_key = Ed25519PublicKey.from_public_bytes(bytes(public_key_bytes))
            public_key.verify(response, challenge)
            return True
        except InvalidSignature:
            logger.warning("Federation handshake verification failed: invalid signature")
            return False
        except Exception as e:
            logger.warning(f"Federation handshake verification failed: {e}")
            return False

    @staticmethod
    def build_handshake_init(node_name: str, identity_hash: str) -> dict:
        """Build the initiator's handshake message (step 1)."""
        challenge = FederationAuth.create_challenge()
        return {
            "action": "federation_handshake",
            "step": 1,
            "node_name": node_name,
            "identity_hash": identity_hash,
            "challenge": challenge,
            "timestamp": time.time(),
        }

    @staticmethod
    def build_handshake_response(
        node_name: str,
        identity_hash: str,
        challenge_response: bytes,
        counter_challenge: bytes,
    ) -> dict:
        """Build the responder's handshake message (step 2)."""
        return {
            "action": "federation_handshake",
            "step": 2,
            "node_name": node_name,
            "identity_hash": identity_hash,
            "challenge_response": challenge_response,
            "counter_challenge": counter_challenge,
            "timestamp": time.time(),
        }

    @staticmethod
    def build_handshake_ack(counter_response: bytes) -> dict:
        """Build the initiator's ack message (step 3)."""
        return {
            "action": "federation_handshake",
            "step": 3,
            "counter_response": counter_response,
            "timestamp": time.time(),
        }
