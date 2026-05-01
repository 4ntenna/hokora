# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Custom exceptions for Hokora."""


class HokoraError(Exception):
    """Base exception for all Hokora errors."""


class ConfigError(HokoraError):
    """Configuration error."""


class DatabaseError(HokoraError):
    """Database operation error."""


class IdentityError(HokoraError):
    """Identity management error."""


class ChannelError(HokoraError):
    """Channel operation error."""


class MessageError(HokoraError):
    """Message processing error."""


class VerificationError(HokoraError):
    """Signature or verification failure."""


class PermissionDenied(HokoraError):
    """Permission check failed."""


class RateLimitExceeded(HokoraError):
    """Rate limit exceeded."""


class SyncError(HokoraError):
    """Sync protocol error."""


class InviteError(HokoraError):
    """Invite operation error."""


class MediaError(HokoraError):
    """Media storage/transfer error."""


class FederationError(HokoraError):
    """Federation/peering error."""


class SealedChannelError(HokoraError):
    """Sealed channel encryption error."""


class SealedKeyDistributionDeferred(HokoraError):
    """Sealed-key envelope encryption could not run because the recipient's
    full RNS identity (X25519 + Ed25519) is not in RNS's path cache.

    Raised by ``security.sealed.load_peer_rns_identity()`` when a peer has
    never announced. RNS's ``known_destinations`` table has no record, so
    no X25519 public key is available to envelope-encrypt the group key
    with. Operators should retry the role assign / invite redeem after the
    peer has connected once via TUI (which fires their announce).

    NOT raised on transient path expiry — ``load_peer_rns_identity`` issues
    a ``Transport.request_path()`` before raising, so a subsequent retry a
    few seconds later usually succeeds without operator intervention.
    """


class EpochError(FederationError):
    """Forward secrecy epoch protocol error."""
