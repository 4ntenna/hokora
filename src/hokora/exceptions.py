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
    """Recipient not in RNS path cache; envelope encryption deferred.

    Raised by ``security.sealed.load_peer_rns_identity`` after the inline
    ``request_path`` + 3 s poll fails. NOT raised on transient path
    expiry — the inline path-request usually resolves within seconds. A
    permanent miss means the peer has never announced; operator should
    retry the role assign / invite redeem after the peer has connected
    once via TUI.
    """


class EpochError(FederationError):
    """Forward secrecy epoch protocol error."""
