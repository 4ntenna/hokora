# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Structural typing guard for the SyncContext narrow Protocols.

Verifies that the concrete ``SyncContext`` dataclass carries every field
each per-handler ``Protocol`` declares. Because Python's typing.Protocol
is a *static* check, a dropped field in SyncContext wouldn't be caught
at import/runtime — mypy would flag it, but our mypy perimeter doesn't
include ``protocol/sync_utils.py`` yet. This test acts as a cheap
runtime-level guard: every Protocol's declared attribute name must
resolve on a vanilla SyncContext instance.
"""

from __future__ import annotations

from hokora.protocol.sync_utils import (
    FederationContext,
    HistoryContext,
    LiveContext,
    MetadataContext,
    SessionContext,
    SyncContext,
)


def _protocol_attrs(proto) -> set[str]:
    """Return the attribute names a typing.Protocol declares."""
    # Protocols expose their field annotations via __annotations__ on the
    # class itself; base-Protocol noise is filtered out by excluding names
    # that start with '_'.
    return {name for name in proto.__annotations__ if not name.startswith("_")}


def _make_ctx() -> SyncContext:
    return SyncContext(channel_manager=object(), sequencer=object())


def test_sync_context_satisfies_live_context():
    ctx = _make_ctx()
    for attr in _protocol_attrs(LiveContext):
        assert hasattr(ctx, attr), f"SyncContext missing LiveContext.{attr}"


def test_sync_context_satisfies_history_context():
    ctx = _make_ctx()
    for attr in _protocol_attrs(HistoryContext):
        assert hasattr(ctx, attr), f"SyncContext missing HistoryContext.{attr}"


def test_sync_context_satisfies_metadata_context():
    ctx = _make_ctx()
    for attr in _protocol_attrs(MetadataContext):
        assert hasattr(ctx, attr), f"SyncContext missing MetadataContext.{attr}"


def test_sync_context_satisfies_session_context():
    ctx = _make_ctx()
    for attr in _protocol_attrs(SessionContext):
        assert hasattr(ctx, attr), f"SyncContext missing SessionContext.{attr}"


def test_sync_context_satisfies_federation_context():
    ctx = _make_ctx()
    for attr in _protocol_attrs(FederationContext):
        assert hasattr(ctx, attr), f"SyncContext missing FederationContext.{attr}"


def test_narrow_protocols_are_disjoint_from_verifier():
    """Sanity: the 5 per-handler Protocols describe collaborator state,
    not internal helpers like VerificationService. ``verifier`` is an
    implementation detail of SyncContext, not part of any handler's
    declared dep surface."""
    for proto in (
        LiveContext,
        HistoryContext,
        MetadataContext,
        SessionContext,
        FederationContext,
    ):
        assert "verifier" not in _protocol_attrs(proto)
