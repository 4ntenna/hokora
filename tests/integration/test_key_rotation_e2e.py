# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""End-to-end channel RNS identity rotation flow.

Exercises the full code path from ``KeyRotationManager.initiate_rotation``
on node A, through the dual-signed announce serialisation, into
``PeerDiscovery.handle_announce`` on node B, to the ``channels`` row
update on node B's DB. The intermediary pieces (parse_announce dispatch
in AnnounceHandler, signature verification in KeyRotationManager,
session-threaded DB apply in PeerDiscovery._apply_rotation) all run
real — only the RNS transport layer is mocked.

Complements the per-unit tests at ``tests/unit/test_cli.py`` (CLI →
rotation record), ``tests/unit/test_announce.py`` (dispatch), and
``tests/unit/test_federation_peering.py`` (apply + grace).
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

import msgpack
import pytest

from hokora.db.engine import create_db_engine, create_session_factory, init_db
from hokora.db.models import Channel
from hokora.federation.key_rotation import KeyRotationManager
from hokora.federation.peering import PeerDiscovery


@pytest.fixture
def old_identity():
    """Mocked RNS.Identity with deterministic hash + a capturable signer."""
    ident = MagicMock()
    ident.hexhash = "a" * 64
    ident.sign = MagicMock(return_value=b"\xaa" * 64)
    ident.validate = MagicMock(return_value=True)
    return ident


@pytest.fixture
def new_identity():
    ident = MagicMock()
    ident.hexhash = "b" * 64
    ident.sign = MagicMock(return_value=b"\xbb" * 64)
    ident.validate = MagicMock(return_value=True)
    return ident


async def _drain_loop(loop: asyncio.AbstractEventLoop) -> None:
    """Yield until every non-current task on ``loop`` is done — necessary
    because PeerDiscovery hops the DB write through
    ``run_coroutine_threadsafe`` even when we're already on the loop."""
    current = asyncio.current_task()
    for _ in range(50):
        await asyncio.sleep(0)
        pending = [t for t in asyncio.all_tasks(loop) if t is not current and not t.done()]
        if not pending:
            return
    await asyncio.gather(*pending, return_exceptions=True)


async def _seed_channel(session_factory, identity_hash: str, channel_id: str = "chA") -> None:
    async with session_factory() as session:
        async with session.begin():
            session.add(
                Channel(
                    id=channel_id,
                    name="e2e-rot",
                    identity_hash=identity_hash,
                    destination_hash="d" * 32,
                )
            )


async def _get_channel(session_factory, channel_id: str = "chA"):
    from sqlalchemy import select

    async with session_factory() as session:
        row = await session.execute(select(Channel).where(Channel.id == channel_id))
        return row.scalar_one_or_none()


class TestKeyRotationE2E:
    async def test_node_b_applies_rotation_from_node_a_announce(
        self, tmp_dir, old_identity, new_identity
    ):
        """Full A→B flow: KeyRotationManager on A builds the announce
        wrapper; mocked old destination captures the app_data bytes;
        PeerDiscovery on B receives those bytes, verifies both
        signatures, and commits the new identity_hash + grace state.
        """
        # Node B's DB.
        db_b = tmp_dir / "nodeB.db"
        engine_b = create_db_engine(db_b)
        await init_db(engine_b)
        sf_b = create_session_factory(engine_b)
        await _seed_channel(sf_b, identity_hash="a" * 64)

        # Node A initiates rotation. We capture the announce app_data the
        # KeyRotationManager hands to the destination — that's the wire
        # format node B must consume.
        captured_app_data = {}

        def capture_announce(*, app_data):
            captured_app_data["bytes"] = app_data

        old_destination = MagicMock()
        old_destination.announce = MagicMock(side_effect=capture_announce)

        mgr_a = KeyRotationManager()
        mgr_a.initiate_rotation("chA", old_identity, new_identity, old_destination)

        assert "bytes" in captured_app_data, "Node A must emit the announce envelope"

        # Node B receives. RNS.Identity.recall is used in verify_rotation
        # to fetch public keys for signature validation; mock it to return
        # the matching identity stubs for each hash.
        loop = asyncio.get_running_loop()
        discovery_b = PeerDiscovery(session_factory=sf_b, loop=loop)

        def fake_recall(dest_hash: bytes):
            hex_hash = dest_hash.hex()
            if hex_hash == "a" * 64:
                return old_identity
            if hex_hash == "b" * 64:
                return new_identity
            return None

        with (
            patch("hokora.federation.peering.RNS"),
            patch("hokora.federation.key_rotation.RNS") as rns_kr,
        ):
            rns_kr.Identity.recall = MagicMock(side_effect=fake_recall)
            discovery_b.handle_announce(
                b"\x01" * 16,
                MagicMock(),
                captured_app_data["bytes"],
            )
            await _drain_loop(loop)

        channel = await _get_channel(sf_b)
        assert channel is not None
        assert channel.identity_hash == "b" * 64, (
            "Node B must adopt the rotated identity after verification"
        )
        assert channel.rotation_old_hash == "a" * 64
        assert channel.rotation_grace_end is not None
        await engine_b.dispose()

    async def test_node_b_rejects_rotation_when_verification_fails(
        self, tmp_dir, old_identity, new_identity
    ):
        """If one of the dual signatures doesn't validate, node B must
        leave its identity_hash untouched."""
        db_b = tmp_dir / "nodeB-bad.db"
        engine_b = create_db_engine(db_b)
        await init_db(engine_b)
        sf_b = create_session_factory(engine_b)
        await _seed_channel(sf_b, identity_hash="a" * 64)

        captured = {}
        dest = MagicMock()
        dest.announce = MagicMock(side_effect=lambda *, app_data: captured.update(bytes=app_data))

        KeyRotationManager().initiate_rotation("chA", old_identity, new_identity, dest)

        # Tamper: flip one byte of the envelope payload so signatures fail.
        tampered = bytearray(captured["bytes"])
        tampered[-1] ^= 0xFF

        loop = asyncio.get_running_loop()
        discovery_b = PeerDiscovery(session_factory=sf_b, loop=loop)

        # new_identity.validate returns False to simulate verification failure.
        failing_new = MagicMock()
        failing_new.hexhash = "b" * 64
        failing_new.validate = MagicMock(return_value=False)

        with (
            patch("hokora.federation.peering.RNS"),
            patch("hokora.federation.key_rotation.RNS") as rns_kr,
        ):
            rns_kr.Identity.recall = MagicMock(
                side_effect=lambda h: old_identity if h.hex() == "a" * 64 else failing_new
            )
            discovery_b.handle_announce(b"\x01" * 16, MagicMock(), bytes(tampered))
            await _drain_loop(loop)

        channel = await _get_channel(sf_b)
        assert channel.identity_hash == "a" * 64, "unchanged on verify failure"
        assert channel.rotation_old_hash is None
        await engine_b.dispose()

    async def test_node_b_ignores_rotation_for_unknown_channel(
        self, tmp_dir, old_identity, new_identity
    ):
        """Rotation announce for a channel we don't track is verified
        successfully but produces no DB change — the four-way guard in
        ``_apply_rotation`` drops it."""
        db_b = tmp_dir / "nodeB-unknown.db"
        engine_b = create_db_engine(db_b)
        await init_db(engine_b)
        sf_b = create_session_factory(engine_b)
        # Intentionally no Channel row seeded — node B doesn't know chA.

        captured = {}
        dest = MagicMock()
        dest.announce = MagicMock(side_effect=lambda *, app_data: captured.update(bytes=app_data))
        KeyRotationManager().initiate_rotation("chA", old_identity, new_identity, dest)

        loop = asyncio.get_running_loop()
        discovery_b = PeerDiscovery(session_factory=sf_b, loop=loop)

        def recall(h):
            return old_identity if h.hex() == "a" * 64 else new_identity

        with (
            patch("hokora.federation.peering.RNS"),
            patch("hokora.federation.key_rotation.RNS") as rns_kr,
        ):
            rns_kr.Identity.recall = MagicMock(side_effect=recall)
            discovery_b.handle_announce(b"\x01" * 16, MagicMock(), captured["bytes"])
            await _drain_loop(loop)

        channel = await _get_channel(sf_b)
        assert channel is None, "unknown channel stays unknown"
        await engine_b.dispose()

    def test_envelope_round_trip_via_parse_announce(self, old_identity, new_identity):
        """The wire format emitted by initiate_rotation must be a valid
        envelope that parse_announce recognises as key_rotation. This
        guards against serialisation drift between the two sides."""
        from hokora.core.announce import AnnounceHandler

        captured = {}
        dest = MagicMock()
        dest.announce = MagicMock(side_effect=lambda *, app_data: captured.update(bytes=app_data))
        KeyRotationManager().initiate_rotation("chA", old_identity, new_identity, dest)

        parsed = AnnounceHandler.parse_announce(captured["bytes"])
        assert parsed is not None
        assert parsed["type"] == "key_rotation"
        assert parsed["payload"]["channel_id"] == "chA"
        assert parsed["payload"]["old_hash"] == "a" * 64
        assert parsed["payload"]["new_hash"] == "b" * 64

        # And the envelope re-packs under msgpack.
        assert isinstance(parsed["envelope"]["payload"], bytes)
        inner = msgpack.unpackb(parsed["envelope"]["payload"], raw=False)
        assert inner["type"] == "key_rotation"
