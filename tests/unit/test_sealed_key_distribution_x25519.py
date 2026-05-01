# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Wire-shape tests for sealed-key envelope distribution.

Pin the architectural invariant: the X25519 public key for envelope
encryption MUST come from RNS's ``known_destinations`` cache via
``security.sealed.load_peer_rns_identity()``, never from our own
``identities.public_key`` column (which holds the 32-byte Ed25519
signing key only). Feeding the 32-byte Ed25519 bytes into
``RNS.Identity.load_public_key`` (which expects the full 64-byte
X25519+Ed25519 blob) silently derives the wrong X25519 half and
produces ciphertext the recipient cannot decrypt — quiet corruption
that the CLI would otherwise report as success.
``identities.public_key`` column.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
import RNS


def _make_real_rns_identity():
    """Build a real RNS.Identity (not a mock). The whole point is to
    verify behaviour against the actual RNS public-key shape, which a
    mock can't enforce."""
    import RNS

    return RNS.Identity()


class TestLoadPeerRnsIdentityHelper:
    """`security.sealed.load_peer_rns_identity` is the single chokepoint
    for resolving a peer identity_hash to a fully-populated RNS.Identity
    (X25519 + Ed25519). It MUST NOT read from `identities.public_key`."""

    async def test_returns_full_identity_when_peer_in_rns_cache(self):
        from hokora.security.sealed import load_peer_rns_identity

        # Stage: create a real RNS.Identity and inject it into RNS's
        # known_destinations cache directly (this is the same shape the
        # cache holds after a real announce reception).
        peer = _make_real_rns_identity()
        peer_hash = peer.hexhash

        with patch.object(RNS.Identity, "recall", return_value=peer) as recall:
            result = await load_peer_rns_identity(peer_hash)

        recall.assert_called_once()
        # Verify the recall was called with from_identity_hash=True (we
        # search by identity hash, not destination hash, because
        # role-assign provides identity_hash).
        assert recall.call_args.kwargs.get("from_identity_hash") is True
        assert result is peer
        # Confirm the returned identity has BOTH halves usable for
        # encrypt() — the entire reason this fix exists.
        assert result.pub_bytes is not None
        assert len(result.pub_bytes) == 32  # X25519 encryption key
        assert result.sig_pub_bytes is not None
        assert len(result.sig_pub_bytes) == 32  # Ed25519 signing key

    async def test_raises_deferred_when_peer_not_in_rns_cache(self):
        from hokora.exceptions import SealedKeyDistributionDeferred
        from hokora.security.sealed import load_peer_rns_identity

        unknown_hash = "ab" * 16

        # Patch asyncio.sleep so the 3 s post-request_path retry-wait
        # doesn't slow the test suite — we still exercise the loop logic.
        with (
            patch.object(RNS.Identity, "recall", return_value=None),
            patch.object(RNS.Transport, "request_path") as req_path,
            patch("hokora.security.sealed.asyncio.sleep", new=AsyncMock()),
        ):
            with pytest.raises(SealedKeyDistributionDeferred, match="not in RNS path cache"):
                await load_peer_rns_identity(unknown_hash)

        # Path request must have been issued so the next retry has a
        # chance to succeed without operator intervention.
        req_path.assert_called_once()
        # Argument must be bytes (RNS API contract), not the hex string.
        assert isinstance(req_path.call_args.args[0], bytes)
        assert req_path.call_args.args[0] == bytes.fromhex(unknown_hash)

    async def test_resolves_after_path_request_when_recall_eventually_succeeds(self):
        """If the path response arrives during the 3 s retry-wait,
        ``load_peer_rns_identity`` returns the identity — no deferral."""
        from hokora.security.sealed import load_peer_rns_identity

        peer = _make_real_rns_identity()

        # First recall returns None; second recall (after request_path) succeeds.
        recall_results = iter([None, peer])

        def _recall_side_effect(*args, **kwargs):
            return next(recall_results, peer)

        with (
            patch.object(RNS.Identity, "recall", side_effect=_recall_side_effect),
            patch.object(RNS.Transport, "request_path") as req_path,
            patch("hokora.security.sealed.asyncio.sleep", new=AsyncMock()),
        ):
            result = await load_peer_rns_identity(peer.hexhash)

        req_path.assert_called_once()
        assert result is peer

    async def test_invalid_hex_raises_deferred_not_valueerror(self):
        from hokora.exceptions import SealedKeyDistributionDeferred
        from hokora.security.sealed import load_peer_rns_identity

        with pytest.raises(SealedKeyDistributionDeferred, match="Invalid identity_hash"):
            await load_peer_rns_identity("not-a-hex-string")

    async def test_request_path_failure_does_not_mask_deferred_error(self):
        """A flaky ``request_path`` (RNS internal exception) must not
        prevent SealedKeyDistributionDeferred from being raised. The
        operator's actionable signal is the deferral, not the path-
        request failure."""
        from hokora.exceptions import SealedKeyDistributionDeferred
        from hokora.security.sealed import load_peer_rns_identity

        unknown_hash = "cd" * 16

        with (
            patch.object(RNS.Identity, "recall", return_value=None),
            patch.object(
                RNS.Transport,
                "request_path",
                side_effect=RuntimeError("RNS internal hiccup"),
            ),
            patch("hokora.security.sealed.asyncio.sleep", new=AsyncMock()),
        ):
            with pytest.raises(SealedKeyDistributionDeferred):
                await load_peer_rns_identity(unknown_hash)


class TestDistributeSealedKeyEndToEndWithRealKeys:
    """Integration-flavoured: full sign+encrypt+decrypt round-trip using
    real RNS identities. The whole point of the architectural fix is that
    the resulting blob MUST be decryptable by the recipient's real
    private key — which the prior implementation silently broke."""

    async def test_envelope_blob_decrypts_with_recipient_real_private_key(self):
        """Encrypt with peer A's full identity, decrypt with peer A's
        own private key — bytes must round-trip exactly."""
        from hokora.security.sealed import load_peer_rns_identity

        # Two real RNS identities: one is the recipient, one is the
        # node owner (irrelevant for this test, but mirrors the real
        # call shape).
        recipient = _make_real_rns_identity()
        plaintext_group_key = b"\x42" * 32  # AES-256-GCM-shaped key

        with patch.object(RNS.Identity, "recall", return_value=recipient):
            peer_identity = await load_peer_rns_identity(recipient.hexhash)
            blob = peer_identity.encrypt(plaintext_group_key)

        # The recipient (real identity, has both X25519 private and
        # Ed25519 private) decrypts. With the pre-fix code path this
        # would FAIL because the encryption key was derived from the
        # wrong half of a chopped blob.
        decrypted = recipient.decrypt(blob)
        assert decrypted == plaintext_group_key, (
            "Envelope ciphertext must round-trip cleanly via the recipient's "
            "real private key. Failure here means the X25519 half used for "
            "encryption did not match the recipient's actual X25519 private "
            "key — the precise corruption mode the helper exists to prevent."
        )

    def test_pre_fix_codepath_loading_32_byte_pk_into_load_public_key_corrupts_x25519(self):
        """Document, in test form, why the pre-fix code path was wrong.
        Loading a 32-byte (Ed25519-only) blob into RNS.Identity.load_public_key
        causes RNS to treat the FIRST 32 bytes as X25519 — but those bytes
        are the recipient's Ed25519 public key, not their X25519 public key.
        The resulting encryption is unrecoverable by the recipient."""
        import RNS

        recipient = _make_real_rns_identity()
        ed25519_only = recipient.sig_pub_bytes  # 32 bytes Ed25519

        # Reproduce the pre-fix path: build an Identity from 32 bytes.
        broken = RNS.Identity(create_keys=False)
        # RNS logs an internal error here; the assertion below confirms
        # the corruption rather than relying on the log.
        broken.load_public_key(ed25519_only)

        # The "X25519" half RNS now thinks the peer has is actually the
        # Ed25519 bytes. It is NOT the recipient's real X25519 public
        # key — encrypt+decrypt will fail.
        plaintext = b"sealed-group-key-bytes-32bytesX!"  # 32 bytes
        blob = broken.encrypt(plaintext)

        # The recipient cannot decrypt this blob with their real private
        # key, because the encryption used the wrong public key.
        decrypted = recipient.decrypt(blob)
        assert decrypted != plaintext, (
            "If this assertion ever fails, the pre-fix code path was not "
            "actually corrupting envelopes — re-evaluate whether the helper "
            "is still necessary. (Currently expected: decrypted is None or "
            "garbage because the X25519 half was wrong.)"
        )
