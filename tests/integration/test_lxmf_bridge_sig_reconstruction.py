# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""End-to-end test: lxmf_signed_part reconstruction round-trip.

Proves our ``LXMFBridge`` reconstruction of ``lxmf_signed_part`` matches
what LXMF's own inbound validator uses, for both payload shapes:

* stamp=None   — 4-element payload, packed_payload bytes on the wire
                 equal what was signed.
* stamp present — 5-element payload, requires stripping element 4 and
                  re-packing to recover the bytes that were signed.

The test drives a real ``LXMessage.pack()`` → ``unpack_from_bytes()``
round-trip and then calls our bridge's reconstruction through the
``_on_lxmf_delivery`` handler. The final assertion is
``Ed25519.verify(sig, signed_part) == True`` — the actual cryptographic
contract, locked in.

Does NOT exercise Reticulum's networking layer; LXMessage.pack/unpack
work purely on in-memory bytes.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import LXMF
import RNS
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from hokora.protocol.lxmf_bridge import LXMFBridge


def _build_identity_destinations():
    """Create a matched (sender_identity, receiver_identity) pair +
    ``RNS.Destination`` objects wrapped around them so LXMessage can
    sign + address outbound messages.

    Both identities are registered with RNS's known-destinations cache
    via ``RNS.Identity.remember`` so that ``unpack_from_bytes``'s
    ``RNS.Identity.recall(source_hash)`` call returns the identity —
    mimics how a real inbound message arrives post-announce.
    """
    # RNS.Reticulum is a singleton; initialise once, reuse across tests.
    if RNS.Reticulum.get_instance() is None:
        RNS.Reticulum()
    src_identity = RNS.Identity()
    dst_identity = RNS.Identity()

    # Source destination: OUT SINGLE delivery (what LXMF expects to sign from).
    src_dest = RNS.Destination(
        src_identity,
        RNS.Destination.OUT,
        RNS.Destination.SINGLE,
        LXMF.APP_NAME,
        "delivery",
    )
    dst_dest = RNS.Destination(
        dst_identity,
        RNS.Destination.OUT,
        RNS.Destination.SINGLE,
        LXMF.APP_NAME,
        "delivery",
    )
    # Register both in the RNS identity cache so recall() works.
    RNS.Identity.remember(None, src_dest.hash, src_identity.get_public_key())
    RNS.Identity.remember(None, dst_dest.hash, dst_identity.get_public_key())
    return src_identity, src_dest, dst_identity, dst_dest


def _roundtrip_through_bridge(
    packed_bytes, src_identity, _storagepath, channel_id="bridge_test_ch"
):
    """Unpack wire bytes + feed the resulting LXMessage through our
    bridge's ingest path. Returns the ``MessageEnvelope`` the bridge
    constructed (carries lxmf_signature / lxmf_signed_part /
    sender_public_key for downstream verification).

    ``src_identity`` is injected onto ``message.source.identity`` after
    ``unpack_from_bytes`` because that unpacker calls
    ``RNS.Identity.recall(source_hash)`` which returns ``None`` in
    tests — our sender was never announced to the RNS identity cache.
    Real-world receives always have an active announce for the sender.
    """
    from hokora.constants import MSG_TEXT

    message = LXMF.LXMessage.unpack_from_bytes(packed_bytes)
    assert message.source is not None, "Identity.recall must have resolved the sender"

    bridge = LXMFBridge(base_storagepath=str(_storagepath))
    bridge.ingest_callback = MagicMock()

    # Register a fake channel matched to this destination so the bridge
    # doesn't reject on "no channel for destination".
    mock_dest = MagicMock()
    mock_dest.hash = message.destination_hash
    bridge._registered_destinations[channel_id] = {
        "identity": MagicMock(),
        "destination": mock_dest,
    }

    # Hand a minimally-valid MSG_TEXT content payload so the ingest path
    # finishes — the signature fields come from ``message``, not content.
    with patch.object(bridge, "_decode_content", return_value={"type": MSG_TEXT, "body": "hi"}):
        bridge._on_lxmf_delivery(message)

    assert bridge.ingest_callback.called
    envelope = bridge.ingest_callback.call_args[0][0]
    return envelope, message


def test_lxmf_bridge_sig_verifies_when_stamp_absent(tmp_path):
    """Happy path: no stamp → payload on wire equals what was signed.
    Our reconstruction produces identical bytes."""
    src_identity, src_dest, _dst_identity, dst_dest = _build_identity_destinations()

    lxm = LXMF.LXMessage(
        destination=dst_dest,
        source=src_dest,
        content="sig-roundtrip-no-stamp",
        title="t",
        desired_method=LXMF.LXMessage.DIRECT,
    )
    # Disable stamp generation so the wire payload has exactly 4 elements.
    lxm.defer_stamp = False
    lxm.stamp_cost = None
    lxm.pack()
    assert lxm.signature_validated is True

    envelope, message = _roundtrip_through_bridge(lxm.packed, src_identity, tmp_path)

    # Our stored signed_part must be the bytes the sender signed.
    assert envelope.lxmf_signed_part is not None
    assert envelope.lxmf_signature == lxm.signature

    # sender_public_key must be 32 bytes (Ed25519 only, not the 64-byte blob).
    assert envelope.sender_public_key is not None
    assert len(envelope.sender_public_key) == 32

    # Ed25519 verify locks the actual cryptographic contract.
    pk = Ed25519PublicKey.from_public_bytes(envelope.sender_public_key)
    pk.verify(envelope.lxmf_signature, envelope.lxmf_signed_part)


def test_lxmf_bridge_sig_verifies_when_stamp_present(tmp_path):
    """Stamp path: LXMF appends stamp to payload AFTER signing. Our
    reconstruction strips it and repacks the 4-element payload to
    recover the exact bytes that were signed."""
    import msgpack

    src_identity, src_dest, _dst_identity, dst_dest = _build_identity_destinations()

    lxm = LXMF.LXMessage(
        destination=dst_dest,
        source=src_dest,
        content="sig-roundtrip-with-stamp",
        title="t",
        desired_method=LXMF.LXMessage.DIRECT,
    )
    lxm.pack()

    # If stamp generation didn't produce one (LXMF skips on low cost),
    # inject one manually so the code path under test actually fires.
    if lxm.packed and len(msgpack.unpackb(lxm.packed[96:])) == 4:
        import time as _t

        # Re-pack with a synthetic stamp appended. Sign over the ORIGINAL
        # 4-element payload (pre-stamp) to match what LXMF would have done.
        original_payload = list(msgpack.unpackb(lxm.packed[96:]))
        pre_stamp_hashed_part = lxm.packed[:32] + msgpack.packb(original_payload)
        pre_stamp_message_hash = RNS.Identity.full_hash(pre_stamp_hashed_part)
        pre_stamp_signed_part = pre_stamp_hashed_part + pre_stamp_message_hash
        new_signature = src_identity.sign(pre_stamp_signed_part)

        stamped_payload = original_payload + [int(_t.time()).to_bytes(8, "big")]
        wire = (
            lxm.packed[:32]  # dest + source hashes
            + new_signature
            + msgpack.packb(stamped_payload)
        )
    else:
        wire = lxm.packed

    envelope, _message = _roundtrip_through_bridge(wire, src_identity, tmp_path)

    assert envelope.lxmf_signed_part is not None
    assert envelope.sender_public_key is not None
    assert len(envelope.sender_public_key) == 32

    # Final contract: reconstructed signed_part verifies the signature.
    pk = Ed25519PublicKey.from_public_bytes(envelope.sender_public_key)
    pk.verify(envelope.lxmf_signature, envelope.lxmf_signed_part)
