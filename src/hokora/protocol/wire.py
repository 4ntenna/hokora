# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Wire protocol: msgpack encode/decode for sync requests/responses.

Sync protocol frames are MessagePack-encoded, prefixed with a 2-byte
big-endian length header for framing over Reticulum Links.
"""

import os
import struct
from typing import Optional

import msgpack

from hokora.constants import NONCE_SIZE, WIRE_VERSION, CDSP_VERSION
from hokora.exceptions import SyncError

# 2-byte big-endian length header format
_LENGTH_HEADER = struct.Struct("!H")
MAX_FRAME_SIZE = 65535


def generate_nonce() -> bytes:
    """Generate a random nonce for sync requests."""
    return os.urandom(NONCE_SIZE)


def _add_length_header(data: bytes) -> bytes:
    """Prepend a 2-byte big-endian length header."""
    if len(data) > MAX_FRAME_SIZE:
        raise SyncError(f"Frame too large: {len(data)} > {MAX_FRAME_SIZE}")
    return _LENGTH_HEADER.pack(len(data)) + data


def _strip_length_header(data: bytes) -> bytes:
    """Strip the 2-byte length header and validate."""
    if len(data) < 2:
        raise SyncError("Frame too short for length header")
    expected_len = _LENGTH_HEADER.unpack_from(data, 0)[0]
    payload = data[2:]
    if len(payload) != expected_len:
        raise SyncError(f"Frame length mismatch: header says {expected_len}, got {len(payload)}")
    return payload


def encode_sync_request(
    action: int,
    nonce: bytes,
    payload: Optional[dict] = None,
) -> bytes:
    """Encode a sync request to length-prefixed msgpack bytes."""
    if len(nonce) != NONCE_SIZE:
        raise SyncError(f"Nonce must be {NONCE_SIZE} bytes, got {len(nonce)}")

    request = {
        "v": WIRE_VERSION,
        "action": action,
        "nonce": nonce,
    }
    if payload:
        request["payload"] = payload

    return _add_length_header(msgpack.packb(request, use_bin_type=True))


def decode_sync_request(data: bytes) -> dict:
    """Decode a sync request from length-prefixed msgpack bytes."""
    raw = _strip_length_header(data)
    try:
        request = msgpack.unpackb(raw, raw=False)
    except (msgpack.UnpackException, ValueError) as e:
        raise SyncError(f"Failed to decode sync request: {e}")

    if not isinstance(request, dict):
        raise SyncError("Sync request must be a dict")

    if "action" not in request:
        raise SyncError("Sync request missing 'action' field")

    if "nonce" not in request:
        raise SyncError("Sync request missing 'nonce' field")

    nonce = request["nonce"]
    if not isinstance(nonce, bytes) or len(nonce) != NONCE_SIZE:
        raise SyncError(f"Invalid nonce: expected {NONCE_SIZE} bytes")

    return request


def encode_sync_response(
    nonce: bytes,
    payload: dict,
    node_time: Optional[float] = None,
) -> bytes:
    """Encode a sync response to length-prefixed msgpack bytes."""
    response = {
        "v": WIRE_VERSION,
        "nonce": nonce,
        "data": payload,  # Wire field stays "data" for backward compatibility
    }
    if node_time is not None:
        response["node_time"] = node_time

    return _add_length_header(msgpack.packb(response, use_bin_type=True))


def decode_sync_response(data: bytes) -> dict:
    """Decode a sync response from length-prefixed msgpack bytes."""
    raw = _strip_length_header(data)
    try:
        response = msgpack.unpackb(raw, raw=False)
    except (msgpack.UnpackException, ValueError) as e:
        raise SyncError(f"Failed to decode sync response: {e}")

    if not isinstance(response, dict):
        raise SyncError("Sync response must be a dict")

    if "nonce" not in response:
        raise SyncError("Sync response missing 'nonce' field")

    return response


def encode_message_for_sync(msg) -> dict:
    """Encode a Message ORM object to a dict for sync responses.

    ``sender_public_key`` (32-byte Ed25519) is populated by the sync handler
    via the local ``identities`` cache. ``sender_rns_public_key`` (full 64-byte
    X25519||Ed25519 blob) is attached only by the federation pusher path
    (sourced via ``RNS.Identity.recall``); the receiver's
    ``verify_sender_binding`` chokepoint requires it for structural binding
    of ``sender_hash`` to its pubkey.
    """
    return {
        "msg_hash": msg.msg_hash,
        "channel_id": msg.channel_id,
        "sender_hash": msg.sender_hash,
        "seq": msg.seq,
        "thread_seq": msg.thread_seq,
        "timestamp": msg.timestamp,
        "type": msg.type,
        "body": msg.body if msg.body is not None else "",
        "media_path": msg.media_path,
        "media_meta": msg.media_meta,
        "reply_to": msg.reply_to,
        "deleted": msg.deleted,
        "pinned": msg.pinned,
        "pinned_at": msg.pinned_at,
        "edit_chain": msg.edit_chain,
        "edited": bool(msg.edit_chain) if hasattr(msg, "edit_chain") and msg.edit_chain else False,
        "reactions": msg.reactions,
        "lxmf_signature": msg.lxmf_signature,
        "lxmf_signed_part": msg.lxmf_signed_part,
        "sender_public_key": None,
        "sender_rns_public_key": None,
        "display_name": msg.display_name,
        "mentions": msg.mentions,
    }


def encode_cdsp_session_init(
    client_version: int,
    sync_profile: int,
    resume_token: Optional[bytes] = None,
) -> bytes:
    """Encode a CDSP Session Init message."""
    payload = {
        "cdsp_version": client_version,
        "sync_profile": sync_profile,
    }
    if resume_token:
        payload["resume_token"] = resume_token
    return _add_length_header(msgpack.packb(payload, use_bin_type=True))


def decode_cdsp_session_init(data: bytes) -> dict:
    """Decode a CDSP Session Init message."""
    try:
        payload = msgpack.unpackb(data, raw=False)
    except (msgpack.UnpackException, ValueError) as e:
        raise SyncError(f"Failed to decode CDSP Session Init: {e}")
    if not isinstance(payload, dict):
        raise SyncError("CDSP Session Init must be a dict")
    if "sync_profile" not in payload:
        raise SyncError("CDSP Session Init missing sync_profile")
    return payload


def encode_cdsp_session_ack(
    session_id: str,
    accepted_profile: int,
    server_version: int = CDSP_VERSION,
    deferred_count: int = 0,
) -> bytes:
    """Encode a CDSP Session Ack message."""
    payload = {
        "session_id": session_id,
        "accepted_profile": accepted_profile,
        "cdsp_version": server_version,
        "deferred_count": deferred_count,
    }
    return _add_length_header(msgpack.packb(payload, use_bin_type=True))


def decode_cdsp_session_ack(data: bytes) -> dict:
    """Decode a CDSP Session Ack message."""
    try:
        payload = msgpack.unpackb(data, raw=False)
    except (msgpack.UnpackException, ValueError) as e:
        raise SyncError(f"Failed to decode CDSP Session Ack: {e}")
    if not isinstance(payload, dict):
        raise SyncError("CDSP Session Ack must be a dict")
    return payload


def encode_cdsp_profile_update(sync_profile: int) -> bytes:
    """Encode a CDSP Profile Update message."""
    payload = {"sync_profile": sync_profile}
    return _add_length_header(msgpack.packb(payload, use_bin_type=True))


def encode_cdsp_session_reject(error_code: int, server_version: int = CDSP_VERSION) -> bytes:
    """Encode a CDSP Session Reject message."""
    payload = {
        "error_code": error_code,
        "cdsp_version": server_version,
    }
    return _add_length_header(msgpack.packb(payload, use_bin_type=True))


def encode_push_event(event_type: str, data: dict) -> bytes:
    """Encode a live push event."""
    return msgpack.packb(
        {
            "v": WIRE_VERSION,
            "event": event_type,
            "data": data,
        },
        use_bin_type=True,
    )
