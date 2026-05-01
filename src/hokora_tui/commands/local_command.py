# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""LocalCommand — connect to the local daemon DB.

Reads channels and messages directly from the daemon's SQLite database
(no RNS link needed). Useful for offline work and as a fast path when
the user is on the same host as the daemon. Sealed-channel messages
are decrypted in-process using the node identity loaded from the
daemon's identity file.

The work splits into two phases:
1. Background-thread I/O — load config, open DB, read channels +
   messages, decrypt sealed bodies, reconstruct destination hashes.
2. Main-thread UI update — push state, start sync engine (LXMF
   requires the main thread), switch to the channels tab.

Calls ``helpers.ensure_sync_engine`` on the main thread to lazy-create
the sync engine + rewire its callbacks before connecting channels.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hokora_tui.commands._base import CommandContext

logger = logging.getLogger(__name__)


class LocalCommand:
    """``/local`` — connect to the local daemon (auto-discovery via PID file)."""

    name = "local"
    aliases: tuple[str, ...] = ()
    summary = "Connect to the local daemon's DB"

    def execute(self, ctx: "CommandContext", args: str) -> None:
        ctx.status.set_connection("connecting")
        ctx.status.set_context("Connecting to local node...")
        ctx.app._schedule_redraw()

        threading.Thread(target=lambda: self._do_io(ctx), daemon=True).start()

    def _do_io(self, ctx: "CommandContext") -> None:
        """Background thread: ONLY I/O operations. No urwid widget calls."""
        try:
            from hokora.config import load_config
            from hokora.constants import ACCESS_PRIVATE
            from hokora.db.engine import (
                _patch_aiosqlite_for_sqlcipher,
                create_db_engine,
                create_session_factory,
            )
            from hokora.db.queries import ChannelRepo, MessageRepo, RoleRepo

            config = load_config()
            # Resolver returns None when encryption is off or for relay nodes;
            # otherwise reads the keyfile (preferred) or inline db_key (legacy).
            resolved_db_key = config.resolve_db_key()
            if config.db_encrypt and resolved_db_key:
                _patch_aiosqlite_for_sqlcipher()

            identity = ctx.state.identity
            client_hash = identity.hexhash if identity and hasattr(identity, "hexhash") else None

            async def _read_node():
                engine = create_db_engine(
                    config.db_path,
                    encrypt=config.db_encrypt,
                    db_key=resolved_db_key,
                )
                sf = create_session_factory(engine)
                channels = []
                all_messages = {}

                # Load the daemon's node RNS identity once — used for
                # sealed-key decrypt AND for tagging channel rows with
                # node_identity_hash so the UI can disambiguate across
                # multi-node setups.
                node_ident = None
                node_identity_hash_local = None
                try:
                    import RNS as _RNS

                    id_path = config.identity_dir / "node_identity"
                    if id_path.exists():
                        node_ident = _RNS.Identity.from_file(str(id_path))
                        node_identity_hash_local = node_ident.hexhash
                except Exception as e:
                    logger.debug(f"/local: could not load node identity: {e}")

                # Load sealed channel manager for decrypting messages
                sealed_mgr = None
                try:
                    from hokora.db.models import (
                        Channel as ChannelModel,
                    )
                    from hokora.db.models import SealedKey
                    from hokora.security.sealed import SealedChannelManager

                    sealed_mgr = SealedChannelManager()
                    node_hash = node_identity_hash_local

                    async with sf() as s:
                        async with s.begin():
                            from sqlalchemy import select as sa_select

                            result = await s.execute(
                                sa_select(ChannelModel).where(ChannelModel.sealed.is_(True))
                            )
                            for ch in result.scalars().all():
                                key_result = await s.execute(
                                    sa_select(SealedKey)
                                    .where(SealedKey.channel_id == ch.id)
                                    .where(SealedKey.identity_hash == node_hash)
                                    .order_by(SealedKey.epoch.desc())
                                    .limit(1)
                                )
                                sk = key_result.scalar_one_or_none()
                                if sk and node_ident:
                                    try:
                                        raw_key = node_ident.decrypt(sk.encrypted_key_blob)
                                        sealed_mgr._keys[ch.id] = {
                                            "key": raw_key,
                                            "epoch": sk.epoch,
                                        }
                                    except Exception:
                                        logger.debug(
                                            "sealed key decrypt failed for %s",
                                            ch.id,
                                            exc_info=True,
                                        )
                except Exception as sealed_err:
                    logger.warning(f"/local sealed key loading failed: {sealed_err}")
                    sealed_mgr = None

                async with sf() as session:
                    async with session.begin():
                        ch_repo = ChannelRepo(session)
                        msg_repo = MessageRepo(session)
                        role_repo = RoleRepo(session)

                        node_owner_hash = getattr(config, "node_identity_hash", None)
                        is_node_owner = (
                            client_hash and node_owner_hash and client_hash == node_owner_hash
                        )

                        for ch in await ch_repo.list_all():
                            if ch.access_mode == ACCESS_PRIVATE and not is_node_owner:
                                if client_hash:
                                    roles = await role_repo.get_identity_roles(
                                        client_hash,
                                        ch.id,
                                        strict_channel_scope=True,
                                    )
                                    if not roles:
                                        continue
                                else:
                                    continue

                            ch_dict = {
                                "id": ch.id,
                                "name": ch.name,
                                "description": ch.description or "",
                                "access_mode": ch.access_mode,
                                "category_id": ch.category_id,
                                "position": ch.position,
                                "identity_hash": ch.identity_hash,
                                "destination_hash": getattr(ch, "destination_hash", None),
                                "latest_seq": ch.latest_seq,
                                "sealed": getattr(ch, "sealed", False),
                                "node_identity_hash": node_identity_hash_local,
                            }
                            channels.append(ch_dict)

                            msgs = await msg_repo.get_history(ch.id, since_seq=0, limit=50)
                            ch_msgs = []
                            for m in msgs:
                                if m.seq is None:
                                    continue  # Skip thread replies
                                body = m.body if m.body is not None else ""
                                # Decrypt sealed channel messages
                                if (
                                    not body
                                    and sealed_mgr
                                    and getattr(m, "encrypted_body", None)
                                    and getattr(m, "encryption_nonce", None)
                                ):
                                    try:
                                        plaintext = sealed_mgr.decrypt(
                                            m.channel_id,
                                            m.encryption_nonce,
                                            m.encrypted_body,
                                            getattr(m, "encryption_epoch", None),
                                        )
                                        body = plaintext.decode("utf-8")
                                    except Exception:
                                        body = "[encrypted]"
                                ch_msgs.append(
                                    {
                                        "msg_hash": m.msg_hash,
                                        "channel_id": m.channel_id,
                                        "sender_hash": m.sender_hash,
                                        "seq": m.seq,
                                        "timestamp": m.timestamp,
                                        "type": m.type,
                                        "body": body,
                                        "display_name": m.display_name,
                                        "reply_to": m.reply_to,
                                        "deleted": m.deleted,
                                        "pinned": m.pinned,
                                        "reactions": m.reactions or {},
                                        "edited": bool(m.edit_chain)
                                        if hasattr(m, "edit_chain") and m.edit_chain
                                        else False,
                                        "verified": True,
                                    }
                                )
                            all_messages[ch.id] = ch_msgs

                await engine.dispose()
                return channels, all_messages, config

            channels, all_messages, config = asyncio.run(_read_node())
            node_name = getattr(config, "node_name", "local")

            # Reconstruct destination_hash from identity files (pure I/O)
            import binascii
            from pathlib import Path

            try:
                import RNS

                identities_dir = Path(config.data_dir) / "identities"
                for ch in channels:
                    ch_id = ch.get("id", "")
                    if ch_id and identities_dir.exists():
                        id_file = identities_dir / f"channel_{ch_id}"
                        if id_file.exists():
                            ch_identity = RNS.Identity.from_file(str(id_file))
                            dest = RNS.Destination(
                                ch_identity,
                                RNS.Destination.IN,
                                RNS.Destination.SINGLE,
                                "hokora",
                                ch_id,
                            )
                            dest_hash_bytes = dest.hash
                            ch["destination_hash"] = binascii.hexlify(dest_hash_bytes).decode()
                            # Cache identity so connect_channel() succeeds
                            # without waiting for an announce
                            RNS.Identity.remember(
                                None, dest_hash_bytes, ch_identity.get_public_key()
                            )
            except ImportError:
                pass

            # Store channel metadata in client DB (NOT messages —
            # sync_history handles message storage with proper decryption)
            if ctx.db is not None:
                ctx.db.store_channels(channels)

            # Build discovery node entry (pure data, no UI)
            channel_dests = {}
            for ch in channels:
                ch_id = ch.get("id", "")
                dh = ch.get("destination_hash") or ""
                if ch_id and dh:
                    channel_dests[ch_id] = dh

            local_node = {
                "hash": node_name,
                "node_name": node_name,
                "channel_count": len(channels),
                "last_seen": time.time(),
                "channels": [ch.get("name", "") for ch in channels],
                "channel_dests": channel_dests,
                "primary_dest": (
                    next(iter(channel_dests.values()), None) if channel_dests else None
                ),
                "bookmarked": False,
            }

            # Schedule ALL state + UI updates on the main urwid thread.
            # The sync engine init runs here too because LXMF.LXMRouter
            # requires signal handlers which only work on the main
            # thread.
            self._schedule_main_thread(
                ctx,
                lambda: (
                    self._on_success(ctx, channels, all_messages, node_name, local_node)
                    if channels
                    else self._on_empty(ctx)
                ),
            )

        except Exception as e:
            logger.error(f"Local connect failed: {e}", exc_info=True)
            err_msg = str(e)
            self._schedule_main_thread(ctx, lambda: self._on_error(ctx, err_msg))

    @staticmethod
    def _schedule_main_thread(ctx: "CommandContext", fn) -> None:
        """Marshal fn to the main urwid thread + wake the loop."""
        if ctx.app.loop:
            ctx.app.loop.set_alarm_in(0, lambda _l, _d: fn())
            ctx.app._wake_loop()
        else:
            fn()

    @staticmethod
    def _on_success(
        ctx: "CommandContext",
        channels: list,
        all_messages: dict,
        node_name: str,
        local_node: dict,
    ) -> None:
        ctx.state.channels = channels
        ctx.state.messages = all_messages
        ctx.state.connection_status = "connected"
        ctx.state.connected_node_name = node_name
        for ch in channels:
            ctx.state.unread_counts[ch["id"]] = 0
        ctx.state.discovered_nodes[node_name] = local_node

        ctx.state.emit("channels_updated")
        ctx.state.emit("nodes_updated")

        # Start sync engine on main thread (LXMF requires it).
        try:
            from hokora_tui.commands.helpers import ensure_sync_engine

            ensure_sync_engine(ctx.app)
            engine = ctx.app.sync_engine
            if engine:
                for ch in channels:
                    dh = ch.get("destination_hash")
                    ch_id = ch.get("id")
                    if dh and ch_id:
                        try:
                            engine.connect_channel(bytes.fromhex(dh), ch_id)
                        except Exception:
                            logger.debug("connect_channel failed for %s", ch_id, exc_info=True)
        except Exception as exc:
            logger.warning("Could not start sync engine: %s", exc)

        ctx.status.set_connection("connected", node_name)
        ctx.status.set_context(f"Connected to {node_name} ({len(channels)} channels)")
        ctx.app.nav.switch_to(3)
        if channels:
            first_ch = channels[0].get("id")
            if first_ch and hasattr(ctx.app, "channels_view"):
                ctx.app.channels_view.select_channel(first_ch)
        ctx.app._schedule_redraw()

    @staticmethod
    def _on_empty(ctx: "CommandContext") -> None:
        ctx.status.set_connection("disconnected")
        ctx.status.set_context("No channels found on local node.")
        ctx.app._schedule_redraw()

    @staticmethod
    def _on_error(ctx: "CommandContext", err_msg: str) -> None:
        ctx.status.set_connection("disconnected")
        ctx.status.set_context(f"Connect failed: {err_msg}")
        ctx.app._schedule_redraw()
