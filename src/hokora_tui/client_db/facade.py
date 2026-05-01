# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""ClientDB facade: single entry point that delegates to 8 specialized stores.

The facade preserves a stable public surface — every method signature
is preserved across internal refactors so call sites across
hokora_tui/ continue to work without edits. Internally the methods
delegate to one of eight single-responsibility stores
(messages/cursors/channels/identities/bookmarks/settings/discovery/DMs).

Stores share a single ``sqlite3.Connection`` and a single
``threading.Lock``. Store boundaries are logical cohesion, not
transactional isolation — any cross-store write that must be atomic
stays on this facade.

Direct access to individual stores is also available via ``db.messages``,
``db.channels``, etc., for call sites that want namespacing. The
delegating methods below remain for back-compat.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator, Optional

from hokora_tui.client_db._base import TxState
from hokora_tui.client_db._engine import is_plaintext_sqlite, open_encrypted
from hokora_tui.client_db._migration import migrate_to_encrypted
from hokora_tui.client_db._schema import SCHEMA_VERSION, SchemaMigrator
from hokora_tui.client_db.bookmarks import BookmarkStore
from hokora_tui.client_db.channels import ChannelStore
from hokora_tui.client_db.cursors import CursorStore
from hokora_tui.client_db.discovery import DiscoveryStore
from hokora_tui.client_db.dms import DmStore
from hokora_tui.client_db.identities import IdentityStore
from hokora_tui.client_db.messages import MessageStore
from hokora_tui.client_db.sealed_keys import SealedKeyStore
from hokora_tui.client_db.settings import SettingsStore

logger = logging.getLogger(__name__)


class ClientDB:
    """Local SQLite cache for the TUI v2 client (facade over 8 stores)."""

    # Kept on the facade for back-compat with callers that peek at it.
    _SCHEMA_VERSION = SCHEMA_VERSION

    def __init__(
        self,
        db_path: Path,
        key_hex: Optional[str] = None,
        *,
        encrypt: bool = True,
        notice: Optional[Callable[[str], None]] = None,
    ):
        """Open the TUI client cache.

        ``encrypt=True`` (default) requires ``key_hex`` and opens via
        SQLCipher. If ``db_path`` exists as plaintext from a pre-encryption
        TUI version, a one-time silent migration runs first (see
        ``_migration.migrate_to_encrypted``); failure aborts startup
        rather than silently degrading to plaintext.

        ``encrypt=False`` is the test-only escape hatch — opens via
        stdlib sqlite3, ignores ``key_hex``. Mirrors the daemon's
        ``db_encrypt=False`` test pattern.

        ``notice`` is an optional status-area emitter; when provided the
        migration calls it so the operator sees progress.
        """
        self.db_path = db_path
        self._write_lock = threading.Lock()
        self._tx_state = TxState()

        if encrypt:
            if key_hex is None:
                raise ValueError(
                    "ClientDB(encrypt=True) requires key_hex. Resolve via "
                    "hokora_tui.security.client_db_key.resolve_client_db_key()."
                )
            # If the file exists and is plaintext, run the one-time
            # migration before keying any connection. This must abort
            # on failure — never silently fall back to plaintext.
            if is_plaintext_sqlite(str(db_path)):
                migrate_to_encrypted(Path(db_path), key_hex, notice=notice)
            self.conn = open_encrypted(str(db_path), key_hex)
            import sqlcipher3 as _sqlcipher3

            self.conn.row_factory = _sqlcipher3.Row
        else:
            self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            self.conn.execute("PRAGMA journal_mode=WAL")

        # Schema init + migration ladder runs under the shared lock
        # before any store touches the DB.
        SchemaMigrator(self.conn, self._write_lock).init_and_migrate()

        # Sub-stores — all share the same (conn, lock, tx_state). The
        # tx_state flag is shared by reference so ClientDB.transaction()
        # can flip one object and every store's mutators observe it.
        # Namespaced attributes so new call sites can write
        # db.messages.get(...).
        self.messages = MessageStore(self.conn, self._write_lock, self._tx_state)
        self.cursors = CursorStore(self.conn, self._write_lock, self._tx_state)
        self.channels = ChannelStore(self.conn, self._write_lock, self._tx_state)
        self.identities = IdentityStore(self.conn, self._write_lock, self._tx_state)
        self.bookmarks_store = BookmarkStore(self.conn, self._write_lock, self._tx_state)
        self.settings = SettingsStore(self.conn, self._write_lock, self._tx_state)
        self.discovery = DiscoveryStore(self.conn, self._write_lock, self._tx_state)
        self.dms = DmStore(self.conn, self._write_lock, self._tx_state)
        self.sealed_keys = SealedKeyStore(self.conn, self._write_lock, self._tx_state)

    @contextmanager
    def transaction(self) -> Iterator["ClientDB"]:
        """Run a batch of cross-store writes as one atomic transaction.

        Usage::

            with db.transaction() as tx:
                tx.messages.store([msg])
                tx.cursors.set(channel_id, seq)

        Semantics:
          * Acquires the shared write-lock once on entry; every store
            mutation inside the block sees ``tx_state.active=True`` and
            therefore skips its own locking + its own commit.
          * Commits on successful exit, rolls back on exception.
          * Reentrancy is **not** supported — nested ``transaction()``
            calls will deadlock on the non-reentrant ``threading.Lock``.
            That's intentional: nested atomic scopes on a shared
            connection almost always reflect a design error.

        Yields the facade itself so callers can reach any store through
        the usual ``tx.messages``, ``tx.cursors``, etc. attributes.
        """
        if self._tx_state.active:
            raise RuntimeError(
                "ClientDB.transaction() is not reentrant; nested atomic "
                "scopes on a shared sqlite3.Connection are rejected at entry."
            )
        with self._write_lock:
            self._tx_state.active = True
            try:
                yield self
                self.conn.commit()
            except BaseException:
                self.conn.rollback()
                raise
            finally:
                self._tx_state.active = False

    # ─────────────────────────────────────────────────────────────
    # Public facade — every method delegates to its store. Signatures
    # are stable so call sites across hokora_tui/ continue to work.
    # ─────────────────────────────────────────────────────────────

    # ── Messages ───────────────────────────────────────────────

    def store_messages(self, messages: list[dict]):
        return self.messages.store(messages)

    def _store_messages_unlocked(self, messages: list[dict]):
        return self.messages._store_unlocked(messages)

    def get_messages(
        self, channel_id: str, limit: int = 50, before_seq: Optional[int] = None
    ) -> list[dict]:
        return self.messages.get(channel_id, limit=limit, before_seq=before_seq)

    def delete_channel_messages(self, channel_id: str):
        return self.messages.delete_channel(channel_id)

    # ── Cursors ────────────────────────────────────────────────

    def get_cursor(self, channel_id: str) -> int:
        return self.cursors.get(channel_id)

    def get_all_cursors(self) -> dict:
        return self.cursors.get_all()

    def set_cursor(self, channel_id: str, seq: int):
        return self.cursors.set(channel_id, seq)

    def _set_cursor_unlocked(self, channel_id: str, seq: int):
        return self.cursors._set_unlocked(channel_id, seq)

    # ── Channels ───────────────────────────────────────────────

    def store_channels(self, channels: list[dict]):
        return self.channels.store(channels)

    def _store_channels_unlocked(self, channels: list[dict]):
        return self.channels._store_unlocked(channels)

    def get_channels(self) -> list[dict]:
        return self.channels.get_all()

    # ── Channel unread ────────────────────────────────────────

    def get_unread_count(self, channel_id: str) -> int:
        return self.channels.get_unread(channel_id)

    def set_unread_count(self, channel_id: str, count: int):
        return self.channels.set_unread(channel_id, count)

    def increment_channel_unread(self, channel_id: str):
        return self.channels.increment_unread(channel_id)

    def reset_channel_unread(self, channel_id: str):
        return self.channels.reset_unread(channel_id)

    # ── Identities ─────────────────────────────────────────────

    def upsert_identity(self, identity_hash: str, display_name: Optional[str] = None):
        return self.identities.upsert(identity_hash, display_name)

    def get_identity(self, identity_hash: str) -> Optional[dict]:
        return self.identities.get(identity_hash)

    # ── Bookmarks ──────────────────────────────────────────────

    def save_bookmark(self, name: str, destination_hash: str, node_name: Optional[str] = None):
        return self.bookmarks_store.save(name, destination_hash, node_name)

    def get_bookmark(self, name: str) -> Optional[dict]:
        return self.bookmarks_store.get(name)

    def get_bookmarks(self) -> list[dict]:
        return self.bookmarks_store.get_all()

    def delete_bookmark(self, name: str) -> bool:
        return self.bookmarks_store.delete(name)

    # ── Settings ──────────────────────────────────────────────

    def get_setting(self, key: str, default: Optional[str] = None) -> Optional[str]:
        return self.settings.get(key, default)

    def set_setting(self, key: str, value: str):
        return self.settings.set(key, value)

    # ── Discovery (nodes + peers) ─────────────────────────────

    def store_discovered_node(
        self,
        hash: str,
        name: str,
        channel_count: int,
        last_seen: float,
        channels_json: str,
        channel_dests_json: str = "",
    ):
        return self.discovery.store_node(
            hash, name, channel_count, last_seen, channels_json, channel_dests_json
        )

    def get_discovered_nodes(self) -> list[dict]:
        return self.discovery.get_nodes()

    def toggle_node_bookmark(self, hash: str) -> bool:
        return self.discovery.toggle_node_bookmark(hash)

    def store_discovered_peer(
        self,
        hash: str,
        display_name: Optional[str],
        status_text: Optional[str],
        last_seen: float,
    ):
        return self.discovery.store_peer(hash, display_name, status_text, last_seen)

    def get_discovered_peers(self) -> list[dict]:
        return self.discovery.get_peers()

    def toggle_peer_bookmark(self, hash: str) -> bool:
        return self.discovery.toggle_peer_bookmark(hash)

    # ── DMs + conversations ───────────────────────────────────

    def store_dm(
        self,
        sender_hash: str,
        receiver_hash: str,
        timestamp: float,
        body: str,
        signature: Optional[bytes] = None,
    ):
        return self.dms.store(sender_hash, receiver_hash, timestamp, body, signature)

    def get_dms(
        self,
        peer_hash: str,
        limit: int = 50,
        before_time: Optional[float] = None,
    ) -> list[dict]:
        return self.dms.get(peer_hash, limit=limit, before_time=before_time)

    def get_conversations(self) -> list[dict]:
        return self.dms.get_conversations()

    def update_conversation(self, peer_hash: str, peer_name: Optional[str], timestamp: float):
        return self.dms.update_conversation(peer_hash, peer_name, timestamp)

    def mark_conversation_read(self, peer_hash: str):
        return self.dms.mark_conversation_read(peer_hash)

    def increment_unread(self, peer_hash: str):
        return self.dms.increment_unread(peer_hash)

    # ── Schema introspection (back-compat for tests) ──────────

    def _get_schema_version(self) -> int:
        """Return the current schema version as recorded in the DB.

        Test-only escape hatch — exposes the version field directly
        for migration-ladder assertions. Production code should go
        through ``SchemaMigrator`` instead.
        """
        try:
            row = self.conn.execute("SELECT version FROM schema_version WHERE id = 1").fetchone()
            return row["version"] if row else 0
        except Exception:
            return 0

    # ── Cleanup ───────────────────────────────────────────────

    def close(self):
        self.conn.close()
