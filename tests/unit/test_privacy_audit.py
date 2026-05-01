# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Privacy audit tests: ensure no transport/interface metadata leaks.

Per CDSP spec Section 4.1.3: the schema must not accumulate transport metadata.
"""

import os

from hokora.db.models import Base, Session, DeferredSyncItem


class TestSchemaAudit:
    """Verify no column names reveal transport or interface type."""

    _FORBIDDEN_COLUMN_SUBSTRINGS = [
        "interface_type",
        "transport_type",
        "transport_mode",
        "rnode",
        "lora_",
        "tcp_",
        "udp_",
        "serial_port",
        "ble_",
        "wifi_",
        "bitrate",
        "attached_interface",
    ]

    def test_no_transport_columns_in_any_table(self):
        """No table in the schema should have columns referencing transport type."""
        for table in Base.metadata.sorted_tables:
            for col in table.columns:
                col_lower = col.name.lower()
                for forbidden in self._FORBIDDEN_COLUMN_SUBSTRINGS:
                    assert forbidden not in col_lower, (
                        f"Table '{table.name}' column '{col.name}' contains "
                        f"forbidden substring '{forbidden}' — violates CDSP spec 4.1.3"
                    )

    def test_session_model_has_no_transport_field(self):
        """Session model specifically must have no transport-related columns."""
        session_table = Session.__table__
        col_names = {c.name for c in session_table.columns}
        forbidden = {"interface_type", "transport_type", "transport", "interface", "bitrate"}
        overlap = col_names & forbidden
        assert not overlap, f"Session model has forbidden columns: {overlap}"

    def test_deferred_model_has_no_transport_field(self):
        """DeferredSyncItem model must have no transport-related columns."""
        table = DeferredSyncItem.__table__
        col_names = {c.name for c in table.columns}
        forbidden = {"interface_type", "transport_type", "transport", "interface"}
        overlap = col_names & forbidden
        assert not overlap, f"DeferredSyncItem model has forbidden columns: {overlap}"


class TestSyncHandlerPrivacy:
    """Verify SyncHandler never accesses link.attached_interface or similar."""

    def test_sync_handler_no_interface_access(self):
        """Grep sync.py source for interface type access patterns."""
        sync_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "..",
            "src",
            "hokora",
            "protocol",
            "sync.py",
        )
        sync_path = os.path.normpath(sync_path)
        with open(sync_path) as f:
            source = f.read()

        forbidden_patterns = [
            "attached_interface",
            "get_interface_type",
            "interface_type",
            "link.transport",
            "get_bitrate",
        ]
        for pattern in forbidden_patterns:
            assert pattern not in source, (
                f"sync.py contains '{pattern}' — violates CDSP privacy requirement"
            )

    def test_session_manager_no_interface_access(self):
        """session.py must not access interface/transport info."""
        session_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "..",
            "src",
            "hokora",
            "protocol",
            "session.py",
        )
        session_path = os.path.normpath(session_path)
        with open(session_path) as f:
            source = f.read()

        forbidden_patterns = [
            "attached_interface",
            "get_interface_type",
            "interface_type",
        ]
        for pattern in forbidden_patterns:
            assert pattern not in source, (
                f"session.py contains '{pattern}' — violates CDSP privacy requirement"
            )


class TestMigrationPrivacy:
    """Verify the schema migration doesn't carry transport-layer columns."""

    def test_initial_schema_no_transport_columns(self):
        migration_path = os.path.normpath(
            os.path.join(
                os.path.dirname(__file__),
                "..",
                "..",
                "alembic",
                "versions",
                "001_initial_schema.py",
            )
        )
        with open(migration_path) as f:
            source = f.read()

        forbidden = ["interface", "transport", "rnode", "bitrate"]
        source_lower = source.lower()
        for pattern in forbidden:
            assert pattern not in source_lower, (
                f"Initial schema migration contains '{pattern}' — violates CDSP spec 4.1.3"
            )
