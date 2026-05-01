# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Test configuration loading."""

import os
from pathlib import Path

import pytest

from hokora.config import NodeConfig, load_config


class TestNodeConfig:
    def test_defaults_require_db_key(self):
        """db_encrypt=True by default requires db_key."""
        with pytest.raises(ValueError, match="db_key"):
            NodeConfig()

    def test_defaults_with_key(self):
        config = NodeConfig(db_key="a" * 64)
        assert config.node_name == "Hokora Node"
        assert config.log_level == "INFO"
        assert config.max_sync_limit == 100
        assert config.db_encrypt is True

    def test_encrypt_disabled(self):
        config = NodeConfig(db_encrypt=False)
        assert config.db_encrypt is False

    def test_computed_paths(self):
        config = NodeConfig(data_dir=Path("/tmp/test"), db_encrypt=False)
        assert config.db_path == Path("/tmp/test/hokora.db")
        assert config.media_dir == Path("/tmp/test/media")
        assert config.identity_dir == Path("/tmp/test/identities")

    def test_explicit_paths(self):
        config = NodeConfig(
            data_dir=Path("/tmp/test"),
            db_path=Path("/tmp/custom.db"),
            db_encrypt=False,
        )
        assert config.db_path == Path("/tmp/custom.db")

    def test_load_from_toml(self, tmp_path):
        config_file = tmp_path / "test.toml"
        config_file.write_text('node_name = "Test Node"\nlog_level = "DEBUG"\ndb_encrypt = false\n')
        config = load_config(config_file)
        assert config.node_name == "Test Node"
        assert config.log_level == "DEBUG"

    def test_env_var_overlay(self, tmp_path):
        config_file = tmp_path / "test.toml"
        config_file.write_text('node_name = "Original"\ndb_encrypt = false\n')

        os.environ["HOKORA_NODE_NAME"] = "FromEnv"
        try:
            config = load_config(config_file)
            assert config.node_name == "FromEnv"
        finally:
            del os.environ["HOKORA_NODE_NAME"]

    def test_missing_config_uses_defaults(self, tmp_path):
        """Missing config with db_encrypt=True (default) and no key raises."""
        with pytest.raises(ValueError, match="db_key"):
            load_config(tmp_path / "nonexistent.toml")

    def test_invalid_toml_syntax(self, tmp_path):
        config_file = tmp_path / "bad.toml"
        config_file.write_text('node_name = "unclosed string\n')
        with pytest.raises(Exception):
            load_config(config_file)

    def test_wrong_type_for_numeric_field(self, tmp_path):
        config_file = tmp_path / "badtype.toml"
        config_file.write_text('db_encrypt = false\nrate_limit_tokens = "not_a_number"\n')
        with pytest.raises(Exception):
            load_config(config_file)

    def test_metadata_scrub_days_default(self):
        config = NodeConfig(db_encrypt=False)
        assert config.metadata_scrub_days == 0

    def test_metadata_scrub_days_custom(self):
        config = NodeConfig(db_encrypt=False, metadata_scrub_days=30)
        assert config.metadata_scrub_days == 30

    def test_announce_interval_must_be_positive(self):
        """announce_interval <= 0 is rejected — use announce_enabled for disable."""
        with pytest.raises(ValueError, match="announce_interval must be > 0"):
            NodeConfig(db_encrypt=False, announce_interval=0)
        with pytest.raises(ValueError, match="announce_interval must be > 0"):
            NodeConfig(db_encrypt=False, announce_interval=-5)

    def test_announce_enabled_defaults_true(self):
        config = NodeConfig(db_encrypt=False)
        assert config.announce_enabled is True

    def test_announce_enabled_false_with_positive_interval(self):
        """Silent mode: announces off, but interval still positive (cadence preserved)."""
        config = NodeConfig(db_encrypt=False, announce_enabled=False, announce_interval=120)
        assert config.announce_enabled is False
        assert config.announce_interval == 120

    def test_relay_only_exempts_db_key_requirement(self):
        """Relay mode with db_encrypt=True does not require db_key (DB is never opened)."""
        config = NodeConfig(relay_only=True, db_encrypt=True)
        assert config.relay_only is True
        assert config.db_encrypt is True
        assert config.db_key is None

    def test_relay_without_propagation_warns(self, tmp_path, caplog):
        """load_config warns when relay_only=True but propagation_enabled=False."""
        import logging

        config_file = tmp_path / "relay.toml"
        config_file.write_text(
            "db_encrypt = false\nrelay_only = true\npropagation_enabled = false\n"
        )
        with caplog.at_level(logging.WARNING, logger="hokora.config"):
            load_config(config_file)
        assert any(
            "relay_only=True" in rec.message and "propagation_enabled=False" in rec.message
            for rec in caplog.records
        )

    def test_relay_with_propagation_does_not_warn(self, tmp_path, caplog):
        """load_config does not warn when relay_only and propagation_enabled are both True."""
        import logging

        config_file = tmp_path / "relay.toml"
        config_file.write_text(
            "db_encrypt = false\nrelay_only = true\npropagation_enabled = true\n"
        )
        with caplog.at_level(logging.WARNING, logger="hokora.config"):
            load_config(config_file)
        assert not any("propagation_enabled=False" in rec.message for rec in caplog.records)
