# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for hokora init internals (pure functions, no RNS init)."""

import stat

try:
    import tomllib
except ImportError:
    import tomli as tomllib

from hokora.cli.init import _write_config, _write_rns_config
from hokora.config import NodeConfig


class TestWriteConfig:
    def test_community_config_uses_db_keyfile(self, tmp_path):
        """Fresh init writes ``db_keyfile`` (not inline ``db_key``).

        Header docstring mentions both names by design (so legacy operators
        searching for ``db_key`` find the migration hint), so we parse the
        TOML and inspect the actual assignment, not raw text.
        """
        keyfile = tmp_path / "db_key"
        keyfile.write_text("a" * 64 + "\n")
        keyfile.chmod(0o600)
        config = NodeConfig(
            node_name="Community Test",
            data_dir=tmp_path,
            db_encrypt=True,
            db_keyfile=keyfile,
        )
        path = tmp_path / "hokora.toml"
        _write_config(path, config, is_relay=False)
        parsed = tomllib.loads(path.read_text())
        assert parsed["node_name"] == "Community Test"
        assert parsed["db_encrypt"] is True
        assert parsed["db_keyfile"] == str(keyfile)
        assert "db_key" not in parsed
        # Community block
        assert "rate_limit_tokens" in parsed
        assert "enable_fts" in parsed
        # No relay block
        assert parsed.get("relay_only") is not True
        assert parsed.get("propagation_enabled") is not True

    def test_community_config_legacy_inline_db_key_still_writes(self, tmp_path):
        """Backwards-compat: callers passing inline ``db_key`` (e.g. external
        tooling) still get a valid TOML file with the inline form. Real
        ``hokora init`` no longer takes this path."""
        config = NodeConfig(
            node_name="Legacy",
            data_dir=tmp_path,
            db_encrypt=True,
            db_key="a" * 64,
        )
        path = tmp_path / "hokora.toml"
        _write_config(path, config, is_relay=False)
        parsed = tomllib.loads(path.read_text())
        assert parsed["db_key"] == "a" * 64
        assert "db_keyfile" not in parsed

    def test_relay_config_has_relay_block(self, tmp_path):
        config = NodeConfig(
            node_name="Relay Test",
            data_dir=tmp_path,
            db_encrypt=False,
            relay_only=True,
            propagation_enabled=True,
        )
        path = tmp_path / "hokora.toml"
        _write_config(path, config, is_relay=True)
        content = path.read_text()
        assert "db_encrypt = false" in content
        assert "relay_only = true" in content
        assert "propagation_enabled = true" in content
        assert "propagation_storage_mb" in content
        # Community-only keys should be absent
        assert "rate_limit_tokens" not in content
        assert "enable_fts" not in content

    def test_generated_toml_mentions_announce_enabled(self, tmp_path):
        """Community init should document announce_enabled alongside interval."""
        config = NodeConfig(
            node_name="community",
            data_dir=tmp_path,
            db_encrypt=False,
        )
        path = tmp_path / "hokora.toml"
        _write_config(path, config, is_relay=False)
        content = path.read_text()
        assert "announce_enabled = true" in content
        assert "announce_interval" in content

    def test_config_file_is_0o600(self, tmp_path):
        config = NodeConfig(
            node_name="perm test",
            data_dir=tmp_path,
            db_encrypt=False,
        )
        path = tmp_path / "hokora.toml"
        _write_config(path, config, is_relay=False)
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    def test_node_name_special_chars_escaped(self, tmp_path):
        """Quotes and backslashes in node_name must be escaped in TOML output."""
        config = NodeConfig(
            node_name='Weird "Name" with \\ backslash',
            data_dir=tmp_path,
            db_encrypt=False,
        )
        path = tmp_path / "hokora.toml"
        _write_config(path, config, is_relay=False)
        content = path.read_text()
        # Verify the file parses back correctly
        parsed = tomllib.loads(content)
        assert parsed["node_name"] == 'Weird "Name" with \\ backslash'


class TestWriteRNSConfig:
    def test_relay_has_tcp_server_interface(self, tmp_path):
        path = tmp_path / "rns" / "config"
        _write_rns_config(path, is_relay=True)
        content = path.read_text()
        assert "[[TCP Server]]" in content
        assert "TCPServerInterface" in content
        assert "listen_ip = 0.0.0.0" in content
        assert "listen_port = 4242" in content

    def test_community_has_seed_examples_commented(self, tmp_path):
        path = tmp_path / "rns" / "config"
        _write_rns_config(path, is_relay=False)
        content = path.read_text()
        # TCP seed example is commented (lines prefixed with #)
        assert "# [[TCP Seed]]" in content
        assert "# [[I2P Network]]" in content

    def test_both_enable_transport(self, tmp_path):
        """Both relay and community RNS configs enable transport + share_instance."""
        for is_relay in (True, False):
            path = tmp_path / f"rns-{is_relay}" / "config"
            _write_rns_config(path, is_relay=is_relay)
            content = path.read_text()
            assert "enable_transport = Yes" in content
            assert "share_instance = Yes" in content

    def test_creates_parent_dir(self, tmp_path):
        path = tmp_path / "deeply" / "nested" / "rns" / "config"
        _write_rns_config(path, is_relay=False)
        assert path.exists()
