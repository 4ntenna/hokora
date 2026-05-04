# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""SQLCipher master key resolution from a separate keyfile.

Covers ``NodeConfig.resolve_db_key()`` resolution order, file-mode hygiene,
and the deprecation path for the legacy inline ``db_key``.
"""

from __future__ import annotations

import os
import warnings
from pathlib import Path

import pytest

import hokora.config as config_module
from hokora.config import NodeConfig

VALID_KEY = "a" * 64
VALID_KEY_B = "b" * 64


@pytest.fixture(autouse=True)
def reset_inline_warning_flag():
    """Each test starts with the one-shot deprecation flag cleared.

    Without this, the second test in a session would not see the
    ``DeprecationWarning`` because the module-level flag would already be
    set from the first test.
    """
    config_module._inline_db_key_warned = False
    yield
    config_module._inline_db_key_warned = False


def _write_key(tmp_path: Path, body: str = VALID_KEY, mode: int = 0o600) -> Path:
    p = tmp_path / "db_key"
    p.write_text(body)
    os.chmod(p, mode)
    return p


class TestResolverPaths:
    def test_keyfile_set_with_valid_contents(self, tmp_path):
        keyfile = _write_key(tmp_path)
        cfg = NodeConfig(data_dir=tmp_path, db_keyfile=keyfile)
        assert cfg.resolve_db_key() == VALID_KEY

    def test_keyfile_strips_trailing_newline(self, tmp_path):
        keyfile = _write_key(tmp_path, body=VALID_KEY + "\n")
        cfg = NodeConfig(data_dir=tmp_path, db_keyfile=keyfile)
        assert cfg.resolve_db_key() == VALID_KEY

    def test_keyfile_missing_file_raises(self, tmp_path):
        cfg = NodeConfig(data_dir=tmp_path, db_keyfile=tmp_path / "nope")
        with pytest.raises(FileNotFoundError, match="db_keyfile"):
            cfg.resolve_db_key()

    def test_keyfile_invalid_contents_raises(self, tmp_path):
        bad = tmp_path / "db_key"
        bad.write_text("not-hex-not-64-chars")
        os.chmod(bad, 0o600)
        cfg = NodeConfig(data_dir=tmp_path, db_keyfile=bad)
        with pytest.raises(ValueError, match="64 hex"):
            cfg.resolve_db_key()

    def test_keyfile_wins_over_inline(self, tmp_path):
        """Both configured: keyfile takes precedence; inline is not consulted
        and therefore the deprecation warning is NOT emitted."""
        keyfile = _write_key(tmp_path, body=VALID_KEY_B)
        cfg = NodeConfig(data_dir=tmp_path, db_keyfile=keyfile, db_key=VALID_KEY)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            assert cfg.resolve_db_key() == VALID_KEY_B
        assert not any(issubclass(w.category, DeprecationWarning) for w in caught)

    def test_inline_only_warns_once(self, tmp_path):
        cfg = NodeConfig(data_dir=tmp_path, db_key=VALID_KEY)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            assert cfg.resolve_db_key() == VALID_KEY
            # Second resolve in the same process must not re-warn.
            assert cfg.resolve_db_key() == VALID_KEY
        deprecation = [w for w in caught if issubclass(w.category, DeprecationWarning)]
        assert len(deprecation) == 1
        assert "hokora db migrate-key" in str(deprecation[0].message)

    def test_auto_discovery_picks_up_default_keyfile(self, tmp_path):
        """A file at <data_dir>/db_key is auto-detected when neither field is
        set explicitly. Lets a manual install (drop-the-file) work without
        editing toml."""
        _write_key(tmp_path)
        cfg = NodeConfig(data_dir=tmp_path)
        assert cfg.db_keyfile == tmp_path / "db_key"
        assert cfg.resolve_db_key() == VALID_KEY

    def test_no_encrypt_returns_none(self, tmp_path):
        cfg = NodeConfig(data_dir=tmp_path, db_encrypt=False)
        assert cfg.resolve_db_key() is None

    def test_relay_mode_without_key_returns_none(self, tmp_path):
        """Relay nodes never open the DB; resolver returns None when no
        key source is configured."""
        cfg = NodeConfig(data_dir=tmp_path, relay_only=True, db_encrypt=True)
        assert cfg.resolve_db_key() is None

    def test_missing_both_sources_post_init_raises(self, tmp_path):
        """Validator catches missing-key configs at construction time —
        before any resolver call."""
        with pytest.raises(ValueError, match="no key source is configured"):
            NodeConfig(data_dir=tmp_path)


class TestKeyfileModeHygiene:
    def test_loose_mode_logs_warning(self, tmp_path, caplog):
        import logging

        keyfile = _write_key(tmp_path, mode=0o644)
        cfg = NodeConfig(data_dir=tmp_path, db_keyfile=keyfile)
        with caplog.at_level(logging.WARNING, logger="hokora.config"):
            cfg.resolve_db_key()
        assert any("loose permissions" in rec.message for rec in caplog.records)

    def test_strict_mode_no_warning(self, tmp_path, caplog):
        import logging

        keyfile = _write_key(tmp_path, mode=0o600)
        cfg = NodeConfig(data_dir=tmp_path, db_keyfile=keyfile)
        with caplog.at_level(logging.WARNING, logger="hokora.config"):
            cfg.resolve_db_key()
        assert not any("loose permissions" in rec.message for rec in caplog.records)


class TestTomlIntegration:
    def test_toml_with_db_keyfile(self, tmp_path):
        """Loading via TOML still routes through the resolver."""
        keyfile = _write_key(tmp_path)
        toml = tmp_path / "hokora.toml"
        toml.write_text(f'data_dir = "{tmp_path}"\ndb_keyfile = "{keyfile}"\ndb_encrypt = true\n')
        from hokora.config import load_config

        cfg = load_config(toml)
        assert cfg.resolve_db_key() == VALID_KEY

    def test_toml_with_inline_db_key_still_works(self, tmp_path):
        """Backwards compat: existing nodes with inline db_key keep loading."""
        toml = tmp_path / "hokora.toml"
        toml.write_text(f'data_dir = "{tmp_path}"\ndb_key = "{VALID_KEY}"\ndb_encrypt = true\n')
        from hokora.config import load_config

        cfg = load_config(toml)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            assert cfg.resolve_db_key() == VALID_KEY
        assert any(
            issubclass(w.category, DeprecationWarning) and "hokora db migrate-key" in str(w.message)
            for w in caught
        )
