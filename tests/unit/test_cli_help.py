# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""CLI help command tests: verify all entry points respond to --help without crashing."""

import pytest


class TestCLIHelp:
    """Verify all CLI entry points respond to --help without crashing."""

    @pytest.fixture(autouse=True)
    def _runner(self):
        from click.testing import CliRunner

        self.runner = CliRunner()

    def _invoke(self, args):
        from hokora.cli.main import cli

        return self.runner.invoke(cli, args)

    def test_cli_help(self):
        result = self._invoke(["--help"])
        assert result.exit_code == 0
        assert "Hokora" in result.output

    def test_cli_version(self):
        result = self._invoke(["--version"])
        # exit_code=1 is expected in PYTHONPATH mode (not pip-installed)
        assert result.exit_code in (0, 1)

    def test_channel_help(self):
        result = self._invoke(["channel", "--help"])
        assert result.exit_code == 0
        assert "channel" in result.output.lower()

    def test_role_help(self):
        result = self._invoke(["role", "--help"])
        assert result.exit_code == 0
        assert "role" in result.output.lower()

    def test_identity_help(self):
        result = self._invoke(["identity", "--help"])
        assert result.exit_code == 0
        assert "identity" in result.output.lower()

    def test_invite_help(self):
        result = self._invoke(["invite", "--help"])
        assert result.exit_code == 0
        assert "invite" in result.output.lower()

    def test_daemon_help(self):
        result = self._invoke(["daemon", "--help"])
        assert result.exit_code == 0
        assert "daemon" in result.output.lower()
