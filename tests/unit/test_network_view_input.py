# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for parse_seed_input in src/hokora_tui/views/network_view.py."""

from hokora_tui.views.network_view import parse_seed_input


class TestParseSeedInput:
    def test_empty_input(self):
        host, port, label, error = parse_seed_input("")
        assert host == ""
        assert error is not None
        assert "Enter" in error

    def test_whitespace_only(self):
        host, port, label, error = parse_seed_input("   ")
        assert host == ""
        assert error is not None

    def test_tcp_host_port(self):
        host, port, label, error = parse_seed_input("192.0.2.1:4242")
        assert host == "192.0.2.1"
        assert port == 4242
        assert label == "Seed 192.0.2.1:4242"
        assert error is None

    def test_tcp_hostname_no_port_defaults_to_4242(self):
        host, port, label, error = parse_seed_input("seed.example.com")
        assert host == "seed.example.com"
        assert port == 4242
        assert error is None

    def test_tcp_strips_whitespace(self):
        host, port, label, error = parse_seed_input("  1.2.3.4:4242  ")
        assert host == "1.2.3.4"
        assert port == 4242
        assert error is None

    def test_i2p_b32(self):
        addr = "idzhz35r2xfbsmgx7ya6jpd4srfpt5k5rjj47o2tp5l3hcfukcba.b32.i2p"
        host, port, label, error = parse_seed_input(addr)
        assert host == addr
        assert port == 0
        assert label.startswith("I2P ")
        assert error is None

    def test_i2p_plain(self):
        host, port, label, error = parse_seed_input("example.i2p")
        assert host == "example.i2p"
        assert port == 0
        assert error is None

    def test_i2p_with_port_rejected(self):
        host, port, label, error = parse_seed_input("example.b32.i2p:4242")
        assert host == ""
        assert error is not None
        assert "I2P" in error and "port" in error

    def test_empty_host_with_port(self):
        host, port, label, error = parse_seed_input(":4242")
        assert host == ""
        assert error is not None
        assert "Missing host" in error

    def test_non_integer_port(self):
        host, port, label, error = parse_seed_input("host:abc")
        assert host == ""
        assert error is not None
        assert "Invalid port" in error

    def test_port_too_low(self):
        host, port, label, error = parse_seed_input("host:0")
        assert host == ""
        assert error is not None
        assert "out of range" in error

    def test_port_too_high(self):
        host, port, label, error = parse_seed_input("host:70000")
        assert host == ""
        assert error is not None
        assert "out of range" in error

    def test_port_negative(self):
        host, port, label, error = parse_seed_input("host:-1")
        assert host == ""
        assert error is not None
        assert "out of range" in error

    def test_ipv6_parsed_naively(self):
        """IPv6 literals without brackets parse naively via rpartition.

        Documents current behavior — host='::1', port=4242. RNS does not
        support IPv6 seed input through this path, but we don't crash.
        """
        host, port, label, error = parse_seed_input("::1:4242")
        assert host == "::1"
        assert port == 4242
        assert error is None
