# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for the transport log sanitizer."""

import logging

import pytest

from hokora.security.log_sanitizer import TransportLogSanitizer


@pytest.fixture
def sanitizer():
    return TransportLogSanitizer()


@pytest.fixture
def logger_with_sanitizer(sanitizer):
    log = logging.getLogger("test_sanitizer")
    log.setLevel(logging.DEBUG)
    log.handlers.clear()
    handler = logging.StreamHandler()
    handler.addFilter(sanitizer)
    log.addHandler(handler)
    return log


class TestInterfaceRedaction:
    def test_tcp_client_interface_redacted(self, sanitizer):
        record = logging.LogRecord(
            "test",
            logging.INFO,
            "",
            0,
            "Connected via TCPClientInterface on port 4242",
            None,
            None,
        )
        sanitizer.filter(record)
        assert "TCPClientInterface" not in record.getMessage()
        assert "[redacted-interface]" in record.getMessage()

    def test_tcp_server_interface_redacted(self, sanitizer):
        record = logging.LogRecord(
            "test",
            logging.INFO,
            "",
            0,
            "Listening on TCPServerInterface",
            None,
            None,
        )
        sanitizer.filter(record)
        assert "TCPServerInterface" not in record.getMessage()

    def test_rnode_interface_redacted(self, sanitizer):
        record = logging.LogRecord(
            "test",
            logging.INFO,
            "",
            0,
            "RNodeInterface active on /dev/ttyUSB0",
            None,
            None,
        )
        sanitizer.filter(record)
        assert "RNodeInterface" not in record.getMessage()

    def test_rnode_multi_interface_redacted(self, sanitizer):
        record = logging.LogRecord(
            "test",
            logging.INFO,
            "",
            0,
            "RNodeMultiInterface configured",
            None,
            None,
        )
        sanitizer.filter(record)
        assert "RNodeMultiInterface" not in record.getMessage()

    def test_rnode_sub_interface_redacted(self, sanitizer):
        record = logging.LogRecord(
            "test",
            logging.INFO,
            "",
            0,
            "RNodeSubInterface started",
            None,
            None,
        )
        sanitizer.filter(record)
        assert "RNodeSubInterface" not in record.getMessage()

    def test_auto_interface_redacted(self, sanitizer):
        record = logging.LogRecord(
            "test",
            logging.INFO,
            "",
            0,
            "AutoInterface discovered peers",
            None,
            None,
        )
        sanitizer.filter(record)
        assert "AutoInterface" not in record.getMessage()

    def test_auto_interface_peer_redacted(self, sanitizer):
        record = logging.LogRecord(
            "test",
            logging.INFO,
            "",
            0,
            "AutoInterfacePeer connected",
            None,
            None,
        )
        sanitizer.filter(record)
        assert "AutoInterfacePeer" not in record.getMessage()

    def test_udp_interface_redacted(self, sanitizer):
        record = logging.LogRecord(
            "test",
            logging.INFO,
            "",
            0,
            "UDPInterface on 0.0.0.0:4242",
            None,
            None,
        )
        sanitizer.filter(record)
        assert "UDPInterface" not in record.getMessage()

    def test_local_server_interface_redacted(self, sanitizer):
        record = logging.LogRecord(
            "test",
            logging.INFO,
            "",
            0,
            "LocalServerInterface listening",
            None,
            None,
        )
        sanitizer.filter(record)
        assert "LocalServerInterface" not in record.getMessage()

    def test_local_client_interface_redacted(self, sanitizer):
        record = logging.LogRecord(
            "test",
            logging.INFO,
            "",
            0,
            "LocalClientInterface connected",
            None,
            None,
        )
        sanitizer.filter(record)
        assert "LocalClientInterface" not in record.getMessage()

    def test_backbone_interface_redacted(self, sanitizer):
        record = logging.LogRecord(
            "test",
            logging.INFO,
            "",
            0,
            "BackboneInterface ready",
            None,
            None,
        )
        sanitizer.filter(record)
        assert "BackboneInterface" not in record.getMessage()

    def test_backbone_client_interface_redacted(self, sanitizer):
        record = logging.LogRecord(
            "test",
            logging.INFO,
            "",
            0,
            "BackboneClientInterface connecting",
            None,
            None,
        )
        sanitizer.filter(record)
        assert "BackboneClientInterface" not in record.getMessage()

    def test_weave_interface_redacted(self, sanitizer):
        record = logging.LogRecord(
            "test",
            logging.INFO,
            "",
            0,
            "WeaveInterface active",
            None,
            None,
        )
        sanitizer.filter(record)
        assert "WeaveInterface" not in record.getMessage()

    def test_weave_interface_peer_redacted(self, sanitizer):
        record = logging.LogRecord(
            "test",
            logging.INFO,
            "",
            0,
            "WeaveInterfacePeer joined",
            None,
            None,
        )
        sanitizer.filter(record)
        assert "WeaveInterfacePeer" not in record.getMessage()

    def test_kiss_interface_redacted(self, sanitizer):
        record = logging.LogRecord(
            "test",
            logging.INFO,
            "",
            0,
            "KISSInterface on serial port",
            None,
            None,
        )
        sanitizer.filter(record)
        assert "KISSInterface" not in record.getMessage()

    def test_ax25kiss_interface_redacted(self, sanitizer):
        record = logging.LogRecord(
            "test",
            logging.INFO,
            "",
            0,
            "AX25KISSInterface configured",
            None,
            None,
        )
        sanitizer.filter(record)
        assert "AX25KISSInterface" not in record.getMessage()

    def test_serial_interface_redacted(self, sanitizer):
        record = logging.LogRecord(
            "test",
            logging.INFO,
            "",
            0,
            "SerialInterface /dev/ttyACM0",
            None,
            None,
        )
        sanitizer.filter(record)
        assert "SerialInterface" not in record.getMessage()

    def test_pipe_interface_redacted(self, sanitizer):
        record = logging.LogRecord(
            "test",
            logging.INFO,
            "",
            0,
            "PipeInterface started",
            None,
            None,
        )
        sanitizer.filter(record)
        assert "PipeInterface" not in record.getMessage()

    def test_i2p_interface_redacted(self, sanitizer):
        record = logging.LogRecord(
            "test",
            logging.INFO,
            "",
            0,
            "I2PInterface tunnel ready",
            None,
            None,
        )
        sanitizer.filter(record)
        assert "I2PInterface" not in record.getMessage()

    def test_i2p_interface_peer_redacted(self, sanitizer):
        record = logging.LogRecord(
            "test",
            logging.INFO,
            "",
            0,
            "I2PInterfacePeer connected",
            None,
            None,
        )
        sanitizer.filter(record)
        assert "I2PInterfacePeer" not in record.getMessage()

    def test_lora_interface_redacted(self, sanitizer):
        record = logging.LogRecord(
            "test",
            logging.INFO,
            "",
            0,
            "LoRaInterface active",
            None,
            None,
        )
        sanitizer.filter(record)
        assert "LoRaInterface" not in record.getMessage()

    def test_wifi_interface_redacted(self, sanitizer):
        record = logging.LogRecord(
            "test",
            logging.INFO,
            "",
            0,
            "WiFiInterface scanning",
            None,
            None,
        )
        sanitizer.filter(record)
        assert "WiFiInterface" not in record.getMessage()

    def test_ble_interface_redacted(self, sanitizer):
        record = logging.LogRecord(
            "test",
            logging.INFO,
            "",
            0,
            "BLEInterface pairing",
            None,
            None,
        )
        sanitizer.filter(record)
        assert "BLEInterface" not in record.getMessage()


class TestNoFalsePositives:
    def test_normal_message_unchanged(self, sanitizer):
        record = logging.LogRecord(
            "test",
            logging.INFO,
            "",
            0,
            "Link established for channel general",
            None,
            None,
        )
        original_msg = record.getMessage()
        sanitizer.filter(record)
        assert record.getMessage() == original_msg

    def test_empty_message_unchanged(self, sanitizer):
        record = logging.LogRecord(
            "test",
            logging.INFO,
            "",
            0,
            "",
            None,
            None,
        )
        sanitizer.filter(record)
        assert record.getMessage() == ""

    def test_filter_returns_true(self, sanitizer):
        """Sanitizer should never suppress records, only redact."""
        record = logging.LogRecord(
            "test",
            logging.INFO,
            "",
            0,
            "TCPClientInterface connected",
            None,
            None,
        )
        assert sanitizer.filter(record) is True


class TestAllInterfacePatternsCovered:
    def test_all_23_patterns(self, sanitizer):
        """Ensure all interface patterns in the sanitizer are tested."""
        assert len(sanitizer.INTERFACE_PATTERNS) == 23
        for pattern in sanitizer.INTERFACE_PATTERNS:
            record = logging.LogRecord(
                "test",
                logging.INFO,
                "",
                0,
                f"Activity on {pattern}",
                None,
                None,
            )
            sanitizer.filter(record)
            assert pattern not in record.getMessage(), f"Pattern {pattern} was not redacted"
            assert "[redacted-interface]" in record.getMessage()
