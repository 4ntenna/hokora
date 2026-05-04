# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the Prometheus exporter.

The exporter is the single source of truth for both the web dashboard's
``/api/metrics/`` and the relay-node ObservabilityListener. Tests cover:

* Stable metric names and labels — preserved verbatim so existing
  Prometheus configs keep scraping across releases.
* Federation + sync observability families — per-interface bytes,
  channel/peer sync cursor, CDSP profile counts, deferred sync items,
  federation trust, sealed channels, sealed key-age.
"""

from __future__ import annotations

import time

import pytest
import pytest_asyncio

from hokora.constants import (
    CDSP_PROFILE_BATCHED,
    CDSP_PROFILE_FULL,
    CDSP_PROFILE_MINIMAL,
    CDSP_PROFILE_PRIORITIZED,
)
from hokora.core.prometheus_exporter import render_metrics
from hokora.db.models import (
    Channel,
    DeferredSyncItem,
    Identity,
    Message,
    Peer,
    SealedKey,
    Session,
)


# ── Fixtures ───────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def seeded(session_factory):
    """Seed a small DB covering every metric family."""
    async with session_factory() as s:
        async with s.begin():
            # Channels: one public, one sealed, one for sync-cursor lag.
            s.add(Channel(id="pub0" + "0" * 60, name="general", latest_seq=42))
            s.add(Channel(id="sea0" + "0" * 60, name="secret", sealed=True, latest_seq=7))
            s.add(Channel(id="pub1" + "0" * 60, name="lounge", latest_seq=100))

            # Messages: 3 in general, 1 in secret.
            for i in range(3):
                s.add(
                    Message(
                        msg_hash=f"m{i:063d}",
                        channel_id="pub0" + "0" * 60,
                        sender_hash="a" * 64,
                        seq=i + 1,
                        timestamp=time.time(),
                        type=0x01,
                        body="hi",
                    )
                )
            s.add(
                Message(
                    msg_hash="s" + "0" * 63,
                    channel_id="sea0" + "0" * 60,
                    sender_hash="a" * 64,
                    seq=1,
                    timestamp=time.time(),
                    type=0x01,
                    encrypted_body=b"\x00" * 32,
                    encryption_nonce=b"\x00" * 12,
                    encryption_epoch=1,
                )
            )

            # Identities.
            s.add(Identity(hash="a" * 64, display_name="alice"))
            s.add(Identity(hash="b" * 64, display_name="bob"))

            # Peers — one trusted, one untrusted, with sync cursors.
            s.add(
                Peer(
                    identity_hash="c" * 64,
                    node_name="seed-vps",
                    federation_trusted=True,
                    sync_cursor={"pub0" + "0" * 60: 30, "_push": {"whatever": 1}},
                )
            )
            s.add(
                Peer(
                    identity_hash="d" * 64,
                    node_name="remote",
                    federation_trusted=False,
                    sync_cursor={"pub1" + "0" * 60: 85},
                )
            )

            # Sessions: 2 FULL active, 1 BATCHED paused, 1 unknown-profile.
            now = time.time()
            s.add(
                Session(session_id="f1" + "0" * 62, sync_profile=CDSP_PROFILE_FULL, state="active")
            )
            s.add(
                Session(session_id="f2" + "0" * 62, sync_profile=CDSP_PROFILE_FULL, state="active")
            )
            s.add(
                Session(
                    session_id="b1" + "0" * 62, sync_profile=CDSP_PROFILE_BATCHED, state="paused"
                )
            )
            s.add(Session(session_id="u1" + "0" * 62, sync_profile=0xFE, state="active"))

            # Flush so Session parents are visible to the FK check
            # before DeferredSyncItem children INSERT.
            await s.flush()

            # Deferred sync items — 2 for pub0, 1 for sea0, 1 with null channel.
            for i in range(2):
                s.add(
                    DeferredSyncItem(
                        session_id="f1" + "0" * 62,
                        channel_id="pub0" + "0" * 60,
                        sync_action=0x01,
                    )
                )
            s.add(
                DeferredSyncItem(
                    session_id="f1" + "0" * 62,
                    channel_id="sea0" + "0" * 60,
                    sync_action=0x01,
                )
            )
            s.add(DeferredSyncItem(session_id="f1" + "0" * 62, channel_id=None, sync_action=0x05))

            # SealedKey rows: one recent for sea0, none for pub0.
            s.add(
                SealedKey(
                    channel_id="sea0" + "0" * 60,
                    epoch=1,
                    encrypted_key_blob=b"\x00" * 32,
                    identity_hash="a" * 64,
                    created_at=now - 120.0,
                )
            )
    return session_factory


@pytest.fixture
def fake_rns_transport():
    """Stand-in for the ``RNS.Transport`` module."""

    class _Iface:
        def __init__(self, name: str, rxb: int, txb: int, online: bool = True):
            self.name = name
            self.rxb = rxb
            self.txb = txb
            self.online = online

    # type(iface).__name__ drives the `type` label, so give them distinct classes.
    class TCPClientInterface(_Iface):
        pass

    class LocalClientInterface(_Iface):
        pass

    class _Transport:
        interfaces = [
            TCPClientInterface("TCP Seed", rxb=12345, txb=6789),
            LocalClientInterface("Local shared instance", rxb=0, txb=0, online=False),
        ]

    return _Transport


# ── Stable-name tests ──────────────────────────────────────────────


async def test_existing_metric_names_preserved(seeded):
    body = await render_metrics(seeded)
    # Stable metric names — these are what existing Prometheus scrape
    # configs depend on.
    for name in (
        "hokora_messages_total",
        "hokora_channels_total",
        "hokora_messages_total_all",
        "hokora_identities_total",
        "hokora_peers_discovered",
        "hokora_daemon_uptime_seconds",
    ):
        assert name in body, f"missing preserved metric: {name}"


async def test_messages_total_per_channel_label(seeded):
    body = await render_metrics(seeded)
    assert 'hokora_messages_total{channel="pub0' in body
    assert 'hokora_messages_total{channel="sea0' in body


async def test_totals_match_seeded_counts(seeded):
    body = await render_metrics(seeded)
    # 3 channels, 4 messages, 2 identities, 2 peers.
    assert "hokora_channels_total 3" in body
    assert "hokora_messages_total_all 4" in body
    assert "hokora_identities_total 2" in body
    assert "hokora_peers_discovered 2" in body


# ── RNS interface metrics ──────────────────────────────────────────


async def test_interface_metrics_emitted_when_transport_given(seeded, fake_rns_transport):
    body = await render_metrics(seeded, rns_transport=fake_rns_transport)
    assert (
        'hokora_rns_interface_bytes_rx_total{interface="TCP Seed",type="TCPClientInterface"} 12345'
        in body
    )
    assert (
        'hokora_rns_interface_bytes_tx_total{interface="TCP Seed",type="TCPClientInterface"} 6789'
        in body
    )
    assert 'hokora_rns_interface_up{interface="TCP Seed",type="TCPClientInterface"} 1' in body
    assert (
        'hokora_rns_interface_up{interface="Local shared instance",type="LocalClientInterface"} 0'
        in body
    )


async def test_interface_metrics_omitted_when_transport_none(seeded):
    body = await render_metrics(seeded, rns_transport=None)
    assert "hokora_rns_interface_" not in body


async def test_interface_metrics_tolerate_broken_interface(seeded):
    """A single malformed interface must not kill the whole scrape."""

    class _Broken:
        name = "bad"

        # Accessing rxb raises — the exporter must skip this row, not fail.
        @property
        def rxb(self):
            raise RuntimeError("boom")

    class _Good:
        name = "good"
        rxb = 1
        txb = 2
        online = True

    class _Transport:
        interfaces = [_Broken(), _Good()]

    body = await render_metrics(seeded, rns_transport=_Transport)
    assert 'hokora_rns_interface_bytes_rx_total{interface="good"' in body
    # The broken iface's bad row must not appear.
    assert 'interface="bad"' not in body


async def test_interface_metrics_transport_with_no_interfaces_attr(seeded):
    """Defensive: a Transport stand-in missing ``interfaces`` yields nothing, no crash."""

    class _Empty:
        pass

    body = await render_metrics(seeded, rns_transport=_Empty())
    assert "hokora_rns_interface_" not in body


# ── RNode LoRa hardware telemetry ──────────────────────────────────


def _make_fake_rnode_iface(
    name: str = "RNode LoRa",
    *,
    rxb: int = 1024,
    txb: int = 512,
    online: bool = True,
    r_frequency: int | None = 868_000_000,
    r_bandwidth: int | None = 125_000,
    r_sf: int | None = 8,
    r_cr: int | None = 5,
    r_txpower: int | None = 22,
    bitrate: int = 3120,
    r_noise_floor: int | None = -110,
    r_stat_rssi: int | None = -75,
    r_stat_snr: float | None = 9.5,
    # RNS stores airtime/channel-load as percentages (0–100) directly,
    # matching the format ``rnstatus`` displays. The exporter emits them
    # under ``hokora_rnode_*_percent`` metrics; tests use realistic values
    # observed during live LoRa traffic on the test hardware.
    r_airtime_short: float = 3.84,
    r_airtime_long: float = 0.37,
    r_channel_load_short: float = 10.5,
    r_channel_load_long: float = 0.49,
    cpu_temp: float | None = 50.0,
    r_battery_state: int | None = 0x03,
    r_battery_percent: int = 100,
):
    """Build a fake RNodeInterface stand-in. Detection in the exporter is
    via duck-typing on ``r_sf``, so any class with that attribute counts
    as an RNode for telemetry purposes — no need to import the real one."""

    class _RNodeInterface:
        pass

    iface = _RNodeInterface()
    iface.name = name
    iface.rxb = rxb
    iface.txb = txb
    iface.online = online
    iface.r_frequency = r_frequency
    iface.r_bandwidth = r_bandwidth
    iface.r_sf = r_sf
    iface.r_cr = r_cr
    iface.r_txpower = r_txpower
    iface.bitrate = bitrate
    iface.r_noise_floor = r_noise_floor
    iface.r_stat_rssi = r_stat_rssi
    iface.r_stat_snr = r_stat_snr
    iface.r_airtime_short = r_airtime_short
    iface.r_airtime_long = r_airtime_long
    iface.r_channel_load_short = r_channel_load_short
    iface.r_channel_load_long = r_channel_load_long
    iface.cpu_temp = cpu_temp
    iface.r_battery_state = r_battery_state
    iface.r_battery_percent = r_battery_percent
    return iface


def _transport_with(*ifaces):
    class _Transport:
        interfaces = list(ifaces)

    return _Transport


async def test_rnode_radio_config_metrics_emitted(seeded):
    """Radio config (frequency / bandwidth / SF / CR / TX power / bitrate)
    appears with the interface label so operators can join with the
    bytes counters."""
    iface = _make_fake_rnode_iface()
    body = await render_metrics(seeded, rns_transport=_transport_with(iface))

    assert 'hokora_rnode_frequency_hz{interface="RNode LoRa"} 868000000.0' in body
    assert 'hokora_rnode_bandwidth_hz{interface="RNode LoRa"} 125000.0' in body
    assert 'hokora_rnode_spreading_factor{interface="RNode LoRa"} 8.0' in body
    assert 'hokora_rnode_coding_rate{interface="RNode LoRa"} 5.0' in body
    assert 'hokora_rnode_tx_power_dbm{interface="RNode LoRa"} 22.0' in body
    assert 'hokora_rnode_bitrate_bps{interface="RNode LoRa"} 3120.0' in body


async def test_rnode_link_quality_metrics_emitted(seeded):
    iface = _make_fake_rnode_iface()
    body = await render_metrics(seeded, rns_transport=_transport_with(iface))

    assert 'hokora_rnode_noise_floor_dbm{interface="RNode LoRa"} -110.0' in body
    assert 'hokora_rnode_last_packet_rssi_dbm{interface="RNode LoRa"} -75.0' in body
    assert 'hokora_rnode_last_packet_snr_db{interface="RNode LoRa"} 9.5' in body


async def test_rnode_utilisation_metrics_emit_both_windows(seeded):
    iface = _make_fake_rnode_iface()
    body = await render_metrics(seeded, rns_transport=_transport_with(iface))

    assert 'hokora_rnode_airtime_percent{interface="RNode LoRa",window="15s"} 3.84' in body
    assert 'hokora_rnode_airtime_percent{interface="RNode LoRa",window="1h"} 0.37' in body
    assert 'hokora_rnode_channel_load_percent{interface="RNode LoRa",window="15s"} 10.5' in body
    assert 'hokora_rnode_channel_load_percent{interface="RNode LoRa",window="1h"} 0.49' in body


async def test_rnode_host_board_health_metrics_emitted(seeded):
    iface = _make_fake_rnode_iface()
    body = await render_metrics(seeded, rns_transport=_transport_with(iface))

    assert 'hokora_rnode_cpu_temp_celsius{interface="RNode LoRa"} 50.0' in body
    assert 'hokora_rnode_battery_percent{interface="RNode LoRa"} 100.0' in body
    # state=charged — exactly one of the four state labels is 1, others 0.
    assert 'hokora_rnode_battery_state{interface="RNode LoRa",state="charged"} 1' in body
    assert 'hokora_rnode_battery_state{interface="RNode LoRa",state="charging"} 0' in body
    assert 'hokora_rnode_battery_state{interface="RNode LoRa",state="discharging"} 0' in body


async def test_rnode_battery_omitted_for_mains_powered_node(seeded):
    """RNodes without a battery report state=0 (unknown) and percent=0.
    Emitting these would surface a permanent 0% alarm on a mains-powered
    deployment. Verify omission instead."""
    iface = _make_fake_rnode_iface(r_battery_state=0x00, r_battery_percent=0)
    body = await render_metrics(seeded, rns_transport=_transport_with(iface))

    assert "hokora_rnode_battery_percent" not in body
    assert "hokora_rnode_battery_state" not in body


async def test_rnode_metrics_omit_unreported_fields(seeded):
    """Freshly-attached RNode has None values until firmware reports them.
    Must not emit fake zeros — those would corrupt rate / threshold queries."""
    iface = _make_fake_rnode_iface(
        r_frequency=None,
        r_bandwidth=None,
        r_sf=8,  # keep set — required for duck-type detection
        r_cr=None,
        r_txpower=None,
        bitrate=0,  # rns init default before SF/BW computed
        r_noise_floor=None,
        r_stat_rssi=None,
        r_stat_snr=None,
        cpu_temp=None,
    )
    body = await render_metrics(seeded, rns_transport=_transport_with(iface))

    assert "hokora_rnode_frequency_hz" not in body
    assert "hokora_rnode_bandwidth_hz" not in body
    assert "hokora_rnode_coding_rate" not in body
    assert "hokora_rnode_tx_power_dbm" not in body
    assert "hokora_rnode_bitrate_bps" not in body
    assert "hokora_rnode_noise_floor_dbm" not in body
    assert "hokora_rnode_last_packet_rssi_dbm" not in body
    assert "hokora_rnode_last_packet_snr_db" not in body
    assert "hokora_rnode_cpu_temp_celsius" not in body
    # SF must still be emitted (required for duck-type, and represents
    # actual firmware-reported config in this scenario).
    assert "hokora_rnode_spreading_factor" in body


async def test_rnode_telemetry_skipped_for_non_rnode_interface(seeded):
    """A TCP/I2P interface (no r_sf attr) must not emit any rnode_* metric."""

    class _TcpIface:
        name = "TCP Seed"
        rxb = 100
        txb = 200
        online = True

    body = await render_metrics(seeded, rns_transport=_transport_with(_TcpIface()))
    assert "hokora_rnode_" not in body
    # Generic interface bytes still emitted.
    assert 'hokora_rns_interface_bytes_rx_total{interface="TCP Seed"' in body


async def test_rnode_telemetry_tolerates_broken_attribute_access(seeded):
    """A property on the RNode that raises on access must not block the
    rest of the rnode telemetry surface."""

    class _RNodeInterface:
        name = "RNode LoRa"
        rxb = 0
        txb = 0
        online = True
        r_sf = 8  # duck-type marker
        r_frequency = 868_000_000

        @property
        def r_bandwidth(self):
            raise RuntimeError("simulated firmware glitch")

        r_cr = 5
        r_txpower = 22
        bitrate = 3120
        r_noise_floor = -110
        r_stat_rssi = None
        r_stat_snr = None
        r_airtime_short = 0.0
        r_airtime_long = 0.0
        r_channel_load_short = 0.0
        r_channel_load_long = 0.0
        cpu_temp = 50.0
        r_battery_state = 0x00
        r_battery_percent = 0

    body = await render_metrics(seeded, rns_transport=_transport_with(_RNodeInterface()))

    # The broken attribute is gone, but the rest of the rnode surface
    # still emits — partial output is better than no output.
    assert "hokora_rnode_frequency_hz" in body
    assert "hokora_rnode_spreading_factor" in body


async def test_rnode_telemetry_label_sanitisation(seeded):
    """An RNode named with a quote character (could come from an operator
    config) must not corrupt the Prometheus exposition format."""
    iface = _make_fake_rnode_iface(name='Bad"Name')
    body = await render_metrics(seeded, rns_transport=_transport_with(iface))
    # _sanitize_label replaces unsafe characters with '_'.
    assert 'interface="Bad_Name"' in body
    assert 'interface="Bad"Name"' not in body


# ── Channel latest_seq + peer sync cursor ──────────────────────────


async def test_channel_latest_seq_ingested(seeded):
    body = await render_metrics(seeded)
    assert 'hokora_channel_latest_seq_ingested{channel="pub0' in body
    # Exact values.
    assert "} 42" in body  # pub0 seq
    assert "} 100" in body  # pub1 seq


async def test_peer_sync_cursor_per_channel(seeded):
    body = await render_metrics(seeded)
    # Trusted peer cursor for pub0 at 30.
    assert (
        'hokora_peer_sync_cursor_seq{peer="cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",channel="pub0'
        in body
    )
    # Untrusted peer cursor for pub1 at 85.
    assert 'hokora_peer_sync_cursor_seq{peer="dddd' in body and "} 85" in body


async def test_peer_sync_cursor_skips_internal_keys(seeded):
    """``_push`` and other underscore-prefixed keys are internal push
    state, not per-channel cursors. They must not appear as metrics."""
    body = await render_metrics(seeded)
    # The _push entry in the seeded fixture's cursor dict must not
    # leak as a channel label.
    assert 'channel="_push"' not in body


# ── CDSP sessions ──────────────────────────────────────────────────


async def test_cdsp_sessions_labelled_by_profile_and_state(seeded):
    body = await render_metrics(seeded)
    assert 'hokora_cdsp_sessions{profile="FULL",state="active"} 2' in body
    assert 'hokora_cdsp_sessions{profile="BATCHED",state="paused"} 1' in body


async def test_cdsp_sessions_unknown_profile_defensive(seeded):
    """An out-of-band profile integer maps to ``unknown`` instead of exploding."""
    body = await render_metrics(seeded)
    assert 'hokora_cdsp_sessions{profile="unknown"' in body


# ── Deferred sync items ────────────────────────────────────────────


async def test_deferred_sync_items_by_channel(seeded):
    body = await render_metrics(seeded)
    assert 'hokora_deferred_sync_items{channel="pub0' in body
    # The null-channel row must render with the "null" label, not crash.
    assert 'hokora_deferred_sync_items{channel="null"} 1' in body


# ── Federation trust ───────────────────────────────────────────────


async def test_federation_peers_by_trust(seeded):
    body = await render_metrics(seeded)
    assert 'hokora_federation_peers{trusted="true"} 1' in body
    assert 'hokora_federation_peers{trusted="false"} 1' in body


# ── Sealed channels + sealed key-age ───────────────────────────────


async def test_sealed_channels_total(seeded):
    body = await render_metrics(seeded)
    assert "hokora_sealed_channels_total 1" in body


async def test_sealed_key_age_seconds(seeded):
    body = await render_metrics(seeded)
    # The seeded key is ~120s old; tolerate timing jitter.
    assert 'hokora_sealed_key_age_seconds{channel="sea0' in body


async def test_sealed_key_age_omitted_for_channels_without_keys(seeded):
    body = await render_metrics(seeded)
    # pub0 has no SealedKey row; there must be no entry for it.
    assert 'hokora_sealed_key_age_seconds{channel="pub0' not in body


# ── Generic ────────────────────────────────────────────────────────


async def test_label_sanitization_strips_quotes_and_backslashes(session_factory):
    """A channel id with unsafe chars must be sanitized, not crash the scrape."""
    async with session_factory() as s:
        async with s.begin():
            s.add(Channel(id='bad"\\id' + "0" * 57, name="bad", latest_seq=1))
    body = await render_metrics(session_factory)
    # Raw double-quote / backslash must not land in output unescaped —
    # sanitizer replaces them with ``_``.
    assert 'bad""\\id' not in body
    assert "bad__id" in body


async def test_empty_db_renders_without_crashing(session_factory):
    """No seeded data — only the scalar totals (all 0) and uptime survive."""
    body = await render_metrics(session_factory)
    assert "hokora_channels_total 0" in body
    assert "hokora_messages_total_all 0" in body
    assert "hokora_identities_total 0" in body
    assert "hokora_peers_discovered 0" in body
    assert "hokora_sealed_channels_total 0" in body
    assert "hokora_daemon_uptime_seconds" in body


async def test_output_ends_with_newline(seeded):
    body = await render_metrics(seeded)
    assert body.endswith("\n")


async def test_all_metric_families_present(seeded, fake_rns_transport):
    body = await render_metrics(seeded, rns_transport=fake_rns_transport)
    for name in (
        "hokora_rns_interface_bytes_rx_total",
        "hokora_rns_interface_bytes_tx_total",
        "hokora_rns_interface_up",
        "hokora_channel_latest_seq_ingested",
        "hokora_peer_sync_cursor_seq",
        "hokora_cdsp_sessions",
        "hokora_deferred_sync_items",
        "hokora_federation_peers",
        "hokora_sealed_channels_total",
        "hokora_sealed_key_age_seconds",
    ):
        assert name in body, f"missing metric: {name}"


# Profile label completeness — each CDSP profile we know must map
# cleanly when emitted, regardless of whether a session exists.
@pytest.mark.parametrize(
    "profile_int,label",
    [
        (CDSP_PROFILE_FULL, "FULL"),
        (CDSP_PROFILE_PRIORITIZED, "PRIORITIZED"),
        (CDSP_PROFILE_MINIMAL, "MINIMAL"),
        (CDSP_PROFILE_BATCHED, "BATCHED"),
    ],
)
async def test_every_cdsp_profile_label_emits(session_factory, profile_int, label):
    async with session_factory() as s:
        async with s.begin():
            s.add(Session(session_id="x" * 64, sync_profile=profile_int, state="active"))
    body = await render_metrics(session_factory)
    assert f'hokora_cdsp_sessions{{profile="{label}",state="active"}} 1' in body
