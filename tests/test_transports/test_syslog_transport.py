"""Tests for SyslogTransport: framing helpers, pre-framed passthrough, UDP/TCP send paths."""
import asyncio
import sys
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'engine'))

from transports.syslog_transport import SyslogTransport, _rfc5424, _rfc3164
from transports.base import SourceMeta


_META_RAW = SourceMeta(
    source_id="cisco_asa", source_name="Cisco ASA",
    format="raw", transport="syslog", facility=16, severity=5,
)
_META_PREFRAMED = SourceMeta(
    source_id="cisco_asa", source_name="Cisco ASA",
    format="syslog_rfc5424", transport="syslog",
)

_SETTINGS_PATCH = {
    "brokervm_host": "127.0.0.1",
    "brokervm_syslog_port": 514,
    "brokervm_syslog_proto": "udp",
}


# ── framing helpers ───────────────────────────────────────────────────────────

def test_rfc5424_priority():
    # facility=1 (user), severity=6 (info) → priority 14
    data = _rfc5424("hello", facility=1, severity=6)
    assert data.startswith(b"<14>1 ")

def test_rfc5424_fields():
    data = _rfc5424("test msg", hostname="myhost", app_name="myapp", facility=1, severity=6)
    assert b"myhost" in data
    assert b"myapp" in data
    assert b"test msg" in data
    assert data.endswith(b"\n")

def test_rfc5424_custom_facility_severity():
    # facility=16 (local0), severity=3 (err) → priority 131
    data = _rfc5424("err", facility=16, severity=3)
    assert data.startswith(b"<131>1 ")

def test_rfc3164_fields():
    data = _rfc3164("log line", hostname="host1", app_name="app1", facility=1, severity=6)
    assert b"host1" in data
    assert b"app1" in data
    assert b"log line" in data
    assert data.endswith(b"\n")

def test_facility_encoding_range():
    """Facilities 0–23 produce valid priority values < 192."""
    for facility in range(24):
        data = _rfc5424("x", facility=facility, severity=6)
        priority_bytes = data.split(b">")[0][1:]
        priority = int(priority_bytes)
        assert priority == facility * 8 + 6
        assert priority < 192


# ── pre-framed passthrough ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_preframed_passthrough_udp():
    """Pre-framed syslog payloads are sent byte-for-byte without re-wrapping."""
    transport = SyslogTransport()
    raw_msg = "<14>1 2024-01-01T00:00:00Z myhost app - - - test pre-framed"
    captured = []

    mock_dt = MagicMock()
    mock_dt.sendto = lambda data: captured.append(data)
    mock_dt.is_closing.return_value = False

    with patch("transports.syslog_transport.settings") as s:
        s.brokervm_host = "127.0.0.1"
        s.brokervm_syslog_port = 514
        s.brokervm_syslog_proto = "udp"
        with patch("transports.syslog_transport.asyncio.get_event_loop") as mock_loop:
            mock_loop.return_value.create_datagram_endpoint = AsyncMock(
                return_value=(mock_dt, MagicMock())
            )
            result = await transport.send(raw_msg, _META_PREFRAMED)

    assert result.success
    assert len(captured) == 1
    # The pre-framed payload appears verbatim in the sent bytes
    assert raw_msg.encode() in captured[0]


@pytest.mark.asyncio
async def test_raw_format_gets_rfc5424_wrapper():
    """Non-pre-framed payloads are wrapped in RFC 5424 before sending."""
    transport = SyslogTransport()
    captured = []

    mock_dt = MagicMock()
    mock_dt.sendto = lambda data: captured.append(data)
    mock_dt.is_closing.return_value = False

    with patch("transports.syslog_transport.settings") as s:
        s.brokervm_host = "127.0.0.1"
        s.brokervm_syslog_port = 514
        s.brokervm_syslog_proto = "udp"
        with patch("transports.syslog_transport.asyncio.get_event_loop") as mock_loop:
            mock_loop.return_value.create_datagram_endpoint = AsyncMock(
                return_value=(mock_dt, MagicMock())
            )
            result = await transport.send("raw syslog line", _META_RAW)

    assert result.success
    # Wrapped payload must start with RFC 5424 priority "<NNN>1 "
    assert captured[0].startswith(b"<")
    assert b">1 " in captured[0]


# ── TCP send path ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_tcp_send_writes_length_prefix():
    """TCP transport prepends octet-count framing per RFC 6587."""
    transport = SyslogTransport()
    written = []

    mock_writer = MagicMock()
    mock_writer.is_closing.return_value = False
    mock_writer.write = lambda data: written.append(data)
    mock_writer.drain = AsyncMock()

    with patch("transports.syslog_transport.settings") as s:
        s.brokervm_host = "127.0.0.1"
        s.brokervm_syslog_port = 601
        s.brokervm_syslog_proto = "tcp"
        with patch("transports.syslog_transport.asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            mock_conn.return_value = (MagicMock(), mock_writer)
            result = await transport.send("tcp test message", _META_RAW)

    assert result.success
    assert len(written) == 1
    # Length prefix: b"<NNN> <framed_payload>"
    parts = written[0].split(b" ", 1)
    declared_len = int(parts[0])
    assert declared_len == len(parts[1])


@pytest.mark.asyncio
async def test_tcp_reconnects_after_closed_writer():
    """A closed TCP writer triggers reconnection on the next send."""
    transport = SyslogTransport()

    broken_writer = MagicMock()
    broken_writer.is_closing.return_value = True  # already closed

    good_written = []
    good_writer = MagicMock()
    good_writer.is_closing.return_value = False
    good_writer.write = lambda data: good_written.append(data)
    good_writer.drain = AsyncMock()

    with patch("transports.syslog_transport.settings") as s:
        s.brokervm_host = "127.0.0.1"
        s.brokervm_syslog_port = 601
        s.brokervm_syslog_proto = "tcp"
        with patch("transports.syslog_transport.asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            mock_conn.return_value = (MagicMock(), good_writer)
            transport._tcp_writer = broken_writer
            result = await transport.send("reconnect test", _META_RAW)

    assert result.success
    assert len(good_written) == 1
