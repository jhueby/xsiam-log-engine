"""Tests for WECTransport: SOAP envelope, XML escaping, subscription URL parsing, HTTP handling."""
import json
import sys
import os
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from unittest.mock import patch

import httpx
import pytest
import respx

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'engine'))

from transports.wec_transport import WECTransport, _build_event_xml, _parse_subscription_url
from transports.base import SourceMeta

_META = SourceMeta(
    source_id="windows_security", source_name="Windows Security",
    format="json", transport="wec",
)

_SUB_URL = (
    "Server=HTTPS://bvm.lab:5986/wsman/SubscriptionManager/WEC,"
    "Refresh=600,IssuerCA=37210BA1582B95CB0CB558C572B503C349692604"
)


@contextmanager
def _patch_settings():
    """Point all settings at bvm.lab:5986 (no cert) for test isolation."""
    with patch("transports.wec_transport.settings") as s:
        s.wec_subscription_url = _SUB_URL
        s.brokervm_host = "bvm.lab"
        s.brokervm_wec_port = 5986
        s.tls_client_cert_path = ""
        s.tls_client_key_path = ""
        yield s


# ── subscription URL parser ───────────────────────────────────────────────────

def test_parse_subscription_url_host_port():
    with patch("transports.wec_transport.settings") as s:
        s.brokervm_host = "fallback"
        s.brokervm_wec_port = 1234
        host, port = _parse_subscription_url(_SUB_URL)
    assert host == "bvm.lab"
    assert port == 5986

def test_parse_subscription_url_case_insensitive():
    with patch("transports.wec_transport.settings") as s:
        s.brokervm_host = "fallback"
        s.brokervm_wec_port = 1234
        url = "server=HTTPS://HOST.EXAMPLE:9000/wsman,Refresh=300"
        host, port = _parse_subscription_url(url)
    assert host == "host.example"
    assert port == 9000

def test_parse_subscription_url_fallback():
    with patch("transports.wec_transport.settings") as s:
        s.brokervm_host = "fallback.host"
        s.brokervm_wec_port = 4321
        host, port = _parse_subscription_url("no-server-field-here")
    assert host == "fallback.host"
    assert port == 4321


# ── XML escaping ──────────────────────────────────────────────────────────────

def test_build_event_xml_escapes_angle_brackets():
    event = {
        "EventID": 4624,
        "Channel": "<Security>",
        "Computer": "WIN-HOST",
        "EventData": {"Key": "<b>bold</b>"},
    }
    xml = _build_event_xml(event)
    assert "<b>" not in xml
    assert "&lt;b&gt;" in xml

def test_build_event_xml_escapes_ampersand():
    event = {
        "EventID": 4624,
        "Channel": "Security & Audit",
        "Computer": "WIN",
        "EventData": {},
    }
    xml = _build_event_xml(event)
    assert "Security & Audit" not in xml.replace("&amp;", "PLACEHOLDER")
    assert "&amp;" in xml

def test_build_event_xml_contains_event_id():
    event = {"EventID": 4688, "Channel": "Security", "EventData": {}}
    xml = _build_event_xml(event)
    assert "<EventID>4688</EventID>" in xml

def test_build_event_xml_contains_event_data_keys():
    event = {
        "EventID": 4624,
        "Channel": "Security",
        "EventData": {"SubjectUserName": "jsmith", "LogonType": "3"},
    }
    xml = _build_event_xml(event)
    assert 'Name="SubjectUserName"' in xml
    assert "jsmith" in xml
    assert 'Name="LogonType"' in xml

def test_build_event_xml_defaults_missing_fields():
    xml = _build_event_xml({})
    assert "<Event" in xml
    assert "</Event>" in xml
    assert "<EventID>0</EventID>" in xml

def test_build_event_xml_is_parseable():
    event = {"EventID": 4624, "Channel": "Security", "EventData": {"Key": "Value"}}
    xml = _build_event_xml(event)
    # Must parse without raising an exception
    ET.fromstring(xml)


# ── HTTP status handling ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_send_202_accepted():
    transport = WECTransport()
    with respx.mock:
        respx.post("https://bvm.lab:5986/wsman").mock(return_value=httpx.Response(202))
        with _patch_settings():
            result = await transport.send(json.dumps({"EventID": 4624}), _META)
    assert result.success
    assert result.bytes_sent > 0
    await transport.close()

@pytest.mark.asyncio
async def test_send_200_ok():
    transport = WECTransport()
    with respx.mock:
        respx.post("https://bvm.lab:5986/wsman").mock(return_value=httpx.Response(200))
        with _patch_settings():
            result = await transport.send(json.dumps({"EventID": 4624}), _META)
    assert result.success
    await transport.close()

@pytest.mark.asyncio
async def test_send_401_unauthorized():
    transport = WECTransport()
    with respx.mock:
        respx.post("https://bvm.lab:5986/wsman").mock(
            return_value=httpx.Response(401, text="Unauthorized")
        )
        with _patch_settings():
            result = await transport.send(json.dumps({"EventID": 4624}), _META)
    assert not result.success
    assert "401" in result.error
    await transport.close()

@pytest.mark.asyncio
async def test_send_500_server_error():
    transport = WECTransport()
    with respx.mock:
        respx.post("https://bvm.lab:5986/wsman").mock(
            return_value=httpx.Response(500, text="Internal Server Error")
        )
        with _patch_settings():
            result = await transport.send(json.dumps({"EventID": 4624}), _META)
    assert not result.success
    assert "500" in result.error
    await transport.close()

@pytest.mark.asyncio
async def test_send_network_error_clears_client():
    transport = WECTransport()
    with respx.mock:
        respx.post("https://bvm.lab:5986/wsman").mock(
            side_effect=httpx.ConnectError("refused")
        )
        with _patch_settings():
            result = await transport.send(json.dumps({"EventID": 4624}), _META)
    assert not result.success
    assert transport._client is None
    await transport.close()


# ── SOAP envelope structure ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_envelope_uses_soap_xml_content_type():
    transport = WECTransport()
    captured_headers: dict = {}

    def capture(request: httpx.Request) -> httpx.Response:
        captured_headers.update(dict(request.headers))
        return httpx.Response(202)

    with respx.mock:
        respx.post("https://bvm.lab:5986/wsman").mock(side_effect=capture)
        with _patch_settings():
            await transport.send(json.dumps({"EventID": 4624}), _META)

    assert "soap+xml" in captured_headers.get("content-type", "")
    await transport.close()

@pytest.mark.asyncio
async def test_envelope_body_is_valid_xml():
    transport = WECTransport()
    captured_body: list[bytes] = []

    def capture(request: httpx.Request) -> httpx.Response:
        captured_body.append(request.content)
        return httpx.Response(202)

    with respx.mock:
        respx.post("https://bvm.lab:5986/wsman").mock(side_effect=capture)
        with _patch_settings():
            await transport.send(json.dumps({"EventID": 4688, "Channel": "Security"}), _META)

    assert len(captured_body) == 1
    ET.fromstring(captured_body[0])  # must parse without raising
    await transport.close()

@pytest.mark.asyncio
async def test_envelope_contains_wsman_namespace():
    transport = WECTransport()
    captured_body: list[bytes] = []

    def capture(request: httpx.Request) -> httpx.Response:
        captured_body.append(request.content)
        return httpx.Response(202)

    with respx.mock:
        respx.post("https://bvm.lab:5986/wsman").mock(side_effect=capture)
        with _patch_settings():
            await transport.send(json.dumps({"EventID": 4624}), _META)

    assert b"soap-envelope" in captured_body[0]
    assert b"<s:Body>" in captured_body[0] or b"Body>" in captured_body[0]
    await transport.close()
