"""Cribl Stream XSIAM-destination emulation.

Pinned to the documented behaviour of Cribl's Cortex XSIAM Destination
(docs.cribl.io/stream/destinations-xsiam and the XSIAM onboarding guide):

  * events are delivered as {"data": <event>, "collector_ms": <epoch ms>}
  * routing identifiers travel as HTTP headers (Source-Identifier,
    Integration-Identifier, vendor, product, format), derived from Cribl's
    internal __-prefixed fields -- they are NOT left in the payload
  * the destination enforces 5 MB per event and 9.5 MB per batch

plus the standing rule that emulation off is a byte-for-byte no-op.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'engine'))

from transports.base import SourceMeta
from transports.http_transport import (
    CRIBL_MAX_BATCH_BYTES,
    CRIBL_MAX_EVENT_BYTES,
    HTTPTransport,
    _build_body,
)


def _meta(**kw) -> SourceMeta:
    base = dict(source_id="palo_alto_ngfw", source_name="Palo Alto NGFW",
                format="json", transport="http", http_log_type="json")
    base.update(kw)
    return SourceMeta(**base)


ON = _meta(cribl_emulation=True)
OFF = _meta(cribl_emulation=False)


# ── envelope ────────────────────────────────────────────────────────────────

def test_json_event_is_wrapped_in_data_collector_ms():
    body = json.loads(_build_body(json.dumps({"a": 1}), ON).decode())
    assert set(body) == {"data", "collector_ms"}
    assert body["data"]["a"] == 1
    # data is a native JSON object, not a stringified blob
    assert isinstance(body["data"], dict)
    assert isinstance(body["collector_ms"], int)
    # epoch *milliseconds*, so well past the seconds-scale value
    assert body["collector_ms"] > 1_600_000_000_000


def test_engine_tag_survives_inside_the_envelope():
    """simulated_log_source is what the parsing rules filter on, so it has to
    live with the event inside `data`, not alongside it."""
    body = json.loads(_build_body(json.dumps({"a": 1}), ON).decode())
    assert body["data"]["simulated_log_source"] == "palo_alto_ngfw"
    assert "simulated_log_source" not in body


def test_raw_event_is_also_wrapped_with_the_string_in_data():
    meta = _meta(cribl_emulation=True, http_log_type="raw")
    body = json.loads(_build_body("<134>Jun 11 sample cef line", meta).decode())
    assert isinstance(body["data"], str)
    assert "sample cef line" in body["data"]
    assert 'simulated_log_source="palo_alto_ngfw"' in body["data"]


def test_no_invented_cribl_body_fields():
    """Regression: an earlier emulation stamped cribl_pipe / cribl_host /
    cribl_breaker / sourcetype into the payload. No real Cribl worker sends
    those to XSIAM -- its internal fields are __-prefixed and become headers,
    so those keys made the traffic diverge from the thing being emulated."""
    body = _build_body(json.dumps({"a": 1}), ON).decode()
    for invented in ("cribl_pipe", "cribl_host", "cribl_breaker", "sourcetype", "_time"):
        assert invented not in body, f"{invented} should not be in the delivered body"


# ── headers ─────────────────────────────────────────────────────────────────

def test_identifier_headers_are_sent():
    headers = HTTPTransport()._build_headers(ON)
    assert headers["Source-Identifier"] == "palo_alto_ngfw"
    assert headers["Integration-Identifier"] == "cribl:in_palo_alto_ngfw"
    # Real vendor/product, not a mechanical split of the source id: these
    # headers pick the XSIAM parser, so "palo"/"alto_ngfw" would route wrong.
    assert headers["vendor"] == "paloaltonetworks"
    assert headers["product"] == "ngfw"
    assert headers["format"] == "json"


def test_identifier_headers_can_be_overridden():
    meta = _meta(cribl_emulation=True, cribl_source_identifier="pan_fw_prod",
                 cribl_vendor="paloaltonetworks", cribl_product="firewall")
    headers = HTTPTransport()._build_headers(meta)
    assert headers["Source-Identifier"] == "pan_fw_prod"
    assert headers["vendor"] == "paloaltonetworks"
    assert headers["product"] == "firewall"


def test_vendor_product_falls_back_to_a_split_for_unmapped_sources():
    headers = HTTPTransport()._build_headers(
        _meta(cribl_emulation=True, source_id="acme_widget"))
    assert headers["vendor"] == "acme"
    assert headers["product"] == "widget"


def test_format_header_tracks_log_type():
    assert HTTPTransport()._build_headers(
        _meta(cribl_emulation=True, http_log_type="json"))["format"] == "json"
    for lt in ("raw", "cef", "leef"):
        headers = HTTPTransport()._build_headers(_meta(cribl_emulation=True, http_log_type=lt))
        assert headers["format"] == "raw", f"{lt} should be delivered as raw"


def test_content_type_is_json_even_for_raw_events():
    """The envelope is JSON regardless of what `data` holds."""
    headers = HTTPTransport()._build_headers(_meta(cribl_emulation=True, http_log_type="cef"))
    assert headers["Content-Type"] == "application/json"


def test_no_identifier_headers_when_emulation_is_off():
    headers = HTTPTransport()._build_headers(OFF)
    for h in ("Source-Identifier", "Integration-Identifier", "vendor", "product", "format"):
        assert h not in headers
    # ...and the content type still follows the source's own log type
    assert headers["Content-Type"] == "application/json"
    assert HTTPTransport()._build_headers(_meta(http_log_type="cef"))["Content-Type"] == "text/plain"


def test_gzip_still_applies_under_cribl():
    headers = HTTPTransport()._build_headers(_meta(cribl_emulation=True, http_compression="gzip"))
    assert headers["Content-Encoding"] == "gzip"
    assert headers["Content-Type"] == "application/json"


# ── size limits ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_oversized_event_is_rejected_not_sent():
    """The destination enforces 5 MB per event, so an over-limit event must
    fail here rather than report success for something that would be dropped
    in a real pipeline."""
    transport = HTTPTransport()
    huge = json.dumps({"blob": "x" * (CRIBL_MAX_EVENT_BYTES + 1000)})
    result = await transport.send(huge, ON)
    assert result.success is False
    assert "per-event limit" in result.error


@pytest.mark.asyncio
async def test_oversized_event_is_allowed_when_emulation_is_off():
    """The limit belongs to Cribl, not to the engine -- without emulation the
    event should attempt delivery (and fail only on the network, since no
    collector is reachable in tests)."""
    transport = HTTPTransport()
    huge = json.dumps({"blob": "x" * (CRIBL_MAX_EVENT_BYTES + 1000)})
    result = await transport.send(huge, OFF)
    assert result.success is False
    assert "per-event limit" not in (result.error or "")


@pytest.mark.asyncio
async def test_oversized_batch_is_rejected():
    transport = HTTPTransport()
    # Each event is comfortably under the per-event cap; the batch is not.
    chunk = {"blob": "x" * 100_000}
    events = [chunk] * ((CRIBL_MAX_BATCH_BYTES // 100_000) + 5)
    result = await transport.send_batch(events, ON)
    assert result.success is False
    assert "batch limit" in result.error


# ── off is a true no-op ─────────────────────────────────────────────────────

def test_off_is_byte_identical_to_never_touching_the_toggle():
    untouched = _meta()
    explicitly_off = _meta(cribl_emulation=False, cribl_source_identifier="ignored",
                           cribl_vendor="ignored", cribl_product="ignored")
    payload = json.dumps({"a": 1})
    assert _build_body(payload, untouched) == _build_body(payload, explicitly_off)


def test_off_leaves_the_event_unwrapped():
    body = json.loads(_build_body(json.dumps({"a": 1}), OFF).decode())
    assert "data" not in body and "collector_ms" not in body
    assert body["simulated_log_source"] == "palo_alto_ngfw"
    assert body["a"] == 1


def test_off_raw_line_is_a_bare_prefixed_string():
    body = _build_body("<134>sample line", _meta(http_log_type="raw")).decode()
    assert body.startswith('simulated_log_source="palo_alto_ngfw" ')
    assert "collector_ms" not in body


# ── Windows channels share one pack ─────────────────────────────────────────

@pytest.mark.parametrize("source_id", [
    "windows_security", "windows_system", "windows_application", "windows_powershell",
])
def test_windows_channels_share_vendor_product(source_id):
    """Per "Collect Windows Event Logs for Cortex XSIAM via Cribl", a single
    pack covers the Security, System, Application, PowerShell, Firewall and
    TaskScheduler channels -- they share vendor/product and land together in
    microsoft_windows_raw rather than getting a dataset per channel."""
    headers = HTTPTransport()._build_headers(_meta(cribl_emulation=True, source_id=source_id))
    assert headers["vendor"] == "microsoft"
    assert headers["product"] == "windows"


def test_sysmon_is_its_own_pack_not_folded_into_windows():
    headers = HTTPTransport()._build_headers(_meta(cribl_emulation=True, source_id="sysmon"))
    assert headers["vendor"] == "microsoft"
    assert headers["product"] == "sysmon"


def test_routing_note_reports_the_real_destination_dataset():
    """The destination dataset comes from vendor/product, not from the
    source's xsiam_dataset -- which is why enabling emulation can deliver
    into a tenant's real telemetry."""
    from transports.http_transport import cribl_routing_note
    assert cribl_routing_note("windows_security") == "microsoft_windows_raw"
    assert cribl_routing_note("windows_powershell") == "microsoft_windows_raw"
    assert cribl_routing_note("sysmon") == "microsoft_sysmon_raw"
    assert cribl_routing_note("acme_widget") == "acme_widget_raw"
