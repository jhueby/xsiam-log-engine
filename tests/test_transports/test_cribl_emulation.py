"""Tests for Cribl Stream metadata stamping (issue #10) — opt-in, per-source,
default off. Covers both JSON and raw/CEF/LEEF framing, on both send() and
send_batch(), plus the "default off is a true no-op" regression lock."""
import json
import time
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'engine'))

from transports.http_transport import _build_body, _augment_json_event, _augment_raw_line
from transports.base import SourceMeta

BASE = dict(source_id="okta", source_name="Okta", transport="http")


def meta(**overrides) -> SourceMeta:
    return SourceMeta(**{**BASE, "format": "json", **overrides})


# ── Default off: byte-identical to no-cribl output ─────────────────────────

def test_cribl_off_json_is_unchanged():
    off = meta(http_log_type="json", cribl_emulation=False)
    body = _build_body(json.dumps({"a": 1}), off)
    event = json.loads(body)
    assert event == {"simulated_log_source": "okta", "a": 1}
    assert "cribl_pipe" not in event


def test_cribl_off_raw_is_byte_identical_to_original_format():
    off = meta(http_log_type="raw", cribl_emulation=False)
    body = _build_body("some raw log line", off)
    assert body == b'simulated_log_source="okta" some raw log line\n'


# ── Cribl on: JSON framing ──────────────────────────────────────────────────

def test_cribl_on_json_injects_all_fields():
    on = meta(http_log_type="json", cribl_emulation=True)
    body = _build_body(json.dumps({"a": 1}), on)
    event = json.loads(body)

    assert event["simulated_log_source"] == "okta"
    assert event["cribl_pipe"] == "default"
    assert event["cribl_host"] == "cribl-worker.corp.local"
    assert event["cribl_breaker"] == "auto_line_breaker"
    assert event["sourcetype"] == "okta"
    assert event["source"] == "cribl:default:okta"
    assert isinstance(event["_time"], float)
    assert abs(event["_time"] - time.time()) < 5  # sane, current epoch time
    assert event["a"] == 1  # original payload preserved


def test_cribl_on_honors_pipe_and_host_overrides():
    on = meta(http_log_type="json", cribl_emulation=True, cribl_pipe_name="prod_pipe", cribl_host_name="cribl-worker-07")
    body = _build_body(json.dumps({}), on)
    event = json.loads(body)
    assert event["cribl_pipe"] == "prod_pipe"
    assert event["cribl_host"] == "cribl-worker-07"
    assert event["source"] == "cribl:prod_pipe:okta"


# ── Cribl on: raw/CEF/LEEF framing ──────────────────────────────────────────

def test_cribl_on_raw_prefixes_fields_before_simulated_log_source():
    on = meta(http_log_type="raw", cribl_emulation=True)
    body = _build_body("some raw log line", on)
    text = body.decode()
    assert text.startswith('cribl_pipe="default" cribl_host="cribl-worker.corp.local" ')
    assert 'simulated_log_source="okta" some raw log line' in text
    # cribl fields come before simulated_log_source, matching the spec order
    assert text.index("cribl_pipe") < text.index("simulated_log_source")


def test_cribl_on_raw_json_shaped_payload_injects_instead_of_prefixing():
    # A raw/CEF source whose payload happens to already be JSON-shaped still
    # gets fields injected (not prefixed), same rule as simulated_log_source.
    on = meta(http_log_type="raw", cribl_emulation=True)
    body = _build_body(json.dumps({"x": 1}), on)
    event = json.loads(body)
    assert event["cribl_pipe"] == "default"
    assert event["x"] == 1


# ── send_batch() gets the same treatment ────────────────────────────────────

@pytest.mark.asyncio
async def test_send_batch_json_stamps_every_event(monkeypatch):
    import respx
    import httpx
    from config.settings import settings
    from transports.http_transport import HTTPTransport

    on = meta(http_log_type="json", cribl_emulation=True)
    transport = HTTPTransport()
    events = [{"i": i} for i in range(3)]
    with respx.mock:
        route = respx.post(settings.xsiam_url).mock(return_value=httpx.Response(200, json={"ok": True}))
        result = await transport.send_batch(events, on)
    assert result.success
    sent = json.loads(route.calls.last.request.content)
    assert len(sent) == 3
    assert all(e["cribl_pipe"] == "default" and e["sourcetype"] == "okta" for e in sent)
    await transport.close()


@pytest.mark.asyncio
async def test_send_batch_off_has_no_cribl_fields():
    import respx
    import httpx
    from config.settings import settings
    from transports.http_transport import HTTPTransport

    off = meta(http_log_type="json", cribl_emulation=False)
    transport = HTTPTransport()
    with respx.mock:
        route = respx.post(settings.xsiam_url).mock(return_value=httpx.Response(200, json={"ok": True}))
        await transport.send_batch([{"i": 1}], off)
    sent = json.loads(route.calls.last.request.content)
    assert "cribl_pipe" not in sent[0]
    await transport.close()
