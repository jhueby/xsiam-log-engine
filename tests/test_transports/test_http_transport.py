"""Tests for HTTPTransport using respx to mock the HTTP endpoint."""
import json
import pytest
import respx
import httpx
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'engine'))

from config.settings import settings
from transports.http_transport import HTTPTransport
from transports.base import SourceMeta


META = SourceMeta(source_id="okta", source_name="Okta", format="json", transport="http")


@pytest.mark.asyncio
async def test_send_success():
    transport = HTTPTransport()
    with respx.mock:
        respx.post(settings.xsiam_url).mock(return_value=httpx.Response(200, json={"status": "ok"}))
        result = await transport.send(json.dumps({"test": "event"}), META)
    assert result.success
    assert result.bytes_sent > 0
    await transport.close()


@pytest.mark.asyncio
async def test_send_retries_on_500():
    transport = HTTPTransport()
    call_count = 0

    def side_effect(request):
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            return httpx.Response(500)
        return httpx.Response(200, json={"status": "ok"})

    with respx.mock:
        respx.post(settings.xsiam_url).mock(side_effect=side_effect)
        result = await transport.send(json.dumps({"test": "event"}), META)
    assert result.success
    assert call_count == 3
    await transport.close()


@pytest.mark.asyncio
async def test_send_fails_after_max_retries():
    transport = HTTPTransport()
    with respx.mock:
        respx.post(settings.xsiam_url).mock(return_value=httpx.Response(500))
        result = await transport.send(json.dumps({"test": "event"}), META)
    assert not result.success
    await transport.close()


@pytest.mark.asyncio
async def test_send_batch_success():
    transport = HTTPTransport()
    events = [{"event": i, "data": "test"} for i in range(10)]
    with respx.mock:
        respx.post(settings.xsiam_url).mock(return_value=httpx.Response(200, json={"status": "ok"}))
        result = await transport.send_batch(events, META)
    assert result.success
    assert result.bytes_sent > 0
    await transport.close()


@pytest.mark.asyncio
async def test_health_check_unreachable():
    transport = HTTPTransport()
    # No mock — should fail gracefully
    result = await transport.health_check()
    assert isinstance(result, bool)
    await transport.close()
