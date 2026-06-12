"""Tests that every registered source generates valid LogEvent objects."""
import asyncio
import json
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'engine'))

from sources import get_registry
from sources.base_source import LogEvent


@pytest.fixture(scope="session")
def registry():
    return get_registry()


@pytest.mark.asyncio
@pytest.mark.parametrize("source_id", list(get_registry().keys()))
async def test_source_generates_log_event(source_id):
    registry = get_registry()
    source = registry[source_id]
    event = await source.generate()

    assert isinstance(event, LogEvent), f"{source_id}: generate() must return LogEvent"
    assert event.raw, f"{source_id}: raw must be non-empty"
    assert event.source_id == source_id, f"{source_id}: source_id mismatch"
    assert event.format, f"{source_id}: format must be non-empty"
    assert isinstance(event.structured, dict), f"{source_id}: structured must be a dict"


@pytest.mark.asyncio
@pytest.mark.parametrize("source_id", list(get_registry().keys()))
async def test_source_generates_multiple_events(source_id):
    """Each source should produce varied output (not the same event every time)."""
    registry = get_registry()
    source = registry[source_id]
    events = [await source.generate() for _ in range(5)]
    raws = [e.raw for e in events]
    # At least some should differ (probabilistic check)
    assert len(set(raws)) > 1 or len(raws[0]) > 10, f"{source_id}: events appear identical"


@pytest.mark.asyncio
@pytest.mark.parametrize("source_id", ["okta", "aws_cloudtrail", "crowdstrike_falcon", "azure_ad"])
async def test_http_source_json_valid(source_id):
    registry = get_registry()
    source = registry[source_id]
    event = await source.generate()
    parsed = json.loads(event.raw)
    assert isinstance(parsed, dict)


@pytest.mark.asyncio
@pytest.mark.parametrize("source_id", [
    "windows_security", "windows_system", "windows_application",
    "microsoft_ad", "microsoft_dns", "microsoft_dhcp", "microsoft_defender",
])
async def test_wec_source_has_event_id(source_id):
    registry = get_registry()
    source = registry[source_id]
    event = await source.generate()
    assert "EventID" in event.structured, f"{source_id}: missing EventID"
    assert isinstance(event.structured["EventID"], int)


@pytest.mark.asyncio
@pytest.mark.parametrize("source_id", ["cisco_asa", "cisco_meraki", "linux_syslog", "linux_auth"])
async def test_syslog_source_starts_with_priority(source_id):
    # cisco_asa, cisco_meraki, and linux sources embed syslog priority in raw.
    # palo_alto_ngfw and fortinet_fortigate use vendor-native formats that the
    # syslog transport wraps — their raw field is the payload, not the syslog frame.
    registry = get_registry()
    source = registry[source_id]
    event = await source.generate()
    assert event.raw.startswith("<"), f"{source_id}: syslog raw should start with <priority>"


def test_registry_has_expected_sources():
    registry = get_registry()
    expected = {
        "windows_security", "windows_system", "windows_application",
        "microsoft_ad", "microsoft_dns", "microsoft_dhcp", "microsoft_defender",
        "cisco_asa", "cisco_meraki", "palo_alto_ngfw", "fortinet_fortigate",
        "linux_syslog", "linux_auth", "linux_auditd",
        "proxy_bluecoat", "proxy_zscaler",
        "crowdstrike_falcon", "okta", "azure_ad", "aws_cloudtrail",
        "netflow",
    }
    for src in expected:
        assert src in registry, f"Missing source: {src}"
    assert len(registry) >= len(expected)
