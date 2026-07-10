"""Tests that the four scenario-aware sources actually substitute the shared
entity/override values, and that every other source safely falls back to
plain generate() via the base class default."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'engine'))

from sources import get_registry
from sources.base_source import ScenarioEntities

ENTITIES = ScenarioEntities(
    username="jsmith",
    domain_user="jsmith@corp.local",
    host="WIN-TESTHOST",
    internal_ip="10.10.5.5",
    external_ip="203.0.113.9",
)


@pytest.mark.asyncio
async def test_okta_uses_entities_and_overrides():
    source = get_registry()["okta"]
    event = await source.generate_with_entities(ENTITIES, {"event_type": "user.authentication.sso", "outcome": "SUCCESS"})
    data = json.loads(event.raw)
    assert data["eventType"] == "user.authentication.sso"
    assert data["outcome"]["result"] == "SUCCESS"
    assert data["actor"]["alternateId"] == "jsmith@corp.local"
    assert data["client"]["ipAddress"] == "203.0.113.9"


@pytest.mark.asyncio
async def test_crowdstrike_uses_entities_and_overrides():
    source = get_registry()["crowdstrike_falcon"]
    event = await source.generate_with_entities(ENTITIES, {"event_type": "Detection"})
    data = json.loads(event.raw)
    assert data["EventType"] == "Detection"
    assert data["ComputerName"] == "WIN-TESTHOST"
    assert data["UserName"] == "CORP\\jsmith"


@pytest.mark.asyncio
async def test_aws_cloudtrail_uses_entities_and_overrides():
    source = get_registry()["aws_cloudtrail"]
    event = await source.generate_with_entities(ENTITIES, {"event_name": "GetObject"})
    data = json.loads(event.raw)
    assert data["eventName"] == "GetObject"
    assert data["userIdentity"]["userName"] == "jsmith"
    assert data["sourceIPAddress"] == "203.0.113.9"


@pytest.mark.asyncio
async def test_proofpoint_uses_entities_and_overrides():
    source = get_registry()["proofpoint_tap"]
    event = await source.generate_with_entities(ENTITIES, {"event_type": "clicksBlocked"})
    data = json.loads(event.raw)
    assert data["type"] == "clicksBlocked"
    assert data["recipient"] == "jsmith@corp.local"


@pytest.mark.asyncio
async def test_non_participating_source_falls_back_to_generate():
    source = get_registry()["cisco_asa"]
    event = await source.generate_with_entities(ENTITIES, {"event_type": "whatever"})
    assert event.source_id == "cisco_asa"
    assert event.raw


@pytest.mark.asyncio
async def test_crowdstrike_network_and_dns_events_also_carry_the_correlated_user():
    # Regression: _network_connect/_dns_request accepted a `user` param for
    # signature parity but never used it, silently dropping identity
    # correlation for these two event types even though every sibling
    # generator in the file honors it.
    source = get_registry()["crowdstrike_falcon"]

    network = await source.generate_with_entities(ENTITIES, {"event_type": "NetworkConnect"})
    data = json.loads(network.raw)
    assert data["ComputerName"] == "WIN-TESTHOST"
    assert data["UserName"] == "CORP\\jsmith"

    dns = await source.generate_with_entities(ENTITIES, {"event_type": "DnsRequest"})
    data = json.loads(dns.raw)
    assert data["ComputerName"] == "WIN-TESTHOST"
    assert data["UserName"] == "CORP\\jsmith"


# ── Regression: an explicit falsy override must be honored, not silently
# replaced by random data (the old `overrides.get(x) or default` pattern
# treated "" the same as "key absent"). ─────────────────────────────────────

@pytest.mark.asyncio
async def test_okta_honors_falsy_ip_override():
    source = get_registry()["okta"]
    event = await source.generate_with_entities(ENTITIES, {"ip": ""})
    data = json.loads(event.raw)
    assert data["client"]["ipAddress"] == ""


@pytest.mark.asyncio
async def test_aws_cloudtrail_honors_falsy_source_ip_override():
    source = get_registry()["aws_cloudtrail"]
    event = await source.generate_with_entities(ENTITIES, {"source_ip": ""})
    data = json.loads(event.raw)
    assert data["sourceIPAddress"] == ""


@pytest.mark.asyncio
async def test_proofpoint_honors_falsy_sender_ip_override():
    source = get_registry()["proofpoint_tap"]
    event = await source.generate_with_entities(ENTITIES, {"event_type": "messagesBlocked", "sender_ip": ""})
    data = json.loads(event.raw)
    assert data["senderIP"] == ""
