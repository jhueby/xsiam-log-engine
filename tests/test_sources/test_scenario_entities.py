"""Tests that the scenario-aware sources actually substitute the shared
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


@pytest.mark.asyncio
async def test_azure_ad_signin_uses_entities_and_overrides():
    source = get_registry()["azure_ad"]
    event = await source.generate_with_entities(
        ENTITIES, {"log_type": "SignInLogs", "app": "SharePoint Online", "result_type": "0"}
    )
    data = json.loads(event.raw)
    assert data["category"] == "SignInLogs"
    assert data["resultType"] == "0"
    assert data["properties"]["appDisplayName"] == "SharePoint Online"
    assert data["properties"]["userPrincipalName"] == "jsmith@corp.local"
    # Driven from attacker infrastructure, not the user's own workstation.
    assert data["callerIpAddress"] == "203.0.113.9"
    assert data["properties"]["ipAddress"] == "203.0.113.9"
    assert data["properties"]["deviceDetail"]["displayName"] == "WIN-TESTHOST"


@pytest.mark.asyncio
async def test_azure_ad_audit_uses_entities_and_defaults_target_to_self():
    """Self-service operations (registering an authenticator, resetting your
    own password) target the same principal that initiated them -- that
    self-targeting is what makes the abuse blend into normal activity."""
    source = get_registry()["azure_ad"]
    event = await source.generate_with_entities(
        ENTITIES, {"log_type": "AuditLogs", "operation": "User registered security info"}
    )
    data = json.loads(event.raw)
    assert data["category"] == "AuditLogs"
    assert data["operationName"] == "User registered security info"
    assert data["properties"]["initiatedBy"]["user"]["userPrincipalName"] == "jsmith@corp.local"
    assert data["properties"]["targetResources"][0]["userPrincipalName"] == "jsmith@corp.local"


@pytest.mark.asyncio
async def test_azure_ad_honors_falsy_ip_override():
    source = get_registry()["azure_ad"]
    event = await source.generate_with_entities(ENTITIES, {"log_type": "SignInLogs", "ip": ""})
    assert json.loads(event.raw)["callerIpAddress"] == ""


@pytest.mark.asyncio
async def test_azure_ad_plain_generate_still_works():
    """The refactor to shared builders must not change non-scenario output.

    Loops rather than sampling once: generate() picks the log type randomly,
    and the two shapes put the user in different places (SignInLogs at
    properties.userPrincipalName, AuditLogs under initiatedBy), so a single
    call only exercises whichever branch it happened to land on.
    """
    source = get_registry()["azure_ad"]
    seen = set()
    for _ in range(40):
        data = json.loads((await source.generate()).raw)
        category = data["category"]
        seen.add(category)
        assert category in ("SignInLogs", "AuditLogs")
        if category == "SignInLogs":
            assert data["properties"]["userPrincipalName"]
            assert data["properties"]["appDisplayName"]
        else:
            assert data["properties"]["initiatedBy"]["user"]["userPrincipalName"]
            assert data["operationName"]
    assert seen == {"SignInLogs", "AuditLogs"}, f"only exercised {seen}"
