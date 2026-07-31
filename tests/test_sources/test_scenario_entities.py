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


# ── sources added alongside the M365 / cloud-native / remote-access packs ──

@pytest.mark.asyncio
async def test_m365_audit_inbox_rule_uses_entities():
    """The mailbox-rule operation is why this source exists: it's the only
    place T1564.008 (email hiding rules) is representable."""
    source = get_registry()["m365_audit"]
    event = await source.generate_with_entities(ENTITIES, {"operation": "New-InboxRule"})
    data = json.loads(event.raw)
    assert data["Operation"] == "New-InboxRule"
    assert data["Workload"] == "Exchange"          # derived from the operation
    assert data["UserId"] == "jsmith@corp.local"
    assert data["MailboxOwnerUPN"] == "jsmith@corp.local"
    assert data["ClientIP"] == "203.0.113.9"
    # The rule itself must be inspectable, not just named.
    params = {p["Name"]: p["Value"] for p in data["Parameters"]}
    assert params["MoveToFolder"] == "Deleted Items"


@pytest.mark.asyncio
async def test_m365_audit_derives_sharepoint_workload_from_operation():
    source = get_registry()["m365_audit"]
    data = json.loads((await source.generate_with_entities(ENTITIES, {"operation": "FileDownloaded"})).raw)
    assert data["Workload"] == "SharePoint"
    assert data["SourceFileName"]


@pytest.mark.asyncio
async def test_sysmon_process_create_uses_entity_host_and_user():
    source = get_registry()["sysmon"]
    data = json.loads((await source.generate_with_entities(ENTITIES, {"event_id": 1})).raw)
    assert data["EventID"] == 1
    assert data["Computer"] == "WIN-TESTHOST"
    assert data["EventData"]["User"].endswith("jsmith")
    assert data["EventData"]["CommandLine"]


@pytest.mark.asyncio
async def test_sysmon_network_connect_uses_entity_ips():
    source = get_registry()["sysmon"]
    data = json.loads((await source.generate_with_entities(ENTITIES, {"event_id": 3})).raw)
    assert data["EventData"]["SourceIp"] == "10.10.5.5"
    assert data["EventData"]["DestinationIp"] == "203.0.113.9"


@pytest.mark.asyncio
async def test_gcp_audit_uses_entities_and_honors_unknown_method():
    source = get_registry()["gcp_audit"]
    data = json.loads((await source.generate_with_entities(
        ENTITIES, {"method_name": "storage.objects.get"})).raw)
    assert data["protoPayload"]["methodName"] == "storage.objects.get"
    assert data["protoPayload"]["authenticationInfo"]["principalEmail"] == "jsmith@corp.local"
    assert data["protoPayload"]["requestMetadata"]["callerIp"] == "203.0.113.9"

    # An unrecognized method must not be silently swapped for a different call.
    data = json.loads((await source.generate_with_entities(
        ENTITIES, {"method_name": "some.future.method"})).raw)
    assert data["protoPayload"]["methodName"] == "some.future.method"


@pytest.mark.asyncio
async def test_kubernetes_audit_exec_carries_command_and_entity():
    source = get_registry()["kubernetes_audit"]
    data = json.loads((await source.generate_with_entities(
        ENTITIES, {"verb": "create", "resource": "pods", "subresource": "exec"})).raw)
    assert data["verb"] == "create"
    assert data["objectRef"]["subresource"] == "exec"
    assert data["user"]["username"] == "jsmith@corp.local"
    assert data["sourceIPs"] == ["10.10.5.5"]
    # The command is the whole point of an exec audit record.
    assert data["requestObject"]["command"]


@pytest.mark.asyncio
async def test_globalprotect_uses_entities_in_raw_and_structured():
    source = get_registry()["globalprotect_vpn"]
    event = await source.generate_with_entities(ENTITIES, {"event": "gateway-auth"})
    assert event.structured["stage"] == "gateway-auth"
    assert event.structured["srcuser"] == "jsmith"
    assert event.structured["public_ip"] == "203.0.113.9"
    assert event.structured["machinename"] == "WIN-TESTHOST"
    # The CSV on the wire must carry them too, not just the parsed view.
    assert "jsmith" in event.raw and "203.0.113.9" in event.raw


@pytest.mark.asyncio
async def test_duo_mfa_fraud_result_uses_entities():
    """result=fraud is the push-fatigue tell -- a user reporting a push they
    didn't trigger."""
    source = get_registry()["duo_mfa"]
    data = json.loads((await source.generate_with_entities(ENTITIES, {"result": "fraud"})).raw)
    assert data["result"] == "fraud"
    assert data["reason"] == "user_marked_fraud"
    assert data["user"]["name"] == "jsmith@corp.local"
    assert data["access_device"]["ip"] == "203.0.113.9"


@pytest.mark.asyncio
async def test_duo_mfa_honors_application_override():
    source = get_registry()["duo_mfa"]
    data = json.loads((await source.generate_with_entities(
        ENTITIES, {"application": "GlobalProtect VPN"})).raw)
    assert data["application"]["name"] == "GlobalProtect VPN"


# ── network detection / windows depth / AWS depth packs ────────────────────

@pytest.mark.asyncio
async def test_zeek_uses_entity_ips():
    source = get_registry()["zeek"]
    data = json.loads((await source.generate_with_entities(ENTITIES, {"log_type": "conn"})).raw)
    assert data["_path"] == "conn"
    assert data["id.orig_h"] == "10.10.5.5"
    assert data["id.resp_h"] == "203.0.113.9"


@pytest.mark.asyncio
async def test_zeek_ssl_carries_ja3():
    """JA3 is why ssl.log matters -- the client fingerprint survives domain
    and certificate rotation."""
    source = get_registry()["zeek"]
    data = json.loads((await source.generate_with_entities(ENTITIES, {"log_type": "ssl"})).raw)
    assert data["ja3"] and data["server_name"]


@pytest.mark.asyncio
async def test_suricata_signature_id_implies_an_alert():
    """Naming a signature should be enough -- a caller shouldn't have to also
    say event_type=alert to get the alert they asked for."""
    source = get_registry()["suricata"]
    data = json.loads((await source.generate_with_entities(
        ENTITIES, {"signature_id": 2034647})).raw)
    assert data["event_type"] == "alert"
    assert data["alert"]["signature_id"] == 2034647
    assert "Log4j" in data["alert"]["signature"]
    assert data["src_ip"] == "10.10.5.5"
    assert data["dest_ip"] == "203.0.113.9"


@pytest.mark.asyncio
async def test_powershell_script_block_uses_entities_and_flags_suspicious():
    """4104 is raised to Warning (Level 3) when PowerShell's own heuristics
    flag the block -- the field most script-block detections key on."""
    source = get_registry()["windows_powershell"]
    data = json.loads((await source.generate_with_entities(
        ENTITIES, {"event_id": 4104, "suspicious": True})).raw)
    assert data["EventID"] == 4104
    assert data["Computer"] == "WIN-TESTHOST"
    assert data["Level"] == 3
    assert data["EventData"]["ScriptBlockText"]

    benign = json.loads((await source.generate_with_entities(
        ENTITIES, {"event_id": 4104, "suspicious": False})).raw)
    assert benign["Level"] == 4


@pytest.mark.asyncio
async def test_powershell_honors_explicit_script_override():
    source = get_registry()["windows_powershell"]
    script = "Invoke-Mimikatz -DumpCreds"
    data = json.loads((await source.generate_with_entities(
        ENTITIES, {"event_id": 4104, "script": script})).raw)
    assert data["EventData"]["ScriptBlockText"] == script


@pytest.mark.asyncio
async def test_amsi_detection_is_in_memory_not_a_file():
    """The point of the AMSI source: the detection has no file on disk, which
    is what distinguishes it from microsoft_defender's file-based events."""
    source = get_registry()["windows_amsi"]
    for _ in range(30):
        data = json.loads((await source.generate_with_entities(
            ENTITIES, {"event_id": 1116})).raw)
        if data["EventData"]["Detection Source"] == "AMSI":
            assert data["EventData"]["Path"].startswith("amsi:")
            assert data["EventData"]["Script Content"]
            assert data["Computer"] == "WIN-TESTHOST"
            return
    raise AssertionError("no AMSI-sourced detection produced in 30 attempts")


@pytest.mark.asyncio
async def test_amsi_honors_threat_and_content_overrides():
    source = get_registry()["windows_amsi"]
    data = json.loads((await source.generate_with_entities(ENTITIES, {
        "event_id": 1116,
        "threat_name": "HackTool:PowerShell/Mimikatz.A",
        "script_content": "Invoke-Mimikatz -DumpCreds",
    })).raw)
    assert data["EventData"]["Threat Name"] == "HackTool:PowerShell/Mimikatz.A"
    assert data["EventData"]["Script Content"] == "Invoke-Mimikatz -DumpCreds"


@pytest.mark.asyncio
async def test_guardduty_finding_uses_entities():
    source = get_registry()["aws_guardduty"]
    data = json.loads((await source.generate_with_entities(ENTITIES, {
        "finding_type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
    })).raw)
    assert data["type"] == "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"
    assert data["resource"]["accessKeyDetails"]["userName"] == "jsmith"
    assert data["service"]["action"]["awsApiCallAction"]["remoteIpDetails"]["ipAddressV4"] == "203.0.113.9"


@pytest.mark.asyncio
async def test_vpc_flow_uses_entity_ips_in_the_wire_line():
    source = get_registry()["aws_vpc_flow"]
    event = await source.generate_with_entities(ENTITIES, {"action": "REJECT", "dstport": 3389})
    # Positional format: the parsed view and the raw line must agree.
    assert event.structured["srcaddr"] == "10.10.5.5"
    assert event.structured["dstaddr"] == "203.0.113.9"
    assert event.structured["action"] == "REJECT"
    assert event.structured["dstport"] == "3389"
    fields = event.raw.split(" ")
    assert fields[3] == "10.10.5.5" and fields[4] == "203.0.113.9"
    assert fields[12] == "REJECT"


@pytest.mark.asyncio
async def test_vpc_flow_nodata_records_have_no_counters():
    """AWS emits '-' rather than 0 when an interface saw no traffic; a
    detection that assumes numeric counters breaks on these."""
    source = get_registry()["aws_vpc_flow"]
    for _ in range(200):
        event = await source.generate()
        if event.structured["log-status"] != "OK":
            assert event.structured["packets"] == "-"
            assert event.structured["bytes"] == "-"
            assert event.structured["packets_int"] is None
            return
    raise AssertionError("no NODATA/SKIPDATA record produced in 200 attempts")
