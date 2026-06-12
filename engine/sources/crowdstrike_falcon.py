from __future__ import annotations

import json
import random
import uuid
from datetime import datetime, timezone

from sources.base_source import LogEvent, LogSource
from utils.faker_helpers import (
    random_windows_host, random_linux_host, random_user,
    random_internal_ip, random_external_ip, random_port,
    PROCESSES_WINDOWS,
)

_EVENT_TYPES = ["Detection", "ProcessRollup2", "NetworkConnect", "DnsRequest", "UserLogon"]
_TYPE_WEIGHTS = [15, 35, 25, 15, 10]

_TACTICS = ["Execution", "Persistence", "PrivilegeEscalation", "DefenseEvasion",
            "CredentialAccess", "Discovery", "LateralMovement", "Collection",
            "CommandAndControl", "Exfiltration", "Impact"]

_TECHNIQUES = {
    "Execution": ["T1059.001", "T1059.003", "T1204.002"],
    "Persistence": ["T1053.005", "T1078", "T1136.001"],
    "PrivilegeEscalation": ["T1055", "T1068", "T1134"],
    "DefenseEvasion": ["T1055", "T1070.004", "T1218.011"],
    "CredentialAccess": ["T1003.001", "T1110.003", "T1558.003"],
    "Discovery": ["T1082", "T1087.001", "T1069.002"],
    "LateralMovement": ["T1021.001", "T1021.002", "T1550.002"],
    "Collection": ["T1005", "T1074.001"],
    "CommandAndControl": ["T1071.001", "T1095", "T1105"],
    "Exfiltration": ["T1048", "T1041"],
    "Impact": ["T1486", "T1490"],
}

_SEVERITIES = ["Low", "Medium", "High", "Critical"]
_SEV_WEIGHTS = [20, 40, 30, 10]


def _detection() -> dict:
    tactic = random.choice(_TACTICS)
    technique = random.choice(_TECHNIQUES[tactic])
    severity = random.choices(_SEVERITIES, weights=_SEV_WEIGHTS)[0]
    host = random_windows_host()
    user = random_user()
    proc = random.choice(PROCESSES_WINDOWS)

    return {
        "EventType": "Detection",
        "DetectionId": f"ldt:{uuid.uuid4().hex[:16]}:{random.randint(10000,99999)}",
        "Severity": severity,
        "SeverityName": severity,
        "Tactic": tactic,
        "Technique": technique,
        "ComputerName": host,
        "UserName": f"CORP\\{user}",
        "LocalIP": random_internal_ip(),
        "FileName": proc,
        "FilePath": f"C:\\Windows\\System32\\{proc}",
        "CommandLine": f"{proc} /c whoami",
        "ParentImageFileName": "C:\\Windows\\System32\\svchost.exe",
        "SHA256HashData": uuid.uuid4().hex * 2,
        "MD5HashData": uuid.uuid4().hex,
        "DetectDescription": f"Potential {tactic} behavior detected",
        "PatternDispositionDescription": random.choice([
            "Prevention", "Detection", "Indeterminate"
        ]),
        "FalconHostLink": f"https://falcon.crowdstrike.com/activity/detections/detail/en-US/{uuid.uuid4().hex}",
    }


def _process_rollup2() -> dict:
    host = random_windows_host()
    user = random_user()
    proc = random.choice(PROCESSES_WINDOWS)
    parent = random.choice(PROCESSES_WINDOWS)
    return {
        "EventType": "ProcessRollup2",
        "ComputerName": host,
        "UserName": f"CORP\\{user}",
        "CommandLine": f"C:\\Windows\\System32\\{proc} -k LocalSystemNetworkRestricted",
        "FileName": proc,
        "ImageFileName": f"\\Device\\HarddiskVolume3\\Windows\\System32\\{proc}",
        "ParentImageFileName": f"C:\\Windows\\System32\\{parent}",
        "ParentCommandLine": f"C:\\Windows\\System32\\{parent}",
        "ProcessId": random.randint(100, 65535),
        "ParentProcessId": random.randint(4, 9999),
        "SHA256HashData": uuid.uuid4().hex * 2,
        "MD5HashData": uuid.uuid4().hex,
        "TargetProcessId": random.randint(100, 65535),
        "IntegrityLevel": random.choice(["Low", "Medium", "High", "System"]),
    }


def _network_connect() -> dict:
    host = random_windows_host()
    proc = random.choice(PROCESSES_WINDOWS)
    return {
        "EventType": "NetworkConnect",
        "ComputerName": host,
        "LocalAddressIP4": random_internal_ip(),
        "LocalPort": random_port(),
        "RemoteAddressIP4": random_external_ip(),
        "RemotePort": random.choice([80, 443, 8080, 8443, 4444, 1337]),
        "Protocol": random.choice(["TCP", "UDP"]),
        "ImageFileName": f"C:\\Windows\\System32\\{proc}",
        "ProcessId": random.randint(100, 65535),
        "ConnectionDirection": random.choice(["Outbound", "Inbound"]),
    }


def _dns_request() -> dict:
    from faker import Faker
    f = Faker()
    host = random_windows_host()
    proc = random.choice(PROCESSES_WINDOWS)
    return {
        "EventType": "DnsRequest",
        "ComputerName": host,
        "DomainName": f.domain_name(),
        "RequestType": random.choice(["A", "AAAA", "MX", "TXT"]),
        "InterfaceIndex": random.randint(1, 10),
        "ImageFileName": f"C:\\Windows\\System32\\{proc}",
        "ProcessId": random.randint(100, 65535),
    }


def _user_logon() -> dict:
    host = random_windows_host()
    user = random_user()
    return {
        "EventType": "UserLogon",
        "ComputerName": host,
        "UserName": f"CORP\\{user}",
        "UserSid": f"S-1-5-21-{random.randint(1000000,9999999)}-{random.randint(1000,9999)}",
        "LogonType": random.choice([2, 3, 10]),
        "RemoteIP": random_internal_ip(),
        "AuthenticationPackage": random.choice(["NTLM", "Kerberos", "Negotiate"]),
    }


_GENERATORS = {
    "Detection": _detection,
    "ProcessRollup2": _process_rollup2,
    "NetworkConnect": _network_connect,
    "DnsRequest": _dns_request,
    "UserLogon": _user_logon,
}


class CrowdStrikeFalconSource(LogSource):
    id = "crowdstrike_falcon"
    display_name = "CrowdStrike Falcon"
    description = "CrowdStrike Falcon EDR — Detection, ProcessRollup2, NetworkConnect events (JSON)"
    default_transport: str = "http"
    supported_transports = ["http"]
    default_eps = 3.0
    tags = ["edr", "endpoint", "windows", "crowdstrike"]

    async def generate(self) -> LogEvent:
        event_type = random.choices(_EVENT_TYPES, weights=_TYPE_WEIGHTS)[0]
        event = _GENERATORS[event_type]()
        event["timestamp"] = datetime.now(timezone.utc).isoformat()
        event["cid"] = uuid.uuid4().hex
        event["aid"] = uuid.uuid4().hex

        return LogEvent(
            raw=json.dumps(event),
            structured=event,
            format="json",
            source_id=self.id,
        )
