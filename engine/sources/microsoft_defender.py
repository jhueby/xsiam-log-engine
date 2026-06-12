from __future__ import annotations

import json
import random
import uuid
from datetime import datetime, timezone

from sources.base_source import LogEvent, LogSource
from utils.faker_helpers import random_windows_host, random_user, random_internal_ip, random_external_ip

_THREAT_NAMES = [
    "Trojan:Win32/Wacatac.B!ml",
    "HackTool:Win32/Mimikatz.A",
    "Ransom:Win32/WannaCrypt",
    "Trojan:Win32/AgentTesla.A!dha",
    "Exploit:Win32/CVE-2021-34527.A",
    "PUA:Win32/CoinMiner",
    "Behavior:Win32/RunPE.C",
    "VirTool:Win32/Obfuscator.XZ",
    "TrojanDownloader:Win32/Agent.V",
    "SuspiciousActivity:Win32/Injection.B!ml",
]

_SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"]
_SEV_WEIGHTS = [5, 20, 35, 25, 15]

_ACTIONS = ["Blocked", "Quarantined", "Removed", "Allowed", "CleanedUp"]
_ACTION_WEIGHTS = [30, 40, 15, 10, 5]

_CATEGORIES = [
    "Malware", "UnwantedSoftware", "Exploit", "RemoteAccess",
    "Ransomware", "CommandAndControl", "CredentialTheft",
]


class MicrosoftDefenderSource(LogSource):
    id = "microsoft_defender"
    display_name = "Microsoft Defender ATP"
    description = "Microsoft Defender — ATP alerts, quarantine, and detection events"
    default_transport: str = "wec"
    supported_transports = ["wec", "http"]
    default_eps = 1.0
    tags = ["windows", "edr", "endpoint", "antivirus"]

    async def generate(self) -> LogEvent:
        threat = random.choice(_THREAT_NAMES)
        severity = random.choices(_SEVERITIES, weights=_SEV_WEIGHTS)[0]
        action = random.choices(_ACTIONS, weights=_ACTION_WEIGHTS)[0]
        host = random_windows_host()
        user = random_user()
        category = random.choice(_CATEGORIES)
        ts = datetime.now(timezone.utc).isoformat()
        alert_id = str(uuid.uuid4()).upper()

        event_data = {
            "ThreatName": threat,
            "ThreatID": str(random.randint(100000, 999999)),
            "Severity": severity,
            "Category": category,
            "Action": action,
            "ActionSuccess": "true",
            "Path": f"C:\\Users\\{user}\\AppData\\Local\\Temp\\{random.randint(10000,99999)}.tmp",
            "SHA256": uuid.uuid4().hex * 2,
            "SHA1": uuid.uuid4().hex[:40],
            "ProcessID": str(random.randint(1000, 65535)),
            "ProcessName": f"C:\\Users\\{user}\\AppData\\Roaming\\{random.randint(10000,99999)}.exe",
            "UserName": user,
            "Domain": "CORP",
            "ComputerName": host,
            "IPAddress": random_internal_ip(),
            "AlertID": alert_id,
            "DetectionSource": random.choice(["WindowsDefenderAv", "WindowsDefenderAtp", "CloudProtection"]),
            "SignatureVersion": f"1.{random.randint(300,400)}.{random.randint(0,9999)}.0",
            "EngineVersion": f"1.{random.randint(18,20)}.{random.randint(10000,19999)}.0",
        }

        structured = {
            "EventID": 1116,
            "TimeCreated": ts,
            "Channel": "Microsoft-Windows-Windows Defender/Operational",
            "Computer": host,
            "Provider": "Microsoft-Windows-Windows Defender",
            "Level": 3 if severity in ("Critical", "High") else 4,
            "Task": 0,
            "Keywords": "0x8000000000000000",
            "EventRecordID": random.randint(1000, 9999999),
            "ProcessID": random.randint(1000, 5000),
            "ThreadID": random.randint(8, 500),
            "SecurityUserID": "S-1-5-18",
            "EventData": event_data,
            "Message": f"Microsoft Defender Antivirus has {action.lower()} {category.lower()}: {threat} on {host} for user {user}",
        }

        return LogEvent(
            raw=json.dumps(structured),
            structured=structured,
            format="windows_evtx",
            source_id=self.id,
        )
