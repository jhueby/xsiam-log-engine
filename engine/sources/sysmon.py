from __future__ import annotations

import hashlib
import json
import random
import uuid
from datetime import datetime, timezone

from sources.base_source import LogEvent, LogSource, ScenarioEntities, TransportName
from utils.faker_helpers import (
    DOMAIN,
    random_external_ip,
    random_internal_ip,
    random_process_windows,
    random_user,
    random_windows_host,
    weighted_choice,
)

# Sysmon event IDs. Weighted toward process creation and network connections,
# which is roughly what a real endpoint produces and what most detection
# content keys on.
EVENT_IDS = [1, 3, 7, 8, 10, 11, 12, 13, 22, 23]
EVENT_WEIGHTS = [35, 25, 8, 2, 4, 12, 3, 5, 5, 1]

_EVENT_META = {
    1: ("Process Create (rule: ProcessCreate)", "ProcessCreate"),
    3: ("Network connection detected (rule: NetworkConnect)", "NetworkConnect"),
    7: ("Image loaded (rule: ImageLoad)", "ImageLoad"),
    8: ("CreateRemoteThread detected (rule: CreateRemoteThread)", "CreateRemoteThread"),
    10: ("Process accessed (rule: ProcessAccess)", "ProcessAccess"),
    11: ("File created (rule: FileCreate)", "FileCreate"),
    12: ("Registry object added or deleted (rule: RegistryEvent)", "RegistryEvent"),
    13: ("Registry value set (rule: RegistryEvent)", "RegistryEvent"),
    22: ("Dns query (rule: DnsQuery)", "DnsQuery"),
    23: ("File Delete archived (rule: FileDelete)", "FileDelete"),
}

_PARENTS = [
    r"C:\Windows\explorer.exe",
    r"C:\Windows\System32\services.exe",
    r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Windows\System32\svchost.exe",
]

_CMDLINES = [
    'powershell.exe -NoP -W Hidden -Enc {b64}',
    'cmd.exe /c whoami /all',
    'rundll32.exe C:\\Windows\\System32\\comsvcs.dll,MiniDump 624 C:\\Windows\\Temp\\l.dmp full',
    'net.exe group "Domain Admins" /domain',
    'wmic.exe process call create "cmd.exe /c tasklist"',
    'reg.exe query HKLM\\SAM /s',
]

_DOMAINS = [
    "login.microsoftonline.com", "graph.microsoft.com", "outlook.office365.com",
    "cdn.jsdelivr.net", "raw.githubusercontent.com", "api.telegram.org",
    "pastebin.com", "corp-sso-verify.example.net",
]

_REG_KEYS = [
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SYSTEM\CurrentControlSet\Services",
]

_FILE_PATHS = [
    r"C:\Users\{user}\AppData\Local\Temp\{name}",
    r"C:\ProgramData\{name}",
    r"C:\Windows\Temp\{name}",
]
_FILE_NAMES = ["update.exe", "payload.dll", "notes.lnk", "install.tmp", "cred.dmp"]


def _hashes(seed: str) -> str:
    """Sysmon emits several digests in one delimited string. Derived from a
    seed so the same image path hashes consistently within an event."""
    md5 = hashlib.md5(seed.encode()).hexdigest().upper()
    sha256 = hashlib.sha256(seed.encode()).hexdigest().upper()
    return f"MD5={md5},SHA256={sha256}"


def _build(*, event_id: int, host: str, user: str, src_ip: str, dst_ip: str) -> dict:
    now = datetime.now(timezone.utc)
    domain = DOMAIN.split(".")[0].upper()
    message, rule_name = _EVENT_META[event_id]
    image = f"C:\\Windows\\System32\\{random_process_windows()}"
    data: dict = {
        "RuleName": rule_name,
        "UtcTime": now.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "ProcessGuid": f"{{{uuid.uuid4()}}}",
        "ProcessId": random.randint(400, 30000),
        "Image": image,
        "User": f"{domain}\\{user}",
    }

    if event_id == 1:
        cmd = random.choice(_CMDLINES).replace("{b64}", "SQBFAFgAIABbAFMAeQBz")
        parent = random.choice(_PARENTS)
        data.update({
            "FileVersion": "10.0.19041.1",
            "Description": "Windows Command Processor",
            "Product": "Microsoft Windows Operating System",
            "Company": "Microsoft Corporation",
            "OriginalFileName": image.rsplit("\\", 1)[-1],
            "CommandLine": cmd,
            "CurrentDirectory": f"C:\\Users\\{user}\\",
            "LogonGuid": f"{{{uuid.uuid4()}}}",
            "LogonId": f"0x{random.randint(0, 0xFFFFFF):x}",
            "TerminalSessionId": random.randint(0, 3),
            "IntegrityLevel": random.choice(["Medium", "High", "System"]),
            "Hashes": _hashes(image + cmd),
            "ParentProcessGuid": f"{{{uuid.uuid4()}}}",
            "ParentProcessId": random.randint(400, 30000),
            "ParentImage": parent,
            "ParentCommandLine": parent,
        })
    elif event_id == 3:
        data.update({
            "Protocol": random.choice(["tcp", "udp"]),
            "Initiated": True,
            "SourceIsIpv6": False,
            "SourceIp": src_ip,
            "SourceHostname": host,
            "SourcePort": random.randint(49152, 65535),
            "DestinationIsIpv6": False,
            "DestinationIp": dst_ip,
            "DestinationHostname": random.choice(_DOMAINS),
            "DestinationPort": random.choice([80, 443, 445, 3389, 8080, 53]),
        })
    elif event_id in (7, 8, 10):
        target = f"C:\\Windows\\System32\\{random_process_windows()}"
        data.update({
            "ImageLoaded" if event_id == 7 else "TargetImage": target,
            "Hashes": _hashes(target),
            "Signed": random.random() < 0.8,
            "Signature": random.choice(["Microsoft Windows", "Microsoft Corporation", "-"]),
            "SignatureStatus": random.choice(["Valid", "Unavailable"]),
        })
        if event_id in (8, 10):
            data["GrantedAccess"] = random.choice(["0x1010", "0x1410", "0x143a", "0x1fffff"])
            data["CallTrace"] = "C:\\Windows\\SYSTEM32\\ntdll.dll+9d234|C:\\Windows\\System32\\KERNELBASE.dll+38f3"
    elif event_id in (11, 23):
        path = random.choice(_FILE_PATHS).format(user=user, name=random.choice(_FILE_NAMES))
        data.update({"TargetFilename": path, "CreationUtcTime": data["UtcTime"]})
        if event_id == 23:
            data["Hashes"] = _hashes(path)
            data["IsExecutable"] = path.endswith((".exe", ".dll"))
    elif event_id in (12, 13):
        key = random.choice(_REG_KEYS)
        data.update({
            "EventType": "SetValue" if event_id == 13 else random.choice(["CreateKey", "DeleteKey"]),
            "TargetObject": f"{key}\\{random.choice(['Updater', 'OneDriveSync', 'SecurityHealth'])}",
        })
        if event_id == 13:
            data["Details"] = f"C:\\Users\\{user}\\AppData\\Local\\Temp\\{random.choice(_FILE_NAMES)}"
    elif event_id == 22:
        data.update({
            "QueryName": random.choice(_DOMAINS),
            "QueryStatus": random.choice(["0", "0", "0", "9003"]),
            "QueryResults": f"type:  5 {random.choice(_DOMAINS)};::ffff:{dst_ip};",
        })

    return {
        "EventID": event_id,
        "TimeCreated": now.isoformat(),
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Computer": host,
        "Provider": "Microsoft-Windows-Sysmon",
        "ProviderGuid": "5770385F-C22A-43E0-BF4C-06F5698FFBD9",
        "Level": 4,
        "Task": event_id,
        "Opcode": 0,
        "Keywords": "0x8000000000000000",
        "EventRecordID": random.randint(100000, 9999999),
        "ProcessID": 3120,
        "ThreadID": random.randint(8, 4000),
        "SecurityUserID": "S-1-5-18",
        "EventData": data,
        "Message": message,
    }


class SysmonSource(LogSource):
    id = "sysmon"
    display_name = "Sysmon"
    description = "Sysinternals Sysmon — process creation, network connections, DNS queries, registry and file events"
    default_transport: TransportName = "wec"
    supported_transports = ["wec", "syslog"]
    default_eps = 8.0
    tags = ["windows", "endpoint", "sysmon", "process"]

    async def generate(self) -> LogEvent:
        event = _build(
            event_id=weighted_choice(EVENT_IDS, EVENT_WEIGHTS),
            host=random_windows_host(),
            user=random_user(),
            src_ip=random_internal_ip(),
            dst_ip=random_external_ip(),
        )
        return LogEvent(raw=json.dumps(event), structured=event, format="windows_evtx", source_id=self.id)

    async def generate_with_entities(
        self, entities: ScenarioEntities, overrides: dict | None = None
    ) -> LogEvent:
        """Scenario mode: pin endpoint telemetry to the run's host/user so
        process and network activity ties back to the same story the identity
        and email sources are telling.

        Recognized overrides: event_id, src_ip, dst_ip.
        """
        overrides = overrides or {}
        # .get(key, default) -- not `or` -- so an explicit falsy override
        # (e.g. "") is honored instead of silently replaced by random data.
        event = _build(
            event_id=int(overrides.get("event_id", weighted_choice(EVENT_IDS, EVENT_WEIGHTS))),
            host=entities.host,
            user=entities.username,
            src_ip=overrides.get("src_ip", entities.internal_ip),
            dst_ip=overrides.get("dst_ip", entities.external_ip),
        )
        return LogEvent(raw=json.dumps(event), structured=event, format="windows_evtx", source_id=self.id)
