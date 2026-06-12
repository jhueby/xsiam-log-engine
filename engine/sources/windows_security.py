from __future__ import annotations

import json
import random
import uuid
from datetime import datetime, timezone

from sources.base_source import LogEvent, LogSource
from utils.faker_helpers import (
    DOMAIN,
    random_internal_ip,
    random_windows_host,
    random_user,
    weighted_choice,
)

EVENT_IDS = [4624, 4625, 4634, 4648, 4663, 4688, 4698, 4720, 4732, 4768, 4769, 4776]
EVENT_WEIGHTS = [40, 8, 20, 5, 5, 8, 2, 1, 1, 5, 4, 1]

LOGON_TYPES = {2: "Interactive", 3: "Network", 4: "Batch", 5: "Service", 7: "Unlock", 10: "RemoteInteractive"}
LOGON_TYPE_WEIGHTS = [5, 60, 5, 10, 5, 15]

_EVENT_META = {
    4624: {"desc": "An account was successfully logged on", "level": 0, "task": 12544, "keywords": "0x8020000000000000"},
    4625: {"desc": "An account failed to log on", "level": 0, "task": 12544, "keywords": "0x8010000000000000"},
    4634: {"desc": "An account was logged off", "level": 0, "task": 12545, "keywords": "0x8020000000000000"},
    4648: {"desc": "A logon was attempted using explicit credentials", "level": 0, "task": 12544, "keywords": "0x8020000000000000"},
    4663: {"desc": "An attempt was made to access an object", "level": 0, "task": 12800, "keywords": "0x8020000000000000"},
    4688: {"desc": "A new process has been created", "level": 0, "task": 13312, "keywords": "0x8020000000000000"},
    4698: {"desc": "A scheduled task was created", "level": 0, "task": 12804, "keywords": "0x8020000000000000"},
    4720: {"desc": "A user account was created", "level": 0, "task": 13824, "keywords": "0x8020000000000000"},
    4732: {"desc": "A member was added to a security-enabled local group", "level": 0, "task": 13826, "keywords": "0x8020000000000000"},
    4768: {"desc": "A Kerberos authentication ticket (TGT) was requested", "level": 0, "task": 14339, "keywords": "0x8020000000000000"},
    4769: {"desc": "A Kerberos service ticket was requested", "level": 0, "task": 14337, "keywords": "0x8020000000000000"},
    4776: {"desc": "The computer attempted to validate the credentials for an account", "level": 0, "task": 14336, "keywords": "0x8020000000000000"},
}

PROCESSES = ["svchost.exe", "lsass.exe", "explorer.exe", "powershell.exe", "cmd.exe",
             "wscript.exe", "msiexec.exe", "rundll32.exe", "regsvr32.exe", "taskhostw.exe"]
STATUS_CODES = ["0x0", "0xC000006D", "0xC0000064", "0xC000006A", "0xC0000234"]


class WindowsSecuritySource(LogSource):
    id = "windows_security"
    display_name = "Windows Security"
    description = "Windows Security Event Log — logon, process, object access, account management"
    default_transport: str = "wec"
    supported_transports = ["wec", "syslog"]
    default_eps = 5.0
    tags = ["windows", "authentication", "endpoint"]

    async def generate(self) -> LogEvent:
        event_id = weighted_choice(EVENT_IDS, EVENT_WEIGHTS)
        host = random_windows_host()
        user = random_user()
        domain = DOMAIN.split(".")[0].upper()
        ts = datetime.now(timezone.utc).isoformat()
        record_id = random.randint(100000, 9999999)

        meta = _EVENT_META[event_id]
        event_data: dict = {}

        if event_id in (4624, 4625):
            logon_type = weighted_choice(list(LOGON_TYPES.keys()), LOGON_TYPE_WEIGHTS)
            event_data = {
                "SubjectUserSid": "S-1-5-18",
                "SubjectUserName": "SYSTEM" if event_id == 4624 else user,
                "SubjectDomainName": domain,
                "SubjectLogonId": f"0x{random.randint(0, 0xFFFFFF):x}",
                "TargetUserSid": f"S-1-5-21-{random.randint(1000000,9999999)}-{random.randint(1000000,9999999)}-{random.randint(1000000,9999999)}-{random.randint(1000,9999)}",
                "TargetUserName": user,
                "TargetDomainName": domain,
                "TargetLogonId": f"0x{random.randint(0, 0xFFFFFF):x}",
                "LogonType": str(logon_type),
                "LogonProcessName": "NtLmSsp" if logon_type == 3 else "User32",
                "AuthenticationPackageName": "NTLM",
                "WorkstationName": random_windows_host(),
                "LogonGuid": f"{{{str(uuid.uuid4()).upper()}}}",
                "TransmittedServices": "-",
                "LmPackageName": "-",
                "KeyLength": "128",
                "ProcessId": f"0x{random.randint(0, 0xFFFF):x}",
                "ProcessName": r"C:\Windows\System32\winlogon.exe",
                "IpAddress": random_internal_ip(),
                "IpPort": str(random.randint(1024, 65535)),
            }
            if event_id == 4625:
                event_data["Status"] = random.choice(STATUS_CODES[1:])
                event_data["SubStatus"] = random.choice(STATUS_CODES[1:])
                event_data["FailureReason"] = "%%2313"

        elif event_id == 4688:
            event_data = {
                "SubjectUserSid": f"S-1-5-21-{random.randint(1000000,9999999)}-500",
                "SubjectUserName": user,
                "SubjectDomainName": domain,
                "SubjectLogonId": f"0x{random.randint(0, 0xFFFFFF):x}",
                "NewProcessId": f"0x{random.randint(0x100, 0xFFFF):x}",
                "NewProcessName": "C:\\Windows\\System32\\" + random.choice(PROCESSES),
                "TokenElevationType": "%%1936",
                "ProcessId": f"0x{random.randint(0x100, 0xFFFF):x}",
                "CommandLine": f"{random.choice(PROCESSES)} /k",
                "TargetUserSid": "S-1-0-0",
                "TargetUserName": "-",
                "TargetDomainName": "-",
                "TargetLogonId": "0x0",
                "ParentProcessName": r"C:\Windows\System32\svchost.exe",
                "MandatoryLabel": "S-1-16-12288",
            }
        elif event_id == 4768:
            event_data = {
                "TargetUserName": user,
                "TargetDomainName": domain,
                "TargetSid": f"S-1-5-21-{random.randint(1000000,9999999)}-1001",
                "ServiceName": "krbtgt",
                "ServiceSid": "S-1-5-21-{random.randint(1000000,9999999)}-502",
                "TicketOptions": "0x40810010",
                "Status": "0x0",
                "TicketEncryptionType": "0x12",
                "PreAuthType": "15",
                "IpAddress": f"::{random_internal_ip()}",
                "IpPort": str(random.randint(1024, 65535)),
                "CertIssuerName": "",
                "CertSerialNumber": "",
                "CertThumbprint": "",
            }
        else:
            event_data = {
                "SubjectUserName": user,
                "SubjectDomainName": domain,
                "SubjectLogonId": f"0x{random.randint(0, 0xFFFFFF):x}",
            }

        structured = {
            "EventID": event_id,
            "TimeCreated": ts,
            "Channel": "Security",
            "Computer": host,
            "Provider": "Microsoft-Windows-Security-Auditing",
            "ProviderGuid": "54849625-5478-4994-A5BA-3E3B0328C30D",
            "Level": meta["level"],
            "Task": meta["task"],
            "Keywords": meta["keywords"],
            "EventRecordID": record_id,
            "ProcessID": 4,
            "ThreadID": random.randint(8, 1000),
            "SecurityUserID": "S-1-5-18",
            "EventData": event_data,
            "Message": meta["desc"],
        }

        return LogEvent(
            raw=json.dumps(structured),
            structured=structured,
            format="windows_evtx",
            source_id=self.id,
        )
