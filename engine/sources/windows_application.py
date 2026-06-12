from __future__ import annotations

import json
import random
from datetime import datetime, timezone

from sources.base_source import LogEvent, LogSource
from utils.faker_helpers import random_windows_host, weighted_choice

_APPS = ["MsiInstaller", "Application Error", ".NET Runtime", "VSS", "MSSQLSERVER", "IIS-W3SVC"]
_CRASH_FAULTS = ["c0000005", "c000001d", "80000003"]
_DOTNET_ERRORS = [
    "System.OutOfMemoryException",
    "System.NullReferenceException",
    "System.IO.IOException",
    "System.UnauthorizedAccessException",
]
_WEIGHTS = [30, 20, 15, 10, 15, 10]

_EVENT_IDS = {
    "MsiInstaller": [1033, 1034, 11707, 11708],
    "Application Error": [1000, 1001],
    ".NET Runtime": [1026, 1025],
    "VSS": [8193, 8194],
    "MSSQLSERVER": [17052, 18456],
    "IIS-W3SVC": [1001, 1003],
}


class WindowsApplicationSource(LogSource):
    id = "windows_application"
    display_name = "Windows Application"
    description = "Windows Application Event Log — MSI installs, crashes, .NET errors"
    default_transport: str = "wec"
    supported_transports = ["wec", "syslog"]
    default_eps = 1.0
    tags = ["windows", "application"]

    async def generate(self) -> LogEvent:
        app = weighted_choice(_APPS, _WEIGHTS)
        event_id = random.choice(_EVENT_IDS[app])
        host = random_windows_host()
        ts = datetime.now(timezone.utc).isoformat()

        if app == "Application Error":
            msg = f"Faulting application name: {random.choice(['chrome.exe','outlook.exe','excel.exe','svchost.exe'])}, faulting module: ntdll.dll, exception code: 0x{random.choice(_CRASH_FAULTS)}"
        elif app == ".NET Runtime":
            msg = f"Application: powershell.exe - {random.choice(_DOTNET_ERRORS)}: {random.choice(['at System.String.Concat','at System.IO.File.Open','at System.Net.Http.HttpClient.Send'])}"
        elif app == "MsiInstaller":
            product = random.choice(["Microsoft Visual C++ 2022", "Adobe Acrobat", "7-Zip 23.01", "Git 2.44"])
            msg = f"{'Installed' if event_id in (1033, 11707) else 'Removal'} product. Product: {product}. Version: {random.randint(1,20)}.{random.randint(0,9)}. Language: 1033."
        else:
            msg = f"{app} event {event_id} on {host}"

        structured = {
            "EventID": event_id,
            "TimeCreated": ts,
            "Channel": "Application",
            "Computer": host,
            "Provider": app,
            "Level": random.choice([2, 3, 4]),
            "Task": 0,
            "Keywords": "0x8080000000000000",
            "EventRecordID": random.randint(1000, 999999),
            "ProcessID": random.randint(4, 9999),
            "ThreadID": random.randint(8, 500),
            "SecurityUserID": "S-1-5-18",
            "EventData": {"Message": msg},
            "Message": msg,
        }

        return LogEvent(
            raw=json.dumps(structured),
            structured=structured,
            format="windows_evtx",
            source_id=self.id,
        )
