from __future__ import annotations

import json
import random
from datetime import datetime, timezone

from sources.base_source import LogEvent, LogSource, TransportName
from utils.faker_helpers import random_windows_host, weighted_choice

_EVENTS = {
    7036: {"provider": "Service Control Manager", "channel": "System",
           "msg": lambda: f"The {random.choice(['Windows Update','Print Spooler','DHCP Client','DNS Client','Windows Firewall','Background Intelligent Transfer Service'])} service entered the {random.choice(['running','stopped'])} state."},
    7040: {"provider": "Service Control Manager", "channel": "System",
           "msg": lambda: f"The start type of the {random.choice(['Windows Update','Background Intelligent Transfer Service'])} service was changed from {random.choice(['auto start','demand start'])} to {random.choice(['demand start','disabled'])}."},
    6005: {"provider": "EventLog", "channel": "System",
           "msg": lambda: "The Event log service was started."},
    6006: {"provider": "EventLog", "channel": "System",
           "msg": lambda: "The Event log service was stopped."},
    1074: {"provider": "USER32", "channel": "System",
           "msg": lambda: f"The process C:\\Windows\\system32\\winlogon.exe has initiated the {random.choice(['restart','shutdown'])} of computer {random_windows_host()} on behalf of user NT AUTHORITY\\SYSTEM for the following reason: {random.choice(['Operating System: Upgrade (Planned)','Application: Maintenance (Planned)'])}."},
}

WEIGHTS = [50, 10, 5, 2, 8]


class WindowsSystemSource(LogSource):
    id = "windows_system"
    display_name = "Windows System"
    description = "Windows System Event Log — service state changes, system start/stop"
    default_transport: TransportName = "wec"
    supported_transports = ["wec", "syslog"]
    default_eps = 1.0
    tags = ["windows", "system"]

    async def generate(self) -> LogEvent:
        event_id = weighted_choice(list(_EVENTS.keys()), WEIGHTS)
        meta = _EVENTS[event_id]
        host = random_windows_host()
        ts = datetime.now(timezone.utc).isoformat()

        structured = {
            "EventID": event_id,
            "TimeCreated": ts,
            "Channel": meta["channel"],
            "Computer": host,
            "Provider": meta["provider"],
            "Level": 4,
            "Task": 0,
            "Keywords": "0x8080000000000000",
            "EventRecordID": random.randint(1000, 999999),
            "ProcessID": random.randint(4, 9999),
            "ThreadID": random.randint(8, 500),
            "SecurityUserID": "S-1-5-18",
            "EventData": {"Message": meta["msg"]()},
            "Message": meta["msg"](),
        }

        return LogEvent(
            raw=json.dumps(structured),
            structured=structured,
            format="windows_evtx",
            source_id=self.id,
        )
