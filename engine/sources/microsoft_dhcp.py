from __future__ import annotations

import json
import random
from datetime import datetime, timezone
from faker import Faker

from sources.base_source import LogEvent, LogSource
from utils.faker_helpers import random_internal_ip, random_windows_host

fake = Faker()

_DHCP_EVENTS = {
    10: "Assign",
    11: "Renew",
    12: "Release",
    13: "DNSUpdateRequest",
    14: "DNSUpdateFailed",
    15: "DNSUpdateSuccess",
    16: "Lease Expired",
    17: "Lease Deleted",
    20: "NACK",
    24: "IP Address State Change",
}


class MicrosoftDHCPSource(LogSource):
    id = "microsoft_dhcp"
    display_name = "Microsoft DHCP Server"
    description = "Windows DHCP Server lease events"
    default_transport: str = "wec"
    supported_transports = ["wec", "syslog"]
    default_eps = 2.0
    tags = ["windows", "dhcp", "network"]

    async def generate(self) -> LogEvent:
        event_id = random.choices(
            list(_DHCP_EVENTS.keys()),
            weights=[40, 30, 5, 5, 2, 3, 3, 2, 5, 5],
        )[0]
        client_ip = random_internal_ip()
        mac = ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))
        hostname = fake.hostname().split(".")[0].upper()
        ts = datetime.now(timezone.utc).isoformat()
        server = random_windows_host()

        event_data = {
            "EventID": str(event_id),
            "Date": ts.split("T")[0],
            "Time": ts.split("T")[1][:8],
            "Description": _DHCP_EVENTS[event_id],
            "IPAddress": client_ip,
            "HostName": hostname,
            "MACAddress": mac,
            "UserName": "",
            "TransactionID": f"0x{random.randint(0, 0xFFFFFFFF):08x}",
            "QResult": "0",
            "ProbationTime": "",
            "CorrelationID": "",
            "DnsRegError": "0",
            "ScopeAddress": ".".join(client_ip.split(".")[:3]) + ".0",
        }

        structured = {
            "EventID": 1000 + event_id,
            "TimeCreated": ts,
            "Channel": "Microsoft-Windows-DHCP-Server/Operational",
            "Computer": server,
            "Provider": "Microsoft-Windows-DHCP-Server",
            "Level": 4,
            "Task": 0,
            "Keywords": "0x0000000000000004",
            "EventRecordID": random.randint(1000, 9999999),
            "ProcessID": random.randint(1000, 5000),
            "ThreadID": random.randint(8, 500),
            "SecurityUserID": "S-1-5-18",
            "EventData": event_data,
            "Message": f"DHCP {_DHCP_EVENTS[event_id]}: IP={client_ip} Host={hostname} MAC={mac}",
        }

        return LogEvent(
            raw=json.dumps(structured),
            structured=structured,
            format="windows_evtx",
            source_id=self.id,
        )
