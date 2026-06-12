from __future__ import annotations

import json
import random
from datetime import datetime, timezone
from faker import Faker

from sources.base_source import LogEvent, LogSource
from utils.faker_helpers import random_internal_ip, random_windows_host

fake = Faker()

_QTYPES = ["A", "AAAA", "MX", "TXT", "CNAME", "PTR", "NS", "SOA", "SRV"]
_QTYPE_WEIGHTS = [50, 15, 8, 10, 8, 4, 2, 1, 2]
_RCODE_NAMES = {0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}
_RCODE_WEIGHTS = [85, 2, 10, 3]


class MicrosoftDNSSource(LogSource):
    id = "microsoft_dns"
    display_name = "Microsoft DNS Server"
    description = "Windows DNS Server ETW logs — queries and responses"
    default_transport: str = "wec"
    supported_transports = ["wec", "syslog"]
    default_eps = 10.0
    tags = ["windows", "dns", "network"]

    async def generate(self) -> LogEvent:
        client_ip = random_internal_ip()
        qname = random.choice([
            fake.domain_name(),
            f"_ldap._tcp.{random.choice(['corp.local','dc._msdcs.corp.local'])}",
            f"wpad.corp.local",
            fake.hostname(),
        ])
        qtype = random.choices(_QTYPES, weights=[50, 15, 8, 10, 8, 4, 2, 1, 2])[0]
        rcode_val = random.choices([0, 2, 3, 5], weights=_RCODE_WEIGHTS)[0]
        rcode = _RCODE_NAMES[rcode_val]
        ts = datetime.now(timezone.utc).isoformat()
        dns_server = random_windows_host()

        event_data = {
            "QNAME": qname,
            "QTYPE": qtype,
            "ClientIP": client_ip,
            "ServerIP": random_internal_ip(),
            "ResponseCode": str(rcode_val),
            "ResponseCodeName": rcode,
            "RecursionDesired": "1",
            "RecursionAvailable": "1",
            "DNSSEC": "0",
            "IsResponse": "1",
            "TransportProtocol": random.choice(["UDP", "TCP"]),
            "InterfaceIP": random_internal_ip(),
        }

        structured = {
            "EventID": 257,
            "TimeCreated": ts,
            "Channel": "Microsoft-Windows-DNSServer/Analytical",
            "Computer": dns_server,
            "Provider": "Microsoft-Windows-DNS-Server",
            "Level": 5,
            "Task": 0,
            "Keywords": "0x0000000000000001",
            "EventRecordID": random.randint(1000, 9999999),
            "ProcessID": random.randint(1000, 5000),
            "ThreadID": random.randint(8, 500),
            "SecurityUserID": "S-1-5-18",
            "EventData": event_data,
            "Message": f"DNS query for {qname} ({qtype}) from {client_ip} returned {rcode}",
        }

        return LogEvent(
            raw=json.dumps(structured),
            structured=structured,
            format="windows_evtx",
            source_id=self.id,
        )
