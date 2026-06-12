from __future__ import annotations

import json
import random
from datetime import datetime, timezone
from faker import Faker

from sources.base_source import LogEvent, LogSource, TransportName
from utils.faker_helpers import random_internal_ip, random_external_ip, random_port, random_well_known_port

fake = Faker()

_TYPES = ["flows", "urls", "ids-alerts", "events", "air_marshal"]
_TYPE_WEIGHTS = [40, 25, 10, 20, 5]
_DISPOSITIONS = ["allow", "block", "deny"]
_PROTOCOLS = ["tcp", "udp", "icmp"]
_IDS_SIGS = [
    "1:2001219:7 ET SCAN Potential VNC Scan",
    "1:2010935:3 ET MALWARE Zbot POST Request",
    "1:2013504:5 ET P2P BitTorrent DHT Node Announce",
    "1:2019714:2 ET SCAN Nmap Scripting Engine User-Agent",
    "1:2006380:9 ET SCAN Potential SSH Scan",
]


class CiscoMerakiSource(LogSource):
    id = "cisco_meraki"
    display_name = "Cisco Meraki"
    description = "Cisco Meraki — JSON-style syslog events (flows, URLs, IDS alerts)"
    default_transport: TransportName = "syslog"
    supported_transports = ["syslog"]
    default_eps = 5.0
    tags = ["network", "firewall", "cisco", "meraki"]

    async def generate(self) -> LogEvent:
        event_type = random.choices(_TYPES, weights=_TYPE_WEIGHTS)[0]
        ts = str(int(datetime.now(timezone.utc).timestamp())) + ".0"
        device = f"MX{random.randint(64,450)}"
        network_id = f"N_{random.randint(100000,999999)}"
        src_ip = random_internal_ip()
        dst_ip = random_external_ip()
        src_port = random_port()
        dst_port = random_well_known_port()
        proto = random.choice(_PROTOCOLS)

        if event_type == "flows":
            payload = {
                "type": "flows",
                "src": src_ip,
                "dst": dst_ip,
                "sport": src_port,
                "dport": dst_port,
                "protocol": proto,
                "disposition": random.choices(_DISPOSITIONS, weights=[80, 15, 5])[0],
            }
        elif event_type == "urls":
            url = f"https://{fake.domain_name()}/{fake.uri_path()}"
            payload = {
                "type": "urls",
                "src": src_ip,
                "dst": dst_ip,
                "request": f"GET {url} HTTP/1.1",
                "status": random.choice([200, 301, 302, 403, 404, 503]),
                "bytes": random.randint(100, 1000000),
            }
        elif event_type == "ids-alerts":
            sig = random.choice(_IDS_SIGS)
            payload = {
                "type": "ids-alerts",
                "src": src_ip,
                "dst": dst_ip,
                "dport": dst_port,
                "priority": random.randint(1, 3),
                "message": sig,
                "protocol": proto,
            }
        elif event_type == "air_marshal":
            payload = {
                "type": "air_marshal",
                "ssid": random.choice(["CorpWifi", "Guest", "IOT-Net", "EmployeeSSID"]),
                "bssid": ":".join(f"{random.randint(0,255):02x}" for _ in range(6)),
                "channels": [random.randint(1, 11)],
                "rssi": random.randint(-90, -30),
                "wired_macs": [],
            }
        else:
            payload = {
                "type": "events",
                "category": random.choice(["VPN", "Switch", "AP", "Security"]),
                "description": random.choice([
                    "VPN client connected", "Client disassociated",
                    "Client blocked", "Port enabled", "DHCP no offers",
                ]),
                "client_ip": src_ip,
            }

        raw = f"<{23 * 8 + 6}>{ts} {device} {network_id} {json.dumps(payload)}"

        return LogEvent(
            raw=raw,
            structured={
                "device": device,
                "network_id": network_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "vendor": "cisco",
                "product": "meraki",
                **payload,
            },
            format="syslog_meraki",
            source_id=self.id,
        )
