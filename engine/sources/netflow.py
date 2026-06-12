from __future__ import annotations

import random
from datetime import datetime, timezone

from sources.base_source import LogEvent, LogSource
from utils.faker_helpers import random_internal_ip, random_external_ip, random_port, random_network_device

_PROTOCOLS = {6: "TCP", 17: "UDP", 1: "ICMP", 47: "GRE", 50: "ESP"}
_PROTO_WEIGHTS = [55, 30, 8, 4, 3]
_DIRECTIONS = ["ingress", "egress"]


class NetFlowSource(LogSource):
    id = "netflow"
    display_name = "NetFlow v5/v9"
    description = "NetFlow v5/v9 records wrapped in syslog format"
    default_transport: str = "syslog"
    supported_transports = ["syslog"]
    default_eps = 50.0
    tags = ["network", "netflow", "flow"]

    async def generate(self) -> LogEvent:
        proto_num = random.choices(list(_PROTOCOLS.keys()), weights=_PROTO_WEIGHTS)[0]
        proto_name = _PROTOCOLS[proto_num]
        src_ip = random.choice([random_internal_ip(), random_external_ip()])
        dst_ip = random.choice([random_internal_ip(), random_external_ip()])
        src_port = random_port() if proto_num in (6, 17) else 0
        dst_port = random_port() if proto_num in (6, 17) else 0
        bytes_count = random.randint(40, 1500000)
        pkts = random.randint(1, 10000)
        duration = random.randint(1, 3600)
        direction = random.choice(_DIRECTIONS)
        device = random_network_device()
        now = datetime.now(timezone.utc)

        # NetFlow v9 syslog-wrapped format
        raw = (f"<{23 * 8 + 6}>{now.strftime('%b %d %H:%M:%S')} {device} NetFlow: "
               f"srcaddr={src_ip} dstaddr={dst_ip} "
               f"srcport={src_port} dstport={dst_port} "
               f"prot={proto_num} tos=0 "
               f"pkts={pkts} bytes={bytes_count} "
               f"first={int(now.timestamp() - duration)}.000 last={int(now.timestamp())}.000 "
               f"flags={random.choice(['0x10', '0x18', '0x02', '0x00'])} "
               f"input={random.randint(1, 48)} output={random.randint(1, 48)} "
               f"router={device} direction={direction}")

        structured = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto_num,
            "protocol_name": proto_name,
            "bytes": bytes_count,
            "packets": pkts,
            "duration_seconds": duration,
            "direction": direction,
            "device": device,
            "timestamp": now.isoformat(),
            "vendor": "generic",
            "product": "netflow",
        }

        return LogEvent(
            raw=raw,
            structured=structured,
            format="syslog_netflow",
            source_id=self.id,
        )
