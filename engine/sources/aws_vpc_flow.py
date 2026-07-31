from __future__ import annotations

import random
import uuid
from datetime import datetime, timezone

from sources.base_source import LogEvent, LogSource, ScenarioEntities, TransportName
from utils.faker_helpers import random_external_ip, random_internal_ip

# VPC Flow Logs are space-delimited positional records, not JSON. The v2
# default format below is the one most accounts actually emit; the field
# order is load-bearing, so it's declared once here and reused for both the
# wire line and the parsed view.
_V2_FIELDS = [
    "version", "account-id", "interface-id", "srcaddr", "dstaddr", "srcport",
    "dstport", "protocol", "packets", "bytes", "start", "end", "action", "log-status",
]

_ACCOUNT = "481516234211"

# IANA protocol numbers: 6=TCP, 17=UDP, 1=ICMP.
_PROTOCOLS = [6, 6, 6, 17, 17, 1]

_COMMON_PORTS = [22, 53, 80, 123, 389, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443]

# REJECT is the interesting minority -- scanning and blocked egress show up
# here, and a stream that is all ACCEPT gives detections nothing to find.
_ACTIONS = ["ACCEPT", "ACCEPT", "ACCEPT", "ACCEPT", "REJECT"]

# NODATA/SKIPDATA are real states: the interface was up but had no traffic in
# the window, or records were dropped. Detections that assume every record has
# byte counts break on them, so they belong in a realistic corpus.
_LOG_STATUS = ["OK"] * 24 + ["NODATA", "SKIPDATA"]


def _build(*, src: str, dst: str, srcport: int | None = None,
           dstport: int | None = None, action: str | None = None) -> tuple[str, dict]:
    now = datetime.now(timezone.utc)
    end = int(now.timestamp())
    start = end - random.randint(10, 600)
    protocol = random.choice(_PROTOCOLS)
    action = action or random.choice(_ACTIONS)
    log_status = random.choice(_LOG_STATUS)

    srcport = srcport if srcport is not None else random.randint(1024, 65535)
    dstport = dstport if dstport is not None else random.choice(_COMMON_PORTS)

    if log_status == "OK":
        packets = random.randint(1, 20000)
        # Rejected flows are almost always a single small probe packet.
        if action == "REJECT":
            packets = random.randint(1, 3)
        size = packets * random.randint(40, 1500)
    else:
        # No traffic observed: AWS emits '-' for the counters, not zero.
        packets = size = None

    interface = f"eni-{uuid.uuid4().hex[:17]}"
    values = [
        "2", _ACCOUNT, interface, src, dst, str(srcport), str(dstport), str(protocol),
        str(packets) if packets is not None else "-",
        str(size) if size is not None else "-",
        str(start), str(end), action, log_status,
    ]
    raw = " ".join(values)

    structured = dict(zip(_V2_FIELDS, values))
    structured.update({
        "vendor": "amazon",
        "product": "vpc_flow",
        "timestamp": now.isoformat(),
        # Numeric copies so downstream filters don't have to cast strings, with
        # None preserved where AWS reported no data rather than coercing to 0.
        "packets_int": packets,
        "bytes_int": size,
        "protocol_name": {6: "tcp", 17: "udp", 1: "icmp"}.get(protocol, str(protocol)),
    })
    return raw, structured


class AWSVPCFlowSource(LogSource):
    id = "aws_vpc_flow"
    display_name = "AWS VPC Flow Logs"
    description = "AWS VPC Flow Logs (v2 default format) — accepted and rejected flows with byte/packet counts"
    default_transport: TransportName = "http"
    supported_transports = ["http", "syslog"]
    default_eps = 20.0
    tags = ["cloud", "aws", "network", "flow"]

    async def generate(self) -> LogEvent:
        # Mostly east-west inside the VPC, with a slice of egress to the
        # internet — matching how a real subnet's flow mix looks.
        if random.random() < 0.6:
            src, dst = random_internal_ip(), random_internal_ip()
        else:
            src, dst = random_internal_ip(), random_external_ip()
        raw, structured = _build(src=src, dst=dst)
        return LogEvent(raw=raw, structured=structured, format="aws_vpc_flow", source_id=self.id)

    async def generate_with_entities(
        self, entities: ScenarioEntities, overrides: dict | None = None
    ) -> LogEvent:
        """Scenario mode: put the flow between the run's internal host and its
        external IP, so cloud network evidence corroborates the endpoint and
        API activity in the same story.

        Recognized overrides: src, dst, srcport, dstport, action.
        """
        overrides = overrides or {}
        # .get(key, default) -- not `or` -- so an explicit falsy override
        # (e.g. "") is honored instead of silently replaced by random data.
        raw, structured = _build(
            src=overrides.get("src", entities.internal_ip),
            dst=overrides.get("dst", entities.external_ip),
            srcport=overrides.get("srcport"),
            dstport=overrides.get("dstport"),
            action=overrides.get("action"),
        )
        return LogEvent(raw=raw, structured=structured, format="aws_vpc_flow", source_id=self.id)
