from __future__ import annotations

import random
from datetime import datetime, timezone

from sources.base_source import LogEvent, LogSource
from utils.faker_helpers import (
    random_internal_ip,
    random_external_ip,
    random_port,
    random_well_known_port,
    random_network_device,
    weighted_choice,
)

_PROTOCOLS = ["tcp", "udp", "icmp"]
_PROTO_WEIGHTS = [60, 30, 10]
_INTERFACES_IN = ["outside", "dmz", "vpn"]
_INTERFACES_OUT = ["inside", "dmz"]

_MESSAGES = {
    106023: lambda h, p: _deny_msg(h, p),
    302013: lambda h, p: _build_msg(302013, h, p),
    302015: lambda h, p: _build_msg(302015, h, p),
    106001: lambda h, p: _inbound_deny(h, p),
    710003: lambda h, p: _tcp_request(h, p),
}
_MSG_WEIGHTS = [30, 30, 20, 10, 10]


def _deny_msg(host: str, _: str) -> str:
    proto = random.choice(_PROTOCOLS)
    src = random_external_ip()
    dst = random_internal_ip()
    sport = random_port()
    dport = random_well_known_port()
    iface = random.choice(_INTERFACES_IN)
    return (f"%ASA-4-106023: Deny {proto} src {iface}:{src}/{sport} "
            f"dst inside:{dst}/{dport} by access-group \"OUTSIDE_IN\" [{host}]")


def _build_msg(eid: int, host: str, _: str) -> str:
    proto = "TCP" if eid == 302013 else "UDP"
    action = "Built" if eid in (302013, 302015) else "Teardown"
    src = random_external_ip()
    dst = random_internal_ip()
    sport = random_port()
    dport = random_well_known_port()
    conn_id = random.randint(100000000, 999999999)
    return (f"%ASA-6-{eid}: {action} {action.lower()} {proto} connection "
            f"{conn_id} for outside:{src}/{sport} ({src}/{sport}) "
            f"to inside:{dst}/{dport} ({dst}/{dport})")


def _inbound_deny(host: str, _: str) -> str:
    src = random_external_ip()
    dst = random_internal_ip()
    dport = random_well_known_port()
    return (f"%ASA-2-106001: Inbound TCP connection denied from "
            f"{src}/{random_port()} to {dst}/{dport} flags SYN on interface outside")


def _tcp_request(host: str, _: str) -> str:
    src = random_internal_ip()
    dst = random_external_ip()
    dport = random_well_known_port()
    return (f"%ASA-7-710003: TCP access permitted from "
            f"{src}/{random_port()} to outside:{dst}/{dport}")


class CiscoASASource(LogSource):
    id = "cisco_asa"
    display_name = "Cisco ASA"
    description = "Cisco ASA firewall — %ASA- prefixed syslog messages"
    default_transport: str = "syslog"
    supported_transports = ["syslog"]
    default_eps = 5.0
    tags = ["network", "firewall", "cisco"]

    async def generate(self) -> LogEvent:
        event_id = weighted_choice(list(_MESSAGES.keys()), _MSG_WEIGHTS)
        host = random_network_device()
        ts = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
        msg = _MESSAGES[event_id](host, ts)

        sev_map = {106023: 4, 302013: 6, 302015: 6, 106001: 2, 710003: 7}
        priority = 23 * 8 + sev_map.get(event_id, 6)

        raw = f"<{priority}>{ts} {host} : {msg}"

        structured = {
            "device": host,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message_id": str(event_id),
            "severity": sev_map.get(event_id, 6),
            "raw_message": msg,
            "vendor": "cisco",
            "product": "asa",
        }

        return LogEvent(
            raw=raw,
            structured=structured,
            format="syslog_rfc3164",
            source_id=self.id,
        )
