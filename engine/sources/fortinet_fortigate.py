from __future__ import annotations

import random
from datetime import datetime, timezone
from faker import Faker

from sources.base_source import LogEvent, LogSource
from utils.faker_helpers import (
    random_internal_ip, random_external_ip, random_port, random_well_known_port,
    random_user, random_network_device, weighted_choice,
)

fake = Faker()

_LOG_TYPES = ["traffic", "utm", "event"]
_TYPE_WEIGHTS = [55, 30, 15]

_ACTIONS = ["accept", "deny", "drop", "close"]
_ACT_WEIGHTS = [65, 20, 10, 5]

_UTM_TYPES = ["webfilter", "antivirus", "ips", "app-ctrl", "emailfilter"]
_UTM_WEIGHTS = [35, 20, 20, 20, 5]

_IPS_ATTACKS = [
    "Log4j.Exploit", "MS.SMB.Server.SMBv1.Code.Execution",
    "ETERNALBLUE", "Apache.Struts.ClassLoader.Remote.Code.Execution",
    "Spring4Shell.RCE",
]

_WEB_CATS = ["Malicious Websites", "Phishing", "Hacking", "Proxy Avoidance",
             "Social Networking", "Streaming Media"]


def _traffic_line() -> tuple[str, dict]:
    src = random_internal_ip()
    dst = random_external_ip()
    sport = random_port()
    dport = random_well_known_port()
    action = random.choices(_ACTIONS, weights=_ACT_WEIGHTS)[0]
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    policy_id = random.randint(1, 50)
    bytes_sent = random.randint(100, 500000)
    bytes_recv = random.randint(100, 2000000)

    raw = (f'date={ts.split()[0]} time={ts.split()[1]} devname="FG{random.randint(100,999)}D" '
           f'devid="FGT{random.randint(1000000,9999999)}" logid="0000000013" type="traffic" '
           f'subtype="forward" level="notice" vd="root" eventtime={int(datetime.now(timezone.utc).timestamp())} '
           f'srcip={src} srcport={sport} srcintf="port1" srcintfrole="lan" '
           f'dstip={dst} dstport={dport} dstintf="wan1" dstintfrole="wan" '
           f'poluuid="{fake.uuid4()}" sessionid={random.randint(100000,9999999)} '
           f'proto={random.choice([6,17])} action="{action}" policyid={policy_id} '
           f'policytype="policy" service="HTTP" dstcountry="United States" srccountry="Reserved" '
           f'trandisp="noop" duration={random.randint(1,3600)} sentbyte={bytes_sent} '
           f'rcvdbyte={bytes_recv} sentpkt={random.randint(1,1000)} rcvdpkt={random.randint(1,2000)} '
           f'appcat="unscanned" dsthwvendor="" mastersrcmac="{":".join(f"{random.randint(0,255):02x}" for _ in range(6))}"')

    structured = {
        "type": "traffic", "action": action, "src_ip": src, "dst_ip": dst,
        "src_port": sport, "dst_port": dport, "policy_id": policy_id,
        "bytes_sent": bytes_sent, "bytes_received": bytes_recv,
    }
    return raw, structured


def _utm_line() -> tuple[str, dict]:
    utm_type = random.choices(_UTM_TYPES, weights=_UTM_WEIGHTS)[0]
    src = random_internal_ip()
    dst = random_external_ip()
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    action = "blocked" if random.random() < 0.4 else "allowed"

    if utm_type == "webfilter":
        url = f"https://{fake.domain_name()}/{fake.uri_path()}"
        cat = random.choice(_WEB_CATS)
        detail = f'url="{url}" catdesc="{cat}" status="{action}"'
    elif utm_type == "ips":
        attack = random.choice(_IPS_ATTACKS)
        detail = f'attack="{attack}" severity="high" status="{action}"'
    elif utm_type == "antivirus":
        detail = f'virus="{random.choice(["EICAR","Trojan.GenericKD","Win32.Conficker"])}" status="{action}"'
    else:
        detail = f'appid={random.randint(10000,60000)} status="{action}"'

    raw = (f'date={ts.split()[0]} time={ts.split()[1]} type="{utm_type}" subtype="{utm_type}" '
           f'level="warning" vd="root" srcip={src} dstip={dst} '
           f'srcport={random_port()} dstport={random_well_known_port()} '
           f'proto=6 {detail}')

    structured = {
        "type": "utm", "subtype": utm_type, "action": action,
        "src_ip": src, "dst_ip": dst,
    }
    return raw, structured


def _event_line() -> tuple[str, dict]:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    user = random_user()
    msgs = [
        f'subtype="vpn" user="{user}" action="ssl-login-fail" msg="SSL user failed to authenticate"',
        f'subtype="system" action="login" user="{user}" ui="ssh({random_internal_ip()})" msg="Administrator {user} logged in"',
        f'subtype="ha" action="state-changed" msg="HA state changed to master"',
        f'subtype="router" action="ospf-neighbor-up" msg="OSPF neighbor {random_internal_ip()} is up"',
    ]
    detail = random.choice(msgs)
    raw = f'date={ts.split()[0]} time={ts.split()[1]} type="event" level="information" vd="root" {detail}'
    structured = {"type": "event", "user": user}
    return raw, structured


_GENERATORS = {"traffic": _traffic_line, "utm": _utm_line, "event": _event_line}


class FortinetFortiGateSource(LogSource):
    id = "fortinet_fortigate"
    display_name = "Fortinet FortiGate"
    description = "Fortinet FortiGate — key=value syslog: traffic, UTM, event types"
    default_transport: str = "syslog"
    supported_transports = ["syslog"]
    default_eps = 5.0
    tags = ["network", "firewall", "fortinet"]
    syslog_facility: int = 16  # local0

    async def generate(self) -> LogEvent:
        log_type = weighted_choice(_LOG_TYPES, _TYPE_WEIGHTS)
        raw, structured = _GENERATORS[log_type]()

        structured.update({
            "vendor": "fortinet",
            "product": "fortigate",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        return LogEvent(
            raw=raw,
            structured=structured,
            format="syslog_kv",
            source_id=self.id,
        )
