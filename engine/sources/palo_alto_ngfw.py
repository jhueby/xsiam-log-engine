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

_LOG_TYPES = ["TRAFFIC", "THREAT", "SYSTEM", "CONFIG"]
_TYPE_WEIGHTS = [55, 25, 12, 8]

_ACTIONS = ["allow", "deny", "drop", "reset-client", "reset-server", "reset-both"]
_ACT_WEIGHTS = [70, 15, 8, 3, 2, 2]

_APPS = ["ssl", "web-browsing", "dns", "smtp", "ssh", "rdp", "kerberos", "msrpc",
         "ms-office365", "zoom", "teams", "dropbox", "sharepoint"]

_THREAT_NAMES = [
    "Cobalt Strike Beacon", "Mimikatz Credential Dumping",
    "CVE-2021-26855 Exchange RCE", "Log4Shell Exploit",
    "EICAR Antivirus Test File", "Trojan.Generic.Win32",
    "SQL Injection Attack", "XSS Attack",
]

_THREAT_TYPES = ["vulnerability", "virus", "wildfire-virus", "spyware", "url"]
_THREAT_SEV = ["critical", "high", "medium", "low", "informational"]
_RULES = ["ALLOW_OUTBOUND", "DENY_INBOUND", "ALLOW_DNS", "BLOCK_APPS", "ALLOW_MGMT"]


def _traffic() -> tuple[str, dict]:
    src = random_internal_ip()
    dst = random_external_ip()
    sport = random_port()
    dport = random_well_known_port()
    app = random.choice(_APPS)
    action = random.choices(_ACTIONS, weights=_ACT_WEIGHTS)[0]
    rule = random.choice(_RULES)
    bytes_sent = random.randint(100, 1000000)
    bytes_recv = random.randint(100, 5000000)
    pkts = random.randint(1, 5000)
    elapsed = random.randint(1, 3600)
    ts = datetime.now(timezone.utc).strftime("%Y/%m/%d %H:%M:%S")

    raw = (f"1,{ts},000000000000000,TRAFFIC,{random.choice(['start','end'])},1,{ts},"
           f"{src},{dst},{src},{dst},allow,{rule},,,{app},vsys1,zone-trust,zone-untrust,"
           f"ethernet1/1,ethernet1/2,,,0,{sport},{dport},{dport},0x0,tcp,"
           f"{action},{bytes_sent},{bytes_recv},{pkts},{pkts},{elapsed},from-policy,,"
           f"0x0,0,0,0,0,,PA-500,from-policy,,,,,,,,,0,0,0,0,{random.randint(1,100)}")

    structured = {
        "type": "TRAFFIC", "action": action, "app": app,
        "src_ip": src, "dst_ip": dst, "src_port": sport, "dst_port": dport,
        "rule": rule, "bytes_sent": bytes_sent, "bytes_received": bytes_recv,
        "elapsed": elapsed, "protocol": "tcp",
    }
    return raw, structured


def _threat() -> tuple[str, dict]:
    src = random_external_ip()
    dst = random_internal_ip()
    threat = random.choice(_THREAT_NAMES)
    ttype = random.choice(_THREAT_TYPES)
    sev = random.choice(_THREAT_SEV)
    action = random.choice(["reset-both", "block-ip", "allow", "sinkhole"])
    ts = datetime.now(timezone.utc).strftime("%Y/%m/%d %H:%M:%S")

    raw = (f"1,{ts},000000000000000,THREAT,{ttype},1,{ts},"
           f"{src},{dst},{src},{dst},allow,DENY_INBOUND,,,web-browsing,vsys1,"
           f"zone-untrust,zone-trust,ethernet1/1,ethernet1/2,,,0,"
           f"{random_port()},{random_well_known_port()},0x0,tcp,{action},"
           f"\"{threat}\",{random.randint(10000,99999)},{ttype},{sev},client-to-server,"
           f"0,0x0,United States,United States,0,{random.randint(1,20)},0,,"
           f"0,0,0,0,,PA-500,,,,,,,,0,0,0,0,{random.randint(1,100)}")

    structured = {
        "type": "THREAT", "threat_name": threat, "threat_type": ttype,
        "severity": sev, "action": action, "src_ip": src, "dst_ip": dst,
    }
    return raw, structured


def _system() -> tuple[str, dict]:
    ts = datetime.now(timezone.utc).strftime("%Y/%m/%d %H:%M:%S")
    msgs = [
        ("general", 3, "System started"),
        ("ha", 4, "HA state changed to active"),
        ("auth", 4, f"Admin {random_user()} logged in from {random_internal_ip()}"),
        ("vpn", 3, "IKE gateway negotiation complete"),
    ]
    subtype, sev, msg = random.choice(msgs)
    raw = (f"1,{ts},000000000000000,SYSTEM,{subtype},1,{ts},general,"
           f"{msg},,,,{sev},0,0,0,PA-500")
    structured = {"type": "SYSTEM", "subtype": subtype, "message": msg, "severity": sev}
    return raw, structured


def _config() -> tuple[str, dict]:
    ts = datetime.now(timezone.utc).strftime("%Y/%m/%d %H:%M:%S")
    user = random_user()
    cmds = [
        "set address HOST_10.0.0.1 ip-netmask 10.0.0.1/32",
        "set security policies pre-rulebase security rules ALLOW_WEB action allow",
        "set network interfaces ethernet ethernet1/3 layer3 units ethernet1/3.100 ip 192.168.100.1/24",
    ]
    cmd = random.choice(cmds)
    raw = (f"1,{ts},000000000000000,CONFIG,,1,{ts},{user},"
           f"Web,{random_internal_ip()},{cmd},Succeeded,PA-500")
    structured = {"type": "CONFIG", "admin": user, "command": cmd, "result": "Succeeded"}
    return raw, structured


_GENERATORS = {"TRAFFIC": _traffic, "THREAT": _threat, "SYSTEM": _system, "CONFIG": _config}


class PaloAltoNGFWSource(LogSource):
    id = "palo_alto_ngfw"
    display_name = "Palo Alto NGFW"
    description = "Palo Alto Networks NGFW/Panorama — TRAFFIC, THREAT, SYSTEM, CONFIG log types"
    default_transport: str = "syslog"
    supported_transports = ["syslog", "http"]
    default_eps = 10.0
    tags = ["network", "firewall", "paloalto"]

    async def generate(self) -> LogEvent:
        log_type = weighted_choice(_LOG_TYPES, _TYPE_WEIGHTS)
        raw, structured = _GENERATORS[log_type]()

        structured.update({
            "vendor": "paloalto",
            "product": "ngfw",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "device": random_network_device(),
        })

        return LogEvent(
            raw=raw,
            structured=structured,
            format="syslog_pan",
            source_id=self.id,
        )
