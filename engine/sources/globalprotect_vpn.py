from __future__ import annotations

import random
from datetime import datetime, timezone

from sources.base_source import LogEvent, LogSource, ScenarioEntities, TransportName
from utils.faker_helpers import (
    DOMAIN,
    random_external_ip,
    random_internal_ip,
    random_network_device,
    random_user,
    weighted_choice,
)

# GlobalProtect stages, in the order a real session walks through them.
# before-login/gateway-auth are where credential abuse shows up; the
# connect/disconnect pair is the bulk of normal volume.
_EVENTS = ["before-login", "login", "gateway-auth", "tunnel-connect", "tunnel-disconnect", "logout"]
_EVENT_WEIGHTS = [5, 25, 15, 25, 20, 10]

_STATUS = ["success", "success", "success", "success", "failure"]

_ERRORS = {
    "failure": [
        "Invalid username or password",
        "User is not authorized to access the portal",
        "Authentication failed: MFA denied",
        "Certificate validation failed",
    ],
}

_CLIENT_OS = ["Windows 10", "Windows 11", "Mac 14.4.1", "iOS 17.4", "Android 14", "Linux"]
_CLIENT_VERSIONS = ["6.2.1-45", "6.1.2-11", "5.2.12-3"]
_PORTALS = ["gp.corp.example.com", "vpn-emea.corp.example.com"]
_GATEWAYS = ["GP-Gateway-US-East", "GP-Gateway-EMEA", "GP-Gateway-APAC"]

# Where the connection appears to originate. Geographically scattered on
# purpose — impossible-travel detections need somewhere to look.
_LOCATIONS = ["US", "GB", "DE", "IN", "BR", "MA", "SG", "NL"]


def _build(*, event: str, user: str, public_ip: str, private_ip: str, host: str) -> tuple[str, dict]:
    ts = datetime.now(timezone.utc).strftime("%Y/%m/%d %H:%M:%S")
    status = random.choice(_STATUS) if event in ("login", "gateway-auth", "before-login") else "success"
    error = random.choice(_ERRORS["failure"]) if status == "failure" else ""
    gateway = random.choice(_GATEWAYS)
    portal = random.choice(_PORTALS)
    client_os = random.choice(_CLIENT_OS)
    client_ver = random.choice(_CLIENT_VERSIONS)
    location = random.choice(_LOCATIONS)
    duration = random.randint(60, 36000) if event == "tunnel-disconnect" else 0

    # PAN-OS GLOBALPROTECT log type, CSV as it appears on the wire. The
    # transport wraps this in RFC 5424 (format isn't pre-framed), matching
    # how palo_alto_ngfw emits its vendor-native rows.
    raw = (
        f"1,{ts},000000000000000,GLOBALPROTECT,0,2049,{ts},,{event},{portal},"
        f"{gateway},,,{user},{DOMAIN},{host},{client_os},{client_ver},"
        f"{public_ip},,{private_ip},,{location},{status},{error},{duration},"
        f"0,0,{random.randint(1, 99999)},{random_network_device()}"
    )

    structured = {
        "vendor": "paloalto",
        "product": "globalprotect",
        "type": "GLOBALPROTECT",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "stage": event,
        "portal": portal,
        "gateway": gateway,
        "srcuser": user,
        "domain": DOMAIN,
        "machinename": host,
        "client_os": client_os,
        "client_version": client_ver,
        "public_ip": public_ip,
        "private_ip": private_ip,
        "source_region": location,
        "status": status,
        "error": error,
        "session_duration_s": duration,
    }
    return raw, structured


class GlobalProtectVPNSource(LogSource):
    id = "globalprotect_vpn"
    display_name = "GlobalProtect VPN"
    description = "Palo Alto GlobalProtect — portal/gateway authentication and tunnel session events"
    default_transport: TransportName = "syslog"
    supported_transports = ["syslog", "http"]
    default_eps = 3.0
    tags = ["network", "vpn", "authentication", "paloalto", "remote-access"]
    syslog_facility: int = 16  # local0

    async def generate(self) -> LogEvent:
        raw, structured = _build(
            event=weighted_choice(_EVENTS, _EVENT_WEIGHTS),
            user=random_user(),
            public_ip=random_external_ip(),
            private_ip=random_internal_ip(),
            host=f"LAPTOP-{random.randint(1000, 9999)}",
        )
        return LogEvent(raw=raw, structured=structured, format="syslog_pan", source_id=self.id)

    async def generate_with_entities(
        self, entities: ScenarioEntities, overrides: dict | None = None
    ) -> LogEvent:
        """Scenario mode: tie the VPN session to the run's identity, host and
        IPs — the join that makes remote-access stories (impossible travel,
        credential reuse from new infrastructure) hold together.

        Recognized overrides: event, public_ip, private_ip.
        """
        overrides = overrides or {}
        # .get(key, default) -- not `or` -- so an explicit falsy override
        # (e.g. "") is honored instead of silently replaced by random data.
        raw, structured = _build(
            event=overrides.get("event", weighted_choice(_EVENTS, _EVENT_WEIGHTS)),
            user=entities.username,
            public_ip=overrides.get("public_ip", entities.external_ip),
            private_ip=overrides.get("private_ip", entities.internal_ip),
            host=entities.host,
        )
        return LogEvent(raw=raw, structured=structured, format="syslog_pan", source_id=self.id)
