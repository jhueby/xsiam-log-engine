from __future__ import annotations

import json
import random
import uuid
from datetime import datetime, timezone

from sources.base_source import LogEvent, LogSource, ScenarioEntities, TransportName
from utils.faker_helpers import random_external_ip, random_internal_ip, weighted_choice

# Suricata's EVE output is one JSON object per event with an event_type
# discriminator. Alerts are the point of the source, but they arrive buried in
# flow/dns/tls records — keeping that ratio is what makes the stream realistic.
_EVENT_TYPES = ["alert", "flow", "dns", "tls", "http", "fileinfo"]
_TYPE_WEIGHTS = [12, 40, 18, 14, 12, 4]

# (signature, sid, category, severity) — severity 1 is highest in Suricata.
_SIGNATURES = [
    ("ET MALWARE Cobalt Strike Beacon Observed", 2027000, "A Network Trojan was detected", 1),
    ("ET TROJAN Observed DNS Query to .top Domain", 2027001, "A Network Trojan was detected", 2),
    ("ET POLICY PE EXE or DLL Windows file download HTTP", 2018959, "Potential Corporate Privacy Violation", 3),
    ("ET SCAN Potential SSH Scan", 2001219, "Attempted Information Leak", 2),
    ("ET EXPLOIT Possible CVE-2021-44228 Log4j RCE Attempt", 2034647, "Attempted Administrator Privilege Gain", 1),
    ("ET INFO Observed DNS over HTTPS Domain", 2027758, "Not Suspicious Traffic", 3),
    ("ET MALWARE Win32/Agent Tesla CnC Exfil", 2027002, "A Network Trojan was detected", 1),
    ("ET POLICY Outbound RDP Connection", 2012713, "Potentially Bad Traffic", 2),
    ("ET SCAN Suspicious inbound to MSSQL port 1433", 2010935, "Potentially Bad Traffic", 2),
]
_SIG_WEIGHTS = [8, 14, 16, 12, 6, 18, 5, 9, 12]

_PROTOS = ["TCP", "UDP", "ICMP"]
_APP_PROTOS = ["http", "tls", "dns", "smb", "ssh", "failed"]
_ACTIONS = ["allowed", "allowed", "allowed", "blocked"]

_DOMAINS = ["login.microsoftonline.com", "cdn.jsdelivr.net", "pastebin.com",
            "api.telegram.org", "corp-sso-verify.example.net", "malicious.top"]
_JA3 = ["e7d705a3286e19ea42f587b344ee6865", "a0e9f5d64349fb13191bc781f81f42e1"]


def _build(*, event_type: str, src_ip: str, dest_ip: str,
           signature: tuple | None = None) -> dict:
    now = datetime.now(timezone.utc)
    src_port = random.randint(1024, 65535)
    dest_port = random.choice([53, 80, 443, 445, 22, 3389, 1433])

    event = {
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000",
        "flow_id": random.randint(10**14, 10**15),
        "in_iface": "eth0",
        "event_type": event_type,
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "proto": random.choice(_PROTOS),
    }

    if event_type == "alert":
        sig, sid, category, severity = signature or weighted_choice(_SIGNATURES, _SIG_WEIGHTS)
        event["alert"] = {
            "action": random.choice(_ACTIONS),
            "gid": 1,
            "signature_id": sid,
            "rev": random.randint(1, 20),
            "signature": sig,
            "category": category,
            "severity": severity,
            "metadata": {
                "attack_target": ["Client_Endpoint"],
                "created_at": ["2024_01_15"],
                "deployment": ["Perimeter"],
                "signature_severity": ["Major" if severity == 1 else "Minor"],
            },
        }
        event["app_proto"] = random.choice(_APP_PROTOS)
        event["flow"] = {
            "pkts_toserver": random.randint(1, 200),
            "pkts_toclient": random.randint(1, 200),
            "bytes_toserver": random.randint(100, 400000),
            "bytes_toclient": random.randint(100, 900000),
            "start": now.isoformat(),
        }
    elif event_type == "flow":
        event["flow"] = {
            "pkts_toserver": random.randint(1, 5000),
            "pkts_toclient": random.randint(0, 5000),
            "bytes_toserver": random.randint(60, 2000000),
            "bytes_toclient": random.randint(0, 9000000),
            "start": now.isoformat(),
            "end": now.isoformat(),
            "age": random.randint(0, 3600),
            "state": random.choice(["established", "closed", "new"]),
            "reason": random.choice(["timeout", "shutdown", "forced"]),
            "alerted": random.random() < 0.05,
        }
        event["app_proto"] = random.choice(_APP_PROTOS)
    elif event_type == "dns":
        event["dns"] = {
            "version": 2,
            "type": random.choice(["query", "answer"]),
            "id": random.randint(1, 65535),
            "rrname": random.choice(_DOMAINS),
            "rrtype": random.choice(["A", "AAAA", "TXT", "CNAME"]),
            "tx_id": random.randint(0, 100),
            "opcode": 0,
        }
    elif event_type == "tls":
        event["tls"] = {
            "subject": f"CN={random.choice(_DOMAINS)}",
            "issuerdn": random.choice([
                "C=US, O=Let's Encrypt, CN=R3",
                "C=US, O=DigiCert Inc, CN=DigiCert TLS RSA SHA256 2020 CA1",
                "CN=localhost",  # self-signed: worth alerting on
            ]),
            "serial": ":".join(uuid.uuid4().hex[i:i + 2].upper() for i in range(0, 16, 2)),
            "fingerprint": ":".join(uuid.uuid4().hex[i:i + 2] for i in range(0, 40, 2)),
            "sni": random.choice(_DOMAINS),
            "version": random.choice(["TLS 1.2", "TLS 1.3"]),
            "notbefore": "2026-01-01T00:00:00",
            "notafter": "2027-01-01T00:00:00",
            "ja3": {"hash": random.choice(_JA3)},
        }
    elif event_type == "http":
        event["http"] = {
            "hostname": random.choice(_DOMAINS),
            "url": random.choice(["/", "/api/v1/session", "/download/update.bin", "/.env"]),
            "http_user_agent": random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0",
                "curl/8.4.0", "python-requests/2.31.0",
            ]),
            "http_content_type": random.choice(["text/html", "application/octet-stream"]),
            "http_method": random.choice(["GET", "POST", "HEAD"]),
            "protocol": "HTTP/1.1",
            "status": random.choice([200, 301, 403, 404, 500]),
            "length": random.randint(0, 900000),
        }
    else:
        event["fileinfo"] = {
            "filename": random.choice(["/update.bin", "/invoice.pdf", "/setup.exe"]),
            "magic": random.choice(["PE32 executable (GUI) Intel 80386", "PDF document, version 1.7"]),
            "state": "CLOSED",
            "md5": uuid.uuid4().hex,
            "sha256": uuid.uuid4().hex + uuid.uuid4().hex,
            "stored": random.random() < 0.4,
            "size": random.randint(1000, 8000000),
            "tx_id": random.randint(0, 10),
        }
        event["app_proto"] = "http"

    return event


class SuricataSource(LogSource):
    id = "suricata"
    display_name = "Suricata IDS"
    description = "Suricata EVE JSON — IDS alerts with signature IDs, plus flow, dns, tls and http records"
    default_transport: TransportName = "http"
    supported_transports = ["http", "syslog"]
    default_eps = 12.0
    tags = ["network", "ids", "suricata", "monitoring"]
    xsiam_dataset: str = "suricata_eve_raw"

    async def generate(self) -> LogEvent:
        event = _build(
            event_type=weighted_choice(_EVENT_TYPES, _TYPE_WEIGHTS),
            src_ip=random_internal_ip(),
            dest_ip=random_external_ip(),
        )
        return LogEvent(raw=json.dumps(event), structured=event, format="json", source_id=self.id)

    async def generate_with_entities(
        self, entities: ScenarioEntities, overrides: dict | None = None
    ) -> LogEvent:
        """Scenario mode: place the detection on the run's host talking to the
        run's external IP.

        Recognized overrides: event_type, signature_id, src_ip, dest_ip.
        """
        overrides = overrides or {}
        # .get(key, default) -- not `or` -- so an explicit falsy override
        # (e.g. "") is honored instead of silently replaced by random data.
        wanted_sid = overrides.get("signature_id")
        signature = next((s for s in _SIGNATURES if s[1] == wanted_sid), None) if wanted_sid else None
        # Naming a signature implies an alert -- don't make callers say both.
        default_type = "alert" if signature else weighted_choice(_EVENT_TYPES, _TYPE_WEIGHTS)

        event = _build(
            event_type=overrides.get("event_type", default_type),
            src_ip=overrides.get("src_ip", entities.internal_ip),
            dest_ip=overrides.get("dest_ip", entities.external_ip),
            signature=signature,
        )
        return LogEvent(raw=json.dumps(event), structured=event, format="json", source_id=self.id)
