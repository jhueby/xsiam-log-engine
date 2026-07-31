from __future__ import annotations

import json
import random
import uuid
from datetime import datetime, timezone

from sources.base_source import LogEvent, LogSource, ScenarioEntities, TransportName
from utils.faker_helpers import random_external_ip, random_internal_ip, weighted_choice

# Zeek splits its output by protocol rather than emitting one event stream, so
# each log type is a genuinely different record shape. conn.log dominates real
# volume; notice.log is rare but is where Zeek states an opinion.
_LOG_TYPES = ["conn", "dns", "http", "ssl", "notice", "files"]
_TYPE_WEIGHTS = [45, 20, 15, 12, 3, 5]

_CONN_STATES = ["SF", "S0", "REJ", "RSTO", "RSTR", "SH", "OTH"]
_CONN_WEIGHTS = [60, 12, 10, 6, 5, 4, 3]

_SERVICES = ["dns", "http", "ssl", "smtp", "ssh", "dhcp", "ntp", None]
_PROTOS = ["tcp", "udp", "icmp"]

_DOMAINS = [
    "login.microsoftonline.com", "graph.microsoft.com", "update.googleapis.com",
    "cdn.jsdelivr.net", "pastebin.com", "api.telegram.org",
    "corp-sso-verify.example.net", "d3f4ult.example.io", "raw.githubusercontent.com",
]
_QTYPES = [("A", 1), ("AAAA", 28), ("TXT", 16), ("CNAME", 5), ("MX", 15), ("NULL", 10)]

_URIS = ["/", "/index.html", "/api/v1/session", "/wp-login.php", "/admin/config.php",
         "/download/update.bin", "/c2/beacon", "/.env"]
_METHODS = ["GET", "GET", "GET", "POST", "HEAD", "PUT"]
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0",
    "curl/8.4.0", "python-requests/2.31.0", "Microsoft-CryptoAPI/10.0",
    "WinHttp.WinHttpRequest.5", "Go-http-client/1.1",
]

# JA3 hashes are the reason ssl.log matters for detection: the client fingerprint
# survives certificate and domain rotation.
_JA3 = ["e7d705a3286e19ea42f587b344ee6865", "a0e9f5d64349fb13191bc781f81f42e1",
        "72a589da586844d7f0818ce684948eea", "6734f37431670b3ab4292b8f60f29984"]

_NOTICES = [
    ("Scan::Port_Scan", "scanned at least 15 unique ports of host"),
    ("Scan::Address_Scan", "scanned at least 25 unique hosts on port 445/tcp"),
    ("SSL::Invalid_Server_Cert", "SSL certificate validation failed with (self signed certificate)"),
    ("Conn::Content_Gap", "content gap detected"),
    ("HTTP::SQL_Injection_Attacker", "SQL injection attacker"),
    ("Weird::Activity", "unexpected_multiple_HTTP_requests"),
]

_MIME_TYPES = ["application/x-dosexec", "application/zip", "text/html",
               "application/pdf", "application/octet-stream"]


def _uid() -> str:
    return "C" + uuid.uuid4().hex[:15]


def _build(*, log_type: str, orig_h: str, resp_h: str) -> dict:
    now = datetime.now(timezone.utc)
    ts = now.timestamp()
    base = {"ts": ts, "uid": _uid(), "id.orig_h": orig_h,
            "id.orig_p": random.randint(1024, 65535), "id.resp_h": resp_h}

    if log_type == "conn":
        proto = random.choice(_PROTOS)
        duration = round(random.uniform(0.001, 300.0), 6)
        orig_bytes = random.randint(0, 500000)
        resp_bytes = random.randint(0, 5000000)
        return {**base,
                "id.resp_p": random.choice([53, 80, 443, 445, 22, 3389, 8080]),
                "proto": proto,
                "service": random.choice(_SERVICES),
                "duration": duration,
                "orig_bytes": orig_bytes,
                "resp_bytes": resp_bytes,
                "conn_state": weighted_choice(_CONN_STATES, _CONN_WEIGHTS),
                "local_orig": True,
                "local_resp": False,
                "missed_bytes": 0,
                "history": random.choice(["ShADadFf", "S0", "Dd", "ShADadfF", "^dDa"]),
                "orig_pkts": random.randint(1, 2000),
                "orig_ip_bytes": orig_bytes + random.randint(0, 4000),
                "resp_pkts": random.randint(0, 4000),
                "resp_ip_bytes": resp_bytes + random.randint(0, 4000),
                "_path": "conn"}

    if log_type == "dns":
        qtype_name, qtype = random.choice(_QTYPES)
        query = random.choice(_DOMAINS)
        # A long label under a lookalike domain is what DNS tunnelling and
        # beaconing actually look like in this log.
        if qtype_name in ("TXT", "NULL") and random.random() < 0.5:
            query = f"{uuid.uuid4().hex}{uuid.uuid4().hex[:12]}.{query}"
        return {**base, "id.resp_p": 53, "proto": "udp",
                "trans_id": random.randint(1, 65535),
                "rtt": round(random.uniform(0.001, 0.4), 6),
                "query": query, "qclass": 1, "qclass_name": "C_INTERNET",
                "qtype": qtype, "qtype_name": qtype_name,
                "rcode": random.choice([0, 0, 0, 3]),
                "rcode_name": random.choice(["NOERROR", "NOERROR", "NOERROR", "NXDOMAIN"]),
                "AA": False, "TC": False, "RD": True, "RA": True, "Z": 0,
                "answers": [random_external_ip()], "TTLs": [random.choice([60, 300, 3600])],
                "rejected": False, "_path": "dns"}

    if log_type == "http":
        return {**base, "id.resp_p": random.choice([80, 8080]),
                "trans_depth": random.randint(1, 4),
                "method": random.choice(_METHODS),
                "host": random.choice(_DOMAINS),
                "uri": random.choice(_URIS),
                "version": "1.1",
                "user_agent": random.choice(_USER_AGENTS),
                "request_body_len": random.randint(0, 8000),
                "response_body_len": random.randint(0, 900000),
                "status_code": random.choice([200, 200, 301, 403, 404, 500]),
                "status_msg": "OK",
                "tags": [],
                "resp_fuids": [f"F{uuid.uuid4().hex[:15]}"],
                "resp_mime_types": [random.choice(_MIME_TYPES)],
                "_path": "http"}

    if log_type == "ssl":
        return {**base, "id.resp_p": 443,
                "version": random.choice(["TLSv12", "TLSv13"]),
                "cipher": random.choice([
                    "TLS_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]),
                "curve": "x25519",
                "server_name": random.choice(_DOMAINS),
                "resumed": random.random() < 0.3,
                "established": True,
                "ja3": random.choice(_JA3),
                "ja3s": random.choice(_JA3),
                "validation_status": random.choice([
                    "ok", "ok", "ok", "self signed certificate",
                    "unable to get local issuer certificate"]),
                "_path": "ssl"}

    if log_type == "notice":
        note, msg = random.choice(_NOTICES)
        return {**base, "id.resp_p": random.choice([445, 443, 80]),
                "fuid": "", "proto": "tcp", "note": note,
                "msg": f"{orig_h} {msg}",
                "sub": "", "src": orig_h, "dst": resp_h,
                "peer_descr": "zeek-worker-1",
                "actions": ["Notice::ACTION_LOG"],
                "suppress_for": 3600.0, "_path": "notice"}

    mime = random.choice(_MIME_TYPES)
    return {"ts": ts, "fuid": f"F{uuid.uuid4().hex[:15]}",
            "tx_hosts": [resp_h], "rx_hosts": [orig_h], "conn_uids": [_uid()],
            "source": "HTTP", "depth": 0, "analyzers": ["SHA1", "MD5"],
            "mime_type": mime,
            "filename": random.choice(["update.bin", "invoice.pdf", "setup.exe", "-"]),
            "duration": round(random.uniform(0.01, 20.0), 6),
            "is_orig": False, "seen_bytes": random.randint(1000, 5000000),
            "missing_bytes": 0, "overflow_bytes": 0, "timedout": False,
            "md5": uuid.uuid4().hex, "sha1": uuid.uuid4().hex + uuid.uuid4().hex[:8],
            "_path": "files"}


class ZeekSource(LogSource):
    id = "zeek"
    display_name = "Zeek"
    description = "Zeek network security monitor — conn, dns, http, ssl (JA3), notice and files logs"
    default_transport: TransportName = "http"
    supported_transports = ["http", "syslog"]
    default_eps = 15.0
    tags = ["network", "nsm", "zeek", "monitoring"]

    async def generate(self) -> LogEvent:
        event = _build(
            log_type=weighted_choice(_LOG_TYPES, _TYPE_WEIGHTS),
            orig_h=random_internal_ip(),
            resp_h=random_external_ip(),
        )
        return LogEvent(raw=json.dumps(event), structured=event, format="json", source_id=self.id)

    async def generate_with_entities(
        self, entities: ScenarioEntities, overrides: dict | None = None
    ) -> LogEvent:
        """Scenario mode: originate the traffic from the run's host and point
        it at the run's external IP, so network evidence lines up with the
        endpoint and identity steps.

        Recognized overrides: log_type, orig_h, resp_h.
        """
        overrides = overrides or {}
        # .get(key, default) -- not `or` -- so an explicit falsy override
        # (e.g. "") is honored instead of silently replaced by random data.
        event = _build(
            log_type=overrides.get("log_type", weighted_choice(_LOG_TYPES, _TYPE_WEIGHTS)),
            orig_h=overrides.get("orig_h", entities.internal_ip),
            resp_h=overrides.get("resp_h", entities.external_ip),
        )
        return LogEvent(raw=json.dumps(event), structured=event, format="json", source_id=self.id)
