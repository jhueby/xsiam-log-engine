from __future__ import annotations

import random
from datetime import datetime, timezone
from faker import Faker

from sources.base_source import LogEvent, LogSource
from utils.faker_helpers import random_internal_ip, random_user

fake = Faker()

_METHODS = ["GET", "POST", "CONNECT", "HEAD", "PUT"]
_METHOD_WEIGHTS = [55, 20, 15, 7, 3]
_CATEGORIES = [
    "Technology/Internet", "News/Media", "Business/Economy",
    "Social Networking", "Streaming Media", "Malicious Outbound Data/Botnets",
    "Phishing", "Hacking", "Proxy Avoidance and Anonymizers",
]
_CAT_WEIGHTS = [30, 20, 15, 10, 10, 5, 4, 3, 3]
_STATUS_CODES = [200, 301, 302, 304, 400, 403, 404, 407, 500, 502, 503]
_STATUS_WEIGHTS = [50, 8, 10, 7, 2, 5, 5, 3, 3, 4, 3]
_ACTIONS = ["TCP_TUNNEL", "TCP_NC", "TCP_HIT", "TCP_MISS", "TCP_DENIED", "TCP_REFRESH_HIT"]
_ACT_WEIGHTS = [35, 20, 15, 15, 10, 5]


class ProxyBlueCoatSource(LogSource):
    id = "proxy_bluecoat"
    display_name = "Blue Coat / Symantec Proxy"
    description = "Blue Coat ProxySG — W3C Extended Log Format (ELFF)"
    default_transport: str = "syslog"
    supported_transports = ["syslog"]
    default_eps = 20.0
    tags = ["proxy", "web", "network"]

    # W3C ELFF header fields
    _FIELDS = [
        "date", "time", "time-taken", "c-ip", "sc-status", "s-action",
        "sc-bytes", "cs-bytes", "cs-method", "cs-uri-scheme", "cs-host",
        "cs-uri-port", "cs-uri-path", "cs-uri-query", "cs-username",
        "s-hierarchy", "s-supplier-name", "rs(Content-Type)",
        "cs(User-Agent)", "sc-filter-result", "cs-categories",
        "x-exception-id", "x-virus-id",
    ]

    async def generate(self) -> LogEvent:
        now = datetime.now(timezone.utc)
        date = now.strftime("%Y-%m-%d")
        time_str = now.strftime("%H:%M:%S")
        client_ip = random_internal_ip()
        user = random_user()
        scheme = random.choice(["http", "https"])
        domain = fake.domain_name()
        port = 443 if scheme == "https" else 80
        path = "/" + fake.uri_path()
        query = f"?q={fake.word()}" if random.random() < 0.3 else "-"
        method = random.choices(_METHODS, weights=_METHOD_WEIGHTS)[0]
        status = random.choices(_STATUS_CODES, weights=_STATUS_WEIGHTS)[0]
        action = random.choices(_ACTIONS, weights=_ACT_WEIGHTS)[0]
        bytes_in = random.randint(300, 2000000)
        bytes_out = random.randint(50, 5000)
        time_taken = random.randint(10, 30000)
        category = random.choices(_CATEGORIES, weights=_CAT_WEIGHTS)[0]
        content_type = random.choice(["text/html", "application/json", "image/png", "application/octet-stream", "-"])
        ua = fake.user_agent()
        filter_result = "OBSERVED" if status < 400 else "DENIED"
        virus = "-"

        fields = [
            date, time_str, str(time_taken), client_ip, str(status), action,
            str(bytes_in), str(bytes_out), method, scheme, domain,
            str(port), path, query, user,
            "DIRECT", domain, content_type,
            ua, filter_result, f'"{category}"',
            "-", virus,
        ]
        raw = " ".join(fields)

        structured = {
            "timestamp": now.isoformat(),
            "client_ip": client_ip,
            "user": user,
            "method": method,
            "url": f"{scheme}://{domain}{path}",
            "status_code": status,
            "action": action,
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "category": category,
            "vendor": "bluecoat",
            "product": "proxysg",
        }

        return LogEvent(
            raw=raw,
            structured=structured,
            format="w3c_elff",
            source_id=self.id,
        )
