from __future__ import annotations

import json
import random
from datetime import datetime, timezone
from faker import Faker

from sources.base_source import LogEvent, LogSource, TransportName
from utils.faker_helpers import random_internal_ip, random_user, random_domain_user

fake = Faker()

_ACTIONS = ["Allowed", "Blocked", "Allowed", "Allowed", "Caution"]
_CATEGORIES = [
    "Business and Economy", "Technology", "News and Media",
    "Social Networking", "Streaming Media", "Malicious Content",
    "Phishing", "Hacking Sites", "Proxy Avoidance",
]
_CAT_WEIGHTS = [25, 20, 15, 10, 10, 8, 5, 4, 3]
_THREATS = ["-", "Win32.Backdoor.CobaltStrike", "HTML.Phishing.Bank", "-", "-"]
_PROTOCOLS = ["HTTPS", "HTTP", "FTP", "SMTP"]
_PROTO_WEIGHTS = [70, 20, 5, 5]


class ProxyZscalerSource(LogSource):
    id = "proxy_zscaler"
    display_name = "Zscaler Internet Access"
    description = "Zscaler NSS feed format — web proxy events"
    default_transport: TransportName = "syslog"
    supported_transports = ["syslog"]
    default_eps = 20.0
    tags = ["proxy", "web", "cloud", "zscaler"]
    syslog_facility: int = 16  # local0

    async def generate(self) -> LogEvent:
        now = datetime.now(timezone.utc)
        user = random_domain_user()
        client_ip = random_internal_ip()
        dst_ip = fake.ipv4_public()
        url = f"https://{fake.domain_name()}/{fake.uri_path()}"
        action = random.choice(_ACTIONS)
        category = random.choices(_CATEGORIES, weights=_CAT_WEIGHTS)[0]
        threat = random.choice(_THREATS)
        protocol = random.choices(_PROTOCOLS, weights=_PROTO_WEIGHTS)[0]
        bytes_in = random.randint(200, 5000000)
        bytes_out = random.randint(50, 10000)
        status = random.choice([200, 301, 302, 400, 403, 404, 503])
        dept = random.choice(["Engineering", "Finance", "HR", "IT", "Marketing", "Sales"])
        location = random.choice(["HQ", "Branch-NYC", "Branch-LON", "Remote-VPN"])

        event = {
            "sourcetype": "zscalernss-web",
            "event": {
                "datetime": now.strftime("%a %b %d %H:%M:%S %Y"),
                "reason": action,
                "event_id": random.randint(100000000, 999999999),
                "protocol": protocol,
                "action": action,
                "transactionsize": bytes_in + bytes_out,
                "responsesize": bytes_in,
                "requestsize": bytes_out,
                "urlcategory": category,
                "serverip": dst_ip,
                "requestmethod": random.choice(["GET", "POST", "CONNECT"]),
                "refererURL": "-",
                "useragent": fake.user_agent(),
                "product": "NSS",
                "location": location,
                "ClientIP": client_ip,
                "status": str(status),
                "user": user,
                "url": url,
                "vendor": "Zscaler",
                "hostname": fake.domain_name(),
                "clientpublicIP": fake.ipv4_public(),
                "threatcategory": "Malware" if threat != "-" else "-",
                "threatname": threat,
                "filetype": random.choice(["-", "HTML", "EXE", "PDF", "ZIP"]),
                "appname": random.choice(["General Browsing", "Office365", "Slack", "Zoom", "-"]),
                "pagerisk": str(random.randint(0, 100)),
                "department": dept,
                "urlsupercategory": "Informational",
                "appclass": "General Browsing",
                "dlpengine": "-",
                "urlclass": "Business Use",
                "threatclass": "Malware" if threat != "-" else "-",
                "dlpdictionaries": "-",
                "dlpidentifier": "0",
                "fileclass": "-",
                "bwthrottle": "NO",
                "servertransactiontime": str(random.randint(1, 5000)),
                "contenttype": random.choice(["text/html", "application/json", "image/jpeg"]),
                "unscannabletype": "-",
                "deviceowner": user.split("@")[0],
                "devicehostname": fake.hostname(),
            },
        }

        raw = json.dumps(event)

        return LogEvent(
            raw=raw,
            structured={
                "timestamp": now.isoformat(),
                "user": user,
                "client_ip": client_ip,
                "url": url,
                "action": action,
                "category": category,
                "threat": threat,
                "protocol": protocol,
                "bytes_in": bytes_in,
                "bytes_out": bytes_out,
                "status_code": status,
                "vendor": "zscaler",
                "product": "zia",
            },
            format="json",
            source_id=self.id,
        )
