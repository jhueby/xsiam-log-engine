from __future__ import annotations

import json
import random
import uuid
from datetime import datetime, timezone
from faker import Faker

from sources.base_source import LogEvent, LogSource
from utils.faker_helpers import random_domain_user, random_external_ip, random_internal_ip, weighted_choice

fake = Faker()

_EVENT_TYPES = [
    ("user.session.start", 30),
    ("user.authentication.auth_via_mfa", 25),
    ("user.authentication.sso", 15),
    ("user.session.end", 15),
    ("user.account.lock", 3),
    ("user.account.unlock_by_admin", 1),
    ("user.mfa.factor.activate", 2),
    ("policy.evaluate_sign_on", 5),
    ("system.agent.update", 1),
    ("user.account.update_password", 3),
]
_OUTCOMES = ["SUCCESS", "FAILURE", "SKIPPED", "ALLOW", "DENY", "UNKNOWN"]
_OUT_WEIGHTS = [70, 15, 5, 5, 3, 2]
_MFA_TYPES = ["OKTA_VERIFY", "GOOGLE_AUTHENTICATOR", "SMS", "EMAIL", "HARDWARE_TOKEN", "YUBIKEY"]
_BROWSERS = ["CHROME", "FIREFOX", "SAFARI", "EDGE", "UNKNOWN"]
_OS_LIST = ["Windows 10", "Windows 11", "macOS 14", "iOS 17", "Android 13"]
_AUTH_PROVIDERS = ["OKTA", "ACTIVE_DIRECTORY", "LDAP"]


class OktaSource(LogSource):
    id = "okta"
    display_name = "Okta"
    description = "Okta Identity — authentication, MFA, admin events (Okta System Log schema)"
    default_transport: str = "http"
    supported_transports = ["http"]
    default_eps = 2.0
    tags = ["identity", "sso", "cloud", "okta"]
    xsiam_dataset: str = "okta_system_log_raw"

    async def generate(self) -> LogEvent:
        event_type, _ = weighted_choice(_EVENT_TYPES, [w for _, w in _EVENT_TYPES])
        user = random_domain_user()
        outcome = random.choices(_OUTCOMES, weights=_OUT_WEIGHTS)[0]
        ip = random.choice([random_external_ip(), random_internal_ip()])
        now = datetime.now(timezone.utc)
        mfa_type = random.choice(_MFA_TYPES)

        actor = {
            "id": f"00u{uuid.uuid4().hex[:16]}",
            "type": "User",
            "alternateId": user,
            "displayName": fake.name(),
        }

        target = []
        if "user" in event_type:
            target.append({
                "id": f"00u{uuid.uuid4().hex[:16]}",
                "type": "User",
                "alternateId": user,
                "displayName": fake.name(),
            })

        auth_context = {}
        if "mfa" in event_type or "authentication" in event_type:
            auth_context = {
                "authProvider": random.choice(_AUTH_PROVIDERS),
                "credentialProvider": mfa_type,
                "credentialType": "MFA_ENROLL" if "activate" in event_type else "MFA",
            }

        event = {
            "uuid": str(uuid.uuid4()),
            "published": now.isoformat(),
            "eventType": event_type,
            "version": "0",
            "severity": "INFO" if outcome == "SUCCESS" else "WARN",
            "legacyEventType": event_type.replace(".", "_").upper(),
            "displayMessage": event_type.replace(".", " ").title(),
            "actor": actor,
            "client": {
                "userAgent": {
                    "rawUserAgent": fake.user_agent(),
                    "os": random.choice(_OS_LIST),
                    "browser": random.choice(_BROWSERS),
                },
                "geographicalContext": {
                    "country": fake.country(),
                    "state": fake.state(),
                    "city": fake.city(),
                    "postalCode": fake.postcode(),
                    "geolocation": {"lat": float(fake.latitude()), "lon": float(fake.longitude())},
                },
                "ipAddress": ip,
                "device": random.choice(["Computer", "Mobile", "Tablet", "Unknown"]),
            },
            "outcome": {
                "result": outcome,
                "reason": None if outcome == "SUCCESS" else random.choice([
                    "INVALID_CREDENTIALS", "LOCKED_OUT", "NETWORK_ZONE_VIOLATION",
                    "MFA_ENROLL_REQUIRED", "ACCESS_DENIED",
                ]),
            },
            "target": target,
            "authenticationContext": auth_context,
            "securityContext": {
                "asNumber": random.randint(1000, 65535),
                "asOrg": fake.company(),
                "domain": fake.domain_name(),
                "isProxy": random.random() < 0.05,
            },
            "transaction": {
                "type": "WEB",
                "id": uuid.uuid4().hex,
                "detail": {},
            },
            "debugContext": {"debugData": {"requestId": uuid.uuid4().hex}},
        }

        return LogEvent(
            raw=json.dumps(event),
            structured=event,
            format="json",
            source_id=self.id,
        )
