from __future__ import annotations

import json
import random
import uuid
from datetime import datetime, timezone

from faker import Faker

from sources.base_source import LogEvent, LogSource, ScenarioEntities, TransportName
from utils.faker_helpers import random_external_ip, random_user

fake = Faker()

# Duo Admin API v2 authentication log shapes.
#
# "fraud" is the interesting result: it's what a user reports when a push
# arrives that they didn't trigger, which is the tell for MFA-fatigue /
# push-bombing. "denied" with reason "user_marked_fraud" is that same signal
# from the other direction, so both stay in the mix at low weight.
_RESULTS = ["success", "success", "success", "success", "denied", "fraud"]
_RESULT_WEIGHTS = [72, 8, 6, 4, 7, 3]

_FACTORS = ["duo_push", "duo_push", "duo_push", "passcode", "phone_call", "webauthn_credential", "bypass_code"]
_FACTOR_WEIGHTS = [55, 15, 8, 12, 4, 5, 1]

_DENY_REASONS = [
    "user_marked_fraud", "denied_by_policy", "no_response", "locked_out",
    "invalid_passcode", "anomalous_push",
]
_ALLOW_REASONS = ["user_approved", "trusted_network", "remembered_device", "allow_unenrolled_user"]

_APPS = [
    ("Microsoft 365", "sso"),
    ("GlobalProtect VPN", "rdp"),
    ("AWS Console", "sso"),
    ("Corp Wiki", "web"),
    ("Windows Logon", "rdp"),
]

_ACCESS_OS = ["Windows", "Mac OS X", "iOS", "Android", "Linux"]
_AUTH_DEVICE_TYPES = ["phone", "phone", "token", "webauthn"]


def _build(*, username: str, ip: str, result: str | None = None,
           factor: str | None = None, application: str | None = None) -> dict:
    now = datetime.now(timezone.utc)
    result = result or random.choices(_RESULTS, weights=_RESULT_WEIGHTS)[0]
    factor = factor or random.choices(_FACTORS, weights=_FACTOR_WEIGHTS)[0]
    app_name, app_type = next(
        ((n, t) for n, t in _APPS if n == application),
        random.choice(_APPS),
    )
    if application and app_name != application:
        app_name = application

    if result == "success":
        reason = random.choice(_ALLOW_REASONS)
        event_type = "authentication"
    elif result == "fraud":
        reason = "user_marked_fraud"
        event_type = "authentication"
    else:
        reason = random.choice(_DENY_REASONS)
        event_type = "authentication"

    return {
        "access_device": {
            "browser": random.choice(["Chrome", "Edge", "Safari", "Firefox"]),
            "browser_version": f"{random.randint(118, 126)}.0.0",
            "ip": ip,
            "location": {
                "city": fake.city(),
                "country": random.choice(["US", "GB", "DE", "MA", "IN", "BR"]),
                "state": fake.state(),
            },
            "os": random.choice(_ACCESS_OS),
            "os_version": f"{random.randint(10, 15)}",
        },
        "application": {"key": uuid.uuid4().hex[:20], "name": app_name},
        "auth_device": {
            "ip": ip if random.random() < 0.3 else random_external_ip(),
            "key": uuid.uuid4().hex[:20],
            "location": {"city": fake.city(), "country": random.choice(["US", "GB", "MA"]), "state": fake.state()},
            "name": f"{random.choice(['iPhone', 'Pixel', 'Galaxy'])} ({random.randint(100, 999)})",
        },
        "event_type": event_type,
        "factor": factor,
        "isotimestamp": now.isoformat(),
        "timestamp": int(now.timestamp()),
        "reason": reason,
        "result": result,
        "txid": str(uuid.uuid4()),
        "user": {"key": uuid.uuid4().hex[:20], "name": username},
        "adaptive_trust_assessments": {},
        "alias": "",
        "email": username if "@" in username else f"{username}@corp.local",
        "trusted_endpoint_status": random.choice(["trusted", "not trusted", "unknown"]),
        "access_device_type": app_type,
    }


class DuoMFASource(LogSource):
    id = "duo_mfa"
    display_name = "Duo MFA"
    description = "Cisco Duo — MFA authentication logs (push, passcode, WebAuthn) with allow/deny/fraud outcomes"
    default_transport: TransportName = "http"
    supported_transports = ["http"]
    default_eps = 3.0
    tags = ["identity", "authentication", "mfa", "cloud", "cisco"]

    async def generate(self) -> LogEvent:
        event = _build(username=random_user(), ip=random_external_ip())
        return LogEvent(raw=json.dumps(event), structured=event, format="json", source_id=self.id)

    async def generate_with_entities(
        self, entities: ScenarioEntities, overrides: dict | None = None
    ) -> LogEvent:
        """Scenario mode: pin the MFA decision to the run's identity, so a
        push-fatigue sequence (repeated denies, then an approval) reads as one
        user being worn down rather than unrelated events.

        Recognized overrides: result, factor, application, ip.
        """
        overrides = overrides or {}
        # .get(key, default) -- not `or` -- so an explicit falsy override
        # (e.g. "") is honored instead of silently replaced by random data.
        event = _build(
            username=entities.domain_user,
            ip=overrides.get("ip", entities.external_ip),
            result=overrides.get("result"),
            factor=overrides.get("factor"),
            application=overrides.get("application"),
        )
        return LogEvent(raw=json.dumps(event), structured=event, format="json", source_id=self.id)
