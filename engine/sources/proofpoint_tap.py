from __future__ import annotations

import json
import random
import uuid
from datetime import datetime, timezone

from faker import Faker

from sources.base_source import LogEvent, LogSource, TransportName
from utils.faker_helpers import random_domain_user, random_external_ip, random_internal_ip

fake = Faker()

_EVENT_TYPES = ["messagesBlocked", "messagesDelivered", "clicksBlocked", "clicksPermitted"]
_TYPE_WEIGHTS = [30, 35, 15, 20]

_THREAT_TYPES = ["url", "attachment", "messageText"]
_THREAT_WEIGHTS = [50, 35, 15]

_CLASSIFICATIONS = ["malware", "phish", "spam", "impostor", "bulkEmail"]
_CLASS_WEIGHTS = [30, 35, 20, 10, 5]

_MALWARE_FAMILIES = [
    "Emotet", "QBot", "IcedID", "AgentTesla", "FormBook",
    "RedLine", "Raccoon", "Vidar", "LokiBot", "NanoCore",
]

_PHISH_THEMES = [
    "Microsoft 365 credential phish", "DocuSign phish", "PayPal phish",
    "HR policy update phish", "SharePoint file share phish",
    "IT password expiry phish", "Zoom meeting phish",
]

_POLICY_ROUTES = [
    "default_inbound", "executive_protection", "finance_protection",
    "allow_list_override", "quarantine_policy",
]

_MODULES = ["spam", "pdr", "urldefense", "sandboxing", "impostor", "content_filter"]

_CLUSTER_IDS = ["proofpoint_cloud_us", "proofpoint_cloud_eu", "proofpoint_hosted"]


def _threat_info(threat_type: str, classification: str) -> dict:
    threat_id = uuid.uuid4().hex * 2
    return {
        "campaignId": f"tid-{uuid.uuid4().hex[:12]}" if random.random() < 0.6 else None,
        "classification": classification,
        "threat": fake.url() if threat_type == "url" else random.choice(_MALWARE_FAMILIES),
        "threatId": threat_id,
        "threatStatus": random.choices(["active", "cleared", "falsePositive"], weights=[70, 20, 10])[0],
        "threatTime": datetime.now(timezone.utc).isoformat(),
        "threatType": threat_type,
        "threatUrl": f"https://threatinsight.proofpoint.com/threat/email/inboundemails/{threat_id}",
    }


def _message_parts(threat_type: str) -> list[dict]:
    parts = [{
        "contentType": "text/html",
        "disposition": "inline",
        "filename": "text.html",
        "md5": uuid.uuid4().hex,
        "oContentType": "text/html",
        "sandboxStatus": None,
        "sha256": uuid.uuid4().hex * 2,
    }]
    if threat_type == "attachment":
        ext = random.choice(["doc", "docx", "xls", "xlsx", "pdf", "zip", "exe", "js", "vbs"])
        parts.append({
            "contentType": "application/octet-stream",
            "disposition": "attachment",
            "filename": f"Invoice_{random.randint(1000,9999)}.{ext}",
            "md5": uuid.uuid4().hex,
            "oContentType": f"application/{ext}",
            "sandboxStatus": random.choice(["threat", "clean", "unsupported"]),
            "sha256": uuid.uuid4().hex * 2,
        })
    return parts


def _message_event(blocked: bool) -> dict:
    threat_type = random.choices(_THREAT_TYPES, weights=_THREAT_WEIGHTS)[0]
    classification = random.choices(_CLASSIFICATIONS, weights=_CLASS_WEIGHTS)[0]
    recipient = random_domain_user()
    sender_domain = fake.domain_name()
    sender = f"{fake.user_name()}@{sender_domain}"
    sender_ip = random_external_ip()
    now = datetime.now(timezone.utc)

    malware_score = random.randint(60, 100) if classification == "malware" else random.randint(0, 20)
    phish_score = random.randint(70, 100) if classification == "phish" else random.randint(0, 30)
    spam_score = random.randint(60, 100) if classification == "spam" else random.randint(0, 40)

    event: dict = {
        "GUID": str(uuid.uuid4()),
        "QID": f"s{random.randint(1000000000, 9999999999)}",
        "ccAddresses": [],
        "clusterId": random.choice(_CLUSTER_IDS),
        "completelyRewritten": threat_type == "url",
        "fromAddress": [sender],
        "headerFrom": f'"{fake.name()}" <{sender}>',
        "headerReplyTo": None,
        "id": str(uuid.uuid4()),
        "impostorScore": random.randint(50, 100) if classification == "impostor" else 0,
        "malwareScore": malware_score,
        "messageID": f"<{uuid.uuid4().hex}@{sender_domain}>",
        "messageParts": _message_parts(threat_type),
        "messageSize": random.randint(4096, 512000),
        "messageTime": now.isoformat(),
        "modulesRun": random.sample(_MODULES, k=random.randint(2, 5)),
        "phishScore": phish_score,
        "policyRoutes": random.sample(_POLICY_ROUTES, k=random.randint(1, 2)),
        "quarantineFolder": "Phish" if blocked else None,
        "quarantineRule": f"module.{classification}" if blocked else None,
        "recipientEmails": [recipient],
        "replyToAddress": [],
        "sender": sender,
        "senderIP": sender_ip,
        "spamScore": spam_score,
        "subject": random.choice(_PHISH_THEMES) if classification in ("phish", "impostor") else fake.sentence(nb_words=5),
        "threatsInfoMap": [_threat_info(threat_type, classification)],
        "toAddresses": [recipient],
        "xmailer": None,
        "type": "messagesBlocked" if blocked else "messagesDelivered",
    }
    return event


def _click_event(blocked: bool) -> dict:
    classification = random.choices(["malware", "phish"], weights=[40, 60])[0]
    threat_type = "url"
    recipient = random_domain_user()
    sender = f"{fake.user_name()}@{fake.domain_name()}"
    now = datetime.now(timezone.utc)
    threat_id = uuid.uuid4().hex * 2

    return {
        "campaignId": f"tid-{uuid.uuid4().hex[:12]}" if random.random() < 0.7 else None,
        "classification": classification,
        "clickIP": random_internal_ip(),
        "clickTime": now.isoformat(),
        "GUID": str(uuid.uuid4()),
        "id": str(uuid.uuid4()),
        "messageID": f"<{uuid.uuid4().hex}@{fake.domain_name()}>",
        "messageSender": sender,
        "messageTime": now.isoformat(),
        "recipient": recipient,
        "sender": sender,
        "senderIP": random_external_ip(),
        "threatID": threat_id,
        "threatTime": now.isoformat(),
        "threatURL": fake.url(),
        "threatStatus": random.choices(["active", "cleared"], weights=[75, 25])[0],
        "type": "clicksBlocked" if blocked else "clicksPermitted",
        "url": fake.url(),
        "userAgent": fake.user_agent(),
    }


_GENERATORS: dict[str, callable] = {
    "messagesBlocked": lambda: _message_event(blocked=True),
    "messagesDelivered": lambda: _message_event(blocked=False),
    "clicksBlocked": lambda: _click_event(blocked=True),
    "clicksPermitted": lambda: _click_event(blocked=False),
}


class ProofpointTAPSource(LogSource):
    id = "proofpoint_tap"
    display_name = "Proofpoint TAP"
    description = "Proofpoint Targeted Attack Protection — blocked/delivered messages and URL click events (SIEM API v2 schema)"
    default_transport: TransportName = "http"
    supported_transports = ["http"]
    default_eps = 2.0
    tags = ["email", "cloud", "proxy"]
    xsiam_dataset: str = "proofpoint_tap_raw"

    async def generate(self) -> LogEvent:
        event_type = random.choices(_EVENT_TYPES, weights=_TYPE_WEIGHTS)[0]
        event = _GENERATORS[event_type]()
        event["timestamp"] = datetime.now(timezone.utc).isoformat()

        return LogEvent(
            raw=json.dumps(event),
            structured=event,
            format="json",
            source_id=self.id,
        )
