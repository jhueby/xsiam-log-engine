from __future__ import annotations

import json
import random
import uuid
from datetime import datetime, timezone

from faker import Faker

from sources.base_source import LogEvent, LogSource, ScenarioEntities, TransportName
from utils.faker_helpers import random_domain_user, random_external_ip

fake = Faker()

# Unified Audit Log operations, grouped by workload. The Exchange set is
# deliberately weighted toward mailbox-rule and message-deletion activity:
# those are the operations behind the email-hiding and mailbox-clearing
# techniques (T1564.008 / T1070.008) that identity-based intrusions use to
# stay quiet, and they have no equivalent in the Entra ID audit log.
_EXCHANGE_OPS = [
    "New-InboxRule", "Set-InboxRule", "UpdateInboxRules", "Remove-InboxRule",
    "MailItemsAccessed", "Send", "SendAs", "MoveToDeletedItems",
    "SoftDelete", "HardDelete", "Add-MailboxPermission", "Set-Mailbox",
]
_EXCHANGE_WEIGHTS = [4, 3, 5, 2, 30, 18, 3, 12, 8, 5, 3, 7]

_SHAREPOINT_OPS = [
    "FileAccessed", "FileDownloaded", "FileUploaded", "FileModified",
    "FileDeleted", "SharingSet", "AnonymousLinkCreated", "FileSyncDownloadedFull",
]
_SHAREPOINT_WEIGHTS = [35, 20, 12, 15, 6, 6, 2, 4]

_WORKLOADS = ["Exchange", "SharePoint", "OneDrive"]
_WORKLOAD_WEIGHTS = [55, 30, 15]

_RECORD_TYPES = {"Exchange": 2, "SharePoint": 6, "OneDrive": 6}

_FILE_NAMES = [
    "Gift Card Issuance Process.docx", "Q3 Vendor Payments.xlsx",
    "VPN Access Guide.pdf", "Employee Handbook.pdf", "Card Program Runbook.docx",
    "Ticketing Export.csv", "Payroll Summary.xlsx", "Network Diagram.vsdx",
]

_CLIENT_APPS = ["Outlook", "OWA", "MacOutlook", "REST", "MobileApp", "Browser"]


def _inbox_rule_params(target_folder: str = "Deleted Items") -> list[dict]:
    """Parameters for an inbox rule that quietly files or forwards mail —
    the shape a defender would look for when hunting mailbox-rule abuse."""
    return [
        {"Name": "AlwaysDeleteOutlookRulesBlob", "Value": "False"},
        {"Name": "Force", "Value": "False"},
        {"Name": "MoveToFolder", "Value": target_folder},
        {"Name": "Name", "Value": random.choice(["...", " ", "..", "Rules", "s"])},
        {"Name": "SubjectOrBodyContainsWords", "Value": random.choice(
            ["invoice;payment;gift card", "password;verify;account", "security;alert"])},
        {"Name": "MarkAsRead", "Value": "True"},
        {"Name": "StopProcessingRules", "Value": "True"},
    ]


def _build(*, operation: str, workload: str, user: str, ip: str) -> dict:
    now = datetime.now(timezone.utc)
    event: dict = {
        "CreationTime": now.isoformat(),
        "Id": str(uuid.uuid4()),
        "Operation": operation,
        "OrganizationId": str(uuid.uuid4()),
        "RecordType": _RECORD_TYPES.get(workload, 2),
        "ResultStatus": "Succeeded",
        "UserKey": str(uuid.uuid4()),
        "UserType": 0,
        "Version": 1,
        "Workload": workload,
        "ClientIP": ip,
        "UserId": user,
        "AppId": str(uuid.uuid4()),
        "ClientAppId": str(uuid.uuid4()),
    }

    if workload == "Exchange":
        event.update({
            "MailboxGuid": str(uuid.uuid4()),
            "MailboxOwnerUPN": user,
            "ClientInfoString": f"Client={random.choice(_CLIENT_APPS)}",
            "ExternalAccess": random.random() < 0.15,
            "InternalLogonType": 0,
            "LogonType": 0,
            "LogonUserSid": f"S-1-5-21-{random.randint(10**8, 10**9)}-{random.randint(1000, 9999)}",
            "OriginatingServer": f"{fake.hostname()} (15.20.0000.000)",
        })
        if operation in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules", "Remove-InboxRule"):
            event["Parameters"] = _inbox_rule_params()
            event["ObjectId"] = f"{user}\\{random.choice(['...', 'Rules'])}"
        elif operation == "MailItemsAccessed":
            event["OperationProperties"] = [
                {"Name": "MailAccessType", "Value": random.choice(["Bind", "Sync"])},
                {"Name": "IsThrottled", "Value": "False"},
            ]
            event["Folders"] = [{
                "Path": random.choice(["\\Inbox", "\\Sent Items", "\\Archive"]),
                "FolderItems": [{"InternetMessageId": f"<{uuid.uuid4()}@corp.local>"}],
            }]
        elif operation in ("MoveToDeletedItems", "SoftDelete", "HardDelete"):
            event["AffectedItems"] = [{
                "Subject": random.choice([
                    "Action required: verify your account",
                    "Your gift card order",
                    "IT: password expiry notice",
                ]),
                "InternetMessageId": f"<{uuid.uuid4()}@corp.local>",
            }]
            event["Folder"] = {"Path": "\\Inbox"}
    else:
        site = random.choice(["Finance", "Operations", "IT", "HR"])
        file_name = random.choice(_FILE_NAMES)
        event.update({
            "ObjectId": f"https://corp.sharepoint.com/sites/{site}/Shared Documents/{file_name}",
            "SiteUrl": f"https://corp.sharepoint.com/sites/{site}/",
            "SourceFileName": file_name,
            "SourceFileExtension": file_name.rsplit(".", 1)[-1],
            "SourceRelativeUrl": f"Shared Documents/{file_name}",
            "EventSource": "SharePoint",
            "ItemType": "File",
            "ListItemUniqueId": str(uuid.uuid4()),
            "UserAgent": fake.user_agent(),
        })
        if operation in ("SharingSet", "AnonymousLinkCreated"):
            event["TargetUserOrGroupName"] = random_domain_user()
            event["TargetUserOrGroupType"] = random.choice(["Guest", "Member"])

    return event


class M365AuditSource(LogSource):
    id = "m365_audit"
    display_name = "Microsoft 365 Audit"
    description = "Microsoft 365 Unified Audit Log — Exchange mailbox, SharePoint/OneDrive file activity"
    default_transport: TransportName = "http"
    supported_transports = ["http"]
    default_eps = 4.0
    tags = ["cloud", "microsoft", "email", "saas", "audit"]
    xsiam_dataset: str = "msft_o365_audit_raw"

    async def generate(self) -> LogEvent:
        workload = random.choices(_WORKLOADS, weights=_WORKLOAD_WEIGHTS)[0]
        if workload == "Exchange":
            operation = random.choices(_EXCHANGE_OPS, weights=_EXCHANGE_WEIGHTS)[0]
        else:
            operation = random.choices(_SHAREPOINT_OPS, weights=_SHAREPOINT_WEIGHTS)[0]

        event = _build(
            operation=operation,
            workload=workload,
            user=random_domain_user(),
            ip=random_external_ip(),
        )
        return LogEvent(raw=json.dumps(event), structured=event, format="json", source_id=self.id)

    async def generate_with_entities(
        self, entities: ScenarioEntities, overrides: dict | None = None
    ) -> LogEvent:
        """Scenario mode: attribute the mailbox/file activity to the run's
        shared identity.

        Recognized overrides: operation, workload, ip.
        """
        overrides = overrides or {}
        # .get(key, default) -- not `or` -- so an explicit falsy override
        # (e.g. "") is honored instead of silently replaced by random data.
        operation = overrides.get("operation")
        if operation is None:
            workload = overrides.get("workload", random.choices(_WORKLOADS, weights=_WORKLOAD_WEIGHTS)[0])
            operation = (random.choices(_EXCHANGE_OPS, weights=_EXCHANGE_WEIGHTS)[0]
                         if workload == "Exchange"
                         else random.choices(_SHAREPOINT_OPS, weights=_SHAREPOINT_WEIGHTS)[0])
        else:
            # Derive the workload from the operation so a caller can name just
            # the operation without also having to know which workload logs it.
            default_workload = "Exchange" if operation in _EXCHANGE_OPS else "SharePoint"
            workload = overrides.get("workload", default_workload)

        event = _build(
            operation=operation,
            workload=workload,
            user=entities.domain_user,
            # External by default: in these stories the mailbox is being driven
            # from attacker infrastructure, not the user's own workstation.
            ip=overrides.get("ip", entities.external_ip),
        )
        return LogEvent(raw=json.dumps(event), structured=event, format="json", source_id=self.id)
